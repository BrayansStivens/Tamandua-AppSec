English · [Español](es/despliegue.md)

# Where to deploy Tamandua

Tamandua has three pieces, and each one can live wherever suits you:

| Piece | What it needs | Image |
| --- | --- | --- |
| **API and panel** | HTTP and the database. No disk of its own: every piece of state is in PostgreSQL. | `ghcr.io/brayansstivens/tamandua` |
| **Worker** | A long-running process that runs the analysis engines. | `ghcr.io/brayansstivens/tamandua-worker` (engines inside), or the API image with the Docker socket |
| **PostgreSQL** | Version 16 or later, managed or in a container. | — |

Each version tag publishes the images, signed and multi-architecture (use `0.10.0` or later: in `0.9.0` and `0.9.1` the `tamandua` image started the worker instead of the API). You can also build them from the repository (`make build`, or `docker build --target worker-standalone -f docker/app/Dockerfile .` for the worker).

## Access while the repository is private

For now the repository and its images on GitHub's registry are private. Without access, `git clone` answers
*Repository not found* and pulling an image answers *denied*. Once the maintainer has given you access, use two
read-only credentials, one per job:

| For | Credential | Permission |
| --- | --- | --- |
| Pulling the images | Classic personal access token, with an expiration date (GitHub's registry doesn't take fine-grained tokens) | Only `read:packages` |
| Cloning the code | Deploy key: an SSH key the maintainer adds to the repository | Read-only, this repository only |

On the server, as the user that runs Docker:

```bash
read -rs GHCR_TOKEN && printf '%s' "$GHCR_TOKEN" | docker login ghcr.io -u <your-github-user> --password-stdin
ssh-keygen -t ed25519 -N '' -f ~/.ssh/tamandua-deploy   # send ~/.ssh/tamandua-deploy.pub to the maintainer
```

The maintainer adds it under *Settings → Deploy keys* without *Allow write access*. Then clone with it, and keep it
for the upgrades' `git fetch`:

```bash
export GIT_SSH_COMMAND='ssh -i ~/.ssh/tamandua-deploy -o IdentitiesOnly=yes'
git clone git@github.com:BrayansStivens/Tamandua-AppSec.git && cd Tamandua-AppSec
git config core.sshCommand "$GIT_SSH_COMMAND"
```

- `docker login` keeps the token in `~/.docker/config.json`, encoded but not encrypted: that's why it only reads
  packages. `make up`, `make update` and `make verify-images` use it; no need to repeat it.
- **One-file Compose** needs the same login. Take `deploy/compose.yaml` from the clone.
- **Coolify, Dokploy, Render, Railway and other platforms:** add `ghcr.io` as a private registry in the platform, with
  your user and the packages token.
- **CI** (the `git clone` in [cli.md](cli.md)): store a deploy key as a secret and clone with it.

When the repository becomes public, none of this is needed: revoke the token, ask for the deploy key to be removed and
run `docker logout ghcr.io`.

## Pick a target

| Target | API and panel | Worker | PostgreSQL | Guide | Tried |
| --- | --- | --- | --- | --- | --- |
| Your own server, with the repository | Compose | Compose, Docker socket | Container | [deploy-vps.md](deploy-vps.md) | Yes |
| Your own server, **one file** (Coolify, Dokploy, Portainer, Hostinger's Docker manager) | Compose | Compose, engines inside | Container | [below](#one-file-any-server-or-docker-panel) | Locally, end to end |
| Render | Web service | Background worker | Render Postgres | [below](#render) | Not yet |
| Railway, Fly.io | Service | Service | Their Postgres | [below](#railway-flyio-and-other-container-platforms) | Not yet |
| Vercel | Python function | Elsewhere (any row above) | Neon, Supabase… | [below](#vercel) | The ASGI entry, locally |
| Kubernetes | Deployment | Deployment | Your operator | [below](#kubernetes) | Not yet |

Whatever the target, the same four values matter:

```bash
TAMANDUA_DATABASE_URL=postgresql://user:password@host:5432/tamandua   # postgres:// and postgresql:// both work
TAMANDUA_MASTER_KEY=<openssl rand -base64 32>                          # the same on the API and every worker
TAMANDUA_PUBLIC_URL=https://tamandua.example.com
TAMANDUA_ALLOWED_ORIGINS=https://tamandua.example.com                  # every address people open it by
```

The master key decrypts every stored secret: GitHub App, AI keys, Jira, notification channels, TOTP seeds and the
session signing key. Keep it in the platform's secrets manager, with a copy apart from the database backups.
`tamandua check-config` checks every setting and names what's wrong.

## One file: any server or Docker panel

[`deploy/compose.yaml`](../deploy/compose.yaml) is self-contained: published images, named volumes, no build, no
repository and no Docker socket (the worker runs the engines inside its own image).

```bash
curl -fsSLO https://raw.githubusercontent.com/BrayansStivens/Tamandua-AppSec/main/deploy/compose.yaml
printf 'TAMANDUA_DB_PASSWORD=%s\nTAMANDUA_MASTER_KEY=%s\nTAMANDUA_PUBLIC_URL=%s\n' \
  "$(openssl rand -hex 24)" "$(openssl rand -base64 32)" "https://tamandua.example.com" > .env
docker compose --profile https up -d        # --profile https: Caddy gets the certificate (skip it behind your own proxy)
docker compose exec api python -m tamandua setup-code
```

- **Coolify and Dokploy:** create a *Docker Compose* resource, paste the file, set the three variables in the
  environment screen and point your domain at the `api` service, port 8766. Leave the `https` profile off: the
  platform's proxy terminates TLS.
- **Hostinger:** in the VPS panel, open the Docker manager, create a project from Compose, and paste the file and the
  variables. With no other proxy on the server, add `COMPOSE_PROFILES=https`.
- **Portainer:** *Stacks → Add stack*, paste the file, add the variables.
- **Backups:** `--profile backup` writes `pg_dump` copies to `./backups` every 24 h (change it with
  `TAMANDUA_BACKUP_INTERVAL_HOURS`). The master key isn't in them: keep it apart.

Sizing: 2 vCPU and 4 GB of memory run one scan at a time; 8 GB leaves room. The worker image is about 1.8 GB.

## Render

[`render.yaml`](../render.yaml) is a Blueprint with the API (web service), the worker (background worker) and
PostgreSQL. *New → Blueprint*, pick the repository, and enter `TAMANDUA_PUBLIC_URL` when asked
(`https://<service>.onrender.com` or your domain). Render generates the master key (32 random bytes in base64, exactly
its format) and shares it with the worker. Read it once from the API's environment and keep a copy.

## Railway, Fly.io and other container platforms

Two services from the published images, plus the platform's PostgreSQL:

| Service | Image | Variables besides the four above |
| --- | --- | --- |
| api | `ghcr.io/brayansstivens/tamandua:<version>` | `TAMANDUA_BIND=0.0.0.0`, `TAMANDUA_EMBEDDED_WORKER=0`, `TAMANDUA_FORWARDED_ALLOW_IPS=*`, port 8766 |
| worker | `ghcr.io/brayansstivens/tamandua-worker:<version>` | none |

On Railway, reference the database as `TAMANDUA_DATABASE_URL=${{Postgres.DATABASE_URL}}`. Give the worker at least
2 GB of memory. Its caches (the engines' databases) can live on ephemeral disk: they download again after a redeploy.

## Vercel

Vercel runs the **API and panel** as a Python function ([`vercel.json`](../vercel.json), entry `api/index.py`, which
imports `tamandua.app.asgi`). It can't run the worker: a scan can take longer than a function may run, and there is no
long-running process. Run the worker on any other row of the table, against the same database and master key.

1. Create a PostgreSQL database (Neon, Supabase or another) that both can reach.
2. Import the repository in Vercel and set the four variables. Put every address you open it by in
   `TAMANDUA_ALLOWED_ORIGINS`: the production domain, and preview URLs if you use them.
3. Start the worker elsewhere with the same `TAMANDUA_DATABASE_URL` and `TAMANDUA_MASTER_KEY`.
4. The setup code shows in the function's logs on the first request; `tamandua setup-code`, run anywhere with the same
   variables, shows it too.

If the worker can't run all the time (it scales to zero), set `TAMANDUA_PERIODIC=external` on both and let a scheduler
trigger the periodic tasks: add `"crons": [{"path": "/api/cron", "schedule": "*/5 * * * *"}]` to `vercel.json` and a
`CRON_SECRET` of at least 32 characters (Vercel sends it as a bearer token). Vercel's Hobby plan only allows one run a
day.

## Kubernetes

No manifests ship yet. The pieces map directly: a Deployment for the API (port 8766, `/api/health` as the probe), one
for the worker image (it needs no Docker socket), the four variables from a Secret, and a PostgreSQL of your choice.
With `TAMANDUA_PERIODIC=external`, a CronJob running `python -m tamandua periodic` replaces the leader worker's clock.

## Periodic tasks

Delivering notifications, polling pull requests, syncing NVD and the daily check for new advisories run on a clock:

- `TAMANDUA_PERIODIC=leader` (default): one worker, elected through a PostgreSQL lock, runs them. Nothing to set up.
- `TAMANDUA_PERIODIC=external`: nothing runs on its own. A scheduler calls `tamandua periodic` (cron, a CronJob) or
  `GET /api/cron` with `Authorization: Bearer <TAMANDUA_CRON_TOKEN or CRON_SECRET>`. Each call runs what is due; the
  API queues the NVD sync and the advisory check for a worker, since they need the engines or take long.
