English · [Español](es/despliegue-vps.md)

# Deploy on a VPS

This guide puts Tamandua on its own server (Hetzner, DigitalOcean, Hostinger, OVH, any VPS with Docker) under your domain, with HTTPS, backups and monitoring. For a laptop, `make up` is still all you need: see [installation.md](installation.md).

With a fresh server and a DNS record already pointing at it, it's four commands:

```bash
git clone https://github.com/BrayansStivens/Tamandua-AppSec.git && cd Tamandua-AppSec
git checkout v0.10.1                                   # the release you want (see Upgrades)
make setup DOMAIN=tamandua.example.com PREBUILT=1   # HTTPS with Caddy + published images
make up                                             # prints https://tamandua.example.com and the setup code
```

While the repository is private, `git clone` and the published images need access and two read-only credentials: set them
up first as shown in [Access while the repository is private](deploy.md#access-while-the-repository-is-private).

The rest of this page covers what to prepare before, and what to do after.

## How it's laid out

```
internet ──443/80──▶ caddy ──edge network──▶ api (panel + API, no published port)
                                               │
                                     default network ── postgres (no published port)
                                               │
                                             worker ──docker.sock──▶ engine containers (one per scan step)
```

- `compose.prod.yaml` adds **Caddy**: it gets and renews the certificate for your domain (Let's Encrypt, with ZeroSSL as fallback), redirects HTTP to HTTPS, and is the only thing that publishes ports. The api publishes none; `TAMANDUA_PUBLIC_URL` and `TAMANDUA_ALLOWED_ORIGINS` become `https://<domain>`.
- `compose.images.yaml` (with `PREBUILT`) runs the images published on GitHub's registry instead of building on the server. They're multi-architecture (amd64 and arm64), carry an SBOM and provenance, and are signed with cosign.
- `make setup DOMAIN=…` writes both overlays into `COMPOSE_FILE` in `.env`, so every `make` command and every plain `docker compose` command uses them.

## 1. Choose the server

| | Minimum | Comfortable |
| --- | --- | --- |
| CPU | 2 vCPU | 4 vCPU |
| Memory | 4 GB (+2 GB swap) | 8 GB |
| Disk | 40 GB SSD | 80 GB SSD |
| Architecture | amd64 or arm64 (Hetzner CAX, Graviton, Ampere) | |

Where it goes: each scan runs one engine at a time, capped at 2 CPUs and 3 GB of memory; the app and PostgreSQL use about 400 MB at rest. On disk, the engine images take ~2 GB, Trivy's database ~1.3 GB, Grype's ~2.1 GB (only if you scan container images), the local NVD copy ~0.7 GB, and each scan keeps a snapshot of the repository while it runs. Add room for your backups if they stay on the same disk before going offsite.

Use a **dedicated server** for Tamandua, not one shared with other applications or other people: see [Hardening](#hardening).

## 2. Prepare the operating system

On Ubuntu 24.04 (Debian works the same, with `debian` in the Docker URLs). As root, the first time only:

```bash
# A user for Tamandua, with your SSH key; after this, never log in as root again.
adduser --disabled-password --gecos "" tamandua
mkdir -p /home/tamandua/.ssh && cp ~/.ssh/authorized_keys /home/tamandua/.ssh/
chown -R tamandua:tamandua /home/tamandua/.ssh && chmod 700 /home/tamandua/.ssh
usermod -aG sudo tamandua && passwd tamandua   # a sudo password for maintenance

# SSH: keys only, no root. A drop-in that sorts first wins over the cloud image's own (50-cloud-init.conf).
printf 'PasswordAuthentication no\nPermitRootLogin no\n' > /etc/ssh/sshd_config.d/10-tamandua.conf
sshd -t && systemctl restart ssh

# Security updates on their own.
apt-get update && apt-get install -y unattended-upgrades && dpkg-reconfigure -plow unattended-upgrades

# Firewall: SSH, HTTP and HTTPS only.
ufw default deny incoming && ufw default allow outgoing
ufw allow 22/tcp && ufw allow 80/tcp && ufw allow 443/tcp && ufw allow 443/udp
ufw enable
```

Docker Engine, from Docker's own repository (the distribution's `docker.io` package lags behind and has no Compose v2):

```bash
apt-get install -y ca-certificates curl make git
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" > /etc/apt/sources.list.d/docker.list
apt-get update && apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
usermod -aG docker tamandua
```

Membership in the `docker` group is equivalent to root on this machine: give it only to the people who administer the server.

**Docker and ufw.** Ports that Docker publishes skip ufw's rules. That's why Tamandua publishes only 80 and 443 (Caddy) and nothing else: PostgreSQL and the API are on internal networks. Don't add `ports:` to other services. If your provider offers a cloud firewall (Hetzner Cloud Firewall, DigitalOcean Cloud Firewalls, Hostinger's VPS firewall), apply the same rule there too: in 22, 80, 443; out, everything.

## 3. Point the domain

Create an **A** record (and **AAAA** if the server has IPv6) for the name you'll use, e.g. `tamandua.example.com`, pointing at the server's public IP. Check it before starting, because Caddy requests the certificate as soon as it starts:

```bash
dig +short tamandua.example.com     # must print the server's IP
```

Optionally, a CAA record `0 issue "letsencrypt.org"` limits who can issue certificates for that name. If you add it, also allow `sectigo.com` (ZeroSSL, Caddy's fallback) or Caddy will only have one option.

## 4. Configure

As the `tamandua` user (while the repository is private, log in to `ghcr.io` first and clone with the deploy key, as in
[Access while the repository is private](deploy.md#access-while-the-repository-is-private)):

```bash
git clone https://github.com/BrayansStivens/Tamandua-AppSec.git && cd Tamandua-AppSec
git checkout v0.10.1
make setup DOMAIN=tamandua.example.com PREBUILT=1
make doctor
```

`make setup` creates `.env` with your UID/GID and a random database password, and in server mode also writes:

| Variable | Value | Why |
| --- | --- | --- |
| `TAMANDUA_DOMAIN` | your domain | Caddy's certificate and site. |
| `TAMANDUA_PUBLIC_URL` / `TAMANDUA_ALLOWED_ORIGINS` | `https://<domain>` | Secure cookies, HSTS, CSRF and allowed `Host`. The overlay derives them from the domain anyway. |
| `COMPOSE_FILE` | `compose.yaml:compose.prod.yaml[:compose.images.yaml]` | Every command uses the overlays. |
| `TAMANDUA_IMAGE` | `ghcr.io/brayansstivens/tamandua` | Only with `PREBUILT`. For a fork: `PREBUILT=ghcr.io/you/tamandua`. |
| `TAMANDUA_METRICS_TOKEN` | 64 random characters | Turns on `/api/metrics` (see [Monitoring](#monitoring)). |

Without `PREBUILT`, the server builds the images from the code (a few minutes, and more memory while it builds). Both ways run the same code.

Worth reviewing in `.env` before the first start (all in [configuration.md](configuration.md)):

- `TAMANDUA_REQUIRE_TOTP=all`: two-factor for everyone, not only admins. Recommended on the internet.
- `TAMANDUA_DEFAULT_LOCALE=es` if your team reads Spanish (PR comments, notifications, reports).
- `TAMANDUA_NVD_API_KEY`: the CVE copy downloads in minutes instead of hours.
- `TAMANDUA_MASTER_KEY`: by default the vault key is generated in `config/master.key`. If you set it here (or from your secrets manager), keep a copy apart: it's no longer in the `config/` backups.
- `COMPOSE_PROFILES=backup`: scheduled backups (see [Backups](#backups)).

Keep a copy of `.env` in your password manager: it holds the database password, the metrics token and, if you set it, the master key.

## 5. Start and create the administrator

With the published images, check their signatures first ([cosign](https://docs.sigstore.dev/cosign/system_config/installation/) installed):

```bash
make verify-images    # Signed by BrayansStivens/Tamandua-AppSec: ghcr.io/brayansstivens/tamandua:0.10 …
make up
```

`make up` pulls (or builds), starts everything, waits until the panel answers, pulls the engines and prints the URL and the **setup code**. Open `https://<domain>`, enter the code and create your admin user; then turn on two-factor under **Account**. If the page doesn't load, `make logs SERVICE=caddy` shows whether the certificate was issued (the usual causes: the DNS record doesn't point here yet, or port 80 is closed).

The code is printed only on the server console: whoever opens the URL before you can't take over the instance. `make setup-code` prints it again while no administrator exists.

## 6. GitHub App on a public domain

Follow [github-app.md](github-app.md) with these values:

| Field | Value |
| --- | --- |
| Homepage URL | `https://<domain>` |
| Setup URL | `https://<domain>/oauth/callback`, with **Redirect on update** |
| Callback URL | empty |
| Webhook | inactive: Tamandua polls pull requests, GitHub never needs to reach your server |

## Backups

Three things make up an instance: the **database** (runs, findings, triage, users and the encrypted secrets), the **master key** (`config/master.key`, or `TAMANDUA_MASTER_KEY` in `.env`) and **`.env`**. `data/` holds caches and logs: useful, but it all rebuilds.

**Scheduled, inside Compose.** Add `COMPOSE_PROFILES=backup` to `.env` and run `make up`. The `backup` service writes `backups/auto-<date>/` (database.dump, config.tgz, data.tgz) every `TAMANDUA_BACKUP_INTERVAL_HOURS` (24) and deletes its own copies older than `TAMANDUA_BACKUP_KEEP_DAYS` (14). It doesn't stop the app (`pg_dump` is consistent on its own), gets only the database password and mounts `config/` and `data/` read-only. Its healthcheck turns unhealthy if the last backup is older than two intervals. `TAMANDUA_BACKUP_DIR` moves them elsewhere (e.g. a mounted volume).

**With cron, from the host.** `make backup` does the same, stopping the API for a few seconds so `data/` is consistent too; it refuses to run while scans are in progress (and then cron retries the next day):

```cron
30 3 * * * cd /home/tamandua/Tamandua-AppSec && make backup >> backups/cron.log 2>&1
```

**Offsite, always.** A backup on the same disk doesn't survive the server. `config.tgz` holds the master key next to the vault it opens, so the offsite copy must be **encrypted**. For example with [restic](https://restic.net) to any S3-compatible bucket (Backblaze B2, Hetzner Object Storage, R2…):

```cron
0 4 * * * cd /home/tamandua/Tamandua-AppSec && restic backup backups/ --tag tamandua && restic forget --keep-daily 14 --keep-weekly 8 --prune
```

(`RESTIC_REPOSITORY`, `RESTIC_PASSWORD_FILE` and the bucket credentials in the crontab environment; keep the restic password outside the server.) Keep old copies locally only for a few days: `find backups -maxdepth 1 -name '20*' -mtime +7 -exec rm -rf {} +`.

**Restore.** Tested, on the same server or on a new one:

```bash
make restore FROM=backups/<date> CONFIRM=restore
make up
```

It checks the backup before touching anything, saves the current state in `backups/pre-restore-<date>/` (so `make restore FROM=backups/pre-restore-<date> CONFIRM=restore` undoes it), drops and recreates the database from `database.dump`, replaces `config/` and extracts `data/`. On a **new server**: prepare it as above, restore your `.env`, clone the same version, `make setup`, copy the backup folder into `backups/` and run the two commands. Restore on the same Tamandua version as the backup or a newer one: the app migrates data forward when it starts, never backwards. It assumes `config/` in the repository (the default `TAMANDUA_HOST_CONFIG_DIR`).

If `config/master.key` is lost (or `TAMANDUA_MASTER_KEY` changes), the secrets can't be decrypted: you'd reconnect the GitHub App and re-enter the AI and Jira keys. Nothing else is lost.

## Upgrades

```bash
git fetch --tags && git checkout v0.9.2    # or stay on main and let make update pull it
make update
```

`make update` pulls the code (`git pull --ff-only` when you're on a branch; on a tag it keeps the version you checked out), takes a backup with `make backup` (it stops if scans are running: try again later), pulls the new images, restarts, and the app migrates the database on start. Read the release notes before a minor version jump. To roll back: check out the previous tag and `make restore FROM=backups/<the backup make update took> CONFIRM=restore`, then `make up`.

With `PREBUILT`, the image tag follows the checked-out code (`tamandua/version.py`), so compose files, rules and images always match. To pin by digest, set `TAMANDUA_IMAGE_TAG=0.9@sha256:…` in `.env`.

## Monitoring

**Health checks.** Docker watches every service: `api` (`/api/health`), `worker` (its heartbeat in the database) and `backup`. `make status` shows them; restart on failure is automatic. From outside, point an uptime monitor at `https://<domain>/api/health`: it answers `200 {"status": "ok"}` while the API is up. For a signed-in person it also says `"status": "degraded"` when no worker has sent a heartbeat (nothing would get scanned), with the number of workers and whether they reach Docker.

**Metrics.** `GET /api/metrics` in Prometheus format, with `Authorization: Bearer <TAMANDUA_METRICS_TOKEN>` (off while the variable is empty; answers 404 then). Only aggregates: no repository names, identifiers or findings.

| Metric | Meaning |
| --- | --- |
| `tamandua_jobs{status}` | Jobs in the queue by status (`queued`, `running`, `done`, `failed`). |
| `tamandua_jobs_oldest_queued_age_seconds` | How long the oldest queued job has waited. |
| `tamandua_jobs_failed_24h` | Jobs that failed in the last 24 hours. |
| `tamandua_workers_alive` / `tamandua_workers_docker` | Workers with a recent heartbeat / that can start the engines. |
| `tamandua_worker_last_heartbeat_age_seconds` | Seconds since the latest heartbeat. |
| `tamandua_runs_24h{type,status}` | Runs created in the last 24 hours. |
| `tamandua_run_duration_seconds_24h{type,status,quantile}` | Duration of those that finished: p50, p95 and the maximum (`quantile="1"`). |
| `tamandua_info{version}` | Version serving the endpoint. |

```yaml
# prometheus.yml
scrape_configs:
  - job_name: tamandua
    scheme: https
    metrics_path: /api/metrics
    authorization: { credentials_file: /etc/prometheus/tamandua-token }
    static_configs: [{ targets: ["tamandua.example.com"] }]
```

Scrape through the domain (the API only accepts its public `Host`). Alerts worth having:

```yaml
- alert: TamanduaNoWorker
  expr: tamandua_workers_alive == 0 or tamandua_workers_docker == 0
  for: 5m
- alert: TamanduaQueueStuck
  expr: tamandua_jobs_oldest_queued_age_seconds > 3600
- alert: TamanduaJobsFailing
  expr: tamandua_jobs_failed_24h > 5
```

**Logs.** `make logs` (API) and `make logs SERVICE=worker|caddy|backup`. Docker rotates them (10 MB × 5 per service). Caddy's access log is JSON and redacts cookies and `Authorization`.

## Hardening

- **The Docker socket is root.** The worker starts the engines through it, so anyone who takes over the worker controls the server. Tamandua keeps the socket away from the service that answers requests (the API has none), but the right boundary is the machine: a **dedicated VM**, no other applications, no other tenants, and only administrators in the `docker` group.
- **Two-factor for everyone** (`TAMANDUA_REQUIRE_TOTP=all`), and remove users who leave.
- **Narrow the audience** if your team has fixed addresses: allow 443 only from them in the cloud firewall.
- **The real client address.** Behind Caddy, the API believes `X-Forwarded-For` (`TAMANDUA_FORWARDED_ALLOW_IPS`, set by the overlay) because only Caddy, the worker and PostgreSQL can reach it, and Caddy replaces any `X-Forwarded-For` a client sends. Sign-in throttling and the audit log then see each person's address instead of the proxy's.
- **What the proxy adds.** HTTP→HTTPS redirect, HTTP/2 and HTTP/3, a 2 MB request limit (the app's own is 1 MB), header and body timeouts, compression only for the panel's static files, and no `Server`/`Via` headers. The security headers (CSP, HSTS, nosniff, frame, referrer) stay the app's, so there's a single, consistent set.
- **Images.** Everything third-party is pinned by digest; the published images are signed and carry an SBOM and SLSA provenance (`docker buildx imagetools inspect ghcr.io/brayansstivens/tamandua:0.9 --format '{{json .SBOM}}'`).

## Coolify and Dokploy

Both platforms put their own proxy (Traefik) and certificates in front, so Caddy isn't used: deploy **`compose.yaml` alone** as a Docker Compose application from the Git repository, and let the platform route your domain to the **`api` service, port 8766**. These notes follow each platform's documented behavior; we haven't run Tamandua on them ourselves yet.

Variables to set in the platform (it writes them to `.env`, which the services read):

```bash
TAMANDUA_DB_PASSWORD=<openssl rand -hex 24>
TAMANDUA_PUBLIC_URL=https://tamandua.example.com
TAMANDUA_ALLOWED_ORIGINS=https://tamandua.example.com
TAMANDUA_FORWARDED_ALLOW_IPS=*              # only the platform's proxy reaches the api
TAMANDUA_METRICS_TOKEN=<openssl rand -hex 32>
TAMANDUA_UID=1000
TAMANDUA_GID=1000
DOCKER_SOCKET_GID=<stat -c %g /var/run/docker.sock, on the server>
```

What to keep in mind on both:

- The worker mounts `/var/run/docker.sock` and starts sibling containers that mount folders by their **host** path. The worker finds those paths by inspecting itself, so bind mounts must be real host folders (not named volumes).
- `config/` must survive redeploys: set `TAMANDUA_HOST_CONFIG_DIR` to an absolute path on the server (e.g. `/srv/tamandua/config`, owned by `TAMANDUA_UID`). Losing it means re-entering every secret. `data/` only holds caches and logs.
- The `opengrep` service builds the engine image and exits: that's expected, not a failed deploy.
- The platform builds the images from the repository (there's no `compose.images.yaml` there). The first deploy takes a few minutes.
- **Coolify:** resource type *Docker Compose*, compose location `/compose.yaml`. Coolify keeps `./data` bind mounts in the application's folder across deploys.
- **Dokploy:** service type *Compose*, path `./compose.yaml`. Each deploy clones the code again, so point `TAMANDUA_HOST_CONFIG_DIR` outside the clone (Dokploy suggests `../files/`).
- The hardening advice above still applies: a PaaS that also runs other people's applications on the same server is exactly what the Docker socket makes risky.

If something fails, [troubleshooting.md](troubleshooting.md) covers the usual causes; for proxy issues, `make logs SERVICE=caddy`.
