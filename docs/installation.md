English · [Español](es/instalacion.md)

# Installation

## Requirements

| | Minimum | Notes |
| --- | --- | --- |
| OS | Linux, macOS, or Windows with WSL2 | amd64 or arm64 (Apple Silicon included). |
| Docker | Engine 24+ and Compose v2.24+ | Docker Desktop, OrbStack or Docker Engine. |
| make and git | any version | `make` ships with macOS; on Debian/Ubuntu, `sudo apt install make git`. On Windows, inside WSL2. |
| Memory | 4 GB free | The app uses ~200 MB at rest; each scan runs one engine at a time, capped at 3 GB. |
| Disk | 8 GB free | Images (~1 GB), Trivy's vulnerability database (~1.3 GB), Grype's (~2.1 GB, only if you scan container images), the local NVD copy (~0.7 GB) and your runs. |
| Outbound network | HTTPS to GitHub, NVD, CISA and EPSS | Details in [security.md](security.md#what-leaves-your-machine). No inbound access from the internet is needed. |
| Account | GitHub (personal, or an organization you administer) | To create your GitHub App. |

You don't need to install Python, Node or the scanning engines: everything runs in containers. **`make doctor`** checks the requirements and tells you how to fix anything missing.

## First install

```bash
git clone https://github.com/BrayansStivens/Tamandua-AppSec.git
cd Tamandua-AppSec
make up
```

`make up` creates `.env` from `.env.example` with your host user (`TAMANDUA_UID`/`TAMANDUA_GID`, so `data/` and `config/` belong to you and not to root), builds, starts and waits until the panel responds. Without `make`: `sh scripts/init-env.sh && docker compose up --build -d`.

The first build takes a few minutes: it compiles the panel, downloads the Opengrep binary and checks its SHA-256. You'll see two containers: `tamandua`, which keeps running, and `opengrep`, which only builds the engine image and **exits right away**. That's expected.

When it finishes it prints the **setup code** (also available with `make setup-code`, or in the logs):

```
================================================================
  First start: create the administrator in the panel with this code
      ABCD-EFGH-JKLM
  (it works once, and only while there are no users)
================================================================
```

Open <http://127.0.0.1:8766>, enter that code and create your admin user. The code proves you're the one who controls the server: without it, whoever opened the URL first could take over the instance. If you restart before using it, a new one is generated.

The panel follows your browser's language; you can switch it from the sidebar or the sign-in screen. Everything Tamandua writes without a person asking (PR comments, notifications, Jira, reports and CLI output) uses `TAMANDUA_DEFAULT_LOCALE` (`en` or `es`, default `en`); set it in `.env` if your team works in Spanish. See [configuration.md](configuration.md).

Then:

1. **Account → Two-factor**: turn on TOTP with your authenticator app and save the backup codes. It's mandatory for admins.
2. **Integrations**: create and connect your GitHub App following the panel's guide (also in [github-app.md](github-app.md)).
3. **Repositories**: pick one and click **Scan**.

The local NVD copy for the CVE tracker downloads in the background: a few hours without an API key, much less with `TAMANDUA_NVD_API_KEY` (free at <https://nvd.nist.gov/developers/request-an-api-key>). Everything else works in the meantime.

## Upgrade

```bash
make update
```

`make update` takes a backup first (`make backup`), then pulls the code and restarts. `data/`, `config/` and the database are kept. If the new version changes the format of any data, it converts it on startup, once, after saving a copy of what it touches in `data/backups/`: there's nothing to do by hand. Before upgrading, take a backup (see below) and check under **Scans** that nothing is running: a restart marks any running scan as failed.

## Backups

| Folder | Contents | How to handle it |
| --- | --- | --- |
| Database (`tamandua-pg` volume) | Runs, finding history and triage (PostgreSQL) | `make backup` dumps it with `pg_dump` into `database.dump`. |
| `data/` | Users (passwords hashed with scrypt), settings, logs, NVD copy and caches | No plaintext secrets. You can leave out `data/feeds/`, `data/trivy-cache/` and `data/grype-cache/`: they're downloaded again. |
| `config/` | `master.key` (unless `TAMANDUA_MASTER_KEY` is set) | **This is the key to your credentials**, which are stored encrypted in the database. Store it separately from the database backups and treat it like a password. |

```bash
make backup        # backups/<date>/database.dump, data.tgz and config.tgz
```

The app pauses for a few seconds so the backup is consistent, and the command refuses to run while scans are in progress (`FORCE=1` overrides it). `config.tgz` holds the encrypted secrets **and** the master key: keep it off the machine and protected. To restore:

```bash
make restore FROM=backups/<date> CONFIRM=restore   # saves the current state in backups/pre-restore-<date>/ first
make up
```

Scheduled backups (a Compose service with retention), cron and offsite copies: [deploy-vps.md](deploy-vps.md#backups).

If you lose `config/master.key` (or change `TAMANDUA_MASTER_KEY`), the stored secrets can't be decrypted: you'll have to reconnect the GitHub App and re-enter the AI and Jira keys. No other data is lost.

## Expose it on your network or the internet

By default the port is only published on `127.0.0.1`. To reach it from other machines you need HTTPS: the server **refuses to start** if `TAMANDUA_PUBLIC_URL` isn't loopback and doesn't start with `https://`. For a server with a domain, `make setup DOMAIN=tamandua.example.com` adds Caddy with automatic certificates: the full guide (sizing, firewall, backups, upgrades, monitoring, Coolify and Dokploy) is [deploy-vps.md](deploy-vps.md).

Even with HTTPS, keep in mind that the app controls Docker through its socket, which is equivalent to root on the host. Only expose the panel to people you trust.

## Uninstall

```bash
make clean                   # containers and images; keeps data/ and config/
make purge CONFIRM=delete    # also deletes data and secrets: only if you no longer need them
```

Also delete your GitHub App on GitHub (*Settings → Developer settings → GitHub Apps → your App → Advanced → Delete*), or at least revoke its private key.
