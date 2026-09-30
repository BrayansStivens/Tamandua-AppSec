English · [Español](es/configuracion.md)

# Configuration

Every variable is optional and goes in `.env` (a copy of `.env.example`). After changing any of them, run `docker compose up -d`. `python -m tamandua check-config` (or `make cli ARGS=check-config`) checks them all; the server and the worker do it on start and stop with a clear message if one is invalid. On other platforms, see [deploy.md](deploy.md).


| Variable | Default | Purpose |
| --- | --- | --- |
| `TAMANDUA_HOST_BIND` / `TAMANDUA_HOST_PORT` | `127.0.0.1` / `8766` | Where the panel is published on the host. |
| `TAMANDUA_PUBLIC_URL` | `http://127.0.0.1:8766` | URL people use to open the panel; it determines `Secure` cookies, HSTS and the App's Setup URL. |
| `TAMANDUA_ALLOWED_ORIGINS` | 127.0.0.1 and localhost | Accepted origins (Host header and CSRF). |
| `TAMANDUA_DEFAULT_LOCALE` | `en` | `en` or `es`. Language for PR comments, notifications, Jira issues, reports and CLI output when no person asked for one. The panel doesn't use it: it follows the browser's language, and each person can change it from the sidebar or the sign-in screen. |
| `TAMANDUA_MASTER_KEY` | generated in `config/` | Master key (`openssl rand -base64 32`): it encrypts every secret in the database. Required where there is no persistent disk; the same on the API and every worker. |
| `TAMANDUA_SESSION_KEY` | generated, sealed in the database | Key that signs session cookies (32 bytes in base64). Only to pin it from a secrets manager. |
| `TAMANDUA_REQUIRE_TOTP` | `admins` | `admins`, `all` or `none`. |
| `TAMANDUA_NVD_API_KEY` | — | NVD API key: faster CVE downloads. Sent in a header and never logged. |
| `TAMANDUA_DB_PASSWORD` | (generated) | PostgreSQL password; `make setup` writes it to `.env`. |
| `TAMANDUA_DATABASE_URL` | (compose) | PostgreSQL connection string. `compose.yaml` builds it from the password; outside compose, e.g. `postgresql://tamandua:…@localhost:5432/tamandua` (the `postgres://` URLs managed databases hand out work as they are). |
| `TAMANDUA_EMBEDDED_WORKER` | `1` | `1`: the server also runs the scans (a single process). In compose the API uses `0` and the `worker` service runs them. |
| `TAMANDUA_CVE_SYNC` | `on` | `off` turns off the local NVD copy. |
| `TAMANDUA_EUVD` | `on` | `off` stops querying EUVD (ENISA) when NVD hasn't scored a CVE. Only the CVE identifier is sent. |
| `TAMANDUA_PR_POLL_SECONDS` | `300` | How often watched PRs are checked. |
| `TAMANDUA_BRANCH_MIN_MINUTES` | `60` | Minimum gap between two automatic rescans of the same repository's main branch (minimum 10). |
| `TAMANDUA_ADVISORY_WATCH_HOURS` | `24` | How many hours between offline checks of already-scanned dependencies against new advisories. `0` turns it off. |
| `TAMANDUA_ALLOW_PRIVATE_WEBHOOKS` | empty | `1` allows alerts to webhooks on your internal network (blocked by default to prevent SSRF). |
| `TAMANDUA_ALLOW_PRIVATE_REGISTRIES` | — | `1` allows scanning images from registries with a private IP (your internal network). Blocked by default to prevent SSRF. |
| `TAMANDUA_TLS_CERT` / `_KEY` | — | TLS without a proxy. |
| `GITHUB_APP_ID` + `GITHUB_APP_SLUG` + `GITHUB_APP_PRIVATE_KEY_FILE` | — | Alternative to the form: mount the App as a deployment secret. Takes precedence over the secret store. |
| `TAMANDUA_HOST_CONFIG_DIR` | `./config` | Host folder for the master key, when `TAMANDUA_MASTER_KEY` isn't set. |
| `TAMANDUA_FORWARDED_ALLOW_IPS` | empty | Behind a reverse proxy that is the only way to reach the API: the proxy addresses whose `X-Forwarded-For` is believed (`*` = any peer). Without it, sign-in throttling and the logs see the proxy's address for everybody. `compose.prod.yaml` sets it for Caddy. |
| `TAMANDUA_ENGINE_RUNNER` | `auto` | `docker`: each engine in a sibling container through the Docker socket. `local`: the engines installed in the worker image (`tamandua-worker`), no socket. `auto`: Docker if it answers, else the installed engines. |
| `TAMANDUA_PERIODIC` | `leader` | `leader`: a worker runs the periodic tasks on its own clock. `external`: a scheduler triggers them with `tamandua periodic` or `GET /api/cron` ([deploy.md](deploy.md#periodic-tasks)). |
| `TAMANDUA_CRON_TOKEN` / `CRON_SECRET` | empty (off) | Bearer token for `GET /api/cron`, only with `TAMANDUA_PERIODIC=external`. At least 32 characters. `CRON_SECRET` is what Vercel Cron sends. |
| `TAMANDUA_LOG_FORMAT` | `text` | `json`: one JSON object per line on the process output. |
| `TAMANDUA_LOG_FILE` | empty (Compose: `logs/app.log`) | Also write JSON logs to this file, rotated at 10 MB × 5; a relative path is under the data folder. |
| `TAMANDUA_METRICS_TOKEN` | empty (off) | Turns on `/api/metrics` (Prometheus) for requests with `Authorization: Bearer <token>`. At least 32 characters: `openssl rand -hex 32`. |
| `TAMANDUA_IMPORT_TOKEN` | empty (off) | Turns on `POST /api/ci/sarif`, which lets CI import another tool's SARIF 2.1.0 into an existing asset with `Authorization: Bearer <token>` (no session). At least 32 characters: `openssl rand -hex 32`. Also what `tamandua import-sarif --server` sends, read from the environment. |

**Server with a domain** ([deploy-vps.md](deploy-vps.md)). Read by Compose, not by the app; `make setup DOMAIN=… [PREBUILT=1]` writes them.

| Variable | Default | Purpose |
| --- | --- | --- |
| `TAMANDUA_DOMAIN` | — | Domain Caddy gets the certificate for (`compose.prod.yaml`). The public URL and allowed origins become `https://<domain>`. |
| `COMPOSE_FILE` | `compose.yaml` | Compose files every command uses, e.g. `compose.yaml:compose.prod.yaml:compose.images.yaml`. |
| `TAMANDUA_IMAGE` | — | Published image to run instead of building (`compose.images.yaml`), e.g. `ghcr.io/brayansstivens/tamandua`. |
| `TAMANDUA_IMAGE_TAG` | the code's version | Tag of that image; accepts a digest (`0.10@sha256:…`). |
| `COMPOSE_PROFILES` | — | `backup` turns on the scheduled backups service. |
| `TAMANDUA_BACKUP_DIR` | `./backups` | Where the backup service writes. |
| `TAMANDUA_BACKUP_INTERVAL_HOURS` / `_KEEP_DAYS` | `24` / `14` | How often it backs up, and for how long it keeps its own copies. |

**Deliberate trade-off:** with the repository's `compose.yaml`, so you don't have to install anything but Docker, the worker launches the engines as sibling containers through the Docker socket, which is equivalent to root on the host. [`deploy/compose.yaml`](../deploy/compose.yaml) uses the worker image with the engines inside instead: no socket at all.
