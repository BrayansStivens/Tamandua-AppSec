English · [Español](es/contenedores.md)

# Containers and Makefile

All of Tamandua runs in Docker. The `Makefile` at the repository root wraps the `docker compose` commands so that starting, upgrading or backing up is a single command.

## What you need

| Tool | Version | How to install it |
| --- | --- | --- |
| Docker Engine | 24 or later | [Docker Desktop](https://docs.docker.com/get-docker/), [OrbStack](https://orbstack.dev) (macOS) or `docker-ce` on Linux |
| Docker Compose | v2.24 or later | Included with Docker Desktop and OrbStack; on Linux, the `docker-compose-plugin` package |
| make | any version (including macOS's 3.81) | macOS: already there (or `xcode-select --install`) · Debian/Ubuntu: `sudo apt install make` · Fedora: `sudo dnf install make` · Windows: inside WSL2 |
| git | any version | To clone and for `make update` |

You **don't** need Python or Node to use it, only to develop it (`make dev-setup`).

`make doctor` checks all of this and tells you how to fix anything missing.

## Start it

```bash
git clone https://github.com/BrayansStivens/appsec-agent.git
cd appsec-agent
make up
```

`make up`:

1. creates `.env` from `.env.example` with your UID/GID (if it doesn't exist yet) and the `data/` and `config/` folders;
2. builds the images if they changed;
3. starts everything and waits until the panel responds;
4. pulls any missing engine images, with progress (the first time can take a while depending on your connection; after that it downloads nothing);
5. prints the URL and, if there's no admin yet, the **setup code**.

It works the same on macOS (Apple Silicon and Intel), Linux, and Windows with WSL or Git Bash. On Linux, and on WSL with native Docker, the Docker socket belongs to the `docker` group: `make` detects its GID and passes it to the container (`DOCKER_SOCKET_GID`). If you start with `docker compose` directly on those machines, set that value in `.env` (`stat -Lc %g /var/run/docker.sock`).

## Command reference

| Command | What it does |
| --- | --- |
| `make help` | Lists the commands. |
| `make doctor` | Checks Docker, Compose, architecture, disk, port, permissions on `data/` and `config/`, and the engines. |
| `make setup` | Only creates `.env` and the folders; never touches an existing `.env`. |
| `make build` | Builds the app and Opengrep images. |
| `make up` | Builds if needed, starts, pulls any missing engines and prints the URL and setup code. |
| `make demo` | Scans the repository's vulnerable examples and imports a threat model, so you can try it without connecting anything. `IMAGE=nginx:1.21` adds an image. |
| `make down` | Stops and removes the containers. `data/` and `config/` are kept. |
| `make restart` | Restarts the app. Running scans are marked as failed. |
| `make status` | State of the containers and the engine images. |
| `make logs` | Follows the app's logs. |
| `make setup-code` | Prints the setup code again. |
| `make scan` | Scans a local folder: `make scan DIR=../my-repo ARGS="--base main"`. See [cli.md](cli.md). |
| `make engines` | Pulls, from the host and with progress, any missing Trivy, OSV-Scanner, Gitleaks, Grype, Checkov and zizmor images. `make up` already does this; use it to retry after a network failure. |
| `make update` | `git pull` and restarts on the new version. |
| `make backup` | Copies `data/` and `config/` into `backups/<date>/`. Refuses to run while scans are in progress (unless `FORCE=1`). |
| `make shell` | Shell inside the container. |
| `make cli ARGS="…"` | The app's CLI, e.g. `make cli ARGS="user list"` or `make cli ARGS="user reset-totp --username ana"`. |
| `make clean` | Stops everything and removes Tamandua's images. |
| `make purge CONFIRM=delete` | **Deletes `data/` and `config/`**: runs, users and secrets. |
| `make dev-setup` · `make dev` | Development environment without containers (see [development.md](development.md)). |
| `make test` · `make lint` · `make check` | Backend tests, panel lint, and both. |

Without `make`, the same with Compose: `sh scripts/init-env.sh && docker compose up --build -d`.

## Layout

```
Makefile                        everyday commands
compose.yaml                    app service + Opengrep engine build
.env.example                    variables (copied to .env)
docker/
  app/Dockerfile                app image: built panel + Python + Docker client
  engines/opengrep/Dockerfile   SAST engine, official binary verified by SHA-256
  engines/opengrep/VERIFY.md    how to repeat the Cosign verification when upgrading
scripts/
  doctor.sh                     environment check
  init-env.sh                   creates .env with your UID/GID and the folders
  backup.sh                     consistent backups
```

## Images

| Image | Source | Approx. size |
| --- | --- | --- |
| `tamandua/app:<version>` | Built from `docker/app/Dockerfile` (Node only in the build stage) | 360 MB |
| `tamandua/opengrep:1.30.0` | Built from `docker/engines/opengrep/` | 230 MB |
| `aquasec/trivy` | Docker Hub, pinned by digest | 240 MB |
| `ghcr.io/gitleaks/gitleaks` | GHCR, pinned by digest | 80 MB |
| `anchore/grype` | Docker Hub, pinned by digest; container images only | 110 MB (+2.1 GB database) |
| `bridgecrew/checkov` | Docker Hub, pinned by digest | 200 MB |
| `ghcr.io/zizmorcore/zizmor` | GHCR, pinned by digest | 15 MB |

The base images (`node`, `python`, `debian`) are pinned by digest, so two builds of the same version use exactly the same layers. The app image's OCI labels declare the version, license and repository (`docker inspect tamandua`).

## App container hardening

| Measure | Effect |
| --- | --- |
| Unprivileged user with your UID/GID | Files in `data/` and `config/` are yours; the process isn't root. |
| `read_only: true` | It can't modify its own code or the system: it only writes to `/data`, `/config` and in-memory temp dirs (`/tmp`, `$HOME`). |
| `cap_drop: [ALL]` and `no-new-privileges` | No Linux capabilities and no way to gain them. |
| `init: true` | Reaps orphan processes and forwards signals: clean shutdowns. |
| Port on `127.0.0.1` | Nobody outside your machine reaches the panel unless you configure it (and then HTTPS is required). |
| Rotated logs (10 MB × 5) | Docker logs don't fill the disk. |

Engines are launched per scan as ephemeral containers (`--rm`) with the code mounted read-only, `--cap-drop ALL`, `no-new-privileges`, and a cap of 3 GB of memory, 2 CPUs and 512 processes; Gitleaks, Opengrep, Checkov and zizmor run with no network.

**The remaining trade-off:** to launch the engines, the app mounts `/var/run/docker.sock`, which is equivalent to root on the host. That's why the panel only listens on `127.0.0.1` by default. If you open it to more people, put a socket proxy with an allowlist of operations in front of the socket (it's on the roadmap).

## Isolation between scans

Each scan uses its own snapshot of the repository (`data/work/snapshot-…/`, one per scan) and fresh engine containers that are destroyed when it finishes, so two scans never share files or processes. Today they run **one at a time** (a queue with a single worker), which keeps resource use to one engine at a time.

We evaluated moving to an ephemeral *runner* per scan (a container with every tool, its own network and its own volume, destroyed at the end) and running several in parallel. It's an open line of work. The evaluation concluded that the direction is right, but the tools shouldn't be downloaded on every scan (slow, and a larger supply-chain surface); they should ship in a pinned image instead, and parallelism needs a configurable limit so it doesn't exhaust the machine.
