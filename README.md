English · [Español](README.es.md)

<p align="center"><img src="docs/assets/tamandua.svg" width="112" alt="Tamandua, a collared anteater catching a beetle with its tongue"></p>

<h1 align="center">Tamandua</h1>

<p align="center"><a href="https://github.com/Tamandua-AppSec/tamandua/actions/workflows/ci.yml"><img src="https://github.com/Tamandua-AppSec/tamandua/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a></p>

<p align="center"><strong>Eats your bugs.</strong> Self-hosted, open-source application security that never sends your code anywhere.</p>

Tamandua scans your repositories and container images, tells you **what to fix first and how** (the exact command or a code example), confirms the fix landed and **keeps watching** whatever changes next. Everything runs on your machine with your credentials: your code never reaches any service of ours.

> Status: **beta (v0.10)**. It works and is tested, but the API and the `data/` formats may still change between releases.

## Why Tamandua

- **Self-hosted and free software (AGPL-3.0).** Your code, dependencies and findings stay on your server.
- **One place for everything:** code (SAST), dependencies, secrets, infrastructure as code, pipelines and images, with seven open-source engines and no duplicates across them.
- **From finding to verified fix:** real prioritization (CISA KEV and EPSS), a fix command for each package manager, a **Verify again** button, and automatic remediation once a finding stops showing up.
- **Built for small teams, in English and Spanish**, with evidence ready for SOC 2 and ISO 27001 audits and threat modeling tied to your actual findings.

## What it does

| | |
| --- | --- |
| **Find** | Opengrep with 58 Tamandua rules (JS/TS, Python, Java, Go, PHP, Ruby, C#), Gitleaks, Trivy and OSV-Scanner for dependencies, Checkov and zizmor for IaC and GitHub Actions, Trivy + Grype for images. Your code is never executed. One repository or many, a whole organization, or several images at once. |
| **Prioritize** | Every advisory is checked against CISA KEV (active exploitation) and EPSS (exploit probability); dependencies are grouped by package, with the version that closes all of their advisories. |
| **Fix** | Each finding tells you how to fix it: the command for your package manager (npm, pip, Poetry, Go, Cargo, Maven…), the override when it's transitive, a before/after example for code, or the steps to rotate a secret. Export to Jira without duplicates. |
| **Verify** | **Verify again** rescans and tells you "Fixed ✓" or "Still present". On pull requests only what the PR introduces counts, with a comment and a status check that can block the merge. |
| **Watch** | Automatic rescans when the main branch changes, a daily offline check of new advisories against your dependencies, and messages to **Slack, Teams or a webhook** when something important shows up. |
| **Prove** | Technical and evidence PDF reports (SOC 2 Type II, ISO/IEC 27001:2022, organization roll-up), SARIF, JSON and Markdown; threat modeling (STRIDE, LINDDUN, PASTA, attack trees, ATT&CK) with a diagram; a local CVE tracker built from NVD. |

**In development** (grayed out in the panel): dynamic testing (DAST), GitLab/Bitbucket/Azure DevOps (covered today by [`scan` in CI](docs/cli.md)) and optional AI assistance.

## Try it in 5 minutes

You need **Docker** (Engine 24+ with Compose v2.24+), **make** and **git**, 4 GB of memory and 8 GB of disk. `make doctor` checks all of it.

```bash
git clone https://github.com/Tamandua-AppSec/tamandua.git
cd tamandua
make up
make demo
```

`make up` builds, pulls the engines, starts everything and prints the URL and the **setup code**. `make demo` runs a real scan of the intentionally vulnerable examples shipped with the repository and imports a threat model, so you can see Tamandua at work without connecting anything (`make demo IMAGE=nginx:1.21` adds an image).

Open <http://127.0.0.1:8766>, create the admin account with the code and follow **Getting started** on the Overview. The full walkthrough, including what's optional: [docs/quickstart.md](docs/quickstart.md).

The panel follows your browser's language and has a language switch in the sidebar and on the sign-in screen. PR comments, notifications, Jira issues, reports and CLI output use `TAMANDUA_DEFAULT_LOCALE` (`en` or `es`, default `en`).

## Documentation

| | |
| --- | --- |
| [Quickstart](docs/quickstart.md) | From zero to your first verified fix, and what to set up next |
| [Installation](docs/installation.md) | Requirements, first run, upgrades, backups, uninstalling |
| [Where to deploy](docs/deploy.md) | One compose file for any server or Docker panel, Render, Railway, Vercel for the API, Kubernetes |
| [Deploy on a VPS](docs/deploy-vps.md) | Your own server with a domain: HTTPS, backups, upgrades, monitoring, Coolify and Dokploy |
| [Connect GitHub](docs/github-app.md) | Create the GitHub App step by step and review PRs |
| [Terminal and CI](docs/cli.md) | `scan`: check a folder or just what a change introduces, with SARIF output and exit codes; in CI, one step with the GitHub Action |
| [Skills for coding assistants](skills/README.md) | Claude Code, Cursor or Codex fix what Tamandua finds and verify it, or wire it into your CI |
| [Features](docs/features.md) | What each part does and the reasoning behind it |
| [Configuration](docs/configuration.md) | `.env` variables |
| [Security](docs/security.md) | Secrets, transport, what leaves your machine, and trade-offs |
| [Containers and Makefile](docs/containers.md) | `make` commands, images and hardening |
| [Architecture](docs/architecture.md) | Components, how a scan flows, and data on disk |
| [Troubleshooting](docs/troubleshooting.md) | Common errors |
| [Development](docs/development.md) | Running without containers, the CLI and tests |
| [Third-party software](docs/third-party-notices.md) | Licenses for the engines, advisory databases and dependencies |

## Security in brief

- Secrets (GitHub App key, AI keys, Jira token, TOTP seeds) are **encrypted with AES-256-GCM** in the database, with a master key kept apart from it. A database dump alone reveals nothing. They never go back to the browser and never show up in logs.
- The GitHub App needs only four permissions (`contents: read`, `metadata: read`, `pull_requests: write`, `statuses: write`), with no webhooks or OAuth; one-hour tokens kept in memory. For several organizations, set it to **Any account** and connect each installation explicitly in the panel.
- The panel listens on `127.0.0.1` by default. If you expose it beyond your machine without **HTTPS**, the server refuses to start.
- Private registry credentials are encrypted and handed to the engines through environment variables; registries on internal networks are blocked unless you explicitly allow them.
- No telemetry. Advisory databases are downloaded and queried locally; your dependency list only goes to OSV if you allow it for a scan. Alerts only go to the channels you configure.
- **Trade-off** with the repository's `compose.yaml`: the worker launches the engines through the Docker socket, which is equivalent to root on the host. The worker image with the engines inside (`deploy/compose.yaml`) needs no socket.

To report a vulnerability: [SECURITY.md](.github/SECURITY.md).

## Run it on a server (HTTPS)

Tamandua runs wherever a container does. [docs/deploy.md](docs/deploy.md) covers every target: a single compose file for any server or Docker panel (Coolify, Dokploy, Portainer, Hostinger), Render, Railway, and Vercel for the API. Its worker can run the engines inside its own image, so no target needs the host's Docker socket.

On your own VPS with this repository, with the DNS record pointing at the server:

```bash
make setup DOMAIN=appsec.your-domain.com   # Caddy with automatic HTTPS
make up
```

This builds the images on the server; `make setup DOMAIN=… PREBUILT=1` runs the published, signed images instead.
While the repository is private, cloning and pulling need access and read-only credentials: see
[Access while the repository is private](docs/deploy.md#access-while-the-repository-is-private).

The API is then reachable only through Caddy, HTTP redirects to HTTPS and the certificate renews itself. The guide covers sizing, OS and firewall, backups offsite and restore, upgrades, Prometheus metrics, and Coolify and Dokploy: [docs/deploy-vps.md](docs/deploy-vps.md).

## Contributing

Issues and PRs are welcome: read [CONTRIBUTING.md](.github/CONTRIBUTING.md). On your first PR you sign the [CLA](.github/CLA.md) with a comment. Tamandua's SAST rules live in `rules/`.

## License

Tamandua is free software under the [GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0-only): you can use, study, modify and redistribute it. If you offer a modified version to other people over a network, you must make that version's source code available to them under the same license.

The SAST rules in [`rules/`](rules/) have their own MIT license, so you can reuse them in other tools.

Copyright © 2026 BrayansStivens and Tamandua contributors.
