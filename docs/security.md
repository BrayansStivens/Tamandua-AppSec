English · [Español](es/seguridad.md)

# Security

Tamandua reads your repositories' code and stores GitHub, AI and Jira credentials. This document explains how it protects that information, what leaves your machine and which trade-offs it makes. To report a vulnerability, see [SECURITY.md](../.github/SECURITY.md).

## Secrets

| Secret | Where it lives | Who can see it |
| --- | --- | --- |
| GitHub App private key | `vault_entries` table, encrypted | Only the server process. GitHub receives a signed JWT, never the key. |
| OpenAI / Anthropic keys | `vault_entries` table, encrypted | Only the server; they're validated against the provider before being saved. The panel shows the last 4 characters. |
| Jira token | `vault_entries` table, encrypted | Same as above. |
| Container registry tokens | `vault_entries` table, encrypted | Only the server. They reach Trivy and Grype as environment variables (`-e NAME` with no value on the command), never on the command line. |
| GitHub installation tokens | Memory, 1 h | Renewed automatically; never written to disk. |
| Master key | `config/master.key` (0400) or `TAMANDUA_MASTER_KEY` | Whoever administers the server. |
| User passwords | `users` table in PostgreSQL, scrypt hash only | Nobody: they can't be recovered. |
| Session cookies | `sessions` table, hash only; signed with a key sealed in the vault (or `TAMANDUA_SESSION_KEY`) | A copy of the database doesn't grant access. |

**Encryption.** AES-256-GCM, a random nonce per secret, and the secret's name as associated data: an encrypted value can't be moved to another entry without decryption failing, and any tampering is detected. If the master key doesn't decrypt the vault, the server says so instead of using corrupted data.

**Separation.** The encrypted secrets live in the database, the master key apart from it (`TAMANDUA_MASTER_KEY` or `config/master.key`), and `data/` only holds caches and logs, so it carries no secrets. A database dump without the master key reveals nothing. On any platform with a secrets manager, set `TAMANDUA_MASTER_KEY` there: it's the one value that must never live next to the database backups.

**Logs.** Request bodies, headers, passwords, TOTP codes and cookies are never logged. On top of that, every message goes through a filter that redacts:

- known patterns: `ghp_`, `ghs_`, `github_pat_`, `sk-…`, `xox…`, `AKIA…`, `ATATT…`, JWTs, `Bearer …`, `Basic …` and `-----BEGIN … PRIVATE KEY-----` blocks;
- any value stored in the vault, matched literally, even if it follows no known pattern.

**Browser.** No secret is ever sent back to the browser. The `.pem` key is read in your browser and travels to the server once, when you connect it; the panel doesn't keep it.

## Panel access

- **First administrator** created with a one-time code that only appears in the server console: whoever opens the URL before you can't take over the instance.
- **Passwords** hashed with scrypt (N=2¹⁵, r=8, p=1), 12 characters minimum. A nonexistent user costs the same as a real one, so response times don't reveal which users exist.
- **Two-factor authentication** with TOTP (RFC 6238), required for administrators by default, with 8 single-use backup codes. A code that was already used doesn't work twice.
- **Server-side sessions**, with an `HttpOnly`, `SameSite=Strict` cookie that is also `Secure` over HTTPS. Changing your password, turning on TOTP or having an administrator reset your credentials signs out your other sessions.
- **Rate limiting** per user and per address: after 5 failures, a progressive lockout from 30 s to 15 min. It also applies to the initial setup and to the return from GitHub. Behind a reverse proxy, the address comes from `X-Forwarded-For` only when the request comes from a proxy listed in `TAMANDUA_FORWARDED_ALLOW_IPS` (`compose.prod.yaml` sets it for Caddy); otherwise everybody would share the proxy's address.
- **CSRF**: every POST requires an allowed `Origin` and an action header specific to its route.
- **Roles**: `admin` connects integrations, manages users and accepts risks; `member` scans and triages.

## Transport

- By default, the port is published on `127.0.0.1` only.
- If `TAMANDUA_PUBLIC_URL` points outside this machine and isn't HTTPS, **the server won't start**. Only `TAMANDUA_ALLOW_INSECURE_HTTP=1` allows it, at your own risk.
- With HTTPS: HSTS (1 year) and `Secure` cookies. TLS 1.2 minimum when the server itself terminates TLS.
- Every response carries a strict `Content-Security-Policy` (no inline scripts or styles), `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` and `Permissions-Policy`.
- Outbound calls use HTTPS with certificate verification and **don't follow redirects**, so a credential never ends up somewhere other than intended.

## What leaves your machine

| Destination | What is sent | When |
| --- | --- | --- |
| `api.github.com` | Your App's JWT, repository and PR requests; comments and commit statuses on your PRs | When you connect, scan and review PRs. Code is **downloaded** from GitHub; it isn't uploaded anywhere else. |
| `services.nvd.nist.gov` | Index and date ranges | Local CVE copy, in the background. |
| `www.cisa.gov`, `epss.empiricalsecurity.com` | Nothing: full public feeds are downloaded | Once a day. They're downloaded whole so they don't reveal which CVEs you care about. |
| Image registry and Trivy database | Nothing of yours | At build time and when Trivy updates its database. |
| Container registries (Docker Hub, GHCR, ECR…) | A request for the image you asked to scan, with your token if you saved one | When scanning an image. Registries on private IPs are blocked unless `TAMANDUA_ALLOW_PRIVATE_REGISTRIES=1`, so the form can't be used as a bridge into your internal network (SSRF). The check runs again when the scan starts, and the engine's container gets the checked address for the registry's name, so an answer that changes in between (DNS rebinding) isn't followed. |
| `api.osv.dev` | Your dependencies' names and versions | **Only if you allow it**, per scan. Not used by default. |
| Your Jira site | Title, description and priority of the issues you export | Only if you connect Jira and click export. |
| `api.openai.com`, `api.anthropic.com` | Your key, to check that it's valid | Only when you save or test it. Today the AI receives no code and no findings. |
| Your domains | An HTTPS `HEAD` and a DNS TXT lookup | Only once dynamic testing is available (in development). Only to public addresses. |

There's no telemetry.

## Code analysis

- Repository code **is never executed**: Tamandua analyzes a read-only snapshot.
- Engines run in ephemeral containers with `--cap-drop ALL`, `no-new-privileges` and memory, CPU and process limits. Gitleaks, Opengrep, Checkov and zizmor have no network; Trivy and Grype use it only for their vulnerability database and, when scanning an image, to read it from the registry.
- Container images you scan **are neither run nor built**: the engines read the manifest and the layers.
- The Trivy, OSV-Scanner, Gitleaks, Grype, Checkov and zizmor images are pinned by digest. The Opengrep image is built from the official binary, checked against its SHA-256.
- Values of secrets found in your code are redacted: findings keep the location and the type, not the value.
- Findings are stored as message codes with parameters, not as frozen sentences, so the panel, reports and PR comments render them in English or Spanish for whoever reads them. Advisory text from NVD, OSV or GHSA is shown as published, never machine-translated.

## Known trade-offs

- **Docker socket.** Engines are launched through `/var/run/docker.sock`, which is equivalent to root on the host. Only the `worker` service mounts it, and it exposes no ports; the service that handles requests (`api`) doesn't have it. That's the price of installing nothing but Docker; to avoid it, use the worker image with the engines inside (`TAMANDUA_ENGINE_RUNNER=local`, as `deploy/compose.yaml` does).
- **Engines inside the worker** (`TAMANDUA_ENGINE_RUNNER=local`). No Docker socket, but also no container per engine: each engine runs as a process of the worker, with a fresh home folder, only `PATH` from the worker's environment (never the database URL or the master key), no core dumps, and its whole process group killed when it times out. Engines that need no network (Gitleaks, Opengrep, Checkov, zizmor) run in an empty network namespace (`unshare --user --net`) where the platform allows it: on a server or a VM, yes; in a container with Docker's default seccomp profile, no, and the worker says so in its log (`local_engines_share_the_network`). Elsewhere they run with their offline options wherever they have them.
- **Job queue.** Pending scans live in PostgreSQL. The code tokens that go with a scan are sealed with the master key (AES-GCM): the database never stores them in plaintext.
- **TOTP seeds** are sealed with the master key too: a database dump alone can't produce codes. Losing the master key
  means resetting second factors (`make cli ARGS="user reset-totp --username <name>"`) as well as re-entering the vault's secrets.
- **Master key on the same server** if you don't set `TAMANDUA_MASTER_KEY`. It protects against a stray copy of the database, not against someone with full access to the server.
- **A single workspace** per installation: every user sees every connected repository.
- **Registry token visible to root.** While a private image is being scanned, the token sits in the engine container's configuration: anyone with Docker access on the host (who is already root) can read it. Use read-only tokens.
- **Registry redirects aren't checked.** Registries serve image layers from other hosts (a CDN, a bucket), so Trivy and Grype follow their redirects. A registry you ask to scan could point them at an internal address. They only request, and what comes back isn't shown. Scan images from registries you trust, or run the engines on a network without access to your internal one.

## Recommendations

1. Keep the panel on `127.0.0.1` unless you need remote access, and then use HTTPS.
2. Require TOTP for everyone (`TAMANDUA_REQUIRE_TOTP=all`) if several people use it.
3. Install the App only on the repositories you want to scan (**Only select repositories**).
4. Back up `config/` separately from `data/`.
5. If an App key leaks: revoke it on GitHub (*Private keys → Delete*), generate a new one and reconnect it in **Integrations**.

## Exclusions and suppressions

- Excluded paths are decided by an administrator in the panel and stored on the server with author, date and reason. A PR can't exclude its own code or change the rules: no `.tamandua-ignore`, no `.gitleaks.toml`, no engine configuration inside the repository is honored.
- Patterns work like `.gitignore`: a pattern that matches a folder excludes everything inside it, so `fixtures` also covers `fixtures/a/b.py`. Patterns that would exclude everything are rejected.
- Excluded findings are counted on every run and can be reviewed; they're never silently deleted.
- In-code suppressions (`# nosemgrep: <rule>`) do travel with the repository and show up in the PR review; add a justification next to them.
