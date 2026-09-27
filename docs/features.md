English · [Español](es/funcionalidades.md)

# Features

What each part of the panel does, and the reasoning behind it. To install it, see [installation.md](installation.md).

**Vocabulary.** Tamandua performs **analysis**: it reads code, dependencies, configuration and images without running them or attacking anything, and its findings are candidates you need to confirm. It is not a *pentest*: a pentest tries to exploit flaws against a running system and demonstrates the impact. The upcoming **dynamic testing** (DAST) will be active scanning, which isn't a pentest either; we'll only talk about an *AI-assisted pentest* once an agent attempts exploitation and confirms the impact. A Tamandua report doesn't replace the pentest that SOC 2 or ISO 27001 require.

**Languages.** The panel, findings, fix guides, reports, PR comments and notifications are available in English and Spanish. Findings are stored as message codes, not sentences, so each person reads them in their own language, and switching language never requires a rescan. Text nobody requests in person (PR comments, notifications, Jira issues, the CLI) uses `TAMANDUA_DEFAULT_LOCALE` (`en` by default). Third-party text such as NVD, OSV or GHSA advisory summaries is shown as published.

## In development

These appear greyed out in the panel, marked **In development**, so you know they're coming. Today they produce no results and can't be used:

| Feature | What it will do |
| --- | --- |
| Dynamic testing of web applications and APIs | Active scanning (DAST) with ZAP or Nuclei in an isolated container, only against domains whose ownership you've verified through DNS. |
| GitLab, Bitbucket, Azure DevOps | Connect repositories with read-only project tokens. |
| AI assistance | Finding explanations and patch proposals with your own key, with consent on every run. |
| Public API | Scoped personal tokens and a documented `/api/v1`. (The CLI for CI already exists: [`scan`](cli.md).) |

## Panel

The **Overview** is computed from runs (`GET /api/dashboard?days=7|30|90|365`) with explicit definitions: *open* is whatever appears in the latest run of each asset; *fixed* is a fingerprint that was in an earlier run of that asset and no longer appears; mean time to fix runs from first detection to first absence. The score is a summary shown next to its formula (`100·e^(−risk/150)`, with risk weighted by severity, KEV and EPSS), not a certification. The charts are dependency-free SVG: new findings per day stacked by severity, open findings by severity, found versus fixed, CWE, most affected assets, exploitability (KEV and EPSS ≥ 10 %), a yearly activity heatmap, and two news panels: additions to CISA KEV and CVEs published in the last 7 days according to NVD, highlighting those that mention a package or CVE from your open findings.

The severity palette is a single-hue ordinal ramp, validated with the palette validator in light and dark mode; text never takes the series color.

## OWASP coverage

A run's matrix is computed from what actually ran: how many Tamandua rules target each category (read from `rules/`), which engines covered it and how many findings it produced. What static analysis can't cover (insecure design, logging and alerting, exceptional conditions) is declared with its reason, not with a generic sentence.

## Background scans

Starting a scan returns `202` immediately with its ID and queues it; a single worker processes scans in order. While it runs, the run exists with status `queued` or `running` and a progress log written for people (which step started, which finished and with what count), which the panel shows as a live console and keeps collapsed once done. Progress never includes internal paths, raw tool output or stack traces: if something fails, it says in which phase and that the team can check the logs with the ID. When it finishes, the panel shows a toast (and a browser notification if you've already granted permission).

## Container images

**New scan → Container image** scans an image exactly as you'd reference it in `docker pull` (`ghcr.io/acme/api:1.4`, `nginx:1.27`, `…@sha256:…`), reading it directly from the registry. **It isn't run or built**, and it takes no space in your Docker.

| What | How |
| --- | --- |
| System and application packages | **Trivy and Grype**. On source code they agree almost completely, but on images they disagree on packages with patches backported by the distribution (on `nginx:1.21`: 781 advisories in common, 99 only from Trivy and 11 only from Grype, one of them critical). Advisories are merged by package, version and identifier (CVE/GHSA); those both engines see get a confidence boost. |
| Secrets in layers | Trivy looks for credentials in each layer's files. |
| Credentials in `ENV` | Variables with a secret-like name (`*_TOKEN`, `*_PASSWORD`, `API_KEY`…) and a hard-coded value: anyone who pulls the image can read them with `docker inspect`. |
| Credentials in the history | `ARG`s used in a `RUN` (e.g. `NPM_TOKEN=… npm ci`), URLs with a username and password, and hard-coded `Authorization` headers: they stay in the image and can be read with `docker history`. The recommended fix is BuildKit's `RUN --mount=type=secret`. |
| Configuration | Tamandua rules: root user, missing `HEALTHCHECK`, `ADD` from a URL, exposed SSH, `latest` tag and images more than a year old. |
| History instructions | **Checkov** on a Dockerfile rebuilt from the image's history: downloads with TLS disabled (`curl -k`, `wget --no-check-certificate`, `NODE_TLS_REJECT_UNAUTHORIZED=0`), `pip --trusted-host`, unsigned package managers, `sudo`, `chpasswd`… Each finding points to the history step. Checkov's own image mode requires a Prisma Cloud account, which is why the Dockerfile is rebuilt. |

No secret value is stored: only the variable name or the history step. Private images need a **read-only** registry token, which an administrator saves (encrypted) in **Integrations → Container registries**. Each image is its own asset in **Findings**, identified by registry and repository, without the tag: when you scan `api:1.5`, whatever no longer appears compared with `api:1.4` is marked fixed.

Also available from the CLI (useful in CI): `make cli ARGS="scan-image --reference ghcr.io/acme/api:1.4"`. It returns `2` if there are findings.

## Findings and their lifecycle

**Findings** groups by repository. Each repository has a **register** with the current state of every finding (by its stable fingerprint), its origin, when it was first and last seen, and whether it's still open. It updates itself:

- **Full scan** of the main branch: whatever appears stays open (and is reopened if it had been fixed); whatever was open and no longer appears is **fixed automatically**.
- **PR review**: whatever the PR introduces stays open with origin "PR #n"; if a later commit in the same PR removes it, it's fixed. A PR closed without merging withdraws its findings; a merged PR leaves them waiting for the next full scan.
- **Manual triage**: in progress, false positive, accepted risk (administrators only, with an expiry date) or fixed. Except for "in progress", all of them require a reason, which is recorded in the history with user and date. A manual fix that reappears in a later scan reopens by itself.

### Excluded paths

Some folders aren't worth looking at: intentionally vulnerable examples (like `fixtures/` in this very project), tests with fake data, or generated code. An **administrator** excludes them per repository in **Findings → Excluded paths**, one per line (`fixtures/**`, `docs/*.md`, `**/testdata/**`; `*` doesn't cross folders, `**` does), with a mandatory reason that's recorded in the history. Patterns work like `.gitignore`: a pattern that matches a folder excludes everything inside it, so `fixtures` or `fixtures/*` also cover `fixtures/a/b.py`.

- Whatever falls under them doesn't count as open, isn't included in the report or the SARIF and **doesn't block PRs**. It doesn't disappear: it stays in the **Excluded** tab, and every run states in its limitations how many findings were left out and by which pattern.
- Excluding isn't fixing: excluded findings never become "fixed". If the exclusion is removed, they go back to open.
- Exclusions live on the server (in its database), **not in the repository**: a file in the repository would let a PR exclude itself. For the same reason, the repository's `.gitleaks.toml` isn't applied.
- Patterns that would exclude everything (`**`, `*/**`), absolute paths and `..` are rejected.

A repository's identity is its GitHub identity (its numeric ID): a renamed repository is still the same one, and findings from a deleted repository are withdrawn after a 24-hour grace period. You can filter by run, view open, fixed or all findings, and export to PDF, JSON, Markdown, SARIF or Jira. The "Current state" view exports its accumulated register through its own route, so it's never confused with an individual run. The PDF dossiers for SOC 2 Type II and ISO/IEC 27001:2022 are technical evidence for review, not certifications or compliance opinions. Reports are generated in English or Spanish.

### Remediation deadlines

Every pending finding has a due date based on its severity, counted from **first detection** (reopening it doesn't
restart the clock). By default: critical 7 days, high 30, medium 90 and low 180. An **administrator** changes them in
**Findings → Due dates** (empty means that severity never falls due), and they apply to every repository. They only run
for open or in-progress findings: fixed, excluded, false positives and accepted risks that haven't expired never fall due.

They show up in **Findings** (the "Overdue" card, an "Overdue by N days" or "Due in N days" badge, and the
**More filters → Due date** filter), in the **Overview** ("Overdue" KPI) and in the **audit report** (a section with the
policy and overdue findings sorted by delay: what SOC 2 and ISO 27001 ask for as evidence of timely remediation).

## Compliance: SBOM, VEX, malicious packages and CRA

- **SBOM (CycloneDX 1.6).** In **Compliance → Evidence** (or **Findings → More formats → SBOM**), for each scan or for the current state of a repository
  or image (taken from the latest full scan). It includes purl, version, licenses when Trivy provides them, whether the
  dependency is direct and, for images, the system packages. It doesn't make up what it doesn't know (supplier,
  per-component hash). Valid against the official schema; it's the baseline required by the CRA (Annex I) and BSI TR-03183-2.
- **VEX (OpenVEX).** Triage turned into standard statements: undecided → `under_investigation`; in progress or
  accepted risk → `affected` with the action; false positive → `not_affected` with the reason; fixed → `fixed`.
- **Malicious packages.** OpenSSF `MAL-*` advisories (via OSV) are flagged as **Malicious**, critical and "Act
  now", with the actual fix: remove the package and rotate the secrets from wherever it was installed. Never "update to…".
- **Audit report frameworks.** Besides SOC 2 and ISO 27001: PCI DSS 4.0.1, CRA, Brazil (CMN Res. 4.893/5.274),
  Chile (Law 21.663) and Colombia (SFC, CE 007/2018). The mapping to each control is indicative.
- **Evidence hub (Compliance view).** Pick a repository or image and download its SBOM, VEX, technical report or
  audit evidence for the chosen framework in one click; or the consolidated audit evidence of every analyzed asset.
  The files are the same exports as in Findings.
- **CRA kit (Compliance view, opt-in).** Only for manufacturers that sell products with software in the EU: an
  administrator turns it on in **Policies** ("We sell products with software in the EU (CRA)", off by default, with a
  reason kept in the history; turning it off keeps the data). Then an administrator marks which repositories or images
  are products. A CVE from the CISA KEV catalog on a product opens an event **to assess**, with no deadline running: KEV
  only says it's exploited somewhere. An administrator records "doesn't affect our product" (with a reason; the event
  closes and can be reopened) or "actively exploited in our product": only then do the Article 14 deadlines start from
  that moment (early warning within 24 h and notification within 72 h; final report 14 days after the fix), with a draft
  for ENISA and a record of who marked each stage as sent. Tamandua doesn't notify on your behalf. A false positive in
  triage doesn't open an event.

## CVE tracker

It searches a local copy of NVD kept in PostgreSQL (full-text search with a GIN index) cross-referenced with CISA KEV and EPSS: free text, CVE by prefix, severity, KEV only, year, sorting by date, CVSS or EPSS, and pagination. A background thread loads it from newest to oldest, resumable after a restart, and then keeps it current every 2 hours by modification date. Without an NVD API key, NVD allows 5 requests every 30 s and the full load (~400,000 CVEs) takes a few hours; with `TAMANDUA_NVD_API_KEY` (sent as a header, never logged) it's about 8 times faster. `TAMANDUA_CVE_SYNC=off` turns it off. Each CVE's detail shows which scanned repositories have it among their findings. When NVD hasn't scored it (since 2026 it only enriches some CVEs), the score comes from **EUVD** (ENISA), queried on demand and cached, which also says whether it's actively exploited.

For each CVE, the page shows severity and CVSS, EPSS, whether it's in CISA KEV, CWE, vector, references and **which of your repositories have it** among their findings. **Only those affecting me** limits the list to CVEs
open in your repositories and images (excluding whatever was dismissed in triage), and each row is marked "affects you". The search is kept in the URL, so you can share or reload it. In the **Overview**, the news panels show CVEs published in the last 7 and 30 days, plus a 3D "skyline" of the last 30 days by severity.

## Pull request review

**Pull requests** lists the open PRs of every repository in the GitHub App. An administrator turns on, per repository, **Watch**, **Comment and set the commit status on GitHub**, and the blocking threshold (critical, high or above, which is the default, medium or above, or never). There are no webhooks, so the server doesn't need to be reachable from the internet: a watcher polls every `TAMANDUA_PR_POLL_SECONDS` (300 s by default, 60 minimum) and queues a review for each new head commit; drafts are skipped, and **Review now** triggers one by hand.

**Main branch kept current.** With watching on, the watcher also checks the latest commit on the main branch: if it changed (a merge), it rescans the whole repository, at most once every `TAMANDUA_BRANCH_MIN_MINUTES` (60 min) and only when the queue is nearly empty. You can turn this off per repository ("Rescan the main branch when it changes").

**New advisories without rescanning.** Every scan stores its dependencies with their versions. Once a day (`TAMANDUA_ADVISORY_WATCH_HOURS`) they're checked against the updated OSV database using OSV-Scanner **offline**: the advisories are downloaded, and the dependency list never leaves the server. Anything the register didn't know about opens as a "New advisories" run that only adds findings: the next full scan has the final say. Operating system packages in images are checked when the images are rescanned.

**Notifications (Integrations → Notifications).** An administrator adds Slack channels, Microsoft Teams (Workflows) or a generic webhook and chooses which events each one receives (new findings from a severity threshold, finished batches). One message per scan, grouped: the five most severe findings, the count and a link to the panel if `TAMANDUA_PUBLIC_URL` is set. URLs are stored encrypted and never sent back to the browser; the generic webhook signs every notification with HMAC-SHA256 (`X-Tamandua-Signature`). PR reviews don't notify here: they already comment on the PR.

The review scans the head commit with the same engines and counts only what the PR **introduces**:

- a code or secret finding counts if it falls on a line the diff adds or modifies; a dependency finding counts if the PR touches the manifest that declares it;
- if its fingerprint was already in the latest scan of the main branch, it's **pre-existing**: it's reported separately and not counted against the PR. Without a previous scan, everything on changed lines counts, and the review says so.

The result stays in the panel as one more run (with triage shared with the main branch and export to Jira). On GitHub, Tamandua publishes a **single comment** that's rewritten on every push (it only ever edits a comment created by this App) and a `tamandua` **commit status** that fails if the PR introduces anything at or above the threshold. Secrets are cited by rule and location; their value is never published.

**App permissions.** Reading PRs and publishing requires **Pull requests: Read and write** and **Commit statuses: Read and write**, which the setup guide already includes. If you change the permissions of an existing App, accept the update in *Settings → Applications → Installed GitHub Apps*; until then, the panel tells you which permission is missing instead of failing silently.

## Threat modeling

**Threats** stores system models: components (user, web app, API, service, function, database, cache, queue, storage, third party, identity provider), data flows (protocol, what data they carry, whether they're authenticated or encrypted) and trust boundaries. Each component can be linked to a scanned repository or to a domain.

- **Each model is a project.** You create it with a name and an approach; it doesn't need repositories. You associate the **project's repositories** whenever you want, one or several (microservices, microfrontends), and a component linked to a repository adds it to the list automatically.
- **Suggestions from any repository, at any time.** When you create the project (optional) or later, from each associated repository, Tamandua suggests components and flows that are **added to the diagram without duplicating** what's already there, respecting what the team drew (new items go into their boundary or to the right). Repositories from the GitHub App or the workspace both work, scanned or not. Only their manifests are read, on the spot, through the git API (repository tree and blobs; `contents: read` is enough, and the repository isn't downloaded): `package.json`, `requirements*.txt`, `pyproject.toml`, `go.mod`, `Cargo.toml`, `Dockerfile` and compose files, up to 40 files and excluding `node_modules`, fixtures and tests. FastAPI, Next.js, Express or axum become processes; psycopg, Prisma, Mongoose or sqlx become databases (an ORM is merged with its engine); Stripe, Twilio, S3, next-auth or an LLM SDK become third parties or identity providers. **Each suggested component cites the dependency and the file it came from** and is marked as suggested so the team can correct it. Only names are kept from the inventory, never versions or configuration values. An unscanned repository is modeled the same way, but its threats have no evidence until it's scanned.
- **Built-in, visible rules** (STRIDE `TM-S01`…`TM-E02` in `threat_model.py`, LINDDUN `PV-*` in `threat_methods.py`). Each threat states what triggers it on that element, its severity (the rule's base, one level up if the element is exposed and carries credentials or payments, one level down if it's internal and not very sensitive), its mitigations and its CWEs.
- **Approaches.** Each model chooses how it's analyzed, and you can switch without losing the diagram:

  | Approach | What for | What Tamandua does |
  | --- | --- | --- |
  | STRIDE | Security threats to components and flows | Built-in rules on the diagram (`TM-*`) |
  | LINDDUN | Threats to people's privacy | Built-in rules on elements that hold personal data (`PV-*`) |
  | PASTA | Business risk in seven stages | Stages with notes; stages 3, 4 and 5 are fed by the diagram, STRIDE and the scans |
  | Attack trees | Paths toward an attacker's goal | AND/OR tree editor with difficulty, element and mitigation; works out which paths are still open |
  | MITRE ATT&CK | Real attackers' techniques | Selection of techniques (web, API, containers, cloud) to map onto components, with suggestions and a link to attack.mitre.org |
  | Custom | Your team's method | Permanent diagram and free selection of STRIDE/LINDDUN rules, your own threats, PASTA stages, trees, ATT&CK and table; saved with the model |

  In any approach you can **add your own threats** (scenario, category, element, severity, likelihood, impact, owner and mitigation). Each approach has a **reference guide** (what each letter means, the stages, how to build a tree) that opens on demand next to your work and remembers whether you left it open; categories show their guiding question on hover.
- **Diagram editor.** In **Diagram**, you drag components, create flows by connecting their handles, and trust boundaries are boxes you can move (taking their components along) and resize; a component belongs to the boundary that contains its center. Clicking an element lets you edit its name, type, technology, description, data and properties in the side panel. Besides the catalog, you can create a **custom type** with any name and a base role that determines which automatic rules apply to it. Positions are saved with the model and used by the exports. **Table** is still available for editing many elements at once.
- **Evidence, not confirmation.** If a component's code has open findings with one of those CWEs, the threat is shown as **Evidenced** and links to them: it's a signal to review, not proof that the scenario is exploitable. Set the component's **folder** within the repository (e.g. `frontend/`) so that in a monorepo only findings from its own code count; without a folder, the whole repository counts and the threat says so. Findings in excluded paths don't count either. Dependency advisories are evidence of "vulnerable dependencies", not of injection in your code. Whatever was dismissed in triage doesn't count.
- **Decisions** per threat (mitigated, accepted, not applicable) with reason, author and date.
- **Native import and export**: from the list, **Import JSON** opens a wizard with six complete examples (one per approach), an editor to paste or modify JSON, file upload, download and copy of the example, instructions for an LLM, and a pre-validation step that creates no model. **Import model** is only enabled after the current text validates successfully. From the editor, **Model JSON** downloads `model.json`. It includes the full diagram (positions, components, flows and boundaries), approach, custom modules, threats written by the team, PASTA stages, trees and ATT&CK techniques. You can edit it by hand or ask an LLM to generate it. It accepts both the `{"format":"tamandua-threat-model","version":1,"model":{...}}` envelope the app downloads and a bare model object. Repositories and domains in the file are saved as `repository_refs` and `asset_ref`: **they're pending references, never automatic links**. They don't need to exist at import time; you can link them later in the editor. Instance IDs, decisions and scan findings aren't part of the portable format. Minimal example:
- **Diagram layout.** In the JSON, `position` (components), `size` (resized components) and `box` (boundaries) are **optional**: without them, the editor lays everything out automatically, in layers (actors → applications → APIs and services → data and third parties), with each boundary as a block that contains its components. If a JSON file has positions that don't fit its boundaries (a box smaller than its components, or two overlapping boxes), it's re-laid out on import and the preview warns you. **Tidy up** applies the same layout at any time. Boundaries and components are resized by dragging an edge or a corner (the handles appear on hover); hold **Shift** to keep the aspect ratio. Flow labels are placed on the stretch of the line that doesn't overlap components or other labels; long labels are shortened and can be read in full by selecting the flow or hovering over it. When the server is updated, open tabs show **Reload** so you don't keep working on the old panel. Types that aren't in the list are created with **Other type (you name it)**, choosing the base role they're analyzed with.

  ```json
  {
    "name": "Portal de clientes",
    "methodology": "custom",
    "custom_modules": ["stride", "trees", "manual"],
    "repository_refs": ["equipo/portal"],
    "components": [
      {"id": "usuario", "name": "Cliente", "kind": "actor"},
      {"id": "api", "name": "API", "kind": "api", "asset_ref": "equipo/portal", "data": ["pii"]}
    ],
    "flows": [{"id": "login", "source": "usuario", "target": "api", "protocol": "https", "authenticated": false}],
    "boundaries": [{"id": "servidor", "name": "Servidor", "components": ["api"]}]
  }
  ```

  The base diagram is shared by every approach. The approach-specific sections are validated: STRIDE and LINDDUN accept your own threats; PASTA accepts its stages and trees; Attack trees accepts trees; ATT&CK accepts techniques. **Custom** accepts any combination, but each section needs its module enabled in `custom_modules`. An incompatible JSON is rejected with a message saying which section doesn't belong and suggesting another approach or Custom. When exporting a fixed approach, only its active sections are included; data from another approach that may remain after switching templates doesn't leak into that file.

- **Other exports**: the diagram on its own as SVG (`diagram.svg`, saving pending changes before downloading), OWASP Threat Dragon v2 JSON, an OWASP pytm script (`tm.py`, for those who keep modeling as code), Markdown, and PDF reports: general, SOC 2 Type II and ISO/IEC 27001:2022. The PDFs include an evidence readiness matrix and explicit limitations; the model's threats aren't presented as confirmed flaws. The Threat Dragon JSON follows the v2 format, but importing it into Threat Dragon hasn't been tested. Downloads go through the authenticated API and show the actual error if they fail.

## Jira

An administrator connects **Jira Cloud** in **Integrations** with the site, the email, an [Atlassian API token](https://id.atlassian.com/manage-profile/security/api-tokens), the project key and the issue type. Before saving, Tamandua checks the account, the project and that the issue type exists. The token is stored encrypted in the `config/` vault and never goes back to the browser: you see the email, the project and its last four characters.

Only `https://<site>.atlassian.net` sites are accepted and redirects aren't followed, so the panel can't be used to send requests anywhere else. Jira Server/Data Center is deliberately out of scope: it would require accepting arbitrary hosts on the customer's network.

In the findings table, **Create in Jira** turns the selection into issues (up to 50 findings at a time; whatever was dismissed in triage isn't exported). Tamandua creates **one issue per remediation task**: advisories for the same package go together with the version that fixes them all, while code and secret findings go one by one. Each issue carries the `appsec-<fingerprint>` label of every finding it covers. Before creating, Tamandua searches by those labels, and the link is remembered per repository and fingerprint (in the database), so exporting again, today or after the next scan, links the existing issue instead of duplicating it. If the project doesn't allow setting the priority on creation, Tamandua retries without it. Issues are written in `TAMANDUA_DEFAULT_LOCALE`, since the whole team reads them.

## Analysis engines

Code review runs five external engines, each in its own container pinned by digest, with no capabilities, no privilege escalation and the snapshot mounted read-only:

| Engine | Coverage | Network | Image |
| --- | --- | --- | --- |
| **Trivy 0.74.0** | dependencies from any ecosystem, infrastructure configuration (Dockerfile, Kubernetes, Terraform) and secrets | only to download its vulnerability database, cached in `data/trivy-cache/`; sends nothing from the repository | `aquasec/trivy@sha256:62b1e65e…` |
| **Gitleaks 8.30.1** | secrets, high precision, values redacted | none | `ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0…` |
| **Opengrep 1.30.0** | SAST with **Tamandua rules** (`rules/`, MIT) for JavaScript, TypeScript, Python, Java, Go, PHP, Ruby and C# | none | `localhost/tamandua/opengrep:1.30.0`, built locally |
| **Checkov 3.3.19** | infrastructure as code (Terraform, CloudFormation, Kubernetes, Helm, Kustomize, ARM, Bicep, Serverless, OpenAPI, Ansible, Dockerfile) and pipelines (GitHub Actions, GitLab CI, Bitbucket, Azure Pipelines, CircleCI, Argo) | none (`--skip-download`, no external modules) | `bridgecrew/checkov@sha256:d3e96ada…` |
| **zizmor 1.30.1** | GitHub Actions in depth: template injection, dangerous triggers (`pull_request_target`), token permissions, actions not pinned by SHA or archived, credentials that persist after `checkout` | none (`--offline`) | `ghcr.io/zizmorcore/zizmor@sha256:a2eb396d…` |

The Opengrep image is built by `make build` (or `make up`): it downloads the official binary and checks it against its pinned SHA-256 (Cosign verification is documented in `docker/engines/opengrep/VERIFY.md`).

Tamandua writes its own rules because the Semgrep registry rules can't be used in a product (internal-use-only license since December 2024). There are 58 of them, aimed at specific sinks with taint analysis where the language allows it, and they're validated against `fixtures/sast-samples/`: all 58 fire on vulnerable code across the seven languages. Each step states which of the repository's languages have rules and which don't. There's no cross-file analysis: that's a limitation of every open source SAST tool, and each run says so in its limitations.

### Several engines, one finding

Trivy and Checkov review the same infrastructure and overlap on many rules, just like Checkov and zizmor on GitHub Actions. When two engines see **the same problem in the same place** (same file, overlapping lines and an equivalent rule), a **single finding** remains: the one from the primary engine, with "Detected by Trivy and Checkov", the equivalent rules in view and one extra point of confidence. Whatever only one engine sees is added as is.

| Coverage | Primary | Adds |
| --- | --- | --- |
| Infrastructure as code | Trivy | Checkov |
| GitHub Actions and other pipelines | zizmor | Checkov |
| Image configuration | Tamandua rules | Trivy and Checkov |

Rule equivalence is a table measured on reference vulnerable repositories (TerraGoat, CfnGoat, KubernetesGoat and CI/CD-Goat) and reviewed pair by pair; when the table doesn't know a pair, titles are compared. Measured on those repositories, Checkov adds between 39 % more issues (Kubernetes) and more than double (Terraform) on top of what Trivy already finds:

| Repository | Trivy | Checkov | Merged | New from Checkov | zizmor |
| --- | --- | --- | --- | --- | --- |
| TerraGoat (Terraform) | 244 | 472 | 196 | 276 | 13 |
| KubernetesGoat (Kubernetes, Helm) | 321 | 349 | 225 | 124 | 0 |
| CfnGoat (CloudFormation) | 67 | 70 | 42 | 28 | 9 |
| CI/CD-Goat (pipelines) | 45 | 90 | 69 | 21 | 209 |

Checkov's free edition doesn't provide severity (its paid platform does). For rules paired with Trivy, Trivy's severity is used; for the rest, a rule visible in the code (`checkov_severity`): public exposure, privileges, credentials or disabled TLS go up to high; tags, monitoring, backups or customer-managed keys go down to low; everything else stays medium. zizmor does provide severity; "action not pinned by SHA" is lowered to medium because exploiting it requires first compromising the third-party action.

Neither Checkov nor zizmor stores code snippets in the report: only rule, file and lines, because the snippet might contain a secret.

If Docker isn't available, the step is declared `not_tested` with the reason, and the review continues with the internal Python rules and the secret patterns, labeled as such. Dependencies are reviewed by **Trivy and OSV-Scanner** together. OSV-Scanner uses the OSV database, which includes Dependabot's GitHub Advisory Database, and understands more formats (.NET `.csproj` and `Directory.Packages.props`, `gradle.lockfile`, `uv.lock`, `Pipfile.lock`, `pubspec.lock`…). Both download their advisory databases and compare locally: the dependency list isn't sent to anyone. An advisory both engines detect (even if one calls it by its CVE and the other by its GHSA) becomes **a single finding**, "detected by Trivy and OSV-Scanner"; the fingerprint is Trivy's, so existing triage and tickets are preserved.

Manifests and lockfiles enter the snapshot by name, without the 2 MB limit that applies to code (a large `package-lock.json` is normal); they have a safety cap of 64 MB.

## Dependency findings

**Development dependencies** (`devDependencies`, development groups) are reviewed too, and marked as such: they don't reach production, but they run on developer machines and in CI, which is exactly where supply chain attacks hit. They drop one priority level unless they're in CISA KEV. For code, Trivy is enough: measured on real repositories, Grype finds the same once development dependencies are included (Grype is used for container images, where it adds value).

Every dependency advisory arrives ready for a decision, not as a bare identifier. From the OSV record, Tamandua takes the summary, CVE/GHSA aliases, CWE and the CVSS vector, whose **score is computed** with the 3.1 formula rather than copied. The **fixed version** is chosen from the range that contains the installed version: someone on `minimatch 9.0.5` hears "update to 9.0.6", not "to 10.2.3". It's cross-referenced with two public feeds downloaded in bulk and stored daily in `data/feeds/` (the **CISA KEV** catalog of active exploitation and **EPSS** probabilities), so nobody receives CVE-by-CVE lookups that would reveal which dependencies customers have.

With that, each finding comes with a **priority with its factors in view** (`act` if it's in KEV or combines CVSS ≥ 9 with a high EPSS; `attend`; `track`), a concrete remediation and a **stable fingerprint** independent of the lockfile's path, which is what prevents duplicate tickets across runs. The panel groups advisories by package and says which version fixes them all; `GET /api/runs/{id}/tickets.json` exports one ticket per finding in that shape, designed for the Jira connector.

If the owner allows sending **only dependency names and versions** to `api.osv.dev`, tick the panel's checkbox for that run or use `--allow-osv-upload` in the CLI. With that permission, OSV-Scanner also resolves transitive dependencies for manifests without a lockfile (querying deps.dev); without it, it only compares what the manifests and lockfiles declare. By default, SCA shows up as `not_tested`. An inconclusive lookup is never presented as zero vulnerabilities either.

```bash
make scan DIR=../my-repo ARGS="--allow-osv-upload"
```

JSON, Markdown, SARIF, SOC 2 Type II and ISO 27001 reports can be downloaded from each run, in English or Spanish. The compliance profiles organize technical evidence; they don't constitute an audit, certification or attestation. CWE/CVE/GHSA links point to the corresponding public records when identifiers exist. DAST against real targets is still pending.

## AI providers

Each user can save their own OpenAI or Anthropic key in **Integrations**; it's checked against the provider's model catalog without sending code or findings. Today, AI **plays no part** in the analysis: when it does, it will be optional, with consent on every run.

```bash
make cli ARGS="providers"
make cli ARGS="ai-check --provider openai"
```

The CLI returns `0` with no findings, `2` with findings, `3` if the analysis was incomplete, and `1` on invalid input.
