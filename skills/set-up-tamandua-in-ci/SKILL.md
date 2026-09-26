---
name: set-up-tamandua-in-ci
description: Add Tamandua (self-hosted, open source application security scanner) to a repository's CI — GitHub Actions or GitLab CI — so pull requests fail only on the vulnerabilities, secrets and misconfigurations they introduce, with SARIF for GitHub code scanning; or add it as a git pre-push hook. Use when the user asks to add security scanning, SAST/SCA/secret scanning or a security gate to CI or to their local workflow. ES: añadir análisis de seguridad al CI, bloquear pull requests, pre-push.
license: AGPL-3.0-only
metadata:
  author: tamandua
  homepage: https://github.com/BrayansStivens/appsec-agent
---

# Tamandua in CI and before pushing

A single CI step that scans what the pull request introduces (not what was already there) and blocks from the
severity the team chooses. Tamandua runs as a container and starts the engines (Opengrep with the Tamandua rules,
Gitleaks, Trivy, OSV-Scanner, Checkov, zizmor) as sibling containers: **the runner needs the Docker socket**.

## 1. Start from the official template

The complete GitHub Actions and GitLab CI templates are in the CI section ("En CI") of `docs/cli.md` in the Tamandua
repository (`${TAMANDUA_DIR:-$HOME/tamandua}/docs/cli.md` if it is cloned). Copy the template instead of writing it
from memory, and adapt only what is needed.

Ask the user, if it is not clear:

- **Threshold** (`--fail-on`): `high` by default; `critical` to start without friction; `never` to report only.
- **Paths with deliberately vulnerable examples** (fixtures, testdata): they go in `--exclude`, one per pattern.

## 2. Non-negotiable rules

- `fetch-depth: 0` in the checkout (GitHub) or `git fetch origin "$CI_MERGE_REQUEST_TARGET_BRANCH_NAME"` (GitLab):
  without history there is no comparison with the base and the scan exits with code 2.
- Branch and repository names **through `env:`**, never interpolated with `${{ … }}` inside `run:` (command
  injection from a branch name).
- Minimal `permissions`: `contents: read` and, only if the SARIF is uploaded, `security-events: write`.
  `persist-credentials: false` in the checkout.
- Actions pinned by commit SHA, not by tag.
- The data folder (`/data`) outside the scanned code; the code mounted read-only (`/src:ro`).
- No `--allow-incomplete` by default: a scan that did not finish is not a clean one (code 3).
- `--exclude` lives in the workflow, which a pull request can change: suggest protecting `.github/workflows/` (or
  `.gitlab-ci.yml`) with CODEOWNERS and mandatory review.
- On GitLab, a runner with the host's socket (`shell` executor, or `docker` with `/var/run/docker.sock` mounted).
  With Docker-in-Docker the engines cannot see the folders.

Step exit codes: `0` pass, `1` block, `2` usage error, `3` incomplete (check the not-analyzed lines in the log).

## 3. Before pushing (optional)

A scan takes around half a minute: it fits `pre-push`, not `pre-commit`. In `.git/hooks/pre-push`
(with `chmod +x`), asking the user for permission first because it changes their local workflow:

```sh
#!/bin/sh
make -s -C "${TAMANDUA_DIR:-$HOME/tamandua}" scan DIR="$(git rev-parse --show-toplevel)" ARGS="--base origin/main --quiet"
```

## 4. Check that it works

Open a test pull request (or run the same `docker run` locally) and confirm that: the step ends with the expected
code, the summary names the base it compared against and, with SARIF, the results appear in *Code scanning*.
If it fails, the reason is in the not-analyzed lines of the summary or in the Docker error. To fix what it finds, use the
`fix-findings-with-tamandua` skill.
