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
severity the team chooses. CI uses the published worker image (`ghcr.io/brayansstivens/tamandua-worker`), which runs
the engines (Opengrep with the Tamandua rules, Gitleaks, Trivy, OSV-Scanner, Checkov, zizmor) inside it: nothing to
build and **no Docker socket**. On GitHub it is the Tamandua Action (`uses: BrayansStivens/appsec-agent@v0.9`).

## 1. Start from the official template

The complete templates (GitHub Actions with the Action and SARIF upload, GitLab CI with the image as the job's image)
and the table of the Action's inputs are in the "In CI" section of `docs/cli.md` in the Tamandua repository
(`${TAMANDUA_DIR:-$HOME/tamandua}/docs/cli.md` if it is cloned). Copy the template instead of writing it from memory,
and adapt only what is needed.

Ask the user, if it is not clear:

- **Threshold** (input `fail-on`, `--fail-on` in GitLab): `high` by default; `critical` to start without friction;
  `never` to report only.
- **Paths with deliberately vulnerable examples** (fixtures, testdata): input `exclude`, one pattern per line
  (`--exclude` per pattern in GitLab).
- **Other scanners already in CI** (Semgrep, CodeQL, Snyk…) and a Tamandua server: their SARIF can go to the server
  with the Action's `import-sarif`, `server` and `token` inputs (the token from a secret, never inline).

## 2. Non-negotiable rules

- `fetch-depth: 0` in the checkout (GitHub) or `GIT_DEPTH: "0"` and a fetch of the target branch (GitLab): without
  history there is no comparison with the base and the step exits with code 2.
- Pin every action by commit SHA with the version in a comment, the Tamandua Action included (the tag's commit).
- Minimal `permissions`: `contents: read` and, only if the SARIF is uploaded, `security-events: write`;
  `packages: read` only while the image is private. `persist-credentials: false` in the checkout.
- Nothing from `${{ … }}` interpolated inside `run:`: pass values through `env:` (command injection from a branch
  name). The Action already does this with its inputs.
- No `allow-incomplete` (`--allow-incomplete`) by default: a scan that did not finish is not a clean one (code 3).
- `exclude` lives in the workflow, which a pull request can change: suggest protecting `.github/workflows/` (or
  `.gitlab-ci.yml`) with CODEOWNERS and mandatory review.
- While the repository and its image are private: the Action's `registry-token` input (the job's `GITHUB_TOKEN` with
  `packages: read`, or a classic token with `read:packages` in a secret); in GitLab, `DOCKER_AUTH_CONFIG`.

Step exit codes: `0` pass, `1` block, `2` usage error, `3` incomplete (check the not-analyzed lines in the log). The
Action exposes it as the `exit-code` output and the SARIF path as `sarif`.

## 3. Before pushing (optional)

A scan takes around half a minute: it fits `pre-push`, not `pre-commit`. It needs Docker and a copy of Tamandua. In
`.git/hooks/pre-push` (with `chmod +x`), asking the user for permission first because it changes their local workflow:

```sh
#!/bin/sh
make -s -C "${TAMANDUA_DIR:-$HOME/tamandua}" scan DIR="$(git rev-parse --show-toplevel)" ARGS="--base origin/main --quiet"
```

## 4. Check that it works

Open a test pull request and confirm that: the step ends with the expected code, the summary names the base it
compared against and, with SARIF, the results appear in *Code scanning*. If it fails, the reason is in the
not-analyzed lines of the summary or in the Docker error (a `denied` on the pull means the registry credentials are
missing). To fix what it finds, use the `fix-findings-with-tamandua` skill.
