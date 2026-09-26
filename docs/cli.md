English · [Español](es/cli.md)

# Scanning from the terminal and in CI (`scan`)

`scan` analyzes a local folder with the same engines as the panel (Opengrep, Gitleaks, Trivy,
OSV-Scanner, Checkov, zizmor). It never runs your code and never sends it to any service. Use it to
check your change before you push, and to block a pull request in CI.

## Quick start

From the Tamandua folder (you only need `make` and Docker):

```bash
make scan DIR=../my-repo
make scan DIR=../my-repo ARGS="--base main"
```

With `--base main`, Tamandua reports only what **your change introduces**. It also scans the
starting point (the merge-base with `main`) and drops whatever was already there: touch a
`package-lock.json` that already had vulnerabilities and they aren't charged to you; add a
vulnerable dependency and they are. It counts what you haven't pushed yet (uncommitted changes and
new files git doesn't ignore), so it works before the push.

```text
Tamandua · my-repo · changes since main (merge-base 73223791, 3 files)

CRITICAL app.py:8  Injection: eval exec non literal
HIGH     requirements.txt  urllib3 1.26.4: 9 advisories (5 high, 4 medium) → update to 2.7.0
HIGH     settings.py:1  Exposed GitHub personal access token

4 already existed in the code you're touching: they don't block.

Engines: Opengrep 1.30.0, Gitleaks 8.30.1, Trivy 0.74.0, OSV-Scanner 2.6.0

BLOCKED · threshold: high or above · 7 new findings at severity high or above
```

Advisories for the same dependency are collapsed into one line, with the version that fixes all of
them. `--format json` and `--format sarif` keep every advisory separate.

The output speaks the language in `TAMANDUA_DEFAULT_LOCALE` (`en` by default, `es` for Spanish): text,
JSON and SARIF alike. In a container, pass it with `-e TAMANDUA_DEFAULT_LOCALE=es`.

## Options

| Option | What it does |
| --- | --- |
| `--base REF` | Starting branch or commit (`main`, `origin/main`, a SHA). Only what the change introduces counts. |
| `--no-baseline` | With `--base`, skip scanning the starting point: it takes half the time, but everything on changed lines counts (and so does any advisory in a lockfile you touch). |
| `--fail-on` | Severity at which the scan fails: `critical`, `high` (default), `medium`, `low` or `never` (report only). |
| `--format` | `text` (default), `json` or `sarif` (SARIF 2.1.0, with `security-severity` for GitHub code scanning). |
| `--output FILE` | Write the result to a file; the text summary still goes to stderr. |
| `--exclude PATTERN` | Path whose findings don't count: a glob relative to the root (`fixtures`, `**/testdata`, `docs/*.md`). It works like `.gitignore`: a folder excludes everything inside it; `*` doesn't cross `/`, `**` does. Repeatable. The output says how many findings were excluded. |
| `--allow-incomplete` | Don't fail if an engine couldn't run. By default it fails: an analysis that didn't finish is not the same as "clean". |
| `--allow-osv-upload` | Allow external lookups (dependency names and versions to OSV and deps.dev, to resolve transitive dependencies). By default nothing leaves the machine. |
| `--name` | Display name (useful inside a container, where the folder is called `/src`). |
| `--quiet` | No progress messages. |

Progress goes to stderr, so stdout stays clean for `json` and `sarif`.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Pass: nothing at or above the threshold. |
| `1` | Blocked: there are new findings at or above the threshold. |
| `2` | Usage error: the folder doesn't exist, or the git reference is invalid or missing (forgot `git fetch`?). |
| `3` | Incomplete: an engine didn't run (Docker, images, network). Check the "Not analyzed" lines. |

`make` turns any failure into its own exit code 2; in CI, use `docker run` (below) to keep the exact
code.

## Before you push (pre-push)

A full scan takes around half a minute, so it fits `pre-push` better than `pre-commit`. In your
repository's `.git/hooks/pre-push` (and `chmod +x` it):

```sh
#!/bin/sh
make -s -C ~/tamandua scan DIR="$(git rev-parse --show-toplevel)" ARGS="--base origin/main --quiet"
```

## In CI

Tamandua runs as a container and launches the engines as sibling containers, so the runner needs
the Docker socket (GitHub Actions Linux runners have it). The data folder (`/data`) caches the
advisory databases between steps.

### GitHub Actions

```yaml
name: Tamandua
on: pull_request

permissions:
  contents: read
  security-events: write   # to upload the SARIF to code scanning

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      # Pin actions by SHA in your organization.
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0              # history is needed to compare against the base
          persist-credentials: false
      - name: Build Tamandua
        run: |
          git clone --depth 1 https://github.com/BrayansStivens/appsec-agent "$RUNNER_TEMP/tamandua"
          make -C "$RUNNER_TEMP/tamandua" build
      - name: Scan what the PR introduces
        env:
          BASE_REF: ${{ github.base_ref }}      # never interpolated directly into the script
          REPO_NAME: ${{ github.event.repository.name }}
        run: |
          mkdir -p "$RUNNER_TEMP/tamandua-data"
          docker run --rm \
            -v /var/run/docker.sock:/var/run/docker.sock --group-add "$(stat -c %g /var/run/docker.sock)" \
            --user "$(id -u):$(id -g)" -e HOME=/tmp \
            -v "$PWD":/src:ro -v "$RUNNER_TEMP/tamandua-data":/data \
            tamandua/app:0.9 python -m tamandua scan /src --name "$REPO_NAME" \
            --base "origin/$BASE_REF" --format sarif --output /data/tamandua.sarif
      - uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: ${{ runner.temp }}/tamandua-data/tamandua.sarif
```

### GitLab CI

You need a runner with access to the host's Docker socket (the `shell` executor, or `docker` with
`/var/run/docker.sock` mounted). With Docker-in-Docker (`dind`), the engines can't see the folders.

```yaml
tamandua:
  stage: test
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script:
    - git fetch origin "$CI_MERGE_REQUEST_TARGET_BRANCH_NAME"
    - git clone --depth 1 https://github.com/BrayansStivens/appsec-agent /tmp/tamandua
    - make -C /tmp/tamandua build
    - mkdir -p /tmp/tamandua-data
    - >
      docker run --rm -v /var/run/docker.sock:/var/run/docker.sock --group-add "$(stat -c %g /var/run/docker.sock)"
      --user "$(id -u):$(id -g)" -e HOME=/tmp -v "$PWD":/src:ro -v /tmp/tamandua-data:/data
      tamandua/app:0.9 python -m tamandua scan /src --name "$CI_PROJECT_NAME"
      --base "origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME"
```

> Tamandua's own repository uses this template in [`.github/workflows/ci.yml`](../.github/workflows/ci.yml)
> (with `--exclude fixtures/` for its intentionally vulnerable examples). The GitLab template has been
> checked with the same `docker run` locally, but not yet on a real runner. If something fails, the
> Docker or engine error shows up on the "Not analyzed" line.

**Exclusions in CI.** `--exclude` lives in the workflow, and a pull request can change the workflow.
Protect `.github/workflows/` with CODEOWNERS and required reviews so nobody can exclude their own code
unnoticed. (That's exactly why the panel keeps exclusions on the server.)

## Privacy

The code is copied to a temporary folder (without symlinks or anything the scan ignores) and deleted
when the scan ends. The engines read it read-only, with no network except to download their public
advisory databases. Nothing from the repository leaves the machine unless you pass
`--allow-osv-upload`.
