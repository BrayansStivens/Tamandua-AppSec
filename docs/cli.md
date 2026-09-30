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

Fixed by this change (1): it was in the starting point, it's gone, and its file changed.
  HIGH     db.py:14  SQL built by concatenating strings

Engines: Opengrep 1.30.0, Gitleaks 8.30.1, Trivy 0.74.0, OSV-Scanner 2.6.0

BLOCKED · threshold: high or above · 7 new findings at severity high or above
```

**What the change fixes.** Comparing both scans also shows what the starting point had and the change no
longer has. It is credited as **fixed** only when both scans finished and its file is one the change
modified. If it went away because the file was deleted, or although its file wasn't touched, the output
says so and doesn't count it as a fix; if either scan was incomplete, it says nothing can be verified. A
finding that only moved (same rule, same file) isn't reported. This works for what Tamandua's engines
detect; findings imported from other tools are verified by importing that tool's results again.

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
| `--summary FILE` | Also append a Markdown summary: verdict, what the change introduces and what it fixes (the Action writes it to the run's summary page). |
| `--quiet` | No progress messages. |

Progress goes to stderr, so stdout stays clean for `json` and `sarif`.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Pass: nothing at or above the threshold. |
| `1` | Blocked: there are new findings at or above the threshold. |
| `2` | Usage error: the folder doesn't exist, or the git reference is invalid or missing (forgot `git fetch`?). |
| `3` | Incomplete: an engine didn't run (Docker, images, network). Check the "Not analyzed" lines. |

`make` turns any failure into its own exit code 2; in CI, the Action and `docker run` (below) keep the
exact code.

## Before you push (pre-push)

A full scan takes around half a minute, so it fits `pre-push` better than `pre-commit`. In your
repository's `.git/hooks/pre-push` (and `chmod +x` it):

```sh
#!/bin/sh
make -s -C ~/tamandua scan DIR="$(git rev-parse --show-toplevel)" ARGS="--base origin/main --quiet"
```

## Import other tools' results (`import-sarif`)

```sh
python -m tamandua import-sarif FILE [FILE...] --asset NAME [--tool NAME] [--partial] [--commit SHA] [--branch NAME] [--server URL]
```

Adds the findings of any tool that writes SARIF 2.1.0 (Semgrep, CodeQL, Snyk, Trivy, Strix…) to the registry of an
asset Tamandua already knows, by its key or its name (`owner/repo`). From then on they have the same lifecycle as
Tamandua's own: triage, deadlines, tickets and notifications.

- **Full by default:** whatever that same tool no longer reports is marked fixed. Tamandua's own scans never fix an
  imported finding, because its engines can't see what another tool found.
- `--partial`: the tool looked at part of the asset; the import opens and updates, never fixes.
- `--tool` replaces the tool name the SARIF carries. Several files are one import.
- `--server https://…` sends the files to that server's `/api/ci/sarif` with the token in `TAMANDUA_IMPORT_TOKEN`
  (an environment variable, never an option; plain `http://` only for localhost). Without `--server` it imports
  into the local database (on the server itself).

It prints one line per tool. Exit codes: `0` imported, `2` usage, document or server error. The panel's
**New scan → Import SARIF** does the same from the browser.

## In CI

In CI, Tamandua runs from the published worker image, `ghcr.io/brayansstivens/tamandua-worker:0.10`, which carries
the engines and runs them as processes of its own: no build, and no Docker socket.

### GitHub Actions

One step with the Tamandua Action. On a pull request it compares against the base branch on its own, and it
writes SARIF for code scanning:

```yaml
name: Tamandua
on:
  pull_request:
  push:
    branches: [main]

permissions: {}

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # upload the SARIF to code scanning
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1  # v7.0.1
        with:
          fetch-depth: 0              # history is needed to compare against the base
          persist-credentials: false
      - id: tamandua
        uses: BrayansStivens/appsec-agent@v0.10.1   # pin it to the tag's commit SHA, as with the other actions
        with:
          exclude: |
            fixtures/
      - uses: github/codeql-action/upload-sarif@2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2  # v4.38.2
        if: always() && steps.tamandua.outputs.sarif != ''
        with:
          sarif_file: ${{ steps.tamandua.outputs.sarif }}
          category: tamandua
```

The step ends with the same code as `scan` (table above): it fails on `1`, `2` and `3`. The report goes to the log,
in English unless the step sets `env: TAMANDUA_DEFAULT_LOCALE: es`.

| Input | Default | What it does |
| --- | --- | --- |
| `path` | `.` | Folder to scan, relative to the workspace. |
| `base` | empty | Like `--base`. Empty: `origin/<base branch>` on a pull request and a full scan otherwise; `none`: always a full scan. |
| `fail-on` | `high` | Like `--fail-on`: `critical`, `high`, `medium`, `low` or `never`. |
| `exclude` | empty | One pattern per line; each becomes an `--exclude`. |
| `name` | the repository's name | Like `--name`. |
| `sarif` | `$RUNNER_TEMP/tamandua.sarif` | Where to write the SARIF (relative paths start at the workspace). |
| `image` | `ghcr.io/brayansstivens/tamandua-worker:0.10` | Worker image. Pin it by digest (`…@sha256:…`) if you want nothing to move under you. |
| `allow-incomplete` | `false` | `true`: like `--allow-incomplete`. |
| `scan` | `true` | `false`: skip the scan and only import (below). |
| `import-sarif` | empty | SARIF files from other tools to send to a Tamandua server, one per line. |
| `server` | empty | The Tamandua server (`https://…`) for `import-sarif`. |
| `token` | empty | The server's `TAMANDUA_IMPORT_TOKEN`, from a secret. It reaches the container only as an environment variable. |
| `asset` | `owner/name` of the repository | Asset (already known to the server) the imported findings belong to. |
| `import-partial` | `false` | `true`: the imported tool looked at part of the asset, so what it doesn't report stays open. Always on in pull requests: their results describe the branch, not the asset. |
| `registry-token` | empty | Token to pull the image while it is private (see below). |
| `registry-user` | the workflow's actor | User for `registry-token`. |

| Output | What it is |
| --- | --- |
| `sarif` | Path of the SARIF the scan wrote (empty if it didn't write one). |
| `exit-code` | `0` pass, `1` blocked, `2` usage error, `3` incomplete. With `import-sarif` too, the scan's code wins unless it is `0`. |

The run's summary page shows the verdict, what the pull request introduces and what it fixes.

How it runs: `docker run` of the image as the runner's user, with no capabilities, a read-only filesystem, the
workspace mounted read-only and the engine caches in `$RUNNER_TEMP/tamandua` (several steps in the same job share
them). The engines can't get an empty network of their own there (a plain `docker run` doesn't allow the user
namespaces it takes), so they share the container's network and run with their offline flags; your code still
isn't sent anywhere.

**While the repository is private.** Another repository can only use the Action if this one allows it
(*Settings → Actions → General → Access*), and pulling the image needs a token with `read:packages`: the job's
`GITHUB_TOKEN` (with `packages: read`) if the package grants your repository access, or else a classic token in a
secret (see [Access while the repository is private](deploy.md#access-while-the-repository-is-private)). The Action
logs in with `--password-stdin` and throws the credential away after the pull:

```yaml
    permissions:
      contents: read
      packages: read
      security-events: write
    steps:
      # …
      - id: tamandua
        uses: BrayansStivens/appsec-agent@v0.10.1
        with:
          registry-token: ${{ secrets.GHCR_TOKEN }}   # or ${{ secrets.GITHUB_TOKEN }}
```

#### Other tools' results

With `import-sarif`, the Action sends the SARIF of any tool (Semgrep, CodeQL, Snyk…) to your Tamandua server, which
adds its findings to the asset's registry next to its own. The server needs `TAMANDUA_IMPORT_TOKEN`
([configuration](configuration.md)) and must already know the asset. For example, Semgrep only, without Tamandua's
own scan:

```yaml
      - name: Semgrep
        run: |
          python -m pip install semgrep   # pin the version
          semgrep scan --config p/ci --metrics off --sarif --output semgrep.sarif
      - uses: BrayansStivens/appsec-agent@v0.10.1
        if: always()
        with:
          scan: false
          import-sarif: semgrep.sarif
          server: https://tamandua.example.com
          token: ${{ secrets.TAMANDUA_IMPORT_TOKEN }}
```

Leave `scan` at `true` to scan and import in the same step.

### GitLab CI

The worker image as the job's image: it already has git, Python and the engines, and it runs as an unprivileged
user. No Docker socket and no Docker-in-Docker.

```yaml
tamandua:
  stage: test
  image: ghcr.io/brayansstivens/tamandua-worker:0.10
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  variables:
    GIT_DEPTH: "0"   # history is needed to compare against the base
    BASE: $CI_MERGE_REQUEST_TARGET_BRANCH_NAME
  script:
    # The checkout belongs to another user: git needs to be told it is safe.
    - git -c safe.directory="$CI_PROJECT_DIR" fetch origin "$BASE:refs/remotes/origin/$BASE"
    - python -m tamandua scan . --name "$CI_PROJECT_NAME" --base "origin/$BASE"
```

While the image is private, the runner needs credentials for `ghcr.io` in `DOCKER_AUTH_CONFIG`. On a runner with
the `shell` executor, use `docker run` as the Action does, without the socket:

```sh
mkdir -p /tmp/tamandua-data   # created by you, not by Docker: it must belong to your user
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -v "$PWD":/src:ro -v /tmp/tamandua-data:/data \
  ghcr.io/brayansstivens/tamandua-worker:0.10 python -m tamandua scan /src --name "$CI_PROJECT_NAME" --base "origin/$BASE"
```

> Tamandua's own repository runs the Action in [`.github/workflows/ci.yml`](../.github/workflows/ci.yml), and also
> scans itself with the image built from each commit (with `--exclude fixtures/` for its intentionally vulnerable examples).
> The GitLab template has been checked locally with the same image and a checkout owned by another user, but not
> yet on a real runner. If something fails, the reason shows up on the "Not analyzed" line.

**Exclusions in CI.** `exclude` lives in the workflow, and a pull request can change the workflow.
Protect `.github/workflows/` (or `.gitlab-ci.yml`) with CODEOWNERS and required reviews so nobody can exclude their
own code unnoticed. (That's exactly why the panel keeps exclusions on the server.)

## Privacy

The code is copied to a temporary folder (without symlinks or anything the scan ignores) and deleted
when the scan ends. The engines read it read-only, with no network except to download their public
advisory databases. Nothing from the repository leaves the machine unless you pass
`--allow-osv-upload`.
