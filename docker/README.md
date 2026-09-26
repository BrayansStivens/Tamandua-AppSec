# docker/

Image definitions. They are built from the repository root with `make build` (or `docker compose build`); you don't need to work in here.

| Folder | Image | Notes |
| --- | --- | --- |
| `app/` | `tamandua/app:<version>` | Panel + API + scan queue. Multi-stage: Node only builds the panel. Base images pinned by digest, unprivileged user, OCI labels. |
| `engines/opengrep/` | `tamandua/opengrep:1.30.0` | SAST engine. Downloads the official binary and checks it against its SHA-256; if it doesn't match, the build fails. `VERIFY.md` explains the Cosign verification. |

The other engines (Trivy, OSV-Scanner, Gitleaks, Grype, Checkov, zizmor) aren't built: their official images are used, pinned by digest (see `tamandua/modules/scanning/engines.py`).

To upgrade an engine, change its version and digest (or SHA-256) in `tamandua/modules/scanning/engines.py` and in the matching Dockerfile; `tests/test_packaging.py` checks that compose and the code agree.

More details, hardening and a command reference in [docs/containers.md](../docs/containers.md).
