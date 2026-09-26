# Opengrep v1.30.0 on a minimal base (pinned by digest). The binary is downloaded from the official release and
# checked against the SHA-256 pinned here (the one GitHub publishes for the artifact; the aarch64
# one was also verified with Cosign, see VERIFY.md). If it doesn't match, the image isn't built.
# No network at runtime: SAST doesn't need it.
# The download runs natively (it picks the binary by TARGETARCH); only the final stage is per architecture.
FROM --platform=$BUILDPLATFORM debian:12-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251 AS download
ARG TARGETARCH
ARG OPENGREP_VERSION=1.30.0
ARG SHA_AMD64=35779bdd72e92129c8df2a77f0c55e8c08356801ea92591ef32108d6b28d564c
ARG SHA_ARM64=a5d5a4a58ba5d46ff51e921663da1c2bba38f4b03987f4aeec87f16c6ad3ecae
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
RUN set -eu; \
    case "${TARGETARCH:-$(dpkg --print-architecture)}" in \
      amd64) artifact=opengrep_manylinux_x86; sha="$SHA_AMD64" ;; \
      arm64) artifact=opengrep_manylinux_aarch64; sha="$SHA_ARM64" ;; \
      *) echo "unsupported architecture" >&2; exit 1 ;; \
    esac; \
    curl -fsSL --proto '=https' --tlsv1.2 -o /opengrep "https://github.com/opengrep/opengrep/releases/download/v${OPENGREP_VERSION}/${artifact}"; \
    echo "${sha}  /opengrep" | sha256sum -c -

FROM debian:12-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251
# The binary embeds a Python runtime: without a UTF-8 locale it can't read rules with accented text.
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8 PYTHONUTF8=1 PYTHONIOENCODING=utf-8
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin scanner \
 && mkdir -p /work && chown scanner:scanner /work
COPY --from=download --chown=root:root --chmod=0755 /opengrep /usr/local/bin/opengrep
USER scanner
WORKDIR /src
# Single-use engine (`docker run --rm` per scan): there's no long-running service to watch.
HEALTHCHECK NONE
ENTRYPOINT ["/usr/local/bin/opengrep"]
