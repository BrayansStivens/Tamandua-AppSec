# syntax=docker/dockerfile:1.7
# Tamandua image: web panel, API and scan queue.
# Built from the repository root:  make build   (or docker compose build)
#
# Two stages: Node builds the panel and only its static files reach the final image,
# which is Python slim + the Docker client (to start the engines) + dig (DNS TXT).
# Base images are pinned by digest.

# ---------- 1. web panel ----------
# Static files are the same on every architecture: build them natively (no emulation in multi-arch builds).
FROM --platform=$BUILDPLATFORM node:22-alpine@sha256:b6f26b36c8ff49624cfdac716b8ea1138d606df02586a77d364bb5536a634f85 AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
# vite.config writes to ../tamandua/app/static: keep the repository layout.
RUN mkdir -p /src/tamandua/app && npm run build

# ---------- 2. runtime ----------
FROM python:3.12-slim-bookworm@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e AS app
ARG VERSION=dev
ARG DOCKER_CLI_VERSION=27.5.1
LABEL org.opencontainers.image.title="Tamandua" \
      org.opencontainers.image.description="Self-hosted application security: SAST, secrets, dependencies, PRs and CVE tracker" \
      org.opencontainers.image.source="https://github.com/BrayansStivens/Tamandua-AppSec" \
      org.opencontainers.image.documentation="https://github.com/BrayansStivens/Tamandua-AppSec/tree/main/docs" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.version="${VERSION}"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 LANG=C.UTF-8 \
    TAMANDUA_BIND=0.0.0.0 TAMANDUA_DATA_DIR=/data TAMANDUA_CONFIG_DIR=/config
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl dnsutils git \
 && ARCH="$(dpkg --print-architecture)" && case "$ARCH" in amd64) A=x86_64 ;; arm64) A=aarch64 ;; *) echo "unsupported architecture: $ARCH" && exit 1 ;; esac \
 && curl -fsSL --proto '=https' --tlsv1.2 "https://download.docker.com/linux/static/stable/${A}/docker-${DOCKER_CLI_VERSION}.tgz" -o /tmp/docker.tgz \
 && tar -xzf /tmp/docker.tgz -C /tmp && install -m 0755 /tmp/docker/docker /usr/local/bin/docker \
 && rm -rf /tmp/docker /tmp/docker.tgz && apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY tamandua/ ./tamandua/
COPY rules/ ./rules/
COPY --from=web /src/tamandua/app/static ./tamandua/app/static
# Unprivileged user; compose aligns its UID/GID with the host's so data/ and config/ are yours.
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin tamandua \
 && mkdir -p /data /config && chown -R tamandua:tamandua /data /config
USER tamandua
VOLUME ["/data", "/config"]
EXPOSE 8766
# The Host header is the first allowed origin's: behind a proxy (public domain only) 127.0.0.1 is refused.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["python", "-c", "import os,sys,urllib.parse as p,urllib.request as r; h=p.urlsplit((os.environ.get('TAMANDUA_ALLOWED_ORIGINS') or 'http://127.0.0.1:8766').split(',')[0].strip()).netloc; sys.exit(0 if r.urlopen(r.Request('http://127.0.0.1:8766/api/health', headers={'Host': h}), timeout=4).status == 200 else 1)"]
CMD ["python", "-m", "tamandua", "--data-dir", "/data", "serve", "--port", "8766"]

# ---------- 3. worker with the engines inside (no Docker socket) ----------
# For platforms that can't hand a container the Docker socket (Railway, Render, Fly.io, Kubernetes, a PaaS):
#   docker build --target worker-standalone -f docker/app/Dockerfile .
# The same pinned engines as the Docker runner (scanning/engines.py IMAGES), copied from their official images by digest,
# and run as processes of the worker (TAMANDUA_ENGINE_RUNNER=local). Opengrep is the SHA-256-verified release binary.
# tests/test_packaging.py checks that these digests and versions match IMAGES and the Opengrep Dockerfile.
FROM aquasec/trivy@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969 AS trivy
FROM ghcr.io/google/osv-scanner@sha256:afd838850ac1a0fcc15ff4a041dc9ba11123c3f0d2666217a5f0fcf9222b55fa AS osv-scanner
FROM ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f AS gitleaks
FROM anchore/grype@sha256:8c2c9234a345577a6d321a4753aa3ee1276d8975c8452d2344a56b57733ecad3 AS grype
FROM ghcr.io/zizmorcore/zizmor@sha256:a2eb396d886c053073405c7a980f2139ba2248ec172243cfa3841e57196e8101 AS zizmor

FROM --platform=$BUILDPLATFORM debian:12-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251 AS opengrep
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

FROM app AS worker-standalone
ARG CHECKOV_VERSION=3.3.19
USER root
COPY docker/checkov/requirements.txt /tmp/checkov-requirements.txt
COPY --from=trivy --chmod=0755 /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=osv-scanner --chmod=0755 /osv-scanner /usr/local/bin/osv-scanner
COPY --from=gitleaks --chmod=0755 /usr/bin/gitleaks /usr/local/bin/gitleaks
COPY --from=grype --chmod=0755 /grype /usr/local/bin/grype
COPY --from=zizmor --chmod=0755 /usr/bin/zizmor /usr/local/bin/zizmor
COPY --from=opengrep --chmod=0755 /opengrep /usr/local/bin/opengrep
# Checkov is Python: its image's interpreter (3.11, Debian 13) can't be copied here, so it gets its own virtual
# environment. It and every dependency are pinned with their hashes (docker/checkov/requirements.txt), wheels only:
# nothing is built from source.
RUN python -m venv /opt/checkov \
 && /opt/checkov/bin/pip install --no-cache-dir --disable-pip-version-check --require-hashes --no-deps --only-binary :all: \
      -r /tmp/checkov-requirements.txt \
 && rm /tmp/checkov-requirements.txt \
 && /opt/checkov/bin/checkov --version | grep -qx "${CHECKOV_VERSION}" \
 && ln -s /opt/checkov/bin/checkov /usr/local/bin/checkov \
 && trivy --version >/dev/null && osv-scanner --version >/dev/null && gitleaks version >/dev/null && grype version >/dev/null \
 && zizmor --version >/dev/null && opengrep --version >/dev/null && checkov --version >/dev/null
ENV TAMANDUA_ENGINE_RUNNER=local PYTHONUTF8=1
USER tamandua
HEALTHCHECK --interval=60s --timeout=15s --start-period=60s --retries=3 \
  CMD ["python", "-m", "tamandua", "--data-dir", "/data", "worker", "--check"]
CMD ["python", "-m", "tamandua", "--data-dir", "/data", "worker"]
