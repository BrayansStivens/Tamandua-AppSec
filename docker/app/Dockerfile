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
      org.opencontainers.image.source="https://github.com/BrayansStivens/appsec-agent" \
      org.opencontainers.image.documentation="https://github.com/BrayansStivens/appsec-agent/tree/main/docs" \
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
