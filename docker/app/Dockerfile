# syntax=docker/dockerfile:1.7
# Imagen de Tamandua: panel web, API y cola de análisis en un solo proceso.
# Se construye desde la raíz del repositorio:  make build   (o docker compose build)
#
# Dos etapas: el panel se compila con Node y solo sus estáticos pasan a la imagen final,
# que es Python slim + el cliente de Docker (para lanzar los motores) + dig (DNS TXT).
# Las imágenes base van fijadas por digest.

# ---------- 1. panel web ----------
FROM node:22-alpine@sha256:b6f26b36c8ff49624cfdac716b8ea1138d606df02586a77d364bb5536a634f85 AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
# vite.config apunta a ../appsec_agent/static: se respeta el mismo layout que en el repositorio.
RUN mkdir -p /src/appsec_agent && npm run build

# ---------- 2. ejecución ----------
FROM python:3.12-slim-bookworm@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e AS app
ARG VERSION=dev
ARG DOCKER_CLI_VERSION=27.5.1
LABEL org.opencontainers.image.title="Tamandua" \
      org.opencontainers.image.description="Seguridad de aplicaciones autoalojada: SAST, secretos, dependencias, PRs y CVE tracker" \
      org.opencontainers.image.source="https://github.com/BrayansStivens/appsec-agent" \
      org.opencontainers.image.documentation="https://github.com/BrayansStivens/appsec-agent/tree/main/docs" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.version="${VERSION}"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 LANG=C.UTF-8 \
    APPSEC_AGENT_BIND=0.0.0.0 APPSEC_AGENT_DATA_DIR=/data APPSEC_AGENT_CONFIG_DIR=/config
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl dnsutils git \
 && ARCH="$(dpkg --print-architecture)" && case "$ARCH" in amd64) A=x86_64 ;; arm64) A=aarch64 ;; *) echo "arquitectura no soportada: $ARCH" && exit 1 ;; esac \
 && curl -fsSL --proto '=https' --tlsv1.2 "https://download.docker.com/linux/static/stable/${A}/docker-${DOCKER_CLI_VERSION}.tgz" -o /tmp/docker.tgz \
 && tar -xzf /tmp/docker.tgz -C /tmp && install -m 0755 /tmp/docker/docker /usr/local/bin/docker \
 && rm -rf /tmp/docker /tmp/docker.tgz && apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY appsec_agent/ ./appsec_agent/
COPY rules/ ./rules/
COPY fixtures/tenant-api-lab/ ./fixtures/tenant-api-lab/
COPY --from=web /src/appsec_agent/static ./appsec_agent/static
# Usuario sin privilegios; compose alinea su UID/GID con el del host para que data/ y config/ sean tuyos.
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin appsec \
 && mkdir -p /data /config && chown -R appsec:appsec /data /config
USER appsec
VOLUME ["/data", "/config"]
EXPOSE 8766
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:8766/api/health', headers={'Host':'127.0.0.1:8766'}), timeout=4).status == 200 else 1)"]
CMD ["python", "-m", "appsec_agent", "--data-dir", "/data", "serve", "--port", "8766"]
