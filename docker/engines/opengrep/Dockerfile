# Opengrep v1.30.0 sobre una base mínima. El binario se descarga del release oficial y se
# comprueba contra su SHA-256 fijado aquí (el que publica GitHub para el artefacto; el de
# aarch64 se verificó además con Cosign, ver VERIFY.md). Si no coincide, la imagen no se
# construye. Sin red en ejecución: el SAST no la necesita.
FROM debian:12-slim AS download
ARG TARGETARCH
ARG OPENGREP_VERSION=1.30.0
ARG SHA_AMD64=35779bdd72e92129c8df2a77f0c55e8c08356801ea92591ef32108d6b28d564c
ARG SHA_ARM64=a5d5a4a58ba5d46ff51e921663da1c2bba38f4b03987f4aeec87f16c6ad3ecae
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
RUN set -eu; \
    case "${TARGETARCH:-$(dpkg --print-architecture)}" in \
      amd64) artifact=opengrep_manylinux_x86; sha="$SHA_AMD64" ;; \
      arm64) artifact=opengrep_manylinux_aarch64; sha="$SHA_ARM64" ;; \
      *) echo "arquitectura no soportada" >&2; exit 1 ;; \
    esac; \
    curl -fsSL --proto '=https' --tlsv1.2 -o /opengrep "https://github.com/opengrep/opengrep/releases/download/v${OPENGREP_VERSION}/${artifact}"; \
    echo "${sha}  /opengrep" | sha256sum -c -

FROM debian:12-slim
# El binario lleva un runtime Python embebido: sin locale UTF-8 no puede leer reglas con acentos.
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8 PYTHONUTF8=1 PYTHONIOENCODING=utf-8
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin scanner \
 && mkdir -p /work && chown scanner:scanner /work
COPY --from=download --chown=root:root --chmod=0755 /opengrep /usr/local/bin/opengrep
USER scanner
WORKDIR /src
# Motor de un solo uso (`docker run --rm` por análisis): no hay un servicio vivo que vigilar.
HEALTHCHECK NONE
ENTRYPOINT ["/usr/local/bin/opengrep"]
