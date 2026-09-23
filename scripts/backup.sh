#!/bin/sh
# Copia de seguridad en backups/<fecha>/: data.tgz (sin cachés regenerables) y config.tgz.
# config.tgz contiene la clave maestra y el almacén cifrado: guárdalo aparte y protegido.
# Para una copia coherente, la app se detiene unos segundos. Uso: make backup
set -eu

stamp=$(date +%Y%m%d-%H%M%S)
target="backups/$stamp"
running=$(docker compose ps --status running --services 2>/dev/null | grep -x appsec || true)

if [ -n "$running" ]; then
  active=$(docker compose exec -T appsec python -c "from pathlib import Path; from appsec_agent.store import list_runs; print(sum(1 for r in list_runs(Path('/data')) if r.get('status') in ('queued', 'running')))" 2>/dev/null || echo 0)
  if [ "${active:-0}" != "0" ] && [ "${FORCE:-}" != "1" ]; then
    echo "Hay $active análisis en marcha. Espera a que terminen o usa FORCE=1 (se marcarán como fallidos)." >&2
    exit 1
  fi
  docker compose stop appsec >/dev/null
fi

mkdir -p "$target"
chmod 700 backups "$target"
tar czf "$target/data.tgz" --exclude=data/feeds --exclude=data/trivy-cache --exclude=data/grype-cache --exclude=data/work data
tar czf "$target/config.tgz" config
chmod 600 "$target"/*.tgz

[ -n "$running" ] && docker compose start appsec >/dev/null
echo "Copia en $target/"
echo "  data.tgz    ejecuciones, hallazgos, usuarios y ajustes (sin secretos)"
echo "  config.tgz  SECRETOS CIFRADOS + CLAVE MAESTRA: guárdalo fuera de esta máquina y protegido"
