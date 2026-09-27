#!/bin/sh
# Backup into backups/<date>/: database.dump, data.tgz (without rebuildable caches) and config.tgz.
# config.tgz holds the master key, which decrypts the secrets in database.dump: keep it apart and protected.
# For a consistent copy the app stops for a few seconds. Usage: make backup
set -eu

stamp=$(date +%Y%m%d-%H%M%S)
target="backups/$stamp"
running=$(docker compose ps --status running --services 2>/dev/null | grep -x api || true)

if [ -n "$running" ]; then
  active=$(docker compose exec -T api python -c "from pathlib import Path; from tamandua.modules.runs.store import list_runs; print(sum(1 for r in list_runs(Path('/data')) if r.get('status') in ('queued', 'running')))" 2>/dev/null || echo 0)
  if [ "${active:-0}" != "0" ] && [ "${FORCE:-}" != "1" ]; then
    echo "$active scans are running. Wait for them to finish or use FORCE=1 (they will be marked as failed)." >&2
    exit 1
  fi
  docker compose stop api >/dev/null
fi

mkdir -p "$target"
chmod 700 backups "$target"
# Runs, findings and triage: PostgreSQL dump (pg_restore custom format).
docker compose exec -T postgres pg_dump -U tamandua -d tamandua -Fc > "$target/database.dump"
tar czf "$target/data.tgz" --exclude=data/feeds --exclude=data/trivy-cache --exclude=data/grype-cache --exclude=data/work --exclude=data/tmp data
tar czf "$target/config.tgz" config
chmod 600 "$target"/*.tgz "$target/database.dump"

[ -n "$running" ] && docker compose start api >/dev/null
echo "Backup in $target/"
echo "  database.dump  users, settings, runs, findings and triage (restore with make restore FROM=$target)"
echo "  data.tgz       data/ without the caches: logs and the session signing key (no secrets)"
echo "  config.tgz     ENCRYPTED SECRETS + MASTER KEY: keep it off this machine and protected"
