#!/bin/sh
# Restores a backup from `make backup` or the backup service: the database (replaced whole), config/ and data/.
# Usage: make restore FROM=backups/<date> CONFIRM=restore
#
# Before touching anything it checks the backup and saves the current state in backups/pre-restore-<date>/ (it's
# a normal backup: `make restore FROM=backups/pre-restore-<date>` undoes the restore). Restore on the same Tamandua
# version as the backup or a newer one: the app migrates the data forward when it starts, never backwards.
set -eu

from=${1:-}
from=${from%/}
if [ -z "$from" ] || [ ! -f "$from/database.dump" ]; then
  echo "Give a backup folder with a database.dump: make restore FROM=backups/<date> CONFIRM=restore" >&2
  exit 2
fi
if [ "${CONFIRM:-}" != "restore" ]; then
  echo "This replaces the database, config/ and data/ with the ones in $from (the current ones are saved first)."
  echo "Run again with: make restore FROM=$from CONFIRM=restore"
  exit 1
fi

# 1. The backup is readable (before stopping anything).
[ "$(head -c 5 "$from/database.dump")" = "PGDMP" ] || { echo "$from/database.dump is not a pg_dump custom-format file." >&2; exit 1; }
for archive in config.tgz data.tgz; do
  if [ -f "$from/$archive" ]; then
    gzip -t "$from/$archive" || { echo "$from/$archive is damaged." >&2; exit 1; }
  fi
done
[ -f "$from/config.tgz" ] || echo "Warning: $from has no config.tgz; the current secrets and master key are kept."

# 2. Stop what writes, keep PostgreSQL up.
docker compose stop api worker backup >/dev/null 2>&1 || docker compose stop api worker >/dev/null
docker compose up -d --wait postgres >/dev/null 2>&1

# 3. Save the current state (a normal backup folder).
stamp=$(date +%Y%m%d-%H%M%S)
safety="backups/pre-restore-$stamp"
mkdir -p "$safety"
chmod 700 backups "$safety"
docker compose exec -T postgres pg_dump -U tamandua -d tamandua -Fc > "$safety/database.dump"
[ -d config ] && tar czf "$safety/config.tgz" config
[ -d data ] && tar czf "$safety/data.tgz" --exclude=data/feeds --exclude=data/trivy-cache --exclude=data/grype-cache \
  --exclude=data/work --exclude=data/tmp data
chmod 600 "$safety"/*
echo "Current state saved in $safety/"

# 4. The database, whole: dropped and recreated, so no table from a newer schema survives.
docker compose exec -T postgres psql -q -U tamandua -d postgres -v ON_ERROR_STOP=1 \
  -c 'DROP DATABASE IF EXISTS tamandua WITH (FORCE)' -c 'CREATE DATABASE tamandua OWNER tamandua'
docker compose exec -T postgres pg_restore -U tamandua -d tamandua --no-owner --exit-on-error < "$from/database.dump"
echo "Database restored."

# 5. Secrets (replaced, not merged: a stale key must not survive) and data (the caches are downloaded again).
if [ -f "$from/config.tgz" ]; then
  rm -rf config.restoring && mkdir config.restoring
  tar xzf "$from/config.tgz" -C config.restoring
  [ -d config.restoring/config ] || { echo "$from/config.tgz has no config/ folder." >&2; exit 1; }
  rm -rf config && mv config.restoring/config config && rmdir config.restoring
  chmod 700 config
  echo "config/ restored."
fi
if [ -f "$from/data.tgz" ]; then
  tar xzf "$from/data.tgz"
  echo "data/ restored."
fi
echo "Done. Start it with: make up"
