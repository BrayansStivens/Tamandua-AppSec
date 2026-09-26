#!/bin/sh
# Scheduled backups inside the `backup` service (compose profile `backup`); not meant to be run on the host.
# Every BACKUP_INTERVAL_HOURS: /backups/auto-<date>/ with database.dump (pg_dump -Fc), config.tgz and data.tgz
# (the same layout as `make backup`), written to a hidden folder first and renamed when complete. Deletes its own
# auto-* folders older than BACKUP_KEEP_DAYS; manual backups are never touched.
#   --check   exit 0 if the newest complete backup is younger than two intervals (the container healthcheck)
set -eu

interval=${BACKUP_INTERVAL_HOURS:-24}
keep=${BACKUP_KEEP_DAYS:-14}
case "$interval$keep" in *[!0-9]*|'') echo "BACKUP_INTERVAL_HOURS and BACKUP_KEEP_DAYS must be whole numbers" >&2; exit 2 ;; esac
[ "$interval" -ge 1 ] || { echo "BACKUP_INTERVAL_HOURS must be at least 1" >&2; exit 2; }

if [ "${1:-}" = "--check" ]; then
  recent=$(find /backups -mindepth 1 -maxdepth 1 -type d -name 'auto-*' -mmin -$((interval * 120)) | head -n1)
  [ -n "$recent" ]
  exit $?
fi

# `set -e` doesn't apply inside `if ! backup`: every step stops the backup on its own.
backup() {
  stamp=$(date -u +%Y%m%d-%H%M%S)
  partial="/backups/.auto-$stamp.partial"
  rm -rf "$partial" && mkdir -m 700 "$partial" || return 1
  pg_dump -Fc -f "$partial/database.dump" || return 1
  tar czf "$partial/config.tgz" -C /source config || return 1
  tar czf "$partial/data.tgz" -C /source --exclude=data/feeds --exclude=data/trivy-cache --exclude=data/grype-cache \
    --exclude=data/work --exclude=data/tmp data || return 1
  chmod 600 "$partial"/* && mv "$partial" "/backups/auto-$stamp" || return 1
  echo "$(date -u +%FT%TZ) backup: auto-$stamp"
  find /backups -mindepth 1 -maxdepth 1 -type d -name 'auto-*' -mtime +"$keep" -print -exec rm -rf {} + | sed 's/^/pruned: /'
}

trap 'exit 0' TERM INT
umask 077
while :; do
  if ! backup; then
    echo "$(date -u +%FT%TZ) backup FAILED: see the lines above; retrying in 1 hour" >&2
    rm -rf /backups/.auto-*.partial
    sleep 3600 & wait $!
    continue
  fi
  sleep $((interval * 3600)) & wait $!
done
