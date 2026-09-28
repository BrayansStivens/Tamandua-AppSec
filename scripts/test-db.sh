#!/bin/sh
# Throwaway Postgres for the tests (data in memory), reused between runs. Each run gets its own database, and each test
# its own schema inside it (TAMANDUA_DB_ISOLATE=data-dir), so nothing piles up in the container's memory.
#   sh scripts/test-db.sh            creates this run's database and prints its URL
#   sh scripts/test-db.sh drop URL   drops that database (`make test` does it when the run ends)
# Databases of runs that never ended (older than six hours) are dropped the next time a run starts.
set -eu
NAME=tamandua-test-db
IMAGE="postgres:18-alpine@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873"
PORT="${TAMANDUA_TEST_DB_PORT:-55432}"
STALE_SECONDS=21600

sql() { docker exec "$NAME" psql -v ON_ERROR_STOP=1 -qtAX -U tamandua -d tamandua -c "$1"; }

if [ "${1:-}" = "drop" ]; then
  database=${2:-}
  database=${database##*/}
  # Only names this script makes (digits alone after the prefix): nothing else ever reaches the SQL.
  if ! printf '%s' "$database" | grep -Eqx 'tamandua_run_[0-9]+_[0-9]+'; then
    echo "Not a test run database: $database" >&2; exit 1
  fi
  sql "DROP DATABASE IF EXISTS \"$database\" WITH (FORCE)" >/dev/null
  exit 0
fi

if ! docker ps --format '{{.Names}}' | grep -qx "$NAME"; then
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker run -d --name "$NAME" -e POSTGRES_USER=tamandua -e POSTGRES_PASSWORD=tamandua -e POSTGRES_DB=tamandua \
    -p "127.0.0.1:$PORT:5432" --tmpfs /var/lib/postgresql:rw "$IMAGE" -c fsync=off -c synchronous_commit=off >/dev/null
fi
i=0
until docker exec "$NAME" pg_isready -U tamandua -d tamandua >/dev/null 2>&1; do
  i=$((i + 1)); [ "$i" -gt 60 ] && { echo "The test Postgres did not start" >&2; exit 1; }; sleep 0.5
done

now=$(date +%s)
for old in $(sql "SELECT datname FROM pg_database WHERE datname ~ '^tamandua_run_[0-9]+_[0-9]+$'"); do
  started=$(echo "$old" | cut -d_ -f3)
  if [ $((now - started)) -gt "$STALE_SECONDS" ]; then sql "DROP DATABASE IF EXISTS \"$old\" WITH (FORCE)" >/dev/null; fi
done
database="tamandua_run_${now}_$$"
sql "CREATE DATABASE \"$database\"" >/dev/null
echo "postgresql+psycopg://tamandua:tamandua@127.0.0.1:$PORT/$database"
