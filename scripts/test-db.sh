#!/bin/sh
# Postgres efímero para las pruebas (datos en memoria). Imprime la URL de conexión.
# Cada prueba usa su propio esquema (TAMANDUA_DB_ISOLATE=data-dir), así que el contenedor se reutiliza.
set -eu
NAME=tamandua-test-db
IMAGE="postgres:18-alpine@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873"
PORT="${TAMANDUA_TEST_DB_PORT:-55432}"
if ! docker ps --format '{{.Names}}' | grep -qx "$NAME"; then
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker run -d --name "$NAME" -e POSTGRES_USER=tamandua -e POSTGRES_PASSWORD=tamandua -e POSTGRES_DB=tamandua \
    -p "127.0.0.1:$PORT:5432" --tmpfs /var/lib/postgresql:rw "$IMAGE" -c fsync=off -c synchronous_commit=off >/dev/null
fi
i=0
until docker exec "$NAME" pg_isready -U tamandua -d tamandua >/dev/null 2>&1; do
  i=$((i + 1)); [ "$i" -gt 60 ] && { echo "Postgres de pruebas no arrancó" >&2; exit 1; }; sleep 0.5
done
echo "postgresql+psycopg://tamandua:tamandua@127.0.0.1:$PORT/tamandua"
