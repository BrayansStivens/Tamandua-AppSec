#!/bin/sh
# Creates .env from .env.example with your UID/GID, and the data/, config/ and backups/ folders (yours, not root's).
# Leaves an existing .env alone, except for what you ask for:
#   make setup                                        local use (http://127.0.0.1:8766)
#   make setup DOMAIN=tamandua.example.com [PREBUILT=1 | PREBUILT=ghcr.io/you/tamandua]
#     server: HTTPS with Caddy for that domain (compose.prod.yaml) and, with PREBUILT, the published images instead of
#     building (compose.images.yaml). Writes COMPOSE_FILE so every make and docker compose command uses them.
set -eu

DOMAIN=${DOMAIN:-}
PREBUILT=${PREBUILT:-}

# Replaces NAME=… in .env, or appends it.
set_var() {
  if grep -q "^$1=" .env; then
    sed -i.bak "s|^$1=.*|$1=$2|" .env && rm -f .env.bak
  else
    printf '%s=%s\n' "$1" "$2" >> .env
  fi
}
random_hex() { od -An -N"$1" -tx1 /dev/urandom | tr -d ' \n'; }

if [ -n "$DOMAIN" ] && ! printf '%s' "$DOMAIN" | grep -Eq '^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$'; then
  echo "DOMAIN must be a host name like tamandua.example.com (no scheme, port or path)." >&2
  exit 2
fi
case "$PREBUILT" in
  ''|0) image= ;;
  1) image=ghcr.io/brayansstivens/tamandua ;;
  *) image=$PREBUILT ;;
esac
# A registry may carry a port (registry.example.com:5000/tamandua); the name itself, no tag or digest.
if [ -n "$image" ] && { ! printf '%s' "$image" | grep -Eq '^[a-z0-9][a-z0-9._:/-]*[a-z0-9]$' || case "${image##*/}" in *:*) true ;; *) false ;; esac; }; then
  echo "PREBUILT must be 1 or an image name without tag, like ghcr.io/you/tamandua." >&2
  exit 2
fi
if [ -n "$image" ] && [ -z "$DOMAIN" ]; then
  echo "PREBUILT goes with DOMAIN: make setup DOMAIN=tamandua.example.com PREBUILT=1" >&2
  exit 2
fi

if [ ! -f .env ]; then
  sed -e "s/^TAMANDUA_UID=.*/TAMANDUA_UID=$(id -u)/" -e "s/^TAMANDUA_GID=.*/TAMANDUA_GID=$(id -g)/" .env.example > .env
  chmod 600 .env
  echo "Created .env with your user ($(id -u):$(id -g)). Review it to change the port, URL or TLS."
else
  echo ".env already exists: left unchanged."
fi
# PostgreSQL password: random and only in .env. An .env from before PostgreSQL gets it appended, nothing else changes.
if ! grep -q '^TAMANDUA_DB_PASSWORD=.' .env; then
  password=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')
  if grep -q '^TAMANDUA_DB_PASSWORD=' .env; then
    sed -i.bak "s/^TAMANDUA_DB_PASSWORD=.*/TAMANDUA_DB_PASSWORD=$password/" .env && rm -f .env.bak
  else
    printf '\n# Database password (generated; do not share it).\nTAMANDUA_DB_PASSWORD=%s\n' "$password" >> .env
  fi
  echo "Generated the PostgreSQL password in .env."
fi
if [ -n "$DOMAIN" ]; then
  files=compose.yaml:compose.prod.yaml
  [ -n "$image" ] && files=$files:compose.images.yaml
  set_var TAMANDUA_DOMAIN "$DOMAIN"
  set_var TAMANDUA_PUBLIC_URL "https://$DOMAIN"
  set_var TAMANDUA_ALLOWED_ORIGINS "https://$DOMAIN"
  set_var COMPOSE_FILE "$files"
  [ -n "$image" ] && set_var TAMANDUA_IMAGE "$image"
  grep -q '^TAMANDUA_METRICS_TOKEN=.' .env || set_var TAMANDUA_METRICS_TOKEN "$(random_hex 32)"
  echo "Server mode: https://$DOMAIN behind Caddy ($files)."
fi
mkdir -p data config backups
chmod 700 config backups
