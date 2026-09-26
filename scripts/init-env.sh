#!/bin/sh
# Creates .env from .env.example with your UID/GID, and the data/ and config/ folders (yours, not root's).
# Leaves an existing .env alone. Usage: make setup
set -eu

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
mkdir -p data config
chmod 700 config
