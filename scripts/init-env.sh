#!/bin/sh
# Crea .env desde .env.example con tu UID/GID y las carpetas data/ y config/ (tuyas, no de root).
# No toca un .env que ya exista. Uso: make setup
set -eu

if [ ! -f .env ]; then
  sed -e "s/^TAMANDUA_UID=.*/TAMANDUA_UID=$(id -u)/" -e "s/^TAMANDUA_GID=.*/TAMANDUA_GID=$(id -g)/" .env.example > .env
  chmod 600 .env
  echo "Creado .env con tu usuario ($(id -u):$(id -g)). Revísalo si quieres cambiar puerto, URL o TLS."
else
  echo ".env ya existe: no se toca."
fi
# Contraseña de PostgreSQL: aleatoria y solo en .env. En un .env de antes de PostgreSQL se añade sin tocar lo demás.
if ! grep -q '^TAMANDUA_DB_PASSWORD=.' .env; then
  password=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')
  if grep -q '^TAMANDUA_DB_PASSWORD=' .env; then
    sed -i.bak "s/^TAMANDUA_DB_PASSWORD=.*/TAMANDUA_DB_PASSWORD=$password/" .env && rm -f .env.bak
  else
    printf '\n# Contraseña de la base de datos (generada; no la compartas).\nTAMANDUA_DB_PASSWORD=%s\n' "$password" >> .env
  fi
  echo "Generada la contraseña de PostgreSQL en .env."
fi
mkdir -p data config
chmod 700 config
