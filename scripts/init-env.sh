#!/bin/sh
# Crea .env desde .env.example con tu UID/GID y las carpetas data/ y config/ (tuyas, no de root).
# No toca un .env que ya exista. Uso: make setup
set -eu

if [ ! -f .env ]; then
  sed -e "s/^APPSEC_UID=.*/APPSEC_UID=$(id -u)/" -e "s/^APPSEC_GID=.*/APPSEC_GID=$(id -g)/" .env.example > .env
  chmod 600 .env
  echo "Creado .env con tu usuario ($(id -u):$(id -g)). Revísalo si quieres cambiar puerto, URL o TLS."
else
  echo ".env ya existe: no se toca."
fi
mkdir -p data config
chmod 700 config
