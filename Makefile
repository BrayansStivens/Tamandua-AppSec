# Tamandua · comandos habituales.  `make help` para la lista.
# Solo necesita make y Docker; los objetivos de desarrollo necesitan además Python 3.12 y Node 22.

SHELL := /bin/sh
COMPOSE ?= docker compose
VERSION := $(shell sed -n 's/^VERSION = "\(.*\)"/\1/p' tamandua/version.py)
PORT := $(shell sed -n 's/^APPSEC_PORT=//p' .env 2>/dev/null | tail -n1)
PUBLIC_URL := $(shell sed -n 's/^APPSEC_AGENT_PUBLIC_URL=//p' .env 2>/dev/null | tail -n1)
HOST_PORT := $(if $(PORT),$(PORT),8766)
URL := $(if $(PUBLIC_URL),$(PUBLIC_URL),http://127.0.0.1:$(HOST_PORT))
PYTHON ?= python3
DIR ?=
ARGS ?=
VENV := .venv
export APPSEC_VERSION := $(VERSION)
# Grupo del socket de Docker en Linux y WSL con Docker nativo (en macOS, Docker Desktop usa el 0).
# Un valor en el entorno o en .env manda sobre la detección.
DOCKER_SOCKET_GID ?= $(shell sed -n 's/^DOCKER_SOCKET_GID=//p' .env 2>/dev/null | tail -n1)
ifeq ($(strip $(DOCKER_SOCKET_GID)),)
DOCKER_SOCKET_GID := $(shell [ "$$(uname -s)" = Linux ] && stat -Lc %g /var/run/docker.sock 2>/dev/null)
endif
# El 0 ya va siempre en compose; repetirlo es un error.
ifeq ($(strip $(DOCKER_SOCKET_GID)),0)
DOCKER_SOCKET_GID :=
endif
export DOCKER_SOCKET_GID
# Imágenes publicadas de los motores, fijadas por digest, leídas del código (sin Python ni la imagen de la app).
# `make engines` las descarga desde el host: se ve el progreso, no hay límite de tiempo y no depende
# de los permisos del socket dentro del contenedor.
ENGINE_IMAGES := sed -n 's/.*"image": "\([^"]*@sha256:[0-9a-f]\{64\}\)".*/\1/p' tamandua/modules/scanning/engines.py

.DEFAULT_GOAL := help
.PHONY: arch openapi help doctor setup build up down restart status logs ps setup-code engines scan demo update backup shell cli \
        clean purge dev-setup dev test lint web check

## —— Uso ———————————————————————————————————————————————————————————————

help: ## Muestra esta ayuda
	@printf 'Tamandua %s · uso: make <objetivo>\n\n' "$(VERSION)"
	@awk 'BEGIN {FS = ":.*## "} /^## ——/ {sub(/^## /, ""); printf "\n\033[1m%s\033[0m\n", $$0} /^[a-z-]+:.*## / {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@printf '\nPrimera vez:  make up\n'

doctor: ## Comprueba requisitos (Docker, Compose, disco, puerto, permisos)
	@sh scripts/doctor.sh

setup: ## Crea .env con tu UID/GID y las carpetas data/ y config/
	@sh scripts/init-env.sh

build: setup ## Construye las imágenes (app y motor Opengrep verificado)
	$(COMPOSE) build

up: setup ## Construye si hace falta, descarga los motores que falten, arranca y muestra la URL
	$(COMPOSE) up --build -d
	@printf 'Esperando a que el panel responda'
	@i=0; until [ "$$(docker inspect -f '{{.State.Health.Status}}' appsec-agent 2>/dev/null)" = healthy ]; do \
	  i=$$((i + 1)); if [ $$i -gt 60 ]; then echo; echo 'No arrancó en 2 minutos: make logs'; exit 1; fi; printf '.'; sleep 2; done; echo
	@$(MAKE) --no-print-directory engines || echo 'Aviso: faltan motores; el panel funciona y se reintentan con make engines.'
	@echo "Panel: $(URL)"
	@$(MAKE) --no-print-directory setup-code

down: ## Para y elimina los contenedores (conserva data/ y config/)
	$(COMPOSE) down

restart: ## Reinicia la app (marca como fallidos los análisis en curso)
	$(COMPOSE) restart appsec worker

status: ## Estado de los contenedores y de los motores
	@$(COMPOSE) ps
	@echo
	@$(COMPOSE) exec -T worker python -m tamandua engines 2>/dev/null || echo "La app no está en marcha: make up"

ps: status

logs: ## Sigue los logs de la app (Ctrl+C para salir)
	$(COMPOSE) logs -f --tail 100 appsec

setup-code: ## Muestra el código para crear el primer administrador
	@code=$$($(COMPOSE) logs appsec 2>/dev/null | grep -A1 'Primer arranque' | tail -n1 | sed 's/.*| *//; s/^ *//'); \
	if [ -n "$$code" ] && curl -fsS -H "Host: 127.0.0.1:$(HOST_PORT)" "http://127.0.0.1:$(HOST_PORT)/api/auth/session" 2>/dev/null | grep -q '"setup_required": true'; then \
	  echo "Código de configuración: $$code  (créalo en $(URL))"; \
	else echo "Ya hay un administrador creado: entra con tu usuario."; fi

engines: ## Descarga las imágenes de los motores que falten (Trivy, OSV-Scanner, Gitleaks, Grype, Checkov, zizmor), con progreso
	@images=$$($(ENGINE_IMAGES)); \
	missing=0; for image in $$images; do docker image inspect "$$image" >/dev/null 2>&1 || missing=$$((missing + 1)); done; \
	if [ $$missing -eq 0 ]; then echo 'Motores: todas las imágenes están listas.'; exit 0; fi; \
	echo "Motores: faltan $$missing imágenes; la primera vez puede tardar según tu conexión."; \
	for image in $$images; do \
	  docker image inspect "$$image" >/dev/null 2>&1 && continue; \
	  echo "→ $${image%%@*}"; \
	  docker pull "$$image" || { echo "Falló la descarga de $${image%%@*}: revisa la conexión y repite make engines."; exit 1; }; \
	done; echo 'Motores: listos.'

scan: ## Analiza una carpeta local: make scan DIR=../mi-repo ARGS="--base main --fail-on high"
	@[ -d "$(DIR)" ] || { echo 'Indica la carpeta: make scan DIR=../mi-repo (y opciones en ARGS="--base main")'; exit 2; }
	@$(COMPOSE) run --rm --no-deps -T -v "$(abspath $(DIR))":/src:ro worker python -m tamandua scan /src --name "$(notdir $(abspath $(DIR)))" $(ARGS)

demo: ## Datos de demostración: analiza los ejemplos vulnerables e importa un modelo de amenazas (IMAGE=nginx:1.21 añade una imagen)
	@$(COMPOSE) run --rm -T -v "$(abspath fixtures)":/demo/fixtures:ro -v "$(abspath web/src/examples/threat-models)":/demo/models:ro \
		worker python -m tamandua --data-dir /data demo --fixtures /demo/fixtures --models /demo/models $(if $(IMAGE),--image "$(IMAGE)",)

update: ## Actualiza el código (git pull) y reconstruye
	git pull --ff-only
	$(MAKE) --no-print-directory up

backup: ## Copia data/ y config/ en backups/<fecha>/ (FORCE=1 si hay análisis en curso)
	@sh scripts/backup.sh

shell: ## Abre una terminal dentro del contenedor
	$(COMPOSE) exec appsec sh

cli: ## CLI de la app: make cli ARGS="user list"
	$(COMPOSE) exec appsec python -m tamandua --data-dir /data $(ARGS)

clean: ## Para todo y borra las imágenes locales (conserva data/ y config/)
	$(COMPOSE) down --rmi all

purge: ## ¡BORRA data/ y config/! Pide CONFIRM=borrar
	@if [ "$(CONFIRM)" != "borrar" ]; then echo 'Esto borra ejecuciones, usuarios y secretos. Repite con: make purge CONFIRM=borrar'; exit 1; fi
	$(COMPOSE) down --rmi all
	rm -rf data config

## —— Desarrollo ———————————————————————————————————————————————————————

dev-setup: ## Crea .venv e instala dependencias de Python y del panel
	$(PYTHON) -m venv $(VENV)
	$(VENV)/bin/pip install -q -r requirements-dev.txt
	cd web && npm ci --no-audit --no-fund

dev: ## Servidor local sin contenedor en 127.0.0.1:8767 (motores vía tu Docker)
	APPSEC_AGENT_PUBLIC_URL=http://127.0.0.1:8767 APPSEC_AGENT_ALLOWED_ORIGINS=http://127.0.0.1:8767,http://localhost:8767 \
	APPSEC_AGENT_CONFIG_DIR=$(CURDIR)/.dev/config $(VENV)/bin/python -m tamandua --data-dir .dev/data serve --port 8767

web: ## Compila el panel en tamandua/app/static/
	cd web && npm run build

test: ## Pruebas del backend (arranca un Postgres efímero de pruebas si hace falta)
	@url=$$(sh scripts/test-db.sh) && APPSEC_AGENT_DATABASE_URL="$$url" APPSEC_AGENT_DB_ISOLATE=data-dir $(VENV)/bin/python -m unittest discover -s tests

openapi: ## Esquema OpenAPI de la API y tipos TypeScript del panel (web/src/shared/api/)
	@mkdir -p web/src/shared/api
	$(VENV)/bin/python -c "from tamandua.app.api import openapi_document; print(openapi_document(), end='')" > web/src/shared/api/openapi.json
	cd web && npx --yes openapi-typescript@7.13.0 src/shared/api/openapi.json -o src/shared/api/schema.d.ts

arch: ## Contratos de arquitectura (import-linter, ver pyproject.toml)
	$(VENV)/bin/lint-imports

lint: ## Lint y tipos del panel
	cd web && npx tsc -b && npm run lint

check: test arch lint ## Pruebas, contratos de arquitectura y lint (lo que se exige antes de un PR)
