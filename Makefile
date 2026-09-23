# AppSec Agent · comandos habituales.  `make help` para la lista.
# Solo necesita make y Docker; los objetivos de desarrollo necesitan además Python 3.12 y Node 22.

SHELL := /bin/sh
COMPOSE ?= docker compose
VERSION := $(shell sed -n 's/^VERSION = "\(.*\)"/\1/p' appsec_agent/api/core.py)
PORT := $(shell sed -n 's/^APPSEC_PORT=//p' .env 2>/dev/null | tail -n1)
PUBLIC_URL := $(shell sed -n 's/^APPSEC_AGENT_PUBLIC_URL=//p' .env 2>/dev/null | tail -n1)
HOST_PORT := $(if $(PORT),$(PORT),8766)
URL := $(if $(PUBLIC_URL),$(PUBLIC_URL),http://127.0.0.1:$(HOST_PORT))
PYTHON ?= python3
VENV := .venv
export APPSEC_VERSION := $(VERSION)

.DEFAULT_GOAL := help
.PHONY: help doctor setup build up down restart status logs ps setup-code engines update backup shell cli \
        clean purge dev-setup dev test lint web check

## —— Uso ———————————————————————————————————————————————————————————————

help: ## Muestra esta ayuda
	@printf 'AppSec Agent %s · uso: make <objetivo>\n\n' "$(VERSION)"
	@awk 'BEGIN {FS = ":.*## "} /^## ——/ {sub(/^## /, ""); printf "\n\033[1m%s\033[0m\n", $$0} /^[a-z-]+:.*## / {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@printf '\nPrimera vez:  make up\n'

doctor: ## Comprueba requisitos (Docker, Compose, disco, puerto, permisos)
	@sh scripts/doctor.sh

setup: ## Crea .env con tu UID/GID y las carpetas data/ y config/
	@sh scripts/init-env.sh

build: setup ## Construye las imágenes (app y motor Opengrep verificado)
	$(COMPOSE) build

up: setup ## Construye si hace falta, arranca y muestra la URL y el código de configuración
	$(COMPOSE) up --build -d
	@printf 'Esperando a que el panel responda'
	@i=0; until [ "$$(docker inspect -f '{{.State.Health.Status}}' appsec-agent 2>/dev/null)" = healthy ]; do \
	  i=$$((i + 1)); if [ $$i -gt 60 ]; then echo; echo 'No arrancó en 2 minutos: make logs'; exit 1; fi; printf '.'; sleep 2; done; echo
	@echo "Panel: $(URL)"
	@$(MAKE) --no-print-directory setup-code

down: ## Para y elimina los contenedores (conserva data/ y config/)
	$(COMPOSE) down

restart: ## Reinicia la app (marca como fallidos los análisis en curso)
	$(COMPOSE) restart appsec

status: ## Estado de los contenedores y de los motores
	@$(COMPOSE) ps
	@echo
	@$(COMPOSE) exec -T appsec python -m appsec_agent engines 2>/dev/null || echo "La app no está en marcha: make up"

ps: status

logs: ## Sigue los logs de la app (Ctrl+C para salir)
	$(COMPOSE) logs -f --tail 100 appsec

setup-code: ## Muestra el código para crear el primer administrador
	@code=$$($(COMPOSE) logs appsec 2>/dev/null | grep -A1 'Primer arranque' | tail -n1 | sed 's/.*| *//; s/^ *//'); \
	if [ -n "$$code" ] && curl -fsS -H "Host: 127.0.0.1:$(HOST_PORT)" "http://127.0.0.1:$(HOST_PORT)/api/auth/session" 2>/dev/null | grep -q '"setup_required": true'; then \
	  echo "Código de configuración: $$code  (créalo en $(URL))"; \
	else echo "Ya hay un administrador creado: entra con tu usuario."; fi

engines: ## Descarga por adelantado las imágenes de Trivy, Gitleaks y Grype
	$(COMPOSE) run --rm --no-deps appsec python -m appsec_agent engines --pull

update: ## Actualiza el código (git pull) y reconstruye
	git pull --ff-only
	$(MAKE) --no-print-directory up

backup: ## Copia data/ y config/ en backups/<fecha>/ (FORCE=1 si hay análisis en curso)
	@sh scripts/backup.sh

shell: ## Abre una terminal dentro del contenedor
	$(COMPOSE) exec appsec sh

cli: ## CLI de la app: make cli ARGS="user list"
	$(COMPOSE) exec appsec python -m appsec_agent --data-dir /data $(ARGS)

clean: ## Para todo y borra las imágenes locales (conserva data/ y config/)
	$(COMPOSE) down --rmi all

purge: ## ¡BORRA data/ y config/! Pide CONFIRM=borrar
	@if [ "$(CONFIRM)" != "borrar" ]; then echo 'Esto borra ejecuciones, usuarios y secretos. Repite con: make purge CONFIRM=borrar'; exit 1; fi
	$(COMPOSE) down --rmi all
	rm -rf data config

## —— Desarrollo ———————————————————————————————————————————————————————

dev-setup: ## Crea .venv e instala dependencias de Python y del panel
	$(PYTHON) -m venv $(VENV)
	$(VENV)/bin/pip install -q -r requirements.txt
	cd web && npm ci --no-audit --no-fund

dev: ## Servidor local sin contenedor en 127.0.0.1:8767 (motores vía tu Docker)
	APPSEC_AGENT_PUBLIC_URL=http://127.0.0.1:8767 APPSEC_AGENT_ALLOWED_ORIGINS=http://127.0.0.1:8767,http://localhost:8767 \
	APPSEC_AGENT_CONFIG_DIR=$(CURDIR)/.dev/config $(VENV)/bin/python -m appsec_agent --data-dir .dev/data serve --port 8767

web: ## Compila el panel en appsec_agent/static/
	cd web && npm run build

test: ## Pruebas del backend
	$(VENV)/bin/python -m unittest discover -s tests

lint: ## Lint y tipos del panel
	cd web && npx tsc -b && npm run lint

check: test lint ## Pruebas + lint (lo que se exige antes de un PR)
