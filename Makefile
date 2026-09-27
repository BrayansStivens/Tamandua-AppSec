# Tamandua · common commands. `make help` for the list.
# Only needs make and Docker; the development targets also need Python 3.12 and Node 22.

SHELL := /bin/sh
COMPOSE ?= docker compose
VERSION := $(shell sed -n 's/^VERSION = "\(.*\)"/\1/p' tamandua/version.py)
PORT := $(shell sed -n 's/^TAMANDUA_HOST_PORT=//p' .env 2>/dev/null | tail -n1)
PUBLIC_URL := $(shell sed -n 's/^TAMANDUA_PUBLIC_URL=//p' .env 2>/dev/null | tail -n1)
HOST_PORT := $(if $(PORT),$(PORT),8766)
URL := $(if $(PUBLIC_URL),$(PUBLIC_URL),http://127.0.0.1:$(HOST_PORT))
PYTHON ?= python3
DIR ?=
ARGS ?=
# make setup DOMAIN=… [PREBUILT=1]: server mode (see scripts/init-env.sh). make restore FROM=backups/<date>.
DOMAIN ?=
PREBUILT ?=
FROM ?=
SERVICE ?= api
# Who signs the published images (cosign keyless, GitHub OIDC): the repository whose release workflow built them.
SIGNER ?= BrayansStivens/appsec-agent
OPENGREP_VERSION := $(shell sed -n 's/^ARG OPENGREP_VERSION=//p' docker/engines/opengrep/Dockerfile)
VENV := .venv
export TAMANDUA_VERSION := $(VERSION)
# Docker socket group on Linux and WSL with native Docker (on macOS, Docker Desktop uses 0).
# A value in the environment or in .env overrides detection.
DOCKER_SOCKET_GID ?= $(shell sed -n 's/^DOCKER_SOCKET_GID=//p' .env 2>/dev/null | tail -n1)
ifeq ($(strip $(DOCKER_SOCKET_GID)),)
DOCKER_SOCKET_GID := $(shell [ "$$(uname -s)" = Linux ] && stat -Lc %g /var/run/docker.sock 2>/dev/null)
endif
# 0 is always in compose already; repeating it is an error.
ifeq ($(strip $(DOCKER_SOCKET_GID)),0)
DOCKER_SOCKET_GID :=
endif
export DOCKER_SOCKET_GID
# Published engine images, pinned by digest, read from the code (no Python or app image needed).
# `make engines` pulls them from the host: progress is visible, there is no time limit and it doesn't depend
# on the socket permissions inside the container.
ENGINE_IMAGES := sed -n 's/.*"image": "\([^"]*@sha256:[0-9a-f]\{64\}\)".*/\1/p' tamandua/modules/scanning/engines.py

.DEFAULT_GOAL := help
.PHONY: arch openapi standalone help doctor setup build up down restart status logs ps setup-code engines scan demo update backup restore \
        verify-images shell cli clean purge dev-setup dev test lint web check

## —— Usage —————————————————————————————————————————————————————————————

help: ## Show this help
	@printf 'Tamandua %s · usage: make <target>\n\n' "$(VERSION)"
	@awk 'BEGIN {FS = ":.*## "} /^## ——/ {sub(/^## /, ""); printf "\n\033[1m%s\033[0m\n", $$0} /^[a-z-]+:.*## / {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@printf '\nFirst time:  make up\n'

doctor: ## Check requirements (Docker, Compose, disk, port, permissions)
	@sh scripts/doctor.sh

setup: ## Create .env and the folders. On a server: make setup DOMAIN=tamandua.example.com [PREBUILT=1]
	@DOMAIN="$(DOMAIN)" PREBUILT="$(PREBUILT)" sh scripts/init-env.sh

build: setup ## Build the images (app and verified Opengrep engine)
	$(COMPOSE) build

up: setup ## Build if needed (or pull the published images), start, pull missing engines and show the URL
	$(COMPOSE) up --build -d
	@printf 'Waiting for the panel to respond'
	@i=0; until [ "$$(docker inspect -f '{{.State.Health.Status}}' "$$($(COMPOSE) ps -q api)" 2>/dev/null)" = healthy ]; do \
	  i=$$((i + 1)); if [ $$i -gt 60 ]; then echo; echo 'It did not start within 2 minutes: make logs'; exit 1; fi; printf '.'; sleep 2; done; echo
	@$(MAKE) --no-print-directory engines || echo 'Warning: some engines are missing; the panel works, retry with make engines.'
	@echo "Panel: $(URL)"
	@$(MAKE) --no-print-directory setup-code

down: ## Stop and remove the containers (keeps data/ and config/)
	$(COMPOSE) down

restart: ## Restart the app (marks running scans as failed)
	$(COMPOSE) restart api worker

status: ## Status of the containers and the engines
	@$(COMPOSE) ps
	@echo
	@$(COMPOSE) exec -T worker python -m tamandua engines 2>/dev/null || echo "The app is not running: make up"

ps: status

logs: ## Follow the app logs (Ctrl+C to exit). Another service: make logs SERVICE=caddy
	$(COMPOSE) logs -f --tail 100 $(SERVICE)

setup-code: ## Show the code to create the first administrator
	@sh scripts/setup-code.sh "$(URL)"

engines: ## Pull the missing engine images (Trivy, OSV-Scanner, Gitleaks, Grype, Checkov, zizmor), with progress
	@images=$$($(ENGINE_IMAGES)); \
	missing=0; for image in $$images; do docker image inspect "$$image" >/dev/null 2>&1 || missing=$$((missing + 1)); done; \
	if [ $$missing -eq 0 ]; then echo 'Engines: all images are ready.'; exit 0; fi; \
	echo "Engines: $$missing images missing; the first time can take a while depending on your connection."; \
	for image in $$images; do \
	  docker image inspect "$$image" >/dev/null 2>&1 && continue; \
	  echo "→ $${image%%@*}"; \
	  docker pull "$$image" || { echo "Pulling $${image%%@*} failed: check your connection and run make engines again."; exit 1; }; \
	done; echo 'Engines: ready.'

scan: ## Scan a local folder: make scan DIR=../my-repo ARGS="--base main --fail-on high"
	@[ -d "$(DIR)" ] || { echo 'Give the folder: make scan DIR=../my-repo (and options in ARGS="--base main")'; exit 2; }
	@$(COMPOSE) run --rm --no-deps -T -v "$(abspath $(DIR))":/src:ro worker python -m tamandua scan /src --name "$(notdir $(abspath $(DIR)))" $(ARGS)

demo: ## Demo data: scans the vulnerable examples and imports a threat model (IMAGE=nginx:1.21 adds an image)
	@$(COMPOSE) run --rm -T -v "$(abspath fixtures)":/demo/fixtures:ro -v "$(abspath web/src/examples/threat-models)":/demo/models:ro \
		worker python -m tamandua --data-dir /data demo --fixtures /demo/fixtures --models /demo/models $(if $(IMAGE),--image "$(IMAGE)",)

update: ## Back up, update the code (git pull), pull or rebuild the images and restart (migrates on start)
	@if git symbolic-ref -q HEAD >/dev/null; then git pull --ff-only; \
	else echo "On $$(git describe --tags --always) (a fixed version): not pulling. Check out the version you want first."; fi
	@sh scripts/backup.sh
	$(COMPOSE) pull --ignore-buildable --policy always --quiet
	$(MAKE) --no-print-directory up

backup: ## Database, data/ and config/ to backups/<date>/ (FORCE=1 if scans are running)
	@sh scripts/backup.sh

restore: ## Restore a backup: make restore FROM=backups/<date> CONFIRM=restore (saves the current state first)
	@CONFIRM="$(CONFIRM)" sh scripts/restore.sh "$(FROM)"

verify-images: ## Check the cosign signatures of the published images (TAMANDUA_IMAGE in .env; needs cosign)
	@image=$$(sed -n 's/^TAMANDUA_IMAGE=//p' .env 2>/dev/null | tail -n1); \
	[ -n "$$image" ] || { echo 'There is no TAMANDUA_IMAGE in .env: this server builds its own images.'; exit 2; }; \
	command -v cosign >/dev/null || { echo 'Install cosign first: https://docs.sigstore.dev/cosign/system_config/installation/'; exit 2; }; \
	for ref in "$$image:$(VERSION)" "$$image-opengrep:$(OPENGREP_VERSION)"; do \
	  cosign verify --certificate-oidc-issuer https://token.actions.githubusercontent.com \
	    --certificate-identity-regexp '^https://github\.com/$(SIGNER)/\.github/workflows/release\.yml@refs/tags/v' "$$ref" >/dev/null \
	    && echo "Signed by $(SIGNER): $$ref" || { echo "NOT verified: $$ref"; exit 1; }; \
	done

shell: ## Open a shell inside the container
	$(COMPOSE) exec api sh

cli: ## App CLI: make cli ARGS="user list"
	$(COMPOSE) exec api python -m tamandua --data-dir /data $(ARGS)

clean: ## Stop everything and remove the local images (keeps data/ and config/)
	$(COMPOSE) down --rmi all

purge: ## DELETES data/ and config/. Requires CONFIRM=delete
	@if [ "$(CONFIRM)" != "delete" ] && [ "$(CONFIRM)" != "borrar" ]; then echo 'This deletes runs, users and secrets. Run again with: make purge CONFIRM=delete'; exit 1; fi
	$(COMPOSE) down --rmi all
	rm -rf data config

## —— Development ———————————————————————————————————————————————————————

dev-setup: ## Create .venv and install the Python and panel dependencies
	$(PYTHON) -m venv $(VENV)
	$(VENV)/bin/pip install -q -r requirements-dev.txt
	cd web && npm ci --no-audit --no-fund

dev: ## Local server without a container on 127.0.0.1:8767 (engines through your Docker)
	TAMANDUA_PUBLIC_URL=http://127.0.0.1:8767 TAMANDUA_ALLOWED_ORIGINS=http://127.0.0.1:8767,http://localhost:8767 \
	TAMANDUA_CONFIG_DIR=$(CURDIR)/.dev/config $(VENV)/bin/python -m tamandua --data-dir .dev/data serve --port 8767

web: ## Build the panel into tamandua/app/static/
	cd web && npm run build

test: ## Backend tests (starts a throwaway test Postgres if needed)
	@url=$$(sh scripts/test-db.sh) && config=$$(mktemp -d) && trap 'rm -rf "$$config"' EXIT && \
	TAMANDUA_DATABASE_URL="$$url" TAMANDUA_DB_ISOLATE=data-dir TAMANDUA_CONFIG_DIR="$$config" TAMANDUA_DEFAULT_LOCALE=es \
	$(VENV)/bin/python -m unittest discover -s tests

standalone: ## Regenerate deploy/compose.yaml (one file, published images, no Docker socket)
	python3 scripts/standalone-compose.py

openapi: ## API OpenAPI schema and the panel's TypeScript types (web/src/shared/api/)
	@mkdir -p web/src/shared/api
	$(VENV)/bin/python -c "from tamandua.app.api import openapi_document; print(openapi_document(), end='')" > web/src/shared/api/openapi.json
	cd web && npx --yes openapi-typescript@7.13.0 src/shared/api/openapi.json -o src/shared/api/schema.d.ts

arch: ## Architecture contracts (import-linter, see pyproject.toml)
	$(VENV)/bin/lint-imports

lint: ## Panel lint and types
	cd web && npx tsc -b && npm run lint

check: test arch lint ## Tests, architecture contracts and lint (required before a PR)
