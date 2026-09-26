---
name: set-up-tamandua-in-ci
description: Add Tamandua (self-hosted, open source application security scanner) to a repository's CI — GitHub Actions or GitLab CI — so pull requests fail only on the vulnerabilities, secrets and misconfigurations they introduce, with SARIF for GitHub code scanning; or add it as a git pre-push hook. Use when the user asks to add security scanning, SAST/SCA/secret scanning or a security gate to CI or to their local workflow. ES: añadir análisis de seguridad al CI, bloquear pull requests, pre-push.
license: AGPL-3.0-only
metadata:
  author: tamandua
  homepage: https://github.com/BrayansStivens/appsec-agent
---

# Tamandua en CI y antes de subir

Un solo paso de CI que analiza lo que introduce el pull request (no lo que ya había) y bloquea desde la severidad que
elija el equipo. Tamandua corre como contenedor y lanza los motores (Opengrep, Gitleaks, Trivy, OSV-Scanner,
Checkov, zizmor) como contenedores hermanos: **el runner necesita el socket de Docker**.

## 1. Partir de la plantilla oficial

Las plantillas completas de GitHub Actions y GitLab CI están en la sección «En CI» de `docs/cli.md` del repositorio
de Tamandua (`${TAMANDUA_DIR:-$HOME/tamandua}/docs/cli.md` si está clonado). Cópiala en vez de escribirla de memoria y
adapta solo lo necesario.

Pregunta al usuario, si no está claro:

- **Umbral** (`--fail-on`): `high` por defecto; `critical` para empezar sin fricción; `never` para solo informar.
- **Rutas con ejemplos vulnerables a propósito** (fixtures, testdata): van en `--exclude`, una por patrón.

## 2. Reglas que no se negocian

- `fetch-depth: 0` en el checkout (GitHub) o `git fetch origin "$CI_MERGE_REQUEST_TARGET_BRANCH_NAME"` (GitLab):
  sin historia no hay comparación con la base y el análisis sale con código 2.
- Nombres de rama y de repositorio **por `env:`**, nunca interpolados con `${{ … }}` dentro de `run:` (inyección de
  órdenes desde el nombre de una rama).
- `permissions` mínimos: `contents: read` y, solo si se sube el SARIF, `security-events: write`.
  `persist-credentials: false` en el checkout.
- Acciones fijadas por SHA de commit, no por etiqueta.
- La carpeta de datos (`/data`) fuera del código analizado; el código montado en solo lectura (`/src:ro`).
- Nada de `--allow-incomplete` por defecto: un análisis que no terminó no es un «limpio» (código 3).
- `--exclude` vive en el workflow, que un pull request puede cambiar: propone proteger `.github/workflows/` (o
  `.gitlab-ci.yml`) con CODEOWNERS y revisión obligatoria.
- En GitLab, un runner con el socket del host (ejecutor `shell`, o `docker` con `/var/run/docker.sock` montado).
  Con Docker-in-Docker los motores no ven las carpetas.

Códigos de salida del paso: `0` pasa, `1` bloquea, `2` error de uso, `3` incompleto (revisa «Sin analizar» en el log).

## 3. Antes de subir (opcional)

Un análisis tarda del orden de medio minuto: encaja en `pre-push`, no en `pre-commit`. En `.git/hooks/pre-push`
(con `chmod +x`), pidiendo antes permiso al usuario porque cambia su flujo local:

```sh
#!/bin/sh
make -s -C "${TAMANDUA_DIR:-$HOME/tamandua}" scan DIR="$(git rev-parse --show-toplevel)" ARGS="--base origin/main --quiet"
```

## 4. Comprobarlo

Abre un pull request de prueba (o ejecuta el mismo `docker run` en local) y confirma que: el paso termina con el
código esperado, el resumen dice «cambios respecto a …» y, con SARIF, los resultados aparecen en *Code scanning*.
Si falla, el motivo está en la línea «Sin analizar» o en el error de Docker. Para corregir lo que encuentre, usa la
skill `fix-findings-with-tamandua`.
