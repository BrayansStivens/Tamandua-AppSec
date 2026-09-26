# Analizar desde la terminal y en CI (`scan`)

`scan` analiza una carpeta local con los mismos motores que el panel (Opengrep, Gitleaks,
Trivy, OSV-Scanner, Checkov, zizmor), sin ejecutar su código y sin enviarlo a ningún servicio.
Sirve para revisar tu cambio antes de subirlo y para bloquear un pull request en CI.

## Uso rápido

Desde la carpeta de Tamandua (solo hace falta `make` y Docker):

```bash
make scan DIR=../mi-repo
make scan DIR=../mi-repo ARGS="--base main"
```

Con `--base main` solo se informa de lo que **tu cambio introduce**. Tamandua analiza también el
punto de partida (el merge-base con `main`) y descarta lo que ya estaba: si tocas un
`package-lock.json` que ya tenía vulnerabilidades, no te las cobra; si añades una dependencia
vulnerable, sí. Cuenta lo que aún no has subido (cambios sin commit y archivos nuevos que git no
ignora), así que funciona antes del push.

```text
Tamandua · mi-repo · cambios respecto a main (merge-base 73223791, 3 archivos)

CRÍTICA  app.py:8  Injection: eval exec non literal
ALTA     requirements.txt  urllib3 1.26.4: 9 avisos (5 alta, 4 media) → actualiza a 2.7.0
ALTA     settings.py:1  Token personal de GitHub expuesto

4 ya existían en el código que tocas: no bloquean.

Motores: Opengrep 1.30.0, Gitleaks 8.30.1, Trivy 0.74.0, OSV-Scanner 2.6.0

BLOQUEA · umbral: alta o superior · 7 hallazgos nuevos de severidad alta o superior
```

Los avisos de una misma dependencia salen en una línea con la versión que los cierra todos.
`--format json` y `--format sarif` conservan cada aviso por separado.

## Opciones

| Opción | Qué hace |
| --- | --- |
| `--base REF` | Rama o commit de partida (`main`, `origin/main`, un SHA). Solo cuenta lo que introduce el cambio. |
| `--no-baseline` | Con `--base`, no analiza el punto de partida: tarda la mitad, pero cuenta todo lo que cae en líneas cambiadas (y cualquier aviso de un lockfile que toques). |
| `--fail-on` | Severidad desde la que falla: `critical`, `high` (por defecto), `medium`, `low` o `never` (solo informa). |
| `--format` | `text` (por defecto), `json` o `sarif` (SARIF 2.1.0, con `security-severity` para GitHub code scanning). |
| `--output FILE` | Escribe el resultado en un archivo; el resumen en texto sale igualmente por la salida de errores. |
| `--exclude PATRÓN` | Ruta cuyos hallazgos no cuentan: glob relativo a la raíz (`fixtures/`, `**/testdata/**`; `*` no cruza `/`, `**` sí). Repetible. La salida dice cuántos se excluyeron. |
| `--allow-incomplete` | No falla si un motor no pudo ejecutarse. Por defecto sí falla: un análisis que no terminó no equivale a «limpio». |
| `--allow-osv-upload` | Autoriza consultas externas (nombres y versiones de dependencias a OSV y deps.dev para resolver transitivas). Por defecto no sale nada. |
| `--name` | Nombre a mostrar (útil dentro de un contenedor, donde la carpeta se llama `/src`). |
| `--quiet` | Sin mensajes de progreso. |

El progreso va a la salida de errores; la salida estándar queda limpia para `json` y `sarif`.

## Códigos de salida

| Código | Significado |
| --- | --- |
| `0` | Pasa: nada del umbral o peor. |
| `1` | Bloquea: hay hallazgos nuevos del umbral o peores. |
| `2` | Error de uso: carpeta inexistente, referencia de git inválida o inexistente (¿falta `git fetch`?). |
| `3` | Incompleto: algún motor no se ejecutó (Docker, imágenes, red). Revisa las líneas «Sin analizar». |

`make` convierte cualquier fallo en su propio código 2; en CI usa `docker run` (abajo) para conservar
el código exacto.

## Antes de subir (pre-push)

Un análisis completo tarda del orden de medio minuto, así que encaja mejor en `pre-push` que en
`pre-commit`. En `.git/hooks/pre-push` de tu repositorio (y `chmod +x`):

```sh
#!/bin/sh
make -s -C ~/tamandua scan DIR="$(git rev-parse --show-toplevel)" ARGS="--base origin/main --quiet"
```

## En CI

Tamandua corre como contenedor y lanza los motores como contenedores hermanos, así que el runner
necesita el socket de Docker (los runners Linux de GitHub Actions lo tienen). La carpeta de datos
(`/data`) guarda en caché las bases de avisos entre pasos.

### GitHub Actions

```yaml
name: Tamandua
on: pull_request

permissions:
  contents: read
  security-events: write   # para subir el SARIF a code scanning

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      # Fija las acciones por SHA en tu organización.
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0              # hace falta la historia para comparar con la base
          persist-credentials: false
      - name: Construir Tamandua
        run: |
          git clone --depth 1 https://github.com/BrayansStivens/appsec-agent "$RUNNER_TEMP/tamandua"
          make -C "$RUNNER_TEMP/tamandua" build
      - name: Analizar lo que introduce el PR
        env:
          BASE_REF: ${{ github.base_ref }}      # nunca interpolado directamente en el script
          REPO_NAME: ${{ github.event.repository.name }}
        run: |
          mkdir -p "$RUNNER_TEMP/tamandua-data"
          docker run --rm \
            -v /var/run/docker.sock:/var/run/docker.sock --group-add "$(stat -c %g /var/run/docker.sock)" \
            --user "$(id -u):$(id -g)" -e HOME=/tmp \
            -v "$PWD":/src:ro -v "$RUNNER_TEMP/tamandua-data":/data \
            appsec-agent/app:0.9 python -m tamandua scan /src --name "$REPO_NAME" \
            --base "origin/$BASE_REF" --format sarif --output /data/tamandua.sarif
      - uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: ${{ runner.temp }}/tamandua-data/tamandua.sarif
```

### GitLab CI

Necesita un runner con acceso al socket de Docker del host (ejecutor `shell`, o `docker` con
`/var/run/docker.sock` montado). Con Docker-in-Docker (`dind`) los motores no verían las carpetas.

```yaml
tamandua:
  stage: test
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script:
    - git fetch origin "$CI_MERGE_REQUEST_TARGET_BRANCH_NAME"
    - git clone --depth 1 https://github.com/BrayansStivens/appsec-agent /tmp/tamandua
    - make -C /tmp/tamandua build
    - mkdir -p /tmp/tamandua-data
    - >
      docker run --rm -v /var/run/docker.sock:/var/run/docker.sock --group-add "$(stat -c %g /var/run/docker.sock)"
      --user "$(id -u):$(id -g)" -e HOME=/tmp -v "$PWD":/src:ro -v /tmp/tamandua-data:/data
      appsec-agent/app:0.9 python -m tamandua scan /src --name "$CI_PROJECT_NAME"
      --base "origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME"
```

> El propio repositorio de Tamandua usa esta plantilla en [`.github/workflows/ci.yml`](../.github/workflows/ci.yml)
> (con `--exclude fixtures/` para sus ejemplos vulnerables a propósito). La de GitLab está comprobada con el
> mismo `docker run` en local, pero aún no en un runner real. Si algo falla, el error de Docker o del motor
> aparece en la línea «Sin analizar».

**Exclusiones en CI.** `--exclude` vive en el workflow, que un pull request puede modificar. Protege
`.github/workflows/` con CODEOWNERS y revisión obligatoria para que nadie se excluya a sí mismo sin que se vea.
(En el panel las exclusiones viven en el servidor por eso mismo.)

## Privacidad

El código se copia a una carpeta temporal (sin enlaces simbólicos ni lo que el análisis ignora) y
se borra al terminar. Los motores lo leen en solo lectura, sin red salvo para descargar sus bases
públicas de avisos. Nada del repositorio sale de la máquina salvo que pases `--allow-osv-upload`.
