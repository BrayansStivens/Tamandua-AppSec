[English](../cli.md) · Español

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

Corregido en este cambio (1): estaba en el punto de partida, ya no está y su archivo cambió.
  ALTA     db.py:14  SQL construido concatenando cadenas

Motores: Opengrep 1.30.0, Gitleaks 8.30.1, Trivy 0.74.0, OSV-Scanner 2.6.0

BLOQUEA · umbral: alta o superior · 7 hallazgos nuevos de severidad alta o superior
```

**Lo que corrige el cambio.** Al comparar los dos análisis también sale lo que tenía el punto de partida y el
cambio ya no tiene. Cuenta como **corregido** solo si los dos análisis terminaron y su archivo es uno de los que el
cambio modificó. Si desapareció porque se borró el archivo, o sin que se tocara su archivo, la salida lo dice y no lo
cuenta como corrección; si alguno de los dos análisis quedó incompleto, dice que no se puede verificar. Un hallazgo
que solo se movió (misma regla, mismo archivo) no se reporta. Sirve para lo que detectan los motores de Tamandua; los
hallazgos importados de otras herramientas se verifican importando de nuevo los resultados de esa herramienta.

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
| `--exclude PATRÓN` | Ruta cuyos hallazgos no cuentan: glob relativo a la raíz (`fixtures`, `**/testdata`, `docs/*.md`). Como en `.gitignore`, una carpeta excluye todo lo que tiene dentro; `*` no cruza `/` y `**` sí. Repetible. La salida dice cuántos se excluyeron. |
| `--allow-incomplete` | No falla si un motor no pudo ejecutarse. Por defecto sí falla: un análisis que no terminó no equivale a «limpio». |
| `--allow-osv-upload` | Autoriza consultas externas (nombres y versiones de dependencias a OSV y deps.dev para resolver transitivas). Por defecto no sale nada. |
| `--name` | Nombre a mostrar (útil dentro de un contenedor, donde la carpeta se llama `/src`). |
| `--summary ARCHIVO` | Añade además un resumen en Markdown: veredicto, lo que el cambio introduce y lo que corrige (la Action lo escribe en la página de resumen de la ejecución). |
| `--quiet` | Sin mensajes de progreso. |

El progreso va a la salida de errores; la salida estándar queda limpia para `json` y `sarif`.

## Códigos de salida

| Código | Significado |
| --- | --- |
| `0` | Pasa: nada del umbral o peor. |
| `1` | Bloquea: hay hallazgos nuevos del umbral o peores. |
| `2` | Error de uso: carpeta inexistente, referencia de git inválida o inexistente (¿falta `git fetch`?). |
| `3` | Incompleto: algún motor no se ejecutó (Docker, imágenes, red). Revisa las líneas «Sin analizar». |

`make` convierte cualquier fallo en su propio código 2; en CI, la Action y `docker run` (abajo)
conservan el código exacto.

## Antes de subir (pre-push)

Un análisis completo tarda del orden de medio minuto, así que encaja mejor en `pre-push` que en
`pre-commit`. En `.git/hooks/pre-push` de tu repositorio (y `chmod +x`):

```sh
#!/bin/sh
make -s -C ~/tamandua scan DIR="$(git rev-parse --show-toplevel)" ARGS="--base origin/main --quiet"
```

## Importar resultados de otras herramientas (`import-sarif`)

```sh
python -m tamandua import-sarif ARCHIVO [ARCHIVO...] --asset NOMBRE [--tool NOMBRE] [--partial] [--commit SHA] [--branch NOMBRE] [--server URL]
```

Añade los hallazgos de cualquier herramienta que escriba SARIF 2.1.0 (Semgrep, CodeQL, Snyk, Trivy, Strix…) al
registro de un activo que Tamandua ya conoce, por su clave o por su nombre (`owner/repo`). Desde ese momento siguen el
mismo ciclo que los de Tamandua: triage, plazos, incidencias y avisos.

- **Completa por defecto:** lo que esa misma herramienta deje de reportar queda remediado. Los análisis de Tamandua
  nunca remedian un hallazgo importado, porque sus motores no ven lo que encontró otra herramienta.
- `--partial`: la herramienta miró solo una parte del activo; la importación abre y actualiza, nunca remedia.
- `--tool` reemplaza el nombre de herramienta que trae el SARIF. Varios archivos forman una sola importación.
- `--server https://…` envía los archivos a `/api/ci/sarif` de ese servidor con el token de `TAMANDUA_IMPORT_TOKEN`
  (una variable de entorno, nunca una opción; `http://` sin cifrar solo para localhost). Sin `--server` importa en
  la base de datos local (en el propio servidor).

Muestra una línea por herramienta. Códigos de salida: `0` importado, `2` error de uso, del documento o del servidor.
En el panel, **Nuevo análisis → Importar SARIF** hace lo mismo desde el navegador.

## En CI

En CI, Tamandua corre desde la imagen publicada del worker, `ghcr.io/brayansstivens/tamandua-worker:0.10`, que trae
los motores dentro y los ejecuta como procesos propios: nada que construir y sin socket de Docker.

### GitHub Actions

Un paso con la Action de Tamandua. En un pull request compara por su cuenta con la rama base, y deja un SARIF listo
para code scanning:

```yaml
name: Tamandua
on:
  pull_request:
  push:
    branches: [main]

permissions: {}

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # para subir el SARIF a code scanning
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1  # v7.0.1
        with:
          fetch-depth: 0              # hace falta la historia para comparar con la base
          persist-credentials: false
      - id: tamandua
        uses: BrayansStivens/Tamandua-AppSec@v0.10.1   # fíjala al SHA del commit de la etiqueta, como las demás
        with:
          exclude: |
            fixtures/
      - uses: github/codeql-action/upload-sarif@2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2  # v4.38.2
        if: always() && steps.tamandua.outputs.sarif != ''
        with:
          sarif_file: ${{ steps.tamandua.outputs.sarif }}
          category: tamandua
```

El paso termina con el mismo código que `scan` (tabla de arriba): falla con `1`, `2` y `3`. El informe sale en el
log, en inglés salvo que el paso ponga `env: TAMANDUA_DEFAULT_LOCALE: es`.

| Entrada | Por defecto | Qué hace |
| --- | --- | --- |
| `path` | `.` | Carpeta a analizar, relativa al workspace. |
| `base` | vacío | Como `--base`. Vacío: `origin/<rama base>` en un pull request y análisis completo en lo demás; `none`: siempre completo. |
| `fail-on` | `high` | Como `--fail-on`: `critical`, `high`, `medium`, `low` o `never`. |
| `exclude` | vacío | Un patrón por línea; cada uno se convierte en un `--exclude`. |
| `name` | el nombre del repositorio | Como `--name`. |
| `sarif` | `$RUNNER_TEMP/tamandua.sarif` | Dónde escribir el SARIF (las rutas relativas parten del workspace). |
| `image` | `ghcr.io/brayansstivens/tamandua-worker:0.10` | Imagen del worker. Fíjala por digest (`…@sha256:…`) si no quieres que nada cambie sin avisar. |
| `allow-incomplete` | `false` | `true`: como `--allow-incomplete`. |
| `scan` | `true` | `false`: no analiza, solo importa (más abajo). |
| `import-sarif` | vacío | SARIF de otras herramientas que se envían a un servidor Tamandua, uno por línea. |
| `server` | vacío | El servidor Tamandua (`https://…`) para `import-sarif`. |
| `token` | vacío | El `TAMANDUA_IMPORT_TOKEN` del servidor, desde un secreto. Al contenedor solo le llega como variable de entorno. |
| `asset` | `owner/name` del repositorio | Activo (que el servidor ya conoce) al que se suman los hallazgos importados. |
| `import-partial` | `false` | `true`: la herramienta importada miró solo una parte del activo, así que lo que no reporta sigue abierto. En una pull request siempre está activo: sus resultados son de la rama, no del activo. |
| `registry-token` | vacío | Token para descargar la imagen mientras sea privada (ver abajo). |
| `registry-user` | quien lanzó el workflow | Usuario de `registry-token`. |

| Salida | Qué es |
| --- | --- |
| `sarif` | Ruta del SARIF que escribió el análisis (vacía si no escribió ninguno). |
| `exit-code` | `0` pasa, `1` bloquea, `2` error de uso, `3` incompleto. Si además importa, manda el código del análisis salvo que sea `0`. |

La página de resumen de la ejecución muestra el veredicto, lo que la pull request introduce y lo que corrige.

Cómo corre: `docker run` de la imagen con el usuario del runner, sin capabilities, con el sistema de archivos de
solo lectura, el workspace montado en solo lectura y las cachés de los motores en `$RUNNER_TEMP/tamandua` (varios
pasos del mismo job las comparten). Ahí los motores no pueden tener una red vacía propia (un `docker run` normal no
permite los espacios de nombres de usuario que hacen falta), así que comparten la red del contenedor y corren con sus
opciones sin conexión; tu código sigue sin enviarse a ningún sitio.

**Mientras el repositorio sea privado.** Otro repositorio solo puede usar la Action si este lo permite
(*Settings → Actions → General → Access*), y descargar la imagen pide un token con `read:packages`: el
`GITHUB_TOKEN` del job (con `packages: read`) si el paquete le da acceso a tu repositorio, o si no un token clásico
en un secreto (ver [Acceso mientras el repositorio sea privado](despliegue.md#acceso-mientras-el-repositorio-sea-privado)).
La Action inicia sesión con `--password-stdin` y descarta la credencial después de descargar:

```yaml
    permissions:
      contents: read
      packages: read
      security-events: write
    steps:
      # …
      - id: tamandua
        uses: BrayansStivens/Tamandua-AppSec@v0.10.1
        with:
          registry-token: ${{ secrets.GHCR_TOKEN }}   # o ${{ secrets.GITHUB_TOKEN }}
```

#### Resultados de otras herramientas

Con `import-sarif`, la Action envía el SARIF de cualquier herramienta (Semgrep, CodeQL, Snyk…) a tu servidor
Tamandua, que suma sus hallazgos al registro del activo junto a los suyos. El servidor necesita
`TAMANDUA_IMPORT_TOKEN` ([configuración](configuracion.md)) y debe conocer ya el activo. Por ejemplo, solo Semgrep,
sin el análisis propio de Tamandua:

```yaml
      - name: Semgrep
        run: |
          python -m pip install semgrep   # fija la versión
          semgrep scan --config p/ci --metrics off --sarif --output semgrep.sarif
      - uses: BrayansStivens/Tamandua-AppSec@v0.10.1
        if: always()
        with:
          scan: false
          import-sarif: semgrep.sarif
          server: https://tamandua.example.com
          token: ${{ secrets.TAMANDUA_IMPORT_TOKEN }}
```

Deja `scan` en `true` para analizar e importar en el mismo paso.

### GitLab CI

La imagen del worker como imagen del job: ya trae git, Python y los motores, y corre con un usuario sin privilegios.
Sin socket de Docker y sin Docker-in-Docker.

```yaml
tamandua:
  stage: test
  image: ghcr.io/brayansstivens/tamandua-worker:0.10
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  variables:
    GIT_DEPTH: "0"   # hace falta la historia para comparar con la base
    BASE: $CI_MERGE_REQUEST_TARGET_BRANCH_NAME
  script:
    # El checkout es de otro usuario: hay que decirle a git que es de confianza.
    - git -c safe.directory="$CI_PROJECT_DIR" fetch origin "$BASE:refs/remotes/origin/$BASE"
    - python -m tamandua scan . --name "$CI_PROJECT_NAME" --base "origin/$BASE"
```

Mientras la imagen sea privada, el runner necesita credenciales de `ghcr.io` en `DOCKER_AUTH_CONFIG`. En un runner
con ejecutor `shell`, usa `docker run` como hace la Action, sin el socket:

```sh
mkdir -p /tmp/tamandua-data   # la creas tú, no Docker: tiene que ser de tu usuario
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -v "$PWD":/src:ro -v /tmp/tamandua-data:/data \
  ghcr.io/brayansstivens/tamandua-worker:0.10 python -m tamandua scan /src --name "$CI_PROJECT_NAME" --base "origin/$BASE"
```

> El propio repositorio de Tamandua usa la Action en [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml), y
> además se analiza con la imagen construida en cada commit (con `--exclude fixtures/` para sus ejemplos vulnerables
> a propósito). La plantilla de GitLab está comprobada en local con la misma imagen y un checkout de otro usuario,
> pero aún no en un runner real. Si algo falla, el motivo aparece en la línea «Sin analizar».

**Exclusiones en CI.** `exclude` vive en el workflow, que un pull request puede modificar. Protege
`.github/workflows/` (o `.gitlab-ci.yml`) con CODEOWNERS y revisión obligatoria para que nadie se excluya a sí mismo
sin que se vea. (En el panel las exclusiones viven en el servidor por eso mismo.)

## Privacidad

El código se copia a una carpeta temporal (sin enlaces simbólicos ni lo que el análisis ignora) y
se borra al terminar. Los motores lo leen en solo lectura, sin red salvo para descargar sus bases
públicas de avisos. Nada del repositorio sale de la máquina salvo que pases `--allow-osv-upload`.
