[English](../containers.md) · Español

# Contenedores y Makefile

Todo Tamandua corre en Docker. El `Makefile` de la raíz envuelve los comandos de `docker compose` para que levantarlo, actualizarlo o hacer copias sea una sola orden.

## Qué necesitas

| Herramienta | Versión | Cómo instalarla |
| --- | --- | --- |
| Docker Engine | 24 o superior | [Docker Desktop](https://docs.docker.com/get-docker/), [OrbStack](https://orbstack.dev) (macOS) o `docker-ce` en Linux |
| Docker Compose | v2.24 o superior | Viene con Docker Desktop y OrbStack; en Linux, el paquete `docker-compose-plugin` |
| make | cualquiera (también la 3.81 de macOS) | macOS: ya viene (o `xcode-select --install`) · Debian/Ubuntu: `sudo apt install make` · Fedora: `sudo dnf install make` · Windows: dentro de WSL2 |
| git | cualquiera | Para clonar y para `make update` |

Python y Node **no** hacen falta para usarlo: solo para desarrollar (`make dev-setup`).

`make doctor` comprueba todo esto y te dice cómo arreglar lo que falte.

## Levantarlo

```bash
git clone https://github.com/BrayansStivens/appsec-agent.git
cd appsec-agent
make up
```

`make up`:

1. crea `.env` desde `.env.example` con tu UID/GID (si no existe) y las carpetas `data/` y `config/`;
2. construye las imágenes si han cambiado;
3. arranca y espera a que el panel responda;
4. descarga las imágenes de los motores que falten, con progreso (la primera vez puede tardar según tu conexión; después no descarga nada);
5. muestra la URL y, si aún no hay administrador, el **código de configuración**.

Funciona igual en macOS (Apple Silicon e Intel), Linux y Windows con WSL o Git Bash. En Linux y en WSL con Docker nativo, el socket de Docker es del grupo `docker`: `make` detecta su número y se lo da al contenedor (`DOCKER_SOCKET_GID`). Si arrancas con `docker compose` directamente en esas máquinas, pon ese valor en `.env` (`stat -Lc %g /var/run/docker.sock`).

## Referencia de comandos

| Comando | Qué hace |
| --- | --- |
| `make help` | Lista de comandos. |
| `make doctor` | Comprueba Docker, Compose, arquitectura, disco, puerto, permisos de `data/` y `config/`, y motores. |
| `make setup` | Solo crea `.env` y las carpetas; no toca un `.env` existente. |
| `make build` | Construye las imágenes de la app y de Opengrep. |
| `make up` | Construye si hace falta, arranca, descarga los motores que falten y muestra URL y código. |
| `make demo` | Analiza los ejemplos vulnerables del repositorio e importa un modelo de amenazas, para probar sin conectar nada. `IMAGE=nginx:1.21` añade una imagen. |
| `make down` | Para y elimina los contenedores. `data/` y `config/` se conservan. |
| `make restart` | Reinicia la app. Los análisis en curso se marcan como fallidos. |
| `make status` | Estado de los contenedores y de las imágenes de los motores. |
| `make logs` | Sigue los logs de la app. |
| `make setup-code` | Vuelve a mostrar el código de configuración. |
| `make scan` | Analiza una carpeta local: `make scan DIR=../mi-repo ARGS="--base main"`. Ver [cli.md](cli.md). |
| `make engines` | Descarga desde el host, con progreso, las imágenes de Trivy, OSV-Scanner, Gitleaks, Grype, Checkov y zizmor que falten. `make up` ya lo hace; úsalo para reintentar si falló la conexión. |
| `make update` | `git pull` y vuelve a levantar con la versión nueva. |
| `make backup` | Copia `data/` y `config/` en `backups/<fecha>/`. Se niega si hay análisis en curso (salvo `FORCE=1`). |
| `make shell` | Terminal dentro del contenedor. |
| `make cli ARGS="…"` | CLI de la app, p. ej. `make cli ARGS="user list"` o `make cli ARGS="user reset-totp --username ana"`. |
| `make clean` | Para todo y borra las imágenes de Tamandua. |
| `make purge CONFIRM=delete` | **Borra `data/` y `config/`**: ejecuciones, usuarios y secretos. |
| `make dev-setup` · `make dev` | Entorno de desarrollo sin contenedor (ver [desarrollo.md](desarrollo.md)). |
| `make test` · `make lint` · `make check` | Pruebas del backend, lint del panel y ambos. |

Sin `make`, lo mismo con Compose: `sh scripts/init-env.sh && docker compose up --build -d`.

## Estructura

```
Makefile                        comandos habituales
compose.yaml                    servicio de la app + construcción del motor Opengrep
.env.example                    variables (se copia a .env)
docker/
  app/Dockerfile                imagen de la app: panel compilado + Python + cliente de Docker
  engines/opengrep/Dockerfile   motor SAST, binario oficial verificado por SHA-256
  engines/opengrep/VERIFY.md    cómo repetir la verificación con Cosign al subir de versión
scripts/
  doctor.sh                     comprobación del entorno
  init-env.sh                   crea .env con tu UID/GID y las carpetas
  backup.sh                     copias de seguridad coherentes
```

## Imágenes

| Imagen | Origen | Tamaño aprox. |
| --- | --- | --- |
| `tamandua/app:<versión>` | Se construye de `docker/app/Dockerfile` (Node solo en la etapa de compilación) | 360 MB |
| `tamandua/opengrep:1.30.0` | Se construye de `docker/engines/opengrep/` | 230 MB |
| `aquasec/trivy` | Docker Hub, fijada por digest | 240 MB |
| `ghcr.io/gitleaks/gitleaks` | GHCR, fijada por digest | 80 MB |
| `anchore/grype` | Docker Hub, fijada por digest; solo para imágenes de contenedor | 110 MB (+2,1 GB de base) |
| `bridgecrew/checkov` | Docker Hub, fijada por digest | 200 MB |
| `ghcr.io/zizmorcore/zizmor` | GHCR, fijada por digest | 15 MB |

Las bases (`node`, `python`, `debian`) van fijadas por digest, de modo que dos construcciones de la misma versión usan exactamente las mismas capas. Las etiquetas OCI de la imagen de la app declaran versión, licencia y repositorio (`docker inspect tamandua`).

## Endurecimiento del contenedor de la app

| Medida | Efecto |
| --- | --- |
| Usuario sin privilegios con tu UID/GID | Los ficheros de `data/` y `config/` son tuyos; el proceso no es root. |
| `read_only: true` | No puede modificar su propio código ni el sistema: solo escribe en `/data`, `/config` y temporales en memoria (`/tmp`, `$HOME`). |
| `cap_drop: [ALL]` y `no-new-privileges` | Sin capacidades de Linux ni forma de ganarlas. |
| `init: true` | Recoge procesos huérfanos y reenvía señales: paradas limpias. |
| Puerto en `127.0.0.1` | Nadie fuera de tu máquina llega al panel salvo que lo configures (y entonces exige HTTPS). |
| Logs rotados (10 MB × 5) | Los logs de Docker no llenan el disco. |

Los motores se lanzan por cada análisis como contenedores efímeros (`--rm`) con el código en solo lectura, `--cap-drop ALL`, `no-new-privileges`, 3 GB de memoria, 2 CPU y 512 procesos como máximo; Gitleaks, Opengrep, Checkov y zizmor sin red.

**La concesión que queda:** para lanzar los motores, la app monta `/var/run/docker.sock`, lo que equivale a root en el host. Por eso el panel solo escucha en `127.0.0.1` por defecto. Si lo abres a más gente, pon un socket-proxy con lista blanca de operaciones delante del socket (está en el plan de trabajo).

## Aislamiento entre análisis

Cada análisis usa su propia instantánea del repositorio (`data/work/snapshot-…/`, una por análisis) y contenedores de motor nuevos que se destruyen al terminar, así que dos análisis no comparten ficheros ni procesos. Hoy se ejecutan **de uno en uno** (cola con un trabajador), lo que limita el consumo a un motor a la vez.

Evaluamos pasar a un *runner* efímero por análisis (un contenedor con todas las herramientas, su propia red y su propio volumen, destruido al terminar) y ejecutar varios en paralelo. Es una línea de trabajo abierta y la conclusión de la evaluación es que la dirección es buena, pero las herramientas no deben descargarse en cada análisis (lento y más superficie de cadena de suministro), sino venir en una imagen fijada, y el paralelismo necesita un límite configurable para no agotar la máquina.
