[English](../deploy.md) · Español

# Dónde desplegar Tamandua

Tamandua tiene tres piezas, y cada una puede vivir donde más te convenga:

| Pieza | Qué necesita | Imagen |
| --- | --- | --- |
| **API y panel** | HTTP y la base de datos. Sin disco propio: todo el estado está en PostgreSQL. | `ghcr.io/tamandua-appsec/tamandua` |
| **Worker** | Un proceso permanente que ejecuta los motores de análisis. | `ghcr.io/tamandua-appsec/tamandua-worker` (motores dentro), o la imagen de la API con el socket de Docker |
| **PostgreSQL** | Versión 16 o superior, gestionada o en un contenedor. | — |

Cada etiqueta de versión publica las imágenes, firmadas y multiarquitectura (usa la `0.10.0` o posterior: en la `0.9.0` y la `0.9.1` la imagen `tamandua` arrancaba el worker en lugar de la API). También puedes construirlas desde el repositorio (`make build`, o `docker build --target worker-standalone -f docker/app/Dockerfile .` para el worker).

## Acceso mientras el repositorio sea privado

Por ahora el repositorio y sus imágenes en el registro de GitHub son privados. Sin acceso, `git clone` responde
*Repository not found* y descargar una imagen responde *denied*. Cuando el mantenedor te haya dado acceso, usa dos
credenciales de solo lectura, una para cada cosa:

| Para | Credencial | Permiso |
| --- | --- | --- |
| Descargar las imágenes | Token personal clásico, con fecha de caducidad (el registro de GitHub no acepta los de grano fino) | Solo `read:packages` |
| Clonar el código | Deploy key: una clave SSH que el mantenedor añade al repositorio | Solo lectura, solo este repositorio |

En el servidor, con el usuario que ejecuta Docker:

```bash
read -rs GHCR_TOKEN && printf '%s' "$GHCR_TOKEN" | docker login ghcr.io -u <tu-usuario-de-github> --password-stdin
ssh-keygen -t ed25519 -N '' -f ~/.ssh/tamandua-deploy   # envía ~/.ssh/tamandua-deploy.pub al mantenedor
```

El mantenedor la añade en *Settings → Deploy keys* sin marcar *Allow write access*. Después clona con ella y déjala
configurada para el `git fetch` de las actualizaciones:

```bash
export GIT_SSH_COMMAND='ssh -i ~/.ssh/tamandua-deploy -o IdentitiesOnly=yes'
git clone git@github.com:Tamandua-AppSec/tamandua.git && cd tamandua
git config core.sshCommand "$GIT_SSH_COMMAND"
```

- `docker login` guarda el token en `~/.docker/config.json`, codificado pero sin cifrar: por eso solo lee paquetes.
  `make up`, `make update` y `make verify-images` lo usan sin repetir nada.
- **Compose de un solo archivo:** necesita el mismo inicio de sesión. Toma `deploy/compose.yaml` del clon.
- **Coolify, Dokploy, Render, Railway y demás plataformas:** añade `ghcr.io` como registro privado en la plataforma,
  con tu usuario y el token de paquetes.
- **CI** (el `git clone` de [cli.md](cli.md)): guarda una deploy key como secreto y clona con ella.

Cuando el repositorio sea público nada de esto hará falta: revoca el token, pide que se retire la deploy key y ejecuta
`docker logout ghcr.io`.

## Elige destino

| Destino | API y panel | Worker | PostgreSQL | Guía | Probado |
| --- | --- | --- | --- | --- | --- |
| Tu servidor, con el repositorio | Compose | Compose, socket de Docker | Contenedor | [despliegue-vps.md](despliegue-vps.md) | Sí |
| Tu servidor, **un solo archivo** (Coolify, Dokploy, Portainer, gestor de Docker de Hostinger) | Compose | Compose, motores dentro | Contenedor | [abajo](#un-solo-archivo-cualquier-servidor-o-panel-de-docker) | En local, de principio a fin |
| Render | Web service | Background worker | Render Postgres | [abajo](#render) | Todavía no |
| Railway, Fly.io | Servicio | Servicio | Su PostgreSQL | [abajo](#railway-flyio-y-otras-plataformas-de-contenedores) | Todavía no |
| Vercel | Función de Python | En otro sitio (cualquier fila de arriba) | Neon, Supabase… | [abajo](#vercel) | La entrada ASGI, en local |
| Kubernetes | Deployment | Deployment | Tu operador | [abajo](#kubernetes) | Todavía no |

Sea cual sea el destino, importan los mismos cuatro valores:

```bash
TAMANDUA_DATABASE_URL=postgresql://usuario:contraseña@host:5432/tamandua   # valen postgres:// y postgresql://
TAMANDUA_MASTER_KEY=<openssl rand -base64 32>                               # la misma en la API y en cada worker
TAMANDUA_PUBLIC_URL=https://tamandua.example.com
TAMANDUA_ALLOWED_ORIGINS=https://tamandua.example.com                       # cada dirección con la que se abre
```

La clave maestra descifra todos los secretos guardados: GitHub App, claves de IA, Jira, canales de avisos, semillas
TOTP y la clave de firma de sesiones. Guárdala en el gestor de secretos de la plataforma, con una copia fuera de las
copias de la base. `tamandua check-config` revisa toda la configuración y dice qué está mal.

## Un solo archivo: cualquier servidor o panel de Docker

[`deploy/compose.yaml`](../../deploy/compose.yaml) no necesita nada más: imágenes publicadas, volúmenes con nombre, sin
construir, sin el repositorio y sin el socket de Docker (el worker ejecuta los motores dentro de su propia imagen).

```bash
curl -fsSLO https://raw.githubusercontent.com/Tamandua-AppSec/tamandua/main/deploy/compose.yaml
printf 'TAMANDUA_DB_PASSWORD=%s\nTAMANDUA_MASTER_KEY=%s\nTAMANDUA_PUBLIC_URL=%s\n' \
  "$(openssl rand -hex 24)" "$(openssl rand -base64 32)" "https://tamandua.example.com" > .env
docker compose --profile https up -d        # --profile https: Caddy obtiene el certificado (sin él, detrás de tu proxy)
docker compose exec api python -m tamandua setup-code
```

- **Coolify y Dokploy:** crea un recurso *Docker Compose*, pega el archivo, define las tres variables en la pantalla de
  entorno y apunta tu dominio al servicio `api`, puerto 8766. Deja apagado el perfil `https`: el proxy de la plataforma
  se encarga del TLS.
- **Hostinger:** en el panel del VPS, abre el gestor de Docker, crea un proyecto desde Compose y pega el archivo y las
  variables. Si no hay otro proxy en el servidor, añade `COMPOSE_PROFILES=https`.
- **Portainer:** *Stacks → Add stack*, pega el archivo y añade las variables.
- **Copias de seguridad:** `--profile backup` guarda copias con `pg_dump` en `./backups` cada 24 h (cámbialo con
  `TAMANDUA_BACKUP_INTERVAL_HOURS`). La clave maestra no va en ellas: guárdala aparte.

Dimensionado: con 2 vCPU y 4 GB de memoria corre un análisis a la vez; con 8 GB va holgado. La imagen del worker ocupa
unos 1,8 GB.

## Render

[`render.yaml`](../../render.yaml) es un Blueprint con la API (web service), el worker (background worker) y
PostgreSQL. *New → Blueprint*, elige el repositorio y escribe `TAMANDUA_PUBLIC_URL` cuando te lo pida
(`https://<servicio>.onrender.com` o tu dominio). Render genera la clave maestra (32 bytes aleatorios en base64, justo
su formato) y la comparte con el worker. Léela una vez del entorno de la API y guarda una copia.

## Railway, Fly.io y otras plataformas de contenedores

Dos servicios con las imágenes publicadas, más el PostgreSQL de la plataforma:

| Servicio | Imagen | Variables, además de las cuatro de arriba |
| --- | --- | --- |
| api | `ghcr.io/tamandua-appsec/tamandua:<versión>` | `TAMANDUA_BIND=0.0.0.0`, `TAMANDUA_EMBEDDED_WORKER=0`, `TAMANDUA_FORWARDED_ALLOW_IPS=*`, puerto 8766 |
| worker | `ghcr.io/tamandua-appsec/tamandua-worker:<versión>` | ninguna |

En Railway, referencia la base como `TAMANDUA_DATABASE_URL=${{Postgres.DATABASE_URL}}`. Dale al worker al menos 2 GB de
memoria. Sus cachés (las bases de datos de los motores) pueden ir en disco efímero: se vuelven a descargar tras un
redespliegue.

## Vercel

Vercel ejecuta la **API y el panel** como una función de Python ([`vercel.json`](../../vercel.json), entrada
`api/index.py`, que importa `tamandua.app.asgi`). El worker no cabe ahí: un análisis puede durar más de lo que dura una
función, y no hay proceso permanente. Ejecuta el worker en cualquier otra fila de la tabla, contra la misma base y con
la misma clave maestra.

1. Crea una base PostgreSQL (Neon, Supabase u otra) a la que lleguen los dos.
2. Importa el repositorio en Vercel y define las cuatro variables. En `TAMANDUA_ALLOWED_ORIGINS` pon cada dirección con
   la que lo abras: el dominio de producción, y las URL de vista previa si las usas.
3. Arranca el worker en otro sitio con los mismos `TAMANDUA_DATABASE_URL` y `TAMANDUA_MASTER_KEY`.
4. El código de configuración aparece en los registros de la función con la primera petición; `tamandua setup-code`,
   ejecutado en cualquier sitio con las mismas variables, también lo muestra.

Si el worker no puede estar siempre encendido (escala a cero), define `TAMANDUA_PERIODIC=external` en los dos y deja que
un programador dispare las tareas periódicas: añade `"crons": [{"path": "/api/cron", "schedule": "*/5 * * * *"}]` a
`vercel.json` y un `CRON_SECRET` de al menos 32 caracteres (Vercel lo envía como token bearer). El plan Hobby de Vercel
solo permite una ejecución al día.

## Kubernetes

Todavía no hay manifiestos. Las piezas encajan directamente: un Deployment para la API (puerto 8766, `/api/health` como
sonda), otro para la imagen del worker (no necesita el socket de Docker), las cuatro variables desde un Secret y el
PostgreSQL que prefieras. Con `TAMANDUA_PERIODIC=external`, un CronJob que ejecute `python -m tamandua periodic`
sustituye al reloj del worker líder.

## Tareas periódicas

Entregar los avisos, sondear los pull requests, sincronizar NVD y revisar a diario si hay avisos nuevos van con reloj:

- `TAMANDUA_PERIODIC=leader` (por defecto): las ejecuta un worker, elegido con un cerrojo de PostgreSQL. No hay nada que
  configurar.
- `TAMANDUA_PERIODIC=external`: nada se ejecuta solo. Un programador llama a `tamandua periodic` (cron, un CronJob) o a
  `GET /api/cron` con `Authorization: Bearer <TAMANDUA_CRON_TOKEN o CRON_SECRET>`. Cada llamada ejecuta lo que toca; la
  API encola para un worker la sincronización de NVD y la revisión de avisos, porque necesitan los motores o tardan.
