[English](../configuration.md) · Español

# Configuración

Todas las variables son opcionales y se ponen en `.env` (copia de `.env.example`). Tras cambiarlas: `docker compose up -d`. `python -m tamandua check-config` (o `make cli ARGS=check-config`) las revisa todas; el servidor y el worker lo hacen al arrancar y se detienen con un mensaje claro si alguna no es válida. En otras plataformas, mira [despliegue.md](despliegue.md).


| Variable | Por defecto | Para qué |
| --- | --- | --- |
| `TAMANDUA_HOST_BIND` / `TAMANDUA_HOST_PORT` | `127.0.0.1` / `8766` | Dónde se publica el panel en el host. |
| `TAMANDUA_PUBLIC_URL` | `http://127.0.0.1:8766` | URL con la que se abre el panel; decide cookies `Secure`, HSTS y la Setup URL de la App. |
| `TAMANDUA_ALLOWED_ORIGINS` | 127.0.0.1 y localhost | Orígenes aceptados (Host y CSRF). |
| `TAMANDUA_DEFAULT_LOCALE` | `en` | `en` o `es`. Idioma de los comentarios en PRs, los avisos, las incidencias de Jira, los informes y la salida de la CLI cuando nadie pide uno en persona. El panel no lo usa: sigue el idioma del navegador y cada persona puede cambiarlo desde la barra lateral o la pantalla de inicio de sesión. |
| `TAMANDUA_MASTER_KEY` | se genera en `config/` | Clave maestra (`openssl rand -base64 32`): cifra todos los secretos de la base. Obligatoria donde no hay disco persistente; la misma en la API y en cada worker. |
| `TAMANDUA_SESSION_KEY` | se genera, sellada en la base | Clave que firma las cookies de sesión (32 bytes en base64). Solo para fijarla desde un gestor de secretos. |
| `TAMANDUA_REQUIRE_TOTP` | `admins` | `admins`, `all` o `none`. |
| `TAMANDUA_NVD_API_KEY` | — | API key de NVD: descarga de CVE más rápida. Va en cabecera y nunca se registra. |
| `TAMANDUA_DB_PASSWORD` | (generada) | Contraseña de PostgreSQL; `make setup` la crea en `.env`. |
| `TAMANDUA_DATABASE_URL` | (compose) | Conexión a PostgreSQL. `compose.yaml` la arma con la contraseña; fuera de compose, p. ej. `postgresql://tamandua:…@localhost:5432/tamandua` (las URL `postgres://` que dan las bases gestionadas valen tal cual). |
| `TAMANDUA_EMBEDDED_WORKER` | `1` | `1`: el servidor también ejecuta los análisis (un solo proceso). En compose el API usa `0` y el servicio `worker` los ejecuta. |
| `TAMANDUA_CVE_SYNC` | `on` | `off` desactiva la copia local de NVD. |
| `TAMANDUA_EUVD` | `on` | `off` no consulta EUVD (ENISA) cuando NVD no puntúa un CVE. Solo sale el identificador del CVE. |
| `TAMANDUA_PR_POLL_SECONDS` | `300` | Cada cuánto se consultan los PRs vigilados. |
| `TAMANDUA_BRANCH_MIN_MINUTES` | `60` | Pausa mínima entre dos reanálisis automáticos de la rama principal de un mismo repositorio (mínimo 10). |
| `TAMANDUA_ADVISORY_WATCH_HOURS` | `24` | Cada cuántas horas se contrastan las dependencias ya analizadas con los avisos nuevos (sin conexión). `0` lo apaga. |
| `TAMANDUA_ALLOW_PRIVATE_WEBHOOKS` | vacío | `1` permite avisos a webhooks de la red interna (por defecto se bloquean: SSRF). |
| `TAMANDUA_ALLOW_PRIVATE_REGISTRIES` | — | `1` permite analizar imágenes de registros con IP privada (tu red interna). Por defecto se bloquean para evitar SSRF. |
| `TAMANDUA_TLS_CERT` / `_KEY` | — | TLS sin proxy. |
| `GITHUB_APP_ID` + `GITHUB_APP_SLUG` + `GITHUB_APP_PRIVATE_KEY_FILE` | — | Alternativa al formulario: montar la App como secreto del despliegue. Manda sobre el almacén. |
| `TAMANDUA_HOST_CONFIG_DIR` | `./config` | Carpeta del host para la clave maestra, cuando no se define `TAMANDUA_MASTER_KEY`. |
| `TAMANDUA_FORWARDED_ALLOW_IPS` | vacío | Detrás de un proxy inverso que sea el único camino hasta la API: las direcciones del proxy cuyo `X-Forwarded-For` se cree (`*` = cualquiera). Sin ella, el límite de intentos de inicio de sesión y los logs ven la dirección del proxy para todo el mundo. `compose.prod.yaml` la pone para Caddy. |
| `TAMANDUA_ENGINE_RUNNER` | `auto` | `docker`: cada motor en un contenedor hermano a través del socket de Docker. `local`: los motores instalados en la imagen del worker (`tamandua-worker`), sin socket. `auto`: Docker si responde; si no, los motores instalados. |
| `TAMANDUA_PERIODIC` | `leader` | `leader`: un worker ejecuta las tareas periódicas con su propio reloj. `external`: las dispara un programador con `tamandua periodic` o `GET /api/cron` ([despliegue.md](despliegue.md#tareas-periódicas)). |
| `TAMANDUA_CRON_TOKEN` / `CRON_SECRET` | vacío (apagado) | Token bearer para `GET /api/cron`, solo con `TAMANDUA_PERIODIC=external`. Mínimo 32 caracteres. `CRON_SECRET` es el que envía Vercel Cron. |
| `TAMANDUA_LOG_FORMAT` | `text` | `json`: un objeto JSON por línea en la salida del proceso. |
| `TAMANDUA_LOG_FILE` | vacío (Compose: `logs/app.log`) | Escribe además los registros en JSON en este archivo, rotado a 10 MB × 5; una ruta relativa va dentro de la carpeta de datos. |
| `TAMANDUA_METRICS_TOKEN` | vacío (apagado) | Activa `/api/metrics` (Prometheus) para peticiones con `Authorization: Bearer <token>`. Mínimo 32 caracteres: `openssl rand -hex 32`. |

**Servidor con dominio** ([despliegue-vps.md](despliegue-vps.md)). Las lee Compose, no la app; `make setup DOMAIN=… [PREBUILT=1]` las escribe.

| Variable | Por defecto | Para qué |
| --- | --- | --- |
| `TAMANDUA_DOMAIN` | — | Dominio para el que Caddy pide el certificado (`compose.prod.yaml`). La URL pública y los orígenes permitidos pasan a ser `https://<dominio>`. |
| `COMPOSE_FILE` | `compose.yaml` | Ficheros de Compose que usan todos los comandos, p. ej. `compose.yaml:compose.prod.yaml:compose.images.yaml`. |
| `TAMANDUA_IMAGE` | — | Imagen publicada que se ejecuta en lugar de construirla (`compose.images.yaml`), p. ej. `ghcr.io/brayansstivens/tamandua`. |
| `TAMANDUA_IMAGE_TAG` | la versión del código | Etiqueta de esa imagen; admite digest (`0.9@sha256:…`). |
| `COMPOSE_PROFILES` | — | `backup` activa el servicio de copias programadas. |
| `TAMANDUA_BACKUP_DIR` | `./backups` | Dónde escribe el servicio de copias. |
| `TAMANDUA_BACKUP_INTERVAL_HOURS` / `_KEEP_DAYS` | `24` / `14` | Cada cuánto copia y cuántos días guarda sus propias copias. |

**Concesión consciente:** con el `compose.yaml` del repositorio, para no instalar nada más que Docker, el worker lanza los motores como contenedores hermanos por el socket de Docker, y eso equivale a root en el host. [`deploy/compose.yaml`](../../deploy/compose.yaml) usa en cambio la imagen del worker con los motores dentro: sin socket.

