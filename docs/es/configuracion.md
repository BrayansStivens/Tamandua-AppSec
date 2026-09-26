[English](../configuration.md) · Español

# Configuración

Todas las variables son opcionales y se ponen en `.env` (copia de `.env.example`). Tras cambiarlas: `docker compose up -d`.


| Variable | Por defecto | Para qué |
| --- | --- | --- |
| `TAMANDUA_HOST_BIND` / `TAMANDUA_HOST_PORT` | `127.0.0.1` / `8766` | Dónde se publica el panel en el host. |
| `TAMANDUA_PUBLIC_URL` | `http://127.0.0.1:8766` | URL con la que se abre el panel; decide cookies `Secure`, HSTS y la Setup URL de la App. |
| `TAMANDUA_ALLOWED_ORIGINS` | 127.0.0.1 y localhost | Orígenes aceptados (Host y CSRF). |
| `TAMANDUA_DEFAULT_LOCALE` | `en` | `en` o `es`. Idioma de los comentarios en PRs, los avisos, las incidencias de Jira, los informes y la salida de la CLI cuando nadie pide uno en persona. El panel no lo usa: sigue el idioma del navegador y cada persona puede cambiarlo desde la barra lateral o la pantalla de inicio de sesión. |
| `TAMANDUA_MASTER_KEY` | se genera en `config/` | Clave maestra del almacén (`openssl rand -base64 32`). |
| `TAMANDUA_REQUIRE_TOTP` | `admins` | `admins`, `all` o `none`. |
| `TAMANDUA_NVD_API_KEY` | — | API key de NVD: descarga de CVE más rápida. Va en cabecera y nunca se registra. |
| `TAMANDUA_DB_PASSWORD` | (generada) | Contraseña de PostgreSQL; `make setup` la crea en `.env`. |
| `TAMANDUA_DATABASE_URL` | (compose) | Conexión a PostgreSQL. `compose.yaml` la arma con la contraseña; fuera de compose, p. ej. `postgresql+psycopg://tamandua:…@localhost:5432/tamandua`. |
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
| `TAMANDUA_HOST_CONFIG_DIR` | `./config` | Carpeta del host con los secretos cifrados. |

**Concesión consciente:** para no instalar nada más que Docker, la app lanza los motores como contenedores hermanos por el socket de Docker, y eso equivale a root en el host. Si vas a abrir el panel a más gente, ponlo detrás de un socket-proxy o de un runner aparte.

