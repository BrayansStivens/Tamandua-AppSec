# Configuración

Todas las variables son opcionales y se ponen en `.env` (copia de `.env.example`). Tras cambiarlas: `docker compose up -d`.


| Variable | Por defecto | Para qué |
| --- | --- | --- |
| `APPSEC_BIND` / `APPSEC_PORT` | `127.0.0.1` / `8766` | Dónde se publica el panel en el host. |
| `APPSEC_AGENT_PUBLIC_URL` | `http://127.0.0.1:8766` | URL con la que se abre el panel; decide cookies `Secure`, HSTS y la Setup URL de la App. |
| `APPSEC_AGENT_ALLOWED_ORIGINS` | 127.0.0.1 y localhost | Orígenes aceptados (Host y CSRF). |
| `APPSEC_AGENT_MASTER_KEY` | se genera en `config/` | Clave maestra del almacén (`openssl rand -base64 32`). |
| `APPSEC_AGENT_REQUIRE_TOTP` | `admins` | `admins`, `all` o `none`. |
| `APPSEC_AGENT_NVD_API_KEY` | — | API key de NVD: descarga de CVE más rápida. Va en cabecera y nunca se registra. |
| `APPSEC_AGENT_CVE_SYNC` | `on` | `off` desactiva la copia local de NVD. |
| `APPSEC_AGENT_EUVD` | `on` | `off` no consulta EUVD (ENISA) cuando NVD no puntúa un CVE. Solo sale el identificador del CVE. |
| `APPSEC_AGENT_PR_POLL_SECONDS` | `300` | Cada cuánto se consultan los PRs vigilados. |
| `APPSEC_AGENT_BRANCH_MIN_MINUTES` | `60` | Pausa mínima entre dos reanálisis automáticos de la rama principal de un mismo repositorio (mínimo 10). |
| `APPSEC_AGENT_ADVISORY_WATCH_HOURS` | `24` | Cada cuántas horas se contrastan las dependencias ya analizadas con los avisos nuevos (sin conexión). `0` lo apaga. |
| `APPSEC_AGENT_ALLOW_PRIVATE_WEBHOOKS` | vacío | `1` permite avisos a webhooks de la red interna (por defecto se bloquean: SSRF). |
| `APPSEC_AGENT_ALLOW_PRIVATE_REGISTRIES` | — | `1` permite analizar imágenes de registros con IP privada (tu red interna). Por defecto se bloquean para evitar SSRF. |
| `APPSEC_AGENT_TLS_CERT` / `_KEY` | — | TLS sin proxy. |
| `GITHUB_APP_ID` + `GITHUB_APP_SLUG` + `GITHUB_APP_PRIVATE_KEY_FILE` | — | Alternativa al formulario: montar la App como secreto del despliegue. Manda sobre el almacén. |
| `APPSEC_CONFIG_DIR` | `./config` | Carpeta del host con los secretos cifrados. |

**Concesión consciente:** para no instalar nada más que Docker, la app lanza los motores como contenedores hermanos por el socket de Docker, y eso equivale a root en el host. Si vas a abrir el panel a más gente, ponlo detrás de un socket-proxy o de un runner aparte.

