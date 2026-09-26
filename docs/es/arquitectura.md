[English](../architecture.md) · Español

# Arquitectura

Tamandua son tres servicios: el **API** (FastAPI, sirve también el panel), uno o varios **workers** que ejecutan los
análisis de la cola y las tareas periódicas, y **PostgreSQL**, donde vive todo el estado. Los motores de análisis corren
como contenedores hermanos efímeros lanzados por el worker, con el código montado en solo lectura, sin capacidades y
con límites de memoria, CPU y procesos. El API no tiene acceso a Docker.

```mermaid
flowchart LR
  browser["Navegador<br/>panel React"] -- "HTTPS o loopback<br/>cookie HttpOnly + CSRF" --> api

  subgraph host["Tu máquina (Docker)"]
    api["tamandua<br/>API · panel"]
    worker["worker<br/>cola · tareas periódicas"]
    db[("PostgreSQL<br/>ejecuciones · hallazgos · configuración")]
    api --- db
    worker --- db
    worker -- "socket de Docker" --> engines
    subgraph engines["Motores efímeros (solo lectura, sin capacidades)"]
      trivy["Trivy<br/>SCA · IaC · secretos"]
      gitleaks["Gitleaks<br/>secretos"]
      opengrep["Opengrep<br/>SAST, 58 reglas propias"]
      checkov["Checkov<br/>IaC · pipelines"]
      zizmor["zizmor<br/>GitHub Actions"]
    end
    config[("config/<br/>secretos cifrados")]
    api --- config
    worker --- config
  end

  worker -- "JWT de la App / token de instalación 1 h" --> github["api.github.com"]
  worker -- "rangos de fechas" --> nvd["NVD"]
  worker -- "feeds públicos" --> feeds["CISA KEV · EPSS"]
```

## Estructura del código

Monolito modular (`tamandua/`), con capas que comprueba import-linter en cada PR (`make arch`, ver `pyproject.toml`):

```
tamandua/
  cli/          línea de comandos (scan para CI, demo, usuarios…)
  app/          composición: API (api/: rutas tipadas por contexto y rutas de tabla en api/routes/), worker,
                migraciones (Alembic y de datos), datos de demostración, estáticos del panel
  modules/      el negocio, un paquete por contexto; no importa de app/ ni de cli/
    identity/       usuarios, sesiones, TOTP
    sources/        repositorios, activos (identidad estable), dominios
    scanning/       motores (engines, config_engines), plan, inventario, análisis de repositorio, imagen y local, OWASP
    runs/           ejecuciones, cola de análisis y lotes
    findings/       registro y ciclo de vida, triage, exclusiones, guía de corrección, reverificación, plazos (SLA)
    intel/          avisos, KEV/EPSS, copia local de NVD, EUVD, fuentes y licencias
    compliance/     SBOM, VEX, kit CRA
    reporting/      informes PDF/Markdown, diseño común, Resumen
    integrations/   GitHub App, Jira, avisos (Slack/Teams/webhook), claves de IA
    pullrequests/   revisión de PR y vigilancia
    threats/        modelado de amenazas, diagrama e informe
  shared/       transversal sin negocio: logs, almacén cifrado, rutas, i18n (catálogos en/es); no importa de modules/
```

El panel (`web/src`) sigue la misma idea, por funcionalidad (Feature-Sliced Design ligero), con capas que comprueba
`tests/test_web_layers.py`: una capa no importa de las de arriba.

```
web/src/
  app/        composición: App (navegación), proveedores (TanStack Query)
  pages/      una pantalla por vista (Resumen, Hallazgos, CVE tracker, Cumplimiento…)
  features/   auth, onboarding, analyses, sources, findings, integrations, threats
  shared/     ui (Base UI + Tailwind), charts, api (cliente, tipos generados del OpenAPI, consultas), i18n, lib
```

Los datos del servidor van con TanStack Query (`shared/api/queries.ts`): caché compartida entre vistas y sondeo solo
mientras hay algo en marcha. Los tipos de las rutas migradas salen del OpenAPI (`make openapi`).

La seguridad de la API está en un solo sitio (`app/api/security.py`): host permitido → CSRF (Origin + cabecera de
acción) → sesión → segundo factor → rol → tamaño del cuerpo. La aplican igual las rutas tipadas (`deps.guard`) y las de
tabla (`routing.mount`). Los manejadores no leen cabeceras ni cookies por su cuenta; un error no controlado responde
500 sin traza.
El panel React + TypeScript (`web/`) se compila a `tamandua/app/static/`.

Servicios (compose): `api` (panel y API con FastAPI, sin acceso a Docker), `worker` (ejecuta los análisis de la
cola y las tareas periódicas; el único con el socket de Docker; se puede escalar y las tareas periódicas solo las corre el
líder, elegido con un cerrojo de PostgreSQL), `postgres` y `opengrep` (solo construye la imagen del motor). La cola
(`jobs`) y el buzón de avisos (`outbox`, con reintentos) viven en PostgreSQL: un reinicio no pierde lo encolado.

## Flujo de un análisis

1. Pulsas **Analizar** o se abre un PR en un repositorio vigilado.
2. La API encola el trabajo y responde al momento; el panel muestra el progreso en vivo.
3. El trabajador pide a GitHub un token de instalación de una hora (en memoria) y descarga una instantánea del repositorio en `data/work/`.
4. Se calcula el plan (lenguajes, reglas aplicables, manifiestos, IaC) y se lanzan los motores uno a uno: instantánea en solo lectura, `--cap-drop ALL`, `no-new-privileges`, 3 GB de memoria, 2 CPU y 512 procesos como máximo. Gitleaks, Opengrep, Checkov y zizmor van **sin red**; Trivy la necesita para descargar su base de vulnerabilidades (cacheada en `data/trivy-cache/`) y no envía nada del repositorio.
5. Los resultados se normalizan, se deduplican por huella estable, se enriquecen con KEV/EPSS y se incorporan al registro del repositorio: lo que ya no aparece queda **remediado**.
6. Si era un PR, se publica un comentario único y un estado de commit según el umbral configurado.
7. La instantánea se borra.

## Datos en disco

```
PostgreSQL (volumen tamandua-pg; esquema con migraciones de Alembic en tamandua/app/alembic)
  runs                ejecuciones: fila de listado, registro completo, informe y SARIF (JSONB + columnas para filtrar)
  registry_*          registro de hallazgos por activo (estado, CVE con índice GIN) e idempotencia por ejecución
  triage_decisions    decisiones de triage con su historial
  users, sessions, auth_challenges   identidad: usuarios (scrypt, TOTP cifrado), sesiones y retos de 2FA (solo hashes)
  documents           configuración por documento JSONB: plazos, exclusiones, integraciones, dominios, lotes,
                      modelos de amenazas, vigilancia de PRs y de avisos, enlaces con Jira, kit CRA…
  jobs, workers, outbox   cola de análisis, latido de los workers y buzón de avisos con reintentos
data/
  auth/session.key  clave de firma de cookies (no va a la base: quien lee la base no puede firmar sesiones)
  feeds/            KEV, EPSS, NVD (cves.sqlite; caché regenerable)
  trivy-cache/      base de vulnerabilidades de Trivy
  logs/app.log      JSON por línea, rotado (10 MB × 5), sin secretos
  data-version.json versión de las migraciones de datos aplicadas
  backups/          copia de lo que tocó cada migración de datos (se guardan las 5 últimas)
config/
  secrets.vault     secretos cifrados
  master.key        clave maestra (si no viene del entorno)
```

**Actualizar sin romper los datos.** El esquema de la base lo llevan las migraciones de Alembic
(`tamandua/app/alembic/versions/`), que se aplican al arrancar. Para datos que haya que reescribir,
`tamandua/app/data_migrations.py` compara la versión
guardada en `data-version.json` con la del código y aplica, en orden y una sola vez, las migraciones pendientes,
tras copiar a `data/backups/` solo lo que van a tocar. Cada paso guarda su versión: si uno falla, el siguiente
arranque reanuda desde ahí. Una instalación nueva nace en la última versión; unos datos de una versión más nueva
que el código (volver a una versión anterior) impiden arrancar en vez de arriesgarse a estropearlos.

## Decisiones de diseño

- **Pocas dependencias y fijadas.** FastAPI, uvicorn, Pydantic, SQLAlchemy (Core), psycopg y Alembic, con versión
  exacta: poca superficie de ataque y actualizaciones de seguridad fáciles de seguir.
- **Sondeo en vez de webhooks.** El servidor no necesita ser accesible desde internet.
- **Una GitHub App por workspace**, con cuatro permisos. Para varias organizaciones, GitHub exige que pueda instalarse en cualquier cuenta; el administrador escoge explícitamente cuáles conectar al workspace. Una clave filtrada tendría acceso a todas las instalaciones de esa App, por lo que su custodia sigue siendo crítica.
- **Honestidad en los resultados.** Lo que no se pudo probar sale como `not_tested` con su motivo; un análisis incompleto nunca se presenta como «cero vulnerabilidades».
- **Lo guardado no tiene idioma; se muestra en el de quien lee.** Todo texto que lee una persona existe en inglés
  (origen y respaldo) y en español, en catálogos (`tamandua/shared/i18n/locales/` y `web/src/shared/i18n/locales/`).
  Lo que se guarda (hallazgos, progreso, limitaciones, errores) es un código de mensaje con sus parámetros, que se
  muestra al leerlo en el idioma de quien lo lee: la API lo hace por petición, y los informes, comentarios de PR,
  avisos, Jira y la CLI con un idioma explícito (`TAMANDUA_DEFAULT_LOCALE`, `en` por defecto). Un mismo hallazgo se
  lee con naturalidad en los dos idiomas, y cambiar de idioma nunca reescribe datos. El texto de terceros (avisos,
  nombres de comprobaciones de los motores) se muestra tal como se publicó, sin traducción automática.

## Pendiente (aplazado a propósito)

Primero la edición community bien hecha. Queda preparado, pero sin construir:

- **Multiinquilino real.** Cada tabla ya lleva `tenant_id` (hoy siempre `default`); falta Row Level Security en
  PostgreSQL y el concepto de organización.
- **Observabilidad.** Trazas y métricas con OpenTelemetry (hoy: log JSON estructurado y latido de los workers).
- **SSO (OIDC/SAML) y cuotas por consumo.** Son de la edición gestionada y viven fuera de este repositorio.
