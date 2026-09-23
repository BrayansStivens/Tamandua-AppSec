# AppSec Agent

Seguridad de aplicaciones **autoalojada** para personas y equipos pequeños. Conectas tus repositorios de GitHub y AppSec Agent los analiza, comenta en tus pull requests lo que introducen y lleva el estado de cada hallazgo hasta que se corrige. Todo corre en tu máquina, con tus credenciales: tu código no va a ningún servicio nuestro.

> Estado: **beta (v0.9)**. Funcional y con pruebas, pero la API y los formatos de `data/` aún pueden cambiar entre versiones.

## Qué hace

- **Análisis de código** con Trivy (dependencias, IaC, secretos), Gitleaks (secretos) y Opengrep con 58 reglas SAST propias en JavaScript/TypeScript, Python, Java, Go, PHP, Ruby y C#. El código nunca se ejecuta.
- **Imágenes de contenedor** desde su registro (Docker Hub, GHCR, ECR…), sin ejecutarlas: paquetes con **Trivy + Grype**, secretos en capas, en `ENV` y en el historial de construcción, y configuración (root, `HEALTHCHECK`, `ADD` remoto).
- **Priorización real**: cada aviso de dependencia se cruza con CISA KEV (explotación activa) y EPSS (probabilidad de explotación), con la versión exacta que lo corrige.
- **Revisión de pull requests**: solo cuenta lo que el PR introduce; publica un comentario y un estado de commit que puede bloquear el merge según el umbral que elijas.
- **Ciclo de vida de hallazgos** por repositorio: remediación automática cuando un escaneo o un commit del PR ya no lo encuentra, triage con motivo e historial.
- **CVE tracker**: copia local completa de NVD con buscador, filtros por severidad/año/KEV y «¿te afecta?».
- **Modelado de amenazas** STRIDE propuesto a partir de tus repositorios, con las amenazas evidenciadas por hallazgos reales.
- **Informes** JSON, Markdown y SARIF; exportación a **Jira** sin duplicados.
- **Equipo**: invitaciones, roles y segundo factor (TOTP).

## Inicio rápido

Necesitas **Docker** (Engine 24+ con Compose v2.24+), **make** y **git**, 4 GB de memoria y 8 GB de disco libres. `make doctor` comprueba todo; detalles en [docs/instalacion.md](docs/instalacion.md).

```bash
git clone https://github.com/BrayansStivens/appsec-agent.git
cd appsec-agent
make up
```

`make up` crea tu `.env`, construye las imágenes, arranca y te muestra la URL y el **código de configuración**. `make help` lista el resto (logs, copias de seguridad, actualizar…); están todos en [docs/contenedores.md](docs/contenedores.md).

Abre <http://127.0.0.1:8766> y:

1. **Crea el administrador** con el código que imprimió el servidor. Solo sirve una vez: así nadie más que quien controla el servidor puede reclamar la instancia. Después activa el segundo factor.
2. **Crea tu GitHub App** en *Integraciones*: el panel te guía paso a paso con los permisos exactos y al final pegas el App ID y subes la clave `.pem`. También en [docs/github-app.md](docs/github-app.md).
3. **Instálala** en los repositorios que quieras (*Only select repositories*) y lanza el primer análisis desde *Repositorios*.

## Documentación

| | |
| --- | --- |
| [Instalación](docs/instalacion.md) | Requisitos, primer arranque, actualizar, copias de seguridad, desinstalar |
| [Conectar GitHub](docs/github-app.md) | Crear la GitHub App paso a paso y revisar PRs |
| [Contenedores y Makefile](docs/contenedores.md) | Comandos `make`, imágenes y endurecimiento |
| [Configuración](docs/configuracion.md) | Variables de `.env` |
| [Seguridad](docs/seguridad.md) | Secretos, transporte, qué sale de tu máquina y concesiones |
| [Funcionalidades](docs/funcionalidades.md) | Qué hace cada parte y con qué criterio |
| [Arquitectura](docs/arquitectura.md) | Componentes, flujo de un análisis y datos en disco |
| [Solución de problemas](docs/solucion-problemas.md) | Errores frecuentes |
| [Desarrollo](docs/desarrollo.md) | Sin contenedores, CLI y pruebas |

## Seguridad, en corto

- Secretos (clave de la GitHub App, claves de IA, token de Jira) **cifrados con AES-256-GCM** en `config/`, separado de `data/`. Nunca vuelven al navegador ni aparecen en los logs.
- GitHub App **privada** con solo cuatro permisos (`contents: read`, `metadata: read`, `pull_requests: write`, `statuses: write`), sin webhooks ni OAuth; tokens de una hora en memoria.
- Panel en `127.0.0.1` por defecto. Si lo publicas fuera de tu máquina sin **HTTPS**, el servidor no arranca.
- Credenciales de registros privados cifradas y pasadas a los motores por variable de entorno; los registros de red interna se bloquean salvo permiso expreso.
- Sin telemetría. Solo se consulta OSV con los nombres de tus dependencias si lo autorizas en cada análisis.
- **Concesión:** la app lanza los motores por el socket de Docker, lo que equivale a root en el host. Expón el panel solo a gente de confianza.

Para reportar una vulnerabilidad: [SECURITY.md](SECURITY.md).

## Usarlo desde otra máquina (HTTPS)

Pon [Caddy](https://caddyserver.com) delante (obtiene y renueva el certificado solo):

```caddyfile
appsec.tu-dominio.com {
    reverse_proxy 127.0.0.1:8766
}
```

y en `.env`:

```bash
APPSEC_AGENT_PUBLIC_URL=https://appsec.tu-dominio.com
APPSEC_AGENT_ALLOWED_ORIGINS=https://appsec.tu-dominio.com
```

## Contribuir

Issues y PRs son bienvenidos: lee [CONTRIBUTING.md](CONTRIBUTING.md). En el primer PR se firma el [CLA](CLA.md) con un comentario. Las reglas SAST propias están en `rules/`.

## Licencia

AppSec Agent es software libre bajo la [GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0-only): puedes usarlo, estudiarlo, modificarlo y redistribuirlo. Si ofreces una versión modificada a otras personas a través de la red, tienes que poner a su disposición el código fuente de esa versión con la misma licencia.

Las reglas SAST de [`rules/`](rules/) tienen su propia licencia MIT, para que puedas reutilizarlas en otras herramientas.

Copyright © 2026 BrayansStivens y colaboradores de AppSec Agent.
