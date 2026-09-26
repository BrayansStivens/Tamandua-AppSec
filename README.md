<p align="center"><img src="docs/assets/tamandua.svg" width="112" alt="Tamandua, un oso hormiguero de collar atrapando un bug con la lengua"></p>

<h1 align="center">Tamandua</h1>

<p align="center"><strong>Se come tus bugs.</strong> Seguridad de aplicaciones autoalojada, libre y sin enviar tu código a nadie.</p>

Tamandua analiza tus repositorios e imágenes de contenedor, te dice **qué corregir primero y cómo** (el comando exacto o un ejemplo de código), comprueba que quedó corregido y **vigila solo** lo que cambia después. Todo corre en tu máquina, con tus credenciales: tu código no va a ningún servicio nuestro.

> Estado: **beta (v0.9)**. Funcional y con pruebas, pero la API y los formatos de `data/` aún pueden cambiar entre versiones.

## Por qué Tamandua

- **Autoalojado y libre (AGPL-3.0).** El código, las dependencias y los hallazgos se quedan en tu servidor.
- **Un solo sitio para todo:** código (SAST), dependencias, secretos, infraestructura como código, pipelines e imágenes, con siete motores abiertos y sin duplicados entre ellos.
- **Del hallazgo a la corrección verificada:** prioridad real (CISA KEV y EPSS), comando de corrección por gestor de paquetes, botón «Reverificar» y remediación automática cuando deja de aparecer.
- **En español y pensado para equipos pequeños**, con evidencia lista para auditorías SOC 2 e ISO 27001 y modelado de amenazas conectado a los hallazgos reales.

## Qué hace

| | |
| --- | --- |
| **Encontrar** | Opengrep con 58 reglas propias (JS/TS, Python, Java, Go, PHP, Ruby, C#), Gitleaks, Trivy y OSV-Scanner para dependencias, Checkov y zizmor para IaC y GitHub Actions, Trivy + Grype para imágenes. El código nunca se ejecuta. Uno o varios repositorios, una organización entera o varias imágenes a la vez. |
| **Priorizar** | Cada aviso cruzado con CISA KEV (explotación activa) y EPSS (probabilidad de explotación); las dependencias agrupadas por paquete con la versión que cierra todos sus avisos. |
| **Corregir** | En cada hallazgo, cómo corregirlo: el comando de tu gestor (npm, pip, Poetry, Go, Cargo, Maven…), el override si es transitiva, un ejemplo antes/después para el código o los pasos para rotar un secreto. Exportación a Jira sin duplicados. |
| **Verificar** | «Reverificar» vuelve a analizar y te dice «Corregido ✓» o «Sigue presente». En los pull requests solo cuenta lo que el PR introduce, con comentario y estado que puede bloquear el merge. |
| **Vigilar** | Reanálisis automático cuando cambia la rama principal, avisos nuevos a diario contra tus dependencias (sin conexión) y mensajes a **Slack, Teams o un webhook** cuando aparece algo que importa. |
| **Demostrar** | Informes PDF técnicos y de evidencia (SOC 2 Tipo II, ISO/IEC 27001:2022, consolidado de organización), SARIF, JSON y Markdown; modelado de amenazas (STRIDE, LINDDUN, PASTA, árboles, ATT&CK) con diagrama; CVE tracker local de NVD. |

**En desarrollo** (en gris en el panel): pruebas dinámicas (DAST), GitLab/Bitbucket/Azure DevOps (hoy se cubren con [`scan` en CI](docs/cli.md)) y asistencia con IA opcional.

## Pruébalo en 5 minutos

Necesitas **Docker** (Engine 24+ con Compose v2.24+), **make** y **git**, 4 GB de memoria y 8 GB de disco. `make doctor` lo comprueba.

```bash
git clone https://github.com/BrayansStivens/appsec-agent.git
cd appsec-agent
make up
make demo
```

`make up` construye, descarga los motores, arranca y te muestra la URL y el **código de configuración**. `make demo` analiza de verdad los ejemplos vulnerables que trae el repositorio e importa un modelo de amenazas, para ver Tamandua funcionando sin conectar nada (`make demo IMAGE=nginx:1.21` añade una imagen).

Abre <http://127.0.0.1:8766>, crea el administrador con el código y sigue **Primeros pasos** en el Resumen. La guía completa, con qué es opcional: [docs/inicio-rapido.md](docs/inicio-rapido.md).

## Documentación

| | |
| --- | --- |
| [Inicio rápido](docs/inicio-rapido.md) | De cero al primer hallazgo corregido, y qué configurar después |
| [Instalación](docs/instalacion.md) | Requisitos, primer arranque, actualizar, copias de seguridad, desinstalar |
| [Conectar GitHub](docs/github-app.md) | Crear la GitHub App paso a paso y revisar PRs |
| [Terminal y CI](docs/cli.md) | `scan`: analiza una carpeta o lo que introduce un cambio, con salida SARIF y códigos para CI |
| [Funcionalidades](docs/funcionalidades.md) | Qué hace cada parte y con qué criterio |
| [Configuración](docs/configuracion.md) | Variables de `.env` |
| [Seguridad](docs/seguridad.md) | Secretos, transporte, qué sale de tu máquina y concesiones |
| [Contenedores y Makefile](docs/contenedores.md) | Comandos `make`, imágenes y endurecimiento |
| [Arquitectura](docs/arquitectura.md) | Componentes, flujo de un análisis y datos en disco |
| [Solución de problemas](docs/solucion-problemas.md) | Errores frecuentes |
| [Desarrollo](docs/desarrollo.md) | Sin contenedores, CLI y pruebas |
| [Software de terceros](THIRD_PARTY_NOTICES.md) | Licencias de los motores, las bases de avisos y las dependencias |

## Seguridad, en corto

- Secretos (clave de la GitHub App, claves de IA, token de Jira) **cifrados con AES-256-GCM** en `config/`, separado de `data/`. Nunca vuelven al navegador ni aparecen en los logs.
- GitHub App con solo cuatro permisos (`contents: read`, `metadata: read`, `pull_requests: write`, `statuses: write`), sin webhooks ni OAuth; tokens de una hora en memoria. Para varias organizaciones se configura como **Any account** y se conecta cada instalación explícitamente en el panel.
- Panel en `127.0.0.1` por defecto. Si lo publicas fuera de tu máquina sin **HTTPS**, el servidor no arranca.
- Credenciales de registros privados cifradas y pasadas a los motores por variable de entorno; los registros de red interna se bloquean salvo permiso expreso.
- Sin telemetría. Las bases de avisos se descargan y se consultan en local; tus dependencias solo salen hacia OSV si lo autorizas en un análisis. Los avisos solo van a los canales que configures.
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

Tamandua es software libre bajo la [GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0-only): puedes usarlo, estudiarlo, modificarlo y redistribuirlo. Si ofreces una versión modificada a otras personas a través de la red, tienes que poner a su disposición el código fuente de esa versión con la misma licencia.

Las reglas SAST de [`rules/`](rules/) tienen su propia licencia MIT, para que puedas reutilizarlas en otras herramientas.

Copyright © 2026 BrayansStivens y colaboradores de Tamandua.
