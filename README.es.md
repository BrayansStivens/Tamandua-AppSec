[English](README.md) · Español

<p align="center"><img src="docs/assets/tamandua.svg" width="112" alt="Tamandua, un oso hormiguero de collar atrapando un bug con la lengua"></p>

<h1 align="center">Tamandua</h1>

<p align="center"><a href="https://github.com/BrayansStivens/appsec-agent/actions/workflows/ci.yml"><img src="https://github.com/BrayansStivens/appsec-agent/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a></p>

<p align="center"><strong>Se come tus bugs.</strong> Seguridad de aplicaciones autoalojada, libre y sin enviar tu código a nadie.</p>

Tamandua analiza tus repositorios e imágenes de contenedor, te dice **qué corregir primero y cómo** (el comando exacto o un ejemplo de código), comprueba que quedó corregido y **vigila solo** lo que cambia después. Todo corre en tu máquina, con tus credenciales: tu código no va a ningún servicio nuestro.

> Estado: **beta (v0.9)**. Funcional y con pruebas, pero la API y los formatos de `data/` aún pueden cambiar entre versiones.

## Por qué Tamandua

- **Autoalojado y libre (AGPL-3.0).** El código, las dependencias y los hallazgos se quedan en tu servidor.
- **Un solo sitio para todo:** código (SAST), dependencias, secretos, infraestructura como código, pipelines e imágenes, con siete motores abiertos y sin duplicados entre ellos.
- **Del hallazgo a la corrección verificada:** prioridad real (CISA KEV y EPSS), comando de corrección por gestor de paquetes, botón «Reverificar» y remediación automática cuando deja de aparecer.
- **En español e inglés, y pensado para equipos pequeños**, con evidencia lista para auditorías SOC 2 e ISO 27001 y modelado de amenazas conectado a los hallazgos reales.

## Qué hace

| | |
| --- | --- |
| **Encontrar** | Opengrep con 58 reglas propias (JS/TS, Python, Java, Go, PHP, Ruby, C#), Gitleaks, Trivy y OSV-Scanner para dependencias, Checkov y zizmor para IaC y GitHub Actions, Trivy + Grype para imágenes. El código nunca se ejecuta. Uno o varios repositorios, una organización entera o varias imágenes a la vez. |
| **Priorizar** | Cada aviso cruzado con CISA KEV (explotación activa) y EPSS (probabilidad de explotación); las dependencias agrupadas por paquete con la versión que cierra todos sus avisos. |
| **Corregir** | En cada hallazgo, cómo corregirlo: el comando de tu gestor (npm, pip, Poetry, Go, Cargo, Maven…), el override si es transitiva, un ejemplo antes/después para el código o los pasos para rotar un secreto. Exportación a Jira sin duplicados. |
| **Verificar** | «Reverificar» vuelve a analizar y te dice «Corregido ✓» o «Sigue presente». En los pull requests solo cuenta lo que el PR introduce, con comentario y estado que puede bloquear el merge. |
| **Vigilar** | Reanálisis automático cuando cambia la rama principal, avisos nuevos a diario contra tus dependencias (sin conexión) y mensajes a **Slack, Teams o un webhook** cuando aparece algo que importa. |
| **Demostrar** | Informes PDF técnicos y de evidencia (SOC 2 Tipo II, ISO/IEC 27001:2022, consolidado de organización), SARIF, JSON y Markdown; modelado de amenazas (STRIDE, LINDDUN, PASTA, árboles, ATT&CK) con diagrama; CVE tracker local de NVD. |

**En desarrollo** (en gris en el panel): pruebas dinámicas (DAST), GitLab/Bitbucket/Azure DevOps (hoy se cubren con [`scan` en CI](docs/es/cli.md)) y asistencia con IA opcional.

## Pruébalo en 5 minutos

Necesitas **Docker** (Engine 24+ con Compose v2.24+), **make** y **git**, 4 GB de memoria y 8 GB de disco. `make doctor` lo comprueba.

```bash
git clone https://github.com/BrayansStivens/appsec-agent.git
cd appsec-agent
make up
make demo
```

`make up` construye, descarga los motores, arranca y te muestra la URL y el **código de configuración**. `make demo` analiza de verdad los ejemplos vulnerables que trae el repositorio e importa un modelo de amenazas, para ver Tamandua funcionando sin conectar nada (`make demo IMAGE=nginx:1.21` añade una imagen).

Abre <http://127.0.0.1:8766>, crea el administrador con el código y sigue **Primeros pasos** en el Resumen. La guía completa, con qué es opcional: [docs/es/inicio-rapido.md](docs/es/inicio-rapido.md).

El panel sigue el idioma de tu navegador y tiene un selector de idioma en la barra lateral y en la pantalla de inicio de sesión. Los comentarios en PRs, los avisos, Jira, los informes y la salida de la CLI usan `TAMANDUA_DEFAULT_LOCALE` (`en` o `es`, por defecto `en`).

## Documentación

| | |
| --- | --- |
| [Inicio rápido](docs/es/inicio-rapido.md) | De cero al primer hallazgo corregido, y qué configurar después |
| [Instalación](docs/es/instalacion.md) | Requisitos, primer arranque, actualizar, copias de seguridad, desinstalar |
| [Desplegar en un VPS](docs/es/despliegue-vps.md) | Tu propio servidor con dominio: HTTPS, copias, actualizaciones, monitorización, Coolify y Dokploy |
| [Conectar GitHub](docs/es/github-app.md) | Crear la GitHub App paso a paso y revisar PRs |
| [Terminal y CI](docs/es/cli.md) | `scan`: analiza una carpeta o lo que introduce un cambio, con salida SARIF y códigos para CI |
| [Skills para asistentes](skills/README.md) | Claude Code, Cursor o Codex corrigen lo que encuentra Tamandua y lo verifican, o lo montan en tu CI |
| [Funcionalidades](docs/es/funcionalidades.md) | Qué hace cada parte y con qué criterio |
| [Configuración](docs/es/configuracion.md) | Variables de `.env` |
| [Seguridad](docs/es/seguridad.md) | Secretos, transporte, qué sale de tu máquina y concesiones |
| [Contenedores y Makefile](docs/es/contenedores.md) | Comandos `make`, imágenes y endurecimiento |
| [Arquitectura](docs/es/arquitectura.md) | Componentes, flujo de un análisis y datos en disco |
| [Solución de problemas](docs/es/solucion-problemas.md) | Errores frecuentes |
| [Desarrollo](docs/es/desarrollo.md) | Sin contenedores, CLI y pruebas |
| [Software de terceros](THIRD_PARTY_NOTICES.es.md) | Licencias de los motores, las bases de avisos y las dependencias |

## Seguridad, en corto

- Secretos (clave de la GitHub App, claves de IA, token de Jira) **cifrados con AES-256-GCM** en `config/`, separado de `data/`. Nunca vuelven al navegador ni aparecen en los logs.
- GitHub App con solo cuatro permisos (`contents: read`, `metadata: read`, `pull_requests: write`, `statuses: write`), sin webhooks ni OAuth; tokens de una hora en memoria. Para varias organizaciones se configura como **Any account** y se conecta cada instalación explícitamente en el panel.
- Panel en `127.0.0.1` por defecto. Si lo publicas fuera de tu máquina sin **HTTPS**, el servidor no arranca.
- Credenciales de registros privados cifradas y pasadas a los motores por variable de entorno; los registros de red interna se bloquean salvo permiso expreso.
- Sin telemetría. Las bases de avisos se descargan y se consultan en local; tus dependencias solo salen hacia OSV si lo autorizas en un análisis. Los avisos solo van a los canales que configures.
- **Concesión:** la app lanza los motores por el socket de Docker, lo que equivale a root en el host. Expón el panel solo a gente de confianza.

Para reportar una vulnerabilidad: [SECURITY.es.md](SECURITY.es.md).

## Llevarlo a un servidor (HTTPS)

Tamandua está pensado para vivir en su propio VPS (Hetzner, DigitalOcean, Hostinger…) con tu dominio. Con el registro DNS apuntando al servidor:

```bash
make setup DOMAIN=appsec.tu-dominio.com PREBUILT=1   # Caddy con HTTPS automático + las imágenes publicadas y firmadas
make up
```

A partir de ahí solo se llega a la API a través de Caddy, HTTP redirige a HTTPS y el certificado se renueva solo. La guía cubre dimensionado, sistema y cortafuegos, copias fuera del servidor y restauración, actualizaciones, métricas para Prometheus, y Coolify y Dokploy: [docs/es/despliegue-vps.md](docs/es/despliegue-vps.md).

## Contribuir

Issues y PRs son bienvenidos: lee [CONTRIBUTING.es.md](CONTRIBUTING.es.md). En el primer PR se firma el [CLA](CLA.es.md) con un comentario. Las reglas SAST propias están en `rules/`.

## Licencia

Tamandua es software libre bajo la [GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0-only): puedes usarlo, estudiarlo, modificarlo y redistribuirlo. Si ofreces una versión modificada a otras personas a través de la red, tienes que poner a su disposición el código fuente de esa versión con la misma licencia.

Las reglas SAST de [`rules/`](rules/) tienen su propia licencia MIT, para que puedas reutilizarlas en otras herramientas.

Copyright © 2026 BrayansStivens y colaboradores de Tamandua.
