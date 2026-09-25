# Software y datos de terceros

Tamandua (AGPL-3.0, ver `LICENSE`) orquesta motores de análisis de terceros y consulta bases públicas de
vulnerabilidades. Este documento lista qué se usa, bajo qué licencia y qué obliga, tanto al distribuir
Tamandua como al ofrecerlo como servicio gestionado.

Licencias comprobadas el 2026-09-25 contra el repositorio de cada proyecto (API de GitHub) y los metadatos de
los paquetes instalados. Revisa este archivo al cambiar una versión fijada en `appsec_agent/scanners.py`.

## Motores de análisis

Se ejecutan como **procesos independientes en su propio contenedor** (`docker run`), con sus imágenes
oficiales fijadas por digest. Tamandua no enlaza su código ni lo modifica: es agregación, no una obra derivada.

| Motor | Versión | Licencia | Uso en Tamandua | Obligaciones |
|---|---|---|---|---|
| [Trivy](https://github.com/aquasecurity/trivy) | 0.74.0 | Apache-2.0 | Dependencias, imágenes, IaC | Conservar avisos de licencia y NOTICE |
| [OSV-Scanner](https://github.com/google/osv-scanner) | 2.6.0 | Apache-2.0 | Dependencias con la base OSV | Conservar avisos |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | 8.30.1 | MIT | Secretos | Conservar aviso de copyright |
| [Opengrep](https://github.com/opengrep/opengrep) | 1.30.0 | LGPL-2.1 | SAST con reglas propias | Binario oficial sin modificar (`docker/engines/opengrep`, SHA-256 fijado). Si se modificara y distribuyera, publicar esos cambios |
| [Grype](https://github.com/anchore/grype) | 0.119.0 | Apache-2.0 | Segunda opinión en imágenes | Conservar avisos |
| [Checkov](https://github.com/bridgecrewio/checkov) | 3.3.19 | Apache-2.0 | IaC y pipelines | Conservar avisos |
| [zizmor](https://github.com/zizmorcore/zizmor) | 1.30.1 | MIT | GitHub Actions | Conservar aviso de copyright |

Ninguna de estas licencias limita el uso comercial ni el uso como servicio (SaaS).

### Reglas SAST

Las reglas de `rules/` son **propias y van bajo MIT** (`rules/LICENSE`). No se usan reglas del registro de
Semgrep: desde diciembre de 2024 su licencia (Semgrep Rules License) prohíbe ofrecerlas como servicio o en un
producto competidor. Cualquier regla nueva debe ser propia o de una fuente con licencia compatible.

## Bases de vulnerabilidades

Se consultan en tiempo de análisis; no se redistribuyen dentro de Tamandua.

| Fuente | Uso | Licencia o términos | Atribución |
|---|---|---|---|
| [OSV.dev](https://osv.dev) (API) | Avisos por paquete y versión | Servicio de Google (Apache-2.0); cada aviso conserva la licencia de su fuente | Citar la fuente del aviso |
| [GitHub Advisory Database](https://github.com/github/advisory-database) | Avisos (vía OSV y los motores) | CC-BY-4.0 | «Contiene datos de la GitHub Advisory Database (CC-BY-4.0)» |
| [NVD](https://nvd.nist.gov) (API 2.0) | CVSS y descripciones | Dominio público (Gobierno de EE. UU.) | «This product uses data from the NVD API but is not endorsed or certified by the NVD.» |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Explotación activa conocida | Dominio público (Gobierno de EE. UU.) | Citar CISA |
| [EPSS](https://www.first.org/epss/) | Probabilidad de explotación | Uso libre con atribución (FIRST) | «EPSS: FIRST.org» |
| Bases de Trivy y Grype (`trivy-db`, `grype-db`) | Descargadas por cada motor | Código Apache-2.0; los datos agregan fuentes con términos propios (distribuciones, GitLab, etc.) | **Pendiente**: revisar fuente por fuente antes de operar el servicio gestionado |

Los informes de Tamandua muestran los identificadores (CVE, GHSA) y enlazan a la fuente; la descripción
íntegra de cada aviso se conserva con su referencia.

## Dependencias de la aplicación

**Python** (`requirements.txt`):

| Paquete | Licencia |
|---|---|
| cryptography | Apache-2.0 OR BSD-3-Clause |
| cffi (dependencia de cryptography) | MIT-0 |
| pycparser (dependencia de cffi) | BSD-3-Clause |
| ReportLab | BSD (licencia propia de ReportLab Inc., de tipo BSD) |

**Panel web** (lo que viaja compilado en `appsec_agent/static`): React y React DOM (MIT), @xyflow/react (MIT),
@base-ui/react (MIT), lucide-react (ISC), class-variance-authority (Apache-2.0), qrcode (MIT),
tw-animate-css (MIT), Tailwind CSS (MIT) y la fuente **Geist** (SIL OFL-1.1: se puede incrustar y
redistribuir; no se puede vender la fuente por separado).

Revisión completa del árbol de `web/node_modules` (411 paquetes): MIT, ISC, BSD, Apache-2.0, 0BSD, BlueOak-1.0.0,
Python-2.0, CC-BY-4.0 y OFL-1.1. La única excepción es **lightningcss** (MPL-2.0), que solo se usa al compilar
el CSS y no se distribuye.

## Al ofrecer Tamandua como servicio gestionado

- **La AGPL-3.0 de Tamandua** obliga a ofrecer el código fuente de la versión que se ejecuta a quien la usa por
  red. Las funciones de la edición comercial que no sean AGPL deben vivir fuera de este repositorio; el CLA
  (`CLA.md`) permite al titular distribuir las contribuciones también bajo licencia comercial.
- **Los motores y las bases** permiten el uso como servicio con las atribuciones de arriba. Queda pendiente
  revisar los términos de los datos que agregan `trivy-db` y `grype-db`.
- **Modelos de IA**: los términos comerciales del proveedor que se use rigen el reenvío de consumo a clientes.
  Hay que revisarlos antes de revenderlo.
