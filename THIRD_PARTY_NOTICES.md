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
| Bases de Trivy y Grype (`trivy-db`, `grype-db`) | Descargadas por cada motor | Código Apache-2.0; las bases no declaran licencia propia y agregan fuentes con términos distintos | Ver la sección siguiente |

Los informes de Tamandua muestran los identificadores (CVE, GHSA) y enlazan a la fuente; la descripción
íntegra de cada aviso se conserva con su referencia.

## Datos que agregan `trivy-db` y `grype-db`

Revisado el 2026-09-25 fuente por fuente: la URL exacta en el código de `aquasecurity/trivy-db`,
`aquasecurity/vuln-list-update` y `anchore/vunnel`, y la licencia en el origen de cada una. Tamandua no
redistribuye estas bases: cada motor las descarga en la instalación que lo ejecuta. Aun así, al ofrecer
Tamandua como servicio, los resultados derivados de ellas se muestran a clientes.

**Incompatibles con un servicio de pago tal cual:**

| Fuente | Licencia | Por qué |
|---|---|---|
| Wolfi (`packages.wolfi.dev`) y Chainguard (`packages.cgr.dev`, `advisories.cgr.dev`, `libraries.cgr.dev`) | CC BY-NC-ND 4.0, o la *Chainguard License for Commercial Scanners* | Prohíbe el uso comercial y las obras derivadas. La licencia para escáneres excluye el uso «for the benefit of a Competitor of Chainguard» y su redistribución dentro de otra oferta |
| Minimus (`packages.mini.dev`) | CC BY-NC-ND 4.0, sin excepción | Prohíbe el uso comercial y las obras derivadas |

**Ambiguas o sin licencia declarada** (no conceden derechos de forma expresa):

- Amazon Linux ALAS: los términos del sitio de AWS excluyen «resale or commercial use» salvo licencia aparte.
- Echo (sus términos prohíben copiar y el acceso automatizado al sitio) y RapidFort (repositorio sin licencia).
- Root.io, Seal, SecureOS, Debian, Arch Linux, Oracle Linux (solo copyright), Photon, Bottlerocket, Fedora y
  el Ubuntu CVE Tracker que usa Trivy.
- ruby-advisory-db: dominio público, salvo el contenido de OSVDB, cuya licencia es no comercial. Trivy
  descarta los avisos que solo tienen identificador OSVDB.

**Compatibles con atribución:**

| Licencia | Fuentes | Obligación |
|---|---|---|
| CC BY-SA 4.0 | Alpine secdb; avisos de Ubuntu que usa Grype (`canonical/ubuntu-security-notices`) | Atribuir, y compartir bajo la misma licencia el material adaptado de estos avisos |
| CC BY 4.0 | Red Hat (CSAF/VEX, también Hummingbird), SUSE, GitHub Advisory Database, Go, Julia, Kubernetes | Atribuir, enlazar la licencia e indicar si se modificó |
| CC0 / dominio público / Unlicense | CISA KEV, NVD (con su aviso), FriendsOfPHP, RustSec | NVD: «This product uses the NVD API but is not endorsed or certified by the NVD.» |
| MIT / Apache-2.0 / BSD | GitLab Advisory Database *community* (MIT, 30 días de retraso), Node.js security WG, Azure Linux, AlmaLinux OSV, Bitnami, endoflife.date, Rocky (BSD) | Conservar el aviso |
| Sin licencia, uso libre solicitado | EPSS (FIRST pide atribución) | Citar FIRST |

**Descarga de las bases:** `trivy-db` se sirve desde `mirror.gcr.io` y `ghcr.io/aquasecurity/trivy-db` y la base
de Grype desde `grype.anchore.io`. Ninguna declara términos de uso, pero dependen de una infraestructura
gratuita con límites compartidos, y Aqua recomienda a los usos empresariales alojar su propia copia.

**Qué hacer antes de operar el servicio gestionado:**

1. Construir y alojar copias propias de `trivy-db` y de la base de Grype **sin** las fuentes de Wolfi, Chainguard y
   Minimus, o conseguir licencia de esas empresas. Mientras tanto, las imágenes basadas en esas distribuciones
   no se analizan en el servicio de pago.
2. Decidir las fuentes ambiguas (Amazon en primer lugar) pidiendo permiso o excluyéndolas.
3. Mostrar en los informes y en el panel la fuente de cada aviso (Trivy la da en `DataSource`, Grype en
   `dataSource`) y publicar una página de atribuciones de datos.

En la edición community autoalojada, cada organización ejecuta Trivy y Grype con sus bases como cualquier otro
usuario de esas herramientas, y los términos de cada fuente le aplican directamente. Esto es un análisis
técnico, no asesoría legal.

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
- **Los motores** permiten el uso como servicio. **Los datos**, no todos: ver «Datos que agregan `trivy-db` y
  `grype-db`» (Wolfi, Chainguard y Minimus son no comerciales).
- **Modelos de IA**: los términos comerciales del proveedor que se use rigen el reenvío de consumo a clientes.
  Hay que revisarlos antes de revenderlo.
