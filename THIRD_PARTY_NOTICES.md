English · [Español](THIRD_PARTY_NOTICES.es.md)

# Third-party software and data

Tamandua (AGPL-3.0, see `LICENSE`) orchestrates third-party analysis engines and queries public vulnerability
databases. This document lists what is used, under which license, and what each one requires, both when you
distribute Tamandua and when you offer it as a managed service.

Licenses checked on 2026-09-25 against each project's repository (GitHub API) and the metadata of the installed
packages. Review this file whenever you change a version pinned in `tamandua/modules/scanning/engines.py`.

## Analysis engines

They run as **independent processes in their own container** (`docker run`), using their official images pinned
by digest. Tamandua neither links nor modifies their code: this is aggregation, not a derivative work.

| Engine | Version | License | Use in Tamandua | Obligations |
|---|---|---|---|---|
| [Trivy](https://github.com/aquasecurity/trivy) | 0.74.0 | Apache-2.0 | Dependencies, images, IaC | Keep the license notices and NOTICE |
| [OSV-Scanner](https://github.com/google/osv-scanner) | 2.6.0 | Apache-2.0 | Dependencies against the OSV database | Keep the notices |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | 8.30.1 | MIT | Secrets | Keep the copyright notice |
| [Opengrep](https://github.com/opengrep/opengrep) | 1.30.0 | LGPL-2.1 | SAST with Tamandua's own rules | Official binary, unmodified (`docker/engines/opengrep`, pinned SHA-256). If it were modified and distributed, publish those changes |
| [Grype](https://github.com/anchore/grype) | 0.119.0 | Apache-2.0 | Second opinion on images | Keep the notices |
| [Checkov](https://github.com/bridgecrewio/checkov) | 3.3.19 | Apache-2.0 | IaC and pipelines | Keep the notices |
| [zizmor](https://github.com/zizmorcore/zizmor) | 1.30.1 | MIT | GitHub Actions | Keep the copyright notice |

None of these licenses restricts commercial use or use as a service (SaaS).

### SAST rules

The rules in `rules/` are **Tamandua's own and licensed under MIT** (`rules/LICENSE`). No rules from the Semgrep
registry are used: since December 2024 their license (Semgrep Rules License) forbids offering them as a service or
in a competing product. Any new rule must be our own or come from a source with a compatible license.

## Vulnerability databases

They are queried at analysis time; they are not redistributed inside Tamandua.

| Source | Use | License or terms | Attribution |
|---|---|---|---|
| [OSV.dev](https://osv.dev) (API) | Advisories by package and version | Google service (Apache-2.0); each advisory keeps the license of its source | Cite the advisory's source |
| [GitHub Advisory Database](https://github.com/github/advisory-database) | Advisories (through OSV and the engines) | CC-BY-4.0 | "Contains data from the GitHub Advisory Database (CC-BY-4.0)" |
| [NVD](https://nvd.nist.gov) (API 2.0) | CVSS and descriptions | Public domain (U.S. Government) | "This product uses data from the NVD API but is not endorsed or certified by the NVD." |
| [EUVD](https://euvd.enisa.europa.eu) (ENISA, search API) | CVSS when NVD has no score, and the date of active exploitation, on demand in the CVE tracker | ENISA legal notice: reuse allowed with the source cited; the API's own terms are **to be confirmed** | Cite "EUVD (ENISA)"; turn it off with `TAMANDUA_EUVD=off` |
| [OpenSSF Malicious Packages](https://github.com/ossf/malicious-packages) | `MAL-*` advisories for malicious packages (through OSV-Scanner) | Apache-2.0 | Keep the notice |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known active exploitation | Public domain (U.S. Government) | Cite CISA |
| [EPSS](https://www.first.org/epss/) | Exploitation probability | Free use with attribution (FIRST) | "EPSS: FIRST.org" |
| Trivy and Grype databases (`trivy-db`, `grype-db`) | Downloaded by each engine | Code under Apache-2.0; the databases declare no license of their own and aggregate sources with different terms | See the next section |

Tamandua's reports show the identifiers (CVE, GHSA) and link to the source; the full description of each advisory
is kept together with its reference.

## Data aggregated by `trivy-db` and `grype-db`

Reviewed on 2026-09-25 source by source: the exact URL in the code of `aquasecurity/trivy-db`,
`aquasecurity/vuln-list-update` and `anchore/vunnel`, and the license at each origin. Tamandua does not
redistribute these databases: each engine downloads them on the installation that runs it. Even so, when Tamandua
is offered as a service, results derived from them are shown to customers.

**Incompatible with a paid service as is:**

| Source | License | Why |
|---|---|---|
| Wolfi (`packages.wolfi.dev`) and Chainguard (`packages.cgr.dev`, `advisories.cgr.dev`, `libraries.cgr.dev`) | CC BY-NC-ND 4.0, or the *Chainguard License for Commercial Scanners* | Forbids commercial use and derivative works. The scanner license excludes use "for the benefit of a Competitor of Chainguard" and redistribution inside another offering |
| Minimus (`packages.mini.dev`) | CC BY-NC-ND 4.0, with no exception | Forbids commercial use and derivative works |

**Ambiguous or with no declared license** (they do not expressly grant rights):

- Amazon Linux ALAS: the AWS site terms exclude "resale or commercial use" unless separately licensed.
- Echo (its terms forbid copying and automated access to the site) and RapidFort (repository with no license).
- Root.io, Seal, SecureOS, Debian, Arch Linux, Oracle Linux (copyright only), Photon, Bottlerocket, Fedora and
  the Ubuntu CVE Tracker used by Trivy.
- ruby-advisory-db: public domain, except the OSVDB content, whose license is non-commercial. Trivy drops the
  advisories that only have an OSVDB identifier.

**Compatible with attribution:**

| License | Sources | Obligation |
|---|---|---|
| CC BY-SA 4.0 | Alpine secdb; the Ubuntu advisories used by Grype (`canonical/ubuntu-security-notices`) | Give attribution, and share material adapted from these advisories under the same license |
| CC BY 4.0 | Red Hat (CSAF/VEX, also Hummingbird), SUSE, GitHub Advisory Database, Go, Julia, Kubernetes | Give attribution, link to the license and state whether it was modified |
| CC0 / public domain / Unlicense | CISA KEV, NVD (with its notice), FriendsOfPHP, RustSec | NVD: "This product uses the NVD API but is not endorsed or certified by the NVD." |
| MIT / Apache-2.0 / BSD | GitLab Advisory Database *community* (MIT, 30-day delay), Node.js security WG, Azure Linux, AlmaLinux OSV, Bitnami, endoflife.date, Rocky (BSD) | Keep the notice |
| No license, free use requested | EPSS (FIRST asks for attribution) | Cite FIRST |

**Downloading the databases:** `trivy-db` is served from `mirror.gcr.io` and `ghcr.io/aquasecurity/trivy-db`, and
the Grype database from `grype.anchore.io`. Neither declares terms of use, but both depend on free infrastructure
with shared limits, and Aqua recommends that enterprise users host their own copy.

**What to do before running the managed service:**

1. Build and host our own copies of `trivy-db` and the Grype database **without** the Wolfi, Chainguard and
   Minimus sources, or obtain a license from those companies. Until then, images based on those distributions are
   not analyzed in the paid service.
2. Decide on the ambiguous sources (Amazon first) by asking for permission or excluding them.
3. ~~Show the source of each advisory~~ Done: each dependency finding stores its source and license
   (`tamandua/modules/intel/data_sources.py`); the panel shows it in the finding detail, and the technical, audit
   and Markdown reports include "Advisory sources" with each database's attribution and the NVD notice. Analyses
   run before this change have no recorded source until they are analyzed again.

In the self-hosted community edition, each organization runs Trivy and Grype with their databases like any other
user of those tools, and the terms of each source apply to it directly. This is a technical analysis, not legal
advice.

## Application dependencies

**Python** (`requirements.txt`):

| Package | License |
|---|---|
| cryptography | Apache-2.0 OR BSD-3-Clause |
| cffi (dependency of cryptography) | MIT-0 |
| pycparser (dependency of cffi) | BSD-3-Clause |
| ReportLab | BSD (ReportLab Inc.'s own BSD-style license) |

**Web panel** (what ships compiled in `tamandua/app/static`): React and React DOM (MIT), @xyflow/react (MIT),
@base-ui/react (MIT), lucide-react (ISC), class-variance-authority (Apache-2.0), qrcode (MIT),
tw-animate-css (MIT), Tailwind CSS (MIT) and the **Geist** font (SIL OFL-1.1: it can be embedded and
redistributed; the font cannot be sold on its own).

Full review of the `web/node_modules` tree (411 packages): MIT, ISC, BSD, Apache-2.0, 0BSD, BlueOak-1.0.0,
Python-2.0, CC-BY-4.0 and OFL-1.1. The only exception is **lightningcss** (MPL-2.0), which is used only to build
the CSS and is not distributed.

## When offering Tamandua as a managed service

- **Tamandua's AGPL-3.0** requires offering the source code of the running version to anyone who uses it over a
  network. Commercial-edition features that are not AGPL must live outside this repository; the CLA
  (`CLA.md`) lets the owner also distribute contributions under a commercial license.
- **The engines** allow use as a service. **The data** does not, not all of it: see "Data aggregated by `trivy-db`
  and `grype-db`" (Wolfi, Chainguard and Minimus are non-commercial).
- **AI models**: the commercial terms of the provider in use govern passing usage through to customers. Review
  them before reselling it.
