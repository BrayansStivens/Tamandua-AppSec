"""Fuente de cada aviso de dependencias: de qué base viene y bajo qué licencia.

Los avisos que muestra Tamandua salen de bases públicas con licencias distintas (ver THIRD_PARTY_NOTICES.md).
Cada hallazgo guarda su fuente para poder atribuirla en el panel y en los informes, y para que un servicio
gestionado sepa qué fuentes no admiten uso comercial. Licencias revisadas el 2026-09-25.
"""

from __future__ import annotations

from tamandua.shared.i18n import MARK, is_msg, msg, t

UNDECLARED = msg("intel.sources.licenses.undeclared")
# Licenses that say nothing usable: the attribution line skips the terms for them.
NO_LICENSE = {"intel.sources.licenses.undeclared", "intel.sources.licenses.undeclared_copyright",
              "intel.sources.licenses.undeclared_restrictive", "intel.sources.licenses.unreviewed"}

# terms: «open» (sin condiciones), «attribution», «share-alike», «non-commercial», «unclear» (sin licencia o ambigua)
_CATALOG: dict[str, tuple[str, str | dict, str, str]] = {
    # id: (nombre, licencia, página, términos)
    "ghsa": ("GitHub Advisory Database", "CC BY 4.0", "https://github.com/advisories", "attribution"),
    "glad": ("GitLab Advisory Database (community)", "MIT", "https://gitlab.com/gitlab-org/advisories-community", "attribution"),
    "govulndb": ("Go Vulnerability Database", "CC BY 4.0", "https://pkg.go.dev/vuln/", "attribution"),
    "julia": ("Julia SecurityAdvisories", "CC BY 4.0", "https://github.com/JuliaLang/SecurityAdvisories.jl", "attribution"),
    "k8s": ("Kubernetes CVE feed", "CC BY 4.0", "https://kubernetes.io/docs/reference/issues-security/official-cve-feed/", "attribution"),
    "nodejs-security-wg": ("Node.js Security WG", "MIT", "https://github.com/nodejs/security-wg", "attribution"),
    "php-security-advisories": ("FriendsOfPHP security-advisories", "Unlicense", "https://github.com/FriendsOfPHP/security-advisories", "open"),
    "ruby-advisory-db": ("Ruby Advisory Database", msg("intel.sources.licenses.ruby_advisory_db"),
                         "https://github.com/rubysec/ruby-advisory-db", "unclear"),
    "pypa": ("PyPA Advisory Database", "CC BY 4.0", "https://github.com/pypa/advisory-database", "attribution"),
    "rustsec": ("RustSec Advisory Database", "CC0 1.0", "https://rustsec.org", "open"),
    "osv": ("OSV.dev", msg("intel.sources.licenses.per_advisory"), "https://osv.dev", "attribution"),
    "ossf-malicious": ("OpenSSF Malicious Packages", "Apache-2.0", "https://github.com/ossf/malicious-packages", "open"),
    "nvd": ("NVD (NIST)", msg("intel.sources.licenses.public_domain"), "https://nvd.nist.gov", "attribution"),
    "euvd": ("EUVD (ENISA)", msg("intel.sources.licenses.euvd"),
             "https://euvd.enisa.europa.eu", "unclear"),
    "redhat": ("Red Hat Security Data", "CC BY 4.0", "https://access.redhat.com/security/data", "attribution"),
    "suse-cvrf": ("SUSE Security", "CC BY 4.0", "https://www.suse.com/support/security/", "attribution"),
    "ubuntu": ("Ubuntu Security", msg("intel.sources.licenses.ubuntu"), "https://ubuntu.com/security", "share-alike"),
    "alpine": ("Alpine secdb", "CC BY-SA 4.0", "https://secdb.alpinelinux.org", "share-alike"),
    "debian": ("Debian Security Tracker", UNDECLARED, "https://security-tracker.debian.org", "unclear"),
    "amazon": ("Amazon Linux Security Center", msg("intel.sources.licenses.amazon"), "https://alas.aws.amazon.com", "unclear"),
    "oracle-oval": ("Oracle Linux OVAL", msg("intel.sources.licenses.undeclared_copyright"), "https://linux.oracle.com/security/", "unclear"),
    "alma": ("AlmaLinux Errata", msg("intel.sources.licenses.alma"), "https://errata.almalinux.org", "unclear"),
    "rocky": ("Rocky Linux Errata", "BSD", "https://errata.rockylinux.org", "attribution"),
    "centos": ("CentOS", UNDECLARED, "https://www.centos.org", "unclear"),
    "fedora": ("Fedora Bodhi", UNDECLARED, "https://bodhi.fedoraproject.org", "unclear"),
    "arch-linux": ("Arch Linux Security", UNDECLARED, "https://security.archlinux.org", "unclear"),
    "azure": ("Azure Linux", "MIT", "https://github.com/microsoft/AzureLinuxVulnerabilityData", "attribution"),
    "cbl-mariner": ("CBL-Mariner", "MIT", "https://github.com/microsoft/AzureLinuxVulnerabilityData", "attribution"),
    "photon": ("VMware Photon OS", UNDECLARED, "https://packages.broadcom.com/photon/photon_cve_metadata/", "unclear"),
    "bottlerocket": ("Bottlerocket", UNDECLARED, "https://advisories.bottlerocket.aws", "unclear"),
    "bitnami": ("Bitnami Vulnerability Database", "Apache-2.0", "https://github.com/bitnami/vulndb", "attribution"),
    "wolfi": ("Wolfi", "CC BY-NC-ND 4.0", "https://github.com/wolfi-dev/advisories", "non-commercial"),
    "chainguard": ("Chainguard", "CC BY-NC-ND 4.0", "https://images.chainguard.dev/security", "non-commercial"),
    "minimos": ("Minimus", "CC BY-NC-ND 4.0", "https://docs.minimus.io/scanning/advisories-feed", "non-commercial"),
    "echo": ("Echo", msg("intel.sources.licenses.undeclared_restrictive"), "https://advisory.echohq.com", "unclear"),
    "rootio": ("Root.io", UNDECLARED, "https://root.io", "unclear"),
    "seal": ("Seal Security", UNDECLARED, "https://sealsecurity.io", "unclear"),
    "rapidfort": ("RapidFort", UNDECLARED, "https://github.com/rapidfort/security-advisories", "unclear"),
    "secureos": ("SecureOS", UNDECLARED, "https://security.secureos.io", "unclear"),
    "aqua": ("Aqua Security", "Apache-2.0", "https://github.com/aquasecurity/vuln-list-aqua", "attribution"),
}
# Variantes con las que Trivy o Grype nombran la misma base.
_ALIASES = {"redhat-oval": "redhat", "redhat-csaf-vex": "redhat", "hummingbird": "redhat", "rhel": "redhat",
            "github": "ghsa", "sles": "suse-cvrf", "suse": "suse-cvrf", "oracle": "oracle-oval", "oraclelinux": "oracle-oval",
            "mariner": "cbl-mariner", "azurelinux": "azure", "arch": "arch-linux", "amazonlinux": "amazon", "almalinux": "alma",
            "go": "govulndb", "chainguard-libraries": "chainguard", "chainguard_libraries": "chainguard"}
# Prefijo del identificador OSV → base de origen.
_OSV_PREFIX = {"MAL-": "ossf-malicious", "GHSA-": "ghsa", "PYSEC-": "pypa", "RUSTSEC-": "rustsec", "GO-": "govulndb", "JLSEC-": "julia",
               "BIT-": "bitnami", "CGA-": "chainguard", "ALSA-": "alma", "ALBA-": "alma", "RLSA-": "rocky", "UBUNTU-": "ubuntu",
               "USN-": "ubuntu", "DSA-": "debian", "DLA-": "debian", "DEBIAN-": "debian", "SUSE-": "suse-cvrf", "RHSA-": "redhat"}

# Nombre corto para columnas estrechas (el completo va en «Fuentes de los avisos»).
_SHORT = {"ghsa": "GitHub", "glad": "GitLab", "govulndb": "Go", "julia": "Julia", "k8s": "Kubernetes", "nodejs-security-wg": "Node.js",
          "php-security-advisories": "PHP", "ruby-advisory-db": "RubySec", "pypa": "PyPA", "rustsec": "RustSec", "osv": "OSV",
          "nvd": "NVD", "euvd": "EUVD", "redhat": "Red Hat", "suse-cvrf": "SUSE", "ubuntu": "Ubuntu", "alpine": "Alpine", "debian": "Debian",
          "amazon": "Amazon", "oracle-oval": "Oracle", "alma": "AlmaLinux", "rocky": "Rocky", "centos": "CentOS", "fedora": "Fedora",
          "arch-linux": "Arch", "azure": "Azure Linux", "cbl-mariner": "Mariner", "photon": "Photon", "bottlerocket": "Bottlerocket",
          "bitnami": "Bitnami", "wolfi": "Wolfi", "chainguard": "Chainguard", "minimos": "Minimus", "echo": "Echo", "rootio": "Root.io",
          "seal": "Seal", "ossf-malicious": "OpenSSF", "rapidfort": "RapidFort", "secureos": "SecureOS", "aqua": "Aqua"}

TERMS_LABEL = {"open": msg("intel.sources.terms.open"), "attribution": msg("intel.sources.terms.attribution"),
               "share-alike": msg("intel.sources.terms.share_alike"), "non-commercial": msg("intel.sources.terms.non_commercial"),
               "unclear": msg("intel.sources.terms.unclear")}


def describe(source_id: str, *, url: str | None = None, name: str | None = None) -> dict:
    """{id, name, url, license, terms} de una base; lo desconocido queda como «sin licencia clara»."""
    key = _ALIASES.get(source_id, source_id)
    known = _CATALOG.get(key)
    if known:
        label, license_name, home, terms = known
    else:
        label, license_name, home, terms = name or source_id, msg("intel.sources.licenses.unreviewed"), "", "unclear"
    link = url if isinstance(url, str) and url.startswith("https://") else home
    return {"id": key, "name": label, "short": _SHORT.get(key, label[:14]), "url": link[:300], "license": license_name, "terms": terms}


def from_trivy(entry: dict) -> dict | None:
    data = entry.get("DataSource") or {}
    if not data.get("ID"):
        return None
    return describe(str(data["ID"]).lower(), url=data.get("URL"), name=data.get("Name"))


def from_grype(vulnerability: dict) -> dict | None:
    namespace = str(vulnerability.get("namespace") or "")
    if not namespace:
        return None
    return describe(namespace.split(":", 1)[0].lower(), url=vulnerability.get("dataSource"))


def from_osv(identifier: str) -> dict:
    for prefix, key in _OSV_PREFIX.items():
        if identifier.upper().startswith(prefix):
            return describe(key)
    return describe("osv")


def _no_license(value) -> bool:
    if is_msg(value):
        return value[MARK] in NO_LICENSE
    return str(value or "").startswith("Sin")  # runs stored before i18n


def attribution(findings: list[dict], *, locale: str | None = None) -> list[str]:
    """Líneas de atribución de un informe: cada base usada, su licencia y su página, más los avisos de NVD, KEV y EPSS."""
    used: dict[str, tuple[dict, int]] = {}
    for finding in findings:
        source = finding.get("source")
        if isinstance(source, dict) and source.get("id"):
            current = used.get(source["id"])
            used[source["id"]] = (current[0] if current else source, (current[1] if current else 0) + 1)
    lines = []
    for source, count in sorted(used.values(), key=lambda pair: -pair[1]):
        link = describe(source["id"])["url"] or source.get("url") or ""
        if source["terms"] == "unclear" and _no_license(source["license"]):
            line = t("intel.sources.line", locale, name=source["name"], license=source["license"], count=count)
        else:
            line = t("intel.sources.line_terms", locale, name=source["name"], license=source["license"], count=count,
                     terms=TERMS_LABEL.get(source["terms"], source["terms"]))
        lines.append(line + (f" · {link}" if link else ""))
    missing = sum(1 for finding in findings if finding.get("scanner") == "sca" and not (finding.get("source") or {}).get("id"))
    if missing:
        lines.append(t("intel.sources.missing", locale, count=missing))
    if any(finding.get("scanner") == "sca" for finding in findings):
        # Wording required by the NVD terms of use: always in English.
        lines.append("This product uses the NVD API but is not endorsed or certified by the NVD.")
    if any(finding.get("kev") for finding in findings):
        lines.append(t("intel.sources.kev", locale))
    if any(finding.get("epss") for finding in findings):
        lines.append(t("intel.sources.epss", locale))
    return lines
