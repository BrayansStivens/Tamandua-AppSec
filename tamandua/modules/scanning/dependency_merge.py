"""Un aviso de dependencia, un hallazgo: aunque lo detecten varios motores y cada uno lo nombre distinto.

Trivy suele identificar un aviso por su CVE; OSV-Scanner, por su GHSA o PYSEC, con el CVE como
alias. Y cada uno escribe el ecosistema a su manera (`pip`, `poetry`, `PyPI`…). Aquí se
normaliza todo eso para reconocer el mismo aviso sobre el mismo paquete y la misma versión.
"""

from __future__ import annotations

import re
from urllib.parse import quote

from tamandua.modules.intel.advisories import fingerprint

# Tipo de paquete de cada motor → familia común.
FAMILY = {
    # JavaScript
    "npm": "npm", "yarn": "npm", "pnpm": "npm", "bun": "npm", "node-pkg": "npm",
    # Python
    "pypi": "pypi", "pip": "pypi", "pipenv": "pypi", "poetry": "pypi", "uv": "pypi", "pdm": "pypi",
    "python": "pypi", "python-pkg": "pypi", "conda-pkg": "pypi",
    # .NET
    "nuget": "nuget", "dotnet-core": "nuget", "dotnet": "nuget", "packages-props": "nuget",
    # Go, Rust, PHP, Ruby
    "go": "go", "gomod": "go", "gobinary": "go", "go-module": "go",
    "crates.io": "cargo", "cargo": "cargo", "rust-binary": "cargo", "rust-crate": "cargo",
    "packagist": "composer", "composer": "composer", "php-composer": "composer",
    "rubygems": "rubygems", "bundler": "rubygems", "gemspec": "rubygems", "gem": "rubygems",
    # JVM
    "maven": "maven", "pom": "maven", "gradle": "maven", "sbt": "maven", "jar": "maven", "java-archive": "maven",
    # Otros
    "pub": "pub", "hex": "hex", "mix": "hex", "swifturl": "swift", "swift": "swift", "cocoapods": "cocoapods",
    "conancenter": "conan", "conan": "conan",
}


def family(ecosystem: str) -> str:
    value = (ecosystem or "").lower()
    return FAMILY.get(value, value or "unknown")


def package_name(ecosystem: str, name: str) -> str:
    """PyPI no distingue `-`, `_` ni `.` (PEP 503); los demás, solo mayúsculas en la práctica."""
    value = (name or "").strip().lower()
    return re.sub(r"[-_.]+", "-", value) if family(ecosystem) == "pypi" else value


# Package family → purl type (https://github.com/package-url/purl-spec).
PURL_TYPE = {"npm": "npm", "pypi": "pypi", "go": "golang", "cargo": "cargo", "composer": "composer",
             "rubygems": "gem", "maven": "maven", "nuget": "nuget", "pub": "pub", "hex": "hex"}


def purl(dependency: dict) -> str | None:
    kind = PURL_TYPE.get(family(dependency.get("ecosystem") or ""))
    name, version = str(dependency.get("name") or ""), str(dependency.get("version") or "")
    if not kind or not name or not version:
        return None
    if kind == "maven" and ":" in name:
        group, artifact = name.split(":", 1)
        path = f"{quote(group, safe='')}/{quote(artifact, safe='')}"
    elif kind in ("npm", "composer", "golang") and "/" in name:
        # npm con ámbito (@org/nombre), composer (vendor/nombre) y módulos de Go conservan sus segmentos.
        path = "/".join(quote(part, safe="") for part in name.split("/"))
    else:
        path = quote(name, safe="")
    return f"pkg:{kind}/{path}@{quote(version, safe='')}"


def canonical_id(identifiers: set[str], fallback: str) -> str:
    """El CVE si lo hay (es el nombre común entre bases de datos); si no, el identificador propio."""
    cves = sorted(item for item in identifiers if item.startswith("CVE-"))
    return cves[0] if cves else fallback


def identifiers(finding: dict) -> set[str]:
    advisory = finding.get("advisory") or {}
    return {item for item in (finding.get("rule_id"), advisory.get("id"), *(advisory.get("aliases") or []),
                              *(finding.get("cve") or []), *(finding.get("ghsa") or [])) if item}


def stable_fingerprint(identifier: str, aliases: set[str], ecosystem: str, name: str, version: str) -> str:
    """Huella de un aviso para motores nuevos: no depende de cómo nombre el aviso cada motor."""
    return fingerprint("sca", canonical_id(aliases | {identifier}, identifier), family(ecosystem),
                       package_name(ecosystem, name), version)


def _key(finding: dict) -> tuple[str, str, str]:
    package = finding.get("package") or {}
    ecosystem = package.get("ecosystem") or ""
    return family(ecosystem), package_name(ecosystem, package.get("name") or ""), str(package.get("version") or "")


def merge_dependencies(primary: list[dict], *others: tuple[str, list[dict]]) -> tuple[list[dict], dict]:
    """Une los avisos de dependencias de varios motores sin repetir ninguno.

    `primary` manda (sus huellas no cambian, y con ellas el triage y los tickets ya creados).
    Cada motor de `others` suma lo que los anteriores no vieron y, en lo que coincide, se anota
    en `also_detected_by`, completa identificadores y aporta la versión corregida si faltaba.
    """
    merged = list(primary)
    index: dict[tuple[str, str, str], list[dict]] = {}
    for finding in merged:
        index.setdefault(_key(finding), []).append(finding)
    stats = {"joined": 0, "new": 0}
    for tool, findings in others:
        for finding in findings:
            names = identifiers(finding)
            twin = next((item for item in index.get(_key(finding), []) if names & identifiers(item)), None)
            if twin is None:
                merged.append(finding)
                index.setdefault(_key(finding), []).append(finding)
                stats["new"] += 1
                continue
            if tool != twin.get("tool") and tool not in twin.setdefault("also_detected_by", []):
                twin["also_detected_by"].append(tool)
                twin["confidence"] = min(10, int(twin.get("confidence") or 6) + 1)
                stats["joined"] += 1
            twin["cve"] = sorted(set(twin.get("cve") or []) | set(finding.get("cve") or []))
            twin["ghsa"] = sorted(set(twin.get("ghsa") or []) | set(finding.get("ghsa") or []))
            advisory = twin.get("advisory")
            if isinstance(advisory, dict):
                advisory["aliases"] = sorted((set(advisory.get("aliases") or []) | names) - {advisory.get("id")})
            if not twin.get("source") and finding.get("source"):
                twin["source"] = finding["source"]
            package, other = twin.get("package") or {}, finding.get("package") or {}
            if not package.get("fixed_version") and other.get("fixed_version"):
                package["fixed_version"] = other["fixed_version"]
    return merged, stats
