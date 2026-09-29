"""One dependency advisory, one finding: even when several engines detect it and each names it differently.

Trivy usually identifies an advisory by its CVE; OSV-Scanner by its GHSA or PYSEC, with the CVE as an
alias. And each writes the ecosystem its own way (`pip`, `poetry`, `PyPI`…). This normalizes all of
that to recognize the same advisory on the same package and the same version.
"""

from __future__ import annotations

from urllib.parse import quote

from tamandua.modules.intel.packages import FAMILY, canonical_id, dependency_fingerprint, family, package_name  # noqa: F401  (re-exported)


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
        # Scoped npm (@org/name), composer (vendor/name) and Go modules keep their segments.
        path = "/".join(quote(part, safe="") for part in name.split("/"))
    else:
        path = quote(name, safe="")
    return f"pkg:{kind}/{path}@{quote(version, safe='')}"


def identifiers(finding: dict) -> set[str]:
    advisory = finding.get("advisory") or {}
    return {item for item in (finding.get("rule_id"), advisory.get("id"), *(advisory.get("aliases") or []),
                              *(finding.get("cve") or []), *(finding.get("ghsa") or [])) if item}


def stable_fingerprint(identifier: str, aliases: set[str], ecosystem: str, name: str, version: str) -> str:
    return dependency_fingerprint(aliases, identifier, ecosystem, name, version)


def _key(finding: dict) -> tuple[str, str, str]:
    package = finding.get("package") or {}
    ecosystem = package.get("ecosystem") or ""
    return family(ecosystem), package_name(ecosystem, package.get("name") or ""), str(package.get("version") or "")


def merge_dependencies(primary: list[dict], *others: tuple[str, list[dict]]) -> tuple[list[dict], dict]:
    """Merges the dependency advisories of several engines without repeating any.

    `primary` wins (its fingerprints don't change, and with them the triage and tickets already created).
    Each engine in `others` adds what the previous ones didn't see and, where they match, is recorded
    in `also_detected_by`, fills in identifiers and supplies the fixed version if it was missing.
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
