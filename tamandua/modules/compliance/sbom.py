"""CycloneDX 1.6 SBOM built from the inventory every complete scan already stores.

Nothing is scanned again: Trivy lists every package (not only the vulnerable ones) and each scan stores them in
`dependencies` (and, for images, `system_packages`). Here they are turned into the format the CRA (Annex I) and the
BSI TR-03183-2 guideline ask for: purl, version, licenses when known, direct relationship to the product, plus tool,
author and generation time. What we don't know (each package's supplier, per-component hashes) is not made up: it
is left out, and the document says where it comes from in `metadata.properties`.

Tolerant readers: scans from before purl, licenses or the relationship were stored still work; the purl is rebuilt
from the ecosystem and the relationship stays undeclared.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from typing import Any
from urllib.parse import quote
from datetime import datetime, timezone
from pathlib import Path

from tamandua.modules.scanning.dependency_merge import purl as build_purl
from tamandua.modules.reporting.design import coverage_gaps
from tamandua.shared.i18n import default_locale, t

SPEC = "1.6"
TOOL_URL = "https://github.com/BrayansStivens/Tamandua-AppSec"


def _stamp(now: datetime | None) -> str:
    return (now or datetime.now(timezone.utc)).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def root_ref(record: Mapping[str, Any]) -> str:
    """Stable identifier of the scanned product, for the SBOM and the VEX."""
    source = record.get("source") or {}
    image = source.get("image") or {}
    if image.get("reference"):
        return f"oci:{image['reference']}"
    name = str(source.get("name") or source.get("id") or "producto")
    return f"pkg:github/{name}" if source.get("provider") == "github" and "/" in name else f"urn:tamandua:{source.get('id') or name}"


def _root(record: dict) -> dict:
    source = record.get("source") or {}
    image = source.get("image") or {}
    component = {"type": "container" if image else "application", "bom-ref": root_ref(record), "name": str(source.get("name") or "producto")}
    version = image.get("resolved_digest") or (record.get("pull_request") or {}).get("head_sha") or source.get("commit")
    if version:
        component["version"] = str(version)
    if source.get("sha256"):
        # Hash of the scanned snapshot (the file tree), not of a published binary.
        component["hashes"] = [{"alg": "SHA-256", "content": source["sha256"]}]
    identity = [("tamandua:uid", source.get("uid")), ("tamandua:image", image.get("reference")),
                ("tamandua:branch", source.get("branch")), ("tamandua:commit", source.get("commit"))]
    if any(value for _, value in identity):
        component["properties"] = [{"name": name, "value": str(value)} for name, value in identity if value]
    return component


# An image's system packages: purl type by distribution (no architecture qualifiers, since those aren't stored).
OS_PURL = {"debian": ("deb", "debian"), "ubuntu": ("deb", "ubuntu"), "alpine": ("apk", "alpine"), "wolfi": ("apk", "wolfi"),
           "chainguard": ("apk", "chainguard"), "redhat": ("rpm", "redhat"), "centos": ("rpm", "centos"), "rocky": ("rpm", "rocky"),
           "alma": ("rpm", "almalinux"), "amazon": ("rpm", "amazon"), "oracle": ("rpm", "oracle"), "fedora": ("rpm", "fedora"),
           "suse": ("rpm", "suse"), "opensuse": ("rpm", "opensuse"), "photon": ("rpm", "photon"), "azurelinux": ("rpm", "azurelinux")}


def _purl(package: dict) -> str | None:
    if package.get("purl"):
        return str(package["purl"])
    distro = OS_PURL.get(str(package.get("ecosystem") or "").lower().split(":")[0])
    if distro:
        return f"pkg:{distro[0]}/{distro[1]}/{quote(str(package['name']), safe='')}@{quote(str(package['version']), safe='')}"
    return build_purl(package)


def _inventory(record: dict):
    """(package, is_system) from the inventory and, if anything is missing (old scans, repositories where Trivy
    listed no packages), the packages of the dependency findings: never an SBOM without what we know is vulnerable."""
    yield from ((package, False) for package in record.get("dependencies") or [])
    yield from ((package, True) for package in record.get("system_packages") or [])
    for finding in record.get("findings") or []:
        package = finding.get("package") or {}
        if finding.get("scanner") == "sca" and package.get("name") and package.get("version"):
            yield ({**package, "path": finding.get("path"), **({"direct": package["direct"]} if isinstance(package.get("direct"), bool) else {})},
                   str(package.get("ecosystem") or "").lower().split(":")[0] in OS_PURL)


def _component(package: dict, reference: str, system: bool, locale: str) -> dict:
    component = {"type": "library", "bom-ref": reference, "name": package["name"], "version": package["version"], "purl": reference}
    licenses = [{"license": {"name": name}} for name in package.get("licenses") or [] if name]
    if licenses:
        component["licenses"] = licenses
    properties = [{"name": "tamandua:manifest", "value": str(package.get("path") or "")}] if package.get("path") else []
    if system:
        properties.append({"name": "tamandua:package-kind", "value": t("compliance.sbom.os_package", locale)})
    if properties:
        component["properties"] = properties
    return component


def cyclonedx(record: dict, *, version: str, now: datetime | None = None, locale: str | None = None) -> dict:
    """The SBOM of a complete scan. A scan without an inventory yields an SBOM with no components, never an error."""
    locale = locale or default_locale()
    root = _root(record)
    components: dict[str, dict] = {}
    direct: list[str] = []
    known_relation = False
    for package, system in _inventory(record):
        if not isinstance(package, dict) or not package.get("name") or not package.get("version"):
            continue
        reference = _purl(package)
        if not reference or reference in components:
            continue
        components[reference] = _component(package, reference, system, locale)
        if isinstance(package.get("direct"), bool):
            known_relation = True
        if package.get("direct", True) is not False:
            direct.append(reference)
    # Without relationship info (old scans or images), the product depends on everything in the inventory.
    depends_on = direct if known_relation else list(components)
    gaps = coverage_gaps(record.get("steps") or [], locale=locale)
    stamp = _stamp(now)
    scanned = record.get("finished_at") or record.get("created_at")
    return {
        "$schema": f"http://cyclonedx.org/schema/bom-{SPEC}.schema.json", "bomFormat": "CycloneDX", "specVersion": SPEC,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {
            "timestamp": stamp,
            "lifecycles": [{"phase": "post-build" if root["type"] == "container" else "pre-build"}],
            "tools": {"components": [{"type": "application", "name": "Tamandua", "version": version,
                                      "externalReferences": [{"type": "website", "url": TOOL_URL}]}]},
            "authors": [{"name": "Tamandua"}],
            "component": root,
            "properties": [
                {"name": "tamandua:run", "value": str(record.get("id") or "")},
                {"name": "tamandua:scanned", "value": str(scanned or "")},
                *([{"name": "tamandua:incomplete", "value": ", ".join(gaps)}] if gaps else []),
                {"name": "tamandua:origin", "value": t("compliance.sbom.origin_image" if root["type"] == "container"
                                                       else "compliance.sbom.origin", locale)},
            ],
        },
        "components": list(components.values()),
        "dependencies": [{"ref": root["bom-ref"], "dependsOn": depends_on}],
        # If an engine didn't finish, the inventory may be incomplete: declare it, never present it as complete.
        **({"compositions": [{"aggregate": "incomplete", "assemblies": [root["bom-ref"]]}]} if gaps else {}),
    }


def latest_scan(data_dir: Path, key: str) -> dict | None:
    """The latest complete scan of an asset: the SBOM of its current state comes from it."""
    from tamandua.modules.findings.kinds import FULL_SCANS
    from tamandua.modules.runs.store import find_runs, load_run
    for row in find_runs(data_dir, types=FULL_SCANS, statuses=("completed",), assets=[key], limit=1):
        try:
            return load_run(data_dir, row["id"])
        except (ValueError, OSError):
            return None
    return None


# A portfolio SBOM or VEX holds at most this many assets and packages; past it the document says what was left out.
PORTFOLIO_ASSETS = 200
PORTFOLIO_COMPONENTS = 20_000


def portfolio(assets: list[dict], *, total: int, name: str, version: str, now: datetime | None = None,
              locale: str | None = None) -> dict:
    """One SBOM for several assets (`{"key", "ref", "scan"}`, `ref` unique): each asset is a top-level component with
    its packages nested and linked through `dependencies`, built with `cyclonedx()`. Nothing is deduplicated across
    assets, so bom-refs get the asset's ref as prefix. `total` counts every asset with a complete scan."""
    locale = locale or default_locale()
    root = {"type": "application", "bom-ref": "urn:tamandua:portfolio", "name": name}
    components, graph, partial, phases = [], [], [], set()
    budget, kept_total, cut = PORTFOLIO_COMPONENTS, 0, False
    for asset in assets:
        if budget <= 0:
            break
        document = cyclonedx(asset["scan"], version=version, now=now, locale=locale)
        ref, packages = asset["ref"], document["components"]
        kept = packages[:budget]
        budget -= len(kept)
        kept_total += len(kept)
        refs = {package["bom-ref"] for package in kept}
        own = document["metadata"]["component"]
        properties = [*own.get("properties", []), {"name": "tamandua:asset", "value": asset["key"]}, *document["metadata"]["properties"]]
        if len(kept) < len(packages):
            cut = True
            properties.append({"name": "tamandua:truncated",
                               "value": t("compliance.sbom.asset_truncated", locale, shown=len(kept), total=len(packages))})
        component = {**own, "bom-ref": ref, "properties": properties}
        if kept:
            component["components"] = [{**package, "bom-ref": f"{ref}|{package['bom-ref']}"} for package in kept]
        components.append(component)
        graph.append({"ref": ref, "dependsOn": [f"{ref}|{item}" for item in document["dependencies"][0]["dependsOn"] if item in refs]})
        phases.update(phase["phase"] for phase in document["metadata"]["lifecycles"])
        if len(kept) < len(packages) or document.get("compositions"):
            partial.append(ref)
    missing = total - len(components)
    notes = [{"name": "tamandua:assets", "value": str(len(components))}, {"name": "tamandua:components", "value": str(kept_total)}]
    if missing > 0:
        notes.append({"name": "tamandua:truncated", "value": t("compliance.sbom.portfolio_truncated", locale, shown=len(components), total=total,
                                                             max_assets=PORTFOLIO_ASSETS, max_components=PORTFOLIO_COMPONENTS)})
    elif cut:
        notes.append({"name": "tamandua:truncated", "value": t("compliance.sbom.components_truncated", locale, max_components=PORTFOLIO_COMPONENTS)})
    incomplete = partial + ([root["bom-ref"]] if missing > 0 else [])
    return {
        "$schema": f"http://cyclonedx.org/schema/bom-{SPEC}.schema.json", "bomFormat": "CycloneDX", "specVersion": SPEC,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {
            "timestamp": _stamp(now),
            "lifecycles": [{"phase": phase} for phase in sorted(phases)],
            "tools": {"components": [{"type": "application", "name": "Tamandua", "version": version,
                                      "externalReferences": [{"type": "website", "url": TOOL_URL}]}]},
            "authors": [{"name": "Tamandua"}],
            "component": root,
            "properties": [*notes, {"name": "tamandua:origin", "value": t("compliance.sbom.origin_portfolio", locale)}],
        },
        "components": components,
        "dependencies": [{"ref": root["bom-ref"], "dependsOn": [item["bom-ref"] for item in components]}, *graph],
        **({"compositions": [{"aggregate": "incomplete", "assemblies": incomplete}]} if incomplete else {}),
    }
