"""SBOM en CycloneDX 1.6 a partir del inventario que ya guarda cada análisis completo.

No se vuelve a analizar nada: Trivy lista todos los paquetes (no solo los vulnerables) y cada análisis los guarda
en `dependencies` (y, en imágenes, `system_packages`). Aquí se convierten al formato que piden el CRA (Anexo I) y la
guía BSI TR-03183-2: purl, versión, licencias cuando se conocen, relación directa con el producto y herramienta,
autor y momento de generación. Lo que no sabemos (proveedor de cada paquete, hashes de cada componente) no se
inventa: se omite, y el documento dice de dónde sale en `metadata.properties`.

Lectores tolerantes: análisis anteriores a que se guardaran purl, licencias o la relación siguen sirviendo; el purl
se reconstruye desde el ecosistema y la relación queda sin declarar.
"""

from __future__ import annotations

import uuid
from urllib.parse import quote
from datetime import datetime, timezone
from pathlib import Path

from tamandua.modules.intel.advisory_watch import purl as build_purl
from tamandua.modules.reporting.design import coverage_gaps
from tamandua.shared.i18n import default_locale, t

SPEC = "1.6"
TOOL_URL = "https://github.com/BrayansStivens/appsec-agent"


def root_ref(record: dict) -> str:
    """Identificador estable del producto analizado, para el SBOM y para el VEX."""
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
    version = image.get("resolved_digest") or (record.get("pull_request") or {}).get("head_sha")
    if version:
        component["version"] = str(version)
    if source.get("sha256"):
        # Huella de la instantánea analizada (el árbol de archivos), no de un binario publicado.
        component["hashes"] = [{"alg": "SHA-256", "content": source["sha256"]}]
    return component


# Paquetes del sistema de una imagen: tipo de purl según la distribución (sin cualificadores de arquitectura, que no se guardan).
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
    """(paquete, es_del_sistema) del inventario y, si faltara algo (análisis antiguos, repositorios donde Trivy no
    listó paquetes), los paquetes de los hallazgos de dependencias: nunca un SBOM sin lo que sí sabemos vulnerable."""
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
    """El SBOM de un análisis completo. Un análisis sin inventario da un SBOM sin componentes, nunca un error."""
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
    # Sin información de relación (análisis antiguos o imágenes), el producto depende de todo lo inventariado.
    depends_on = direct if known_relation else list(components)
    gaps = coverage_gaps(record.get("steps") or [], locale=locale)
    stamp = (now or datetime.now(timezone.utc)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
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
        # Si algún motor no terminó, el inventario puede estar incompleto: se declara, nunca se da por completo.
        **({"compositions": [{"aggregate": "incomplete", "assemblies": [root["bom-ref"]]}]} if gaps else {}),
    }


def latest_scan(data_dir: Path, key: str) -> dict | None:
    """El último análisis completo de un activo: de él sale el SBOM del estado actual."""
    from tamandua.modules.sources.assets import asset_key
    from tamandua.modules.runs.kinds import FULL_SCANS
    from tamandua.modules.runs.store import list_runs, load_run
    for row in list_runs(data_dir):  # de más reciente a más antiguo
        if row["type"] in FULL_SCANS and row["status"] == "completed" and asset_key(row) == key:
            try:
                return load_run(data_dir, row["id"])
            except (ValueError, OSError):
                return None
    return None
