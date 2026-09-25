"""Avisos nuevos sin reanalizar: una vez al día, las dependencias ya analizadas contra la base OSV actualizada.

Un CVE se publica mañana para una librería que ya usabas hoy. Sin esto, nadie se entera hasta el siguiente
análisis. Cada análisis completo guarda sus paquetes con versión (`dependencies`, de Trivy); aquí se
convierten en un SBOM CycloneDX y se pasan a OSV-Scanner **sin conexión**: se descargan las bases de avisos,
pero la lista de dependencias no sale de esta máquina.

Solo se abren avisos que el registro del activo no conocía (por identificador y paquete, en cualquier estado:
un riesgo aceptado no vuelve a abrirse con otro nombre). Se guardan como una ejecución `advisory_watch`, que
añade al registro y nunca remedia nada: el siguiente análisis completo manda. Los paquetes del sistema
operativo de una imagen no entran (su aviso depende de la versión de la distribución): esos llegan al
reanalizar la imagen.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

from . import logging_setup
from .dependency_merge import family, identifiers, package_name

_log = logging_setup.get("advisory_watch")
_lock = threading.Lock()

# Familia de paquete → tipo de purl (https://github.com/package-url/purl-spec).
PURL_TYPE = {"npm": "npm", "pypi": "pypi", "go": "golang", "cargo": "cargo", "composer": "composer",
             "rubygems": "gem", "maven": "maven", "nuget": "nuget", "pub": "pub", "hex": "hex"}


def hours() -> int:
    """Cada cuántas horas se contrasta (APPSEC_AGENT_ADVISORY_WATCH_HOURS; 0 lo apaga)."""
    try:
        return max(0, int(os.environ.get("APPSEC_AGENT_ADVISORY_WATCH_HOURS", "24") or 24))
    except ValueError:
        return 24


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


def sbom(dependencies: list[dict]) -> dict:
    components, seen = [], set()
    for item in dependencies:
        reference = purl(item)
        if reference and reference not in seen:
            seen.add(reference)
            components.append({"type": "library", "name": item["name"], "version": item["version"], "purl": reference})
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": components}


def _state_path(data_dir: Path) -> Path:
    return data_dir / "advisory-watch.json"


def load_state(data_dir: Path) -> dict:
    try:
        payload = json.loads(_state_path(data_dir).read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else {}
    except (FileNotFoundError, ValueError, OSError):
        return {}


def _save_state(data_dir: Path, state: dict) -> None:
    target = _state_path(data_dir)
    temporary = target.with_suffix(".tmp")
    temporary.write_text(json.dumps(state, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    os.replace(temporary, target)


def latest_complete(data_dir: Path) -> list[dict]:
    """El último análisis completo de cada repositorio o imagen que guarda sus dependencias."""
    from .assets import asset_key
    from .kinds import FULL_SCANS
    from .store import list_runs, load_run
    seen, result = set(), []
    for row in list_runs(data_dir):  # de más reciente a más antiguo
        if row["type"] not in FULL_SCANS or row["status"] != "completed":
            continue
        key = asset_key(row)
        if key in seen:
            continue
        seen.add(key)
        try:
            record = load_run(data_dir, row["id"])
        except (ValueError, OSError):
            continue
        if record.get("dependencies"):
            result.append(record)
    return result


def known(data_dir: Path, key: str) -> set[tuple[str, str, str, str]]:
    """(familia, paquete, versión, identificador) de todo lo que el registro ya conoce, en cualquier estado."""
    from .findings_registry import load
    result = set()
    for entry in load(data_dir, key).get("findings", {}).values():
        finding = entry.get("finding") or {}
        package = finding.get("package") or {}
        if finding.get("scanner") != "sca" or not package.get("name"):
            continue
        base = (family(package.get("ecosystem") or ""), package_name(package.get("ecosystem") or "", package["name"]), str(package.get("version") or ""))
        result |= {(*base, identifier) for identifier in identifiers(finding)}
    return result


def fresh(findings: list[dict], seen: set[tuple[str, str, str, str]]) -> list[dict]:
    new = []
    for finding in findings:
        package = finding.get("package") or {}
        base = (family(package.get("ecosystem") or ""), package_name(package.get("ecosystem") or "", package.get("name") or ""), str(package.get("version") or ""))
        if not any((*base, identifier) in seen for identifier in identifiers(finding)):
            new.append(finding)
    return new


def match(record: dict, *, data_dir: Path, feeds: dict, run=None) -> list[dict] | None:
    """Avisos de OSV-Scanner (sin conexión) para las dependencias guardadas de un análisis. None si no se pudo."""
    from .scanners import _run, docker_available, host_path, parse_osv_scanner, writable_cache
    document = sbom(record.get("dependencies") or [])
    if not document["components"]:
        return []
    if run is None and not docker_available():
        return None
    with tempfile.TemporaryDirectory(prefix="advisory-watch-") as folder:
        root = Path(folder)
        (root / "bom.cdx.json").write_text(json.dumps(document), encoding="utf-8")
        cache_dir = writable_cache(data_dir / "osv-cache")
        arguments = ["scan", "source", "-L", "/src/bom.cdx.json", "--format", "json", "--offline-vulnerabilities",
                     "--download-offline-databases", "--no-resolve"]
        try:
            completed = (run or _run)("osv-scanner", arguments, root, network=True, timeout=1800,
                                      env={"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": "/cache"},
                                      mounts=["-v", f"{host_path(cache_dir)}:/cache"])
        except (subprocess.TimeoutExpired, OSError):
            return None
        if completed.returncode not in (0, 1):
            return None
        if not completed.stdout.strip():
            return []
        try:
            payload = json.loads(completed.stdout)
        except ValueError:
            return None
    findings = parse_osv_scanner(payload, feeds)
    # El SBOM es un archivo temporal: cada aviso vuelve al manifiesto donde se declaró el paquete.
    where = {}
    for item in record.get("dependencies") or []:
        where.setdefault((package_name(item.get("ecosystem") or "", item["name"]), item["version"]), item.get("path") or "")
    for finding in findings:
        package = finding.get("package") or {}
        path = where.get((package_name(package.get("ecosystem") or "", package.get("name") or ""), package.get("version")))
        if path:
            original = str(finding.get("path") or "")
            finding["path"] = path
            if original:
                finding["remediation"] = str(finding.get("remediation") or "").replace(original, path)
        finding["tool"] = "osv-scanner"
    return findings


def check(data_dir: Path, *, run=None, now: datetime | None = None) -> dict:
    """Una pasada sobre todos los activos. Devuelve cuántos se revisaron y cuántos avisos nuevos se abrieron."""
    from .advisories import load_feeds
    from .assets import asset_key
    from .store import save_repository_scan
    now = now or datetime.now(timezone.utc)
    feeds = load_feeds(data_dir)
    checked = opened = failed = 0
    for record in latest_complete(data_dir):
        key = asset_key(record)
        findings = match(record, data_dir=data_dir, feeds=feeds, run=run)
        if findings is None:
            failed += 1
            continue
        checked += 1
        new = fresh(findings, known(data_dir, key))
        if not new:
            continue
        opened += len(new)
        source = record.get("source") or {}
        severities = {level: sum(1 for item in new if item.get("severity") == level) for level in ("critical", "high", "medium", "low", "info")}
        save_repository_scan(data_dir, {
            "type": "advisory_watch", "status": "completed", "source": source, "fixture": record.get("fixture") or source.get("name"),
            "variant": "advisories", "context": "", "requested_by": "vigilante",
            "trigger": {"kind": "advisories", "base_run": record["id"], "base_at": record.get("created_at")},
            "started_at": now.isoformat(timespec="seconds"), "finished_at": now.isoformat(timespec="seconds"),
            "steps": [{"id": "advisory-watch", "name": "Avisos nuevos (OSV-Scanner sin conexión)", "status": "completed",
                       "detail": f"{len(record.get('dependencies') or [])} paquetes del análisis del {str(record.get('created_at'))[:10]} "
                                 f"contrastados con la base OSV actualizada: {len(new)} avisos que no estaban."}],
            "findings": new, "owasp_coverage": [],
            "limitations": ["Solo dependencias de aplicación; los paquetes del sistema operativo de una imagen se revisan al reanalizarla.",
                            "No es un análisis completo: añade avisos y no da nada por corregido."],
            "summary": {"candidates": len(new), "sca": len(new), "files": 0, "dependencies": len(record.get("dependencies") or []),
                        "severities": severities, "kev": sum(1 for item in new if item.get("kev"))}})
        _log.info("advisory_watch_new", extra={"reason": f"{source.get('name')}: {len(new)} avisos nuevos"})
    with _lock:
        state = load_state(data_dir)
        state.update(last_run=now.isoformat(timespec="seconds"), checked=checked, opened=opened, failed=failed)
        _save_state(data_dir, state)
    return {"checked": checked, "opened": opened, "failed": failed}


class Watcher:
    """Hilo que contrasta los avisos una vez cada `hours()` horas. Tras reiniciar, respeta la última pasada."""

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, name="appsec-advisory-watch", daemon=True)

    def start(self) -> None:
        if hours():
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def due(self, now: datetime) -> bool:
        last = load_state(self.data_dir).get("last_run")
        try:
            return not last or now - datetime.fromisoformat(last) >= timedelta(hours=hours())
        except ValueError:
            return True

    def _loop(self) -> None:
        _log.info("advisory_watch_started", extra={"reason": f"cada {hours()} h"})
        delay = 600  # tras arrancar, deja que el panel y los motores se asienten
        while not self._stop.wait(delay):
            delay = 1800
            if not self.due(datetime.now(timezone.utc)):
                continue
            try:
                result = check(self.data_dir)
                _log.info("advisory_watch_done", extra={"reason": f"{result['checked']} activos, {result['opened']} avisos nuevos, "
                                                                  f"{result['failed']} sin poder contrastar"})
            except Exception:  # noqa: BLE001 — un fallo no debe matar al vigilante
                _log.exception("advisory_watch_failed")
