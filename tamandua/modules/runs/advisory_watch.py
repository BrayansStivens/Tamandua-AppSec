"""New advisories without rescanning: once a day, already-scanned dependencies against the updated OSV database.

A CVE is published tomorrow for a library you already used today. Without this, nobody finds out until the next
scan. Each full scan keeps its packages with their versions (`dependencies`, from Trivy); here they become a
CycloneDX SBOM that goes to OSV-Scanner **offline**: the advisory databases are downloaded, but the dependency
list never leaves this machine.

Only advisories the asset's registry didn't know are opened (by identifier and package, in any state: an
accepted risk isn't reopened under another name). They are saved as an `advisory_watch` run, which adds to the
registry and never remediates anything: the next full scan takes over. An image's operating system packages
are left out (their advisories depend on the distribution version): those arrive when the image is
rescanned.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from tamandua.modules.findings import registry
from tamandua.modules.findings.kinds import FULL_SCANS
from tamandua.modules.intel.advisories import load_feeds
from tamandua.modules.runs.store import find_runs, load_run, save_repository_scan
from tamandua.modules.scanning import engines
from tamandua.modules.scanning.dependency_merge import family, identifiers, package_name, purl
from tamandua.modules.sources.assets import asset_key
from tamandua.shared import documents, settings
from tamandua.shared import log as logging_setup
from tamandua.shared.i18n import INLINE, MARK, msg

_log = logging_setup.get("advisory_watch")


def hours() -> int:
    """How many hours between checks (TAMANDUA_ADVISORY_WATCH_HOURS; 0 turns it off)."""
    try:
        return settings.integer("TAMANDUA_ADVISORY_WATCH_HOURS")
    except ValueError:
        return 24


def sbom(dependencies: list[dict]) -> dict:
    components, seen = [], set()
    for item in dependencies:
        reference = purl(item)
        if reference and reference not in seen:
            seen.add(reference)
            components.append({"type": "library", "name": item["name"], "version": item["version"], "purl": reference})
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": components}


def load_state(data_dir: Path) -> dict:
    payload = documents.load(data_dir, "advisory-watch", {})
    return payload if isinstance(payload, dict) else {}


def _save_state(data_dir: Path, state: dict) -> None:
    documents.save(data_dir, "advisory-watch", state)


def latest_complete(data_dir: Path) -> list[dict]:
    """The latest full scan of each repository or image that keeps its dependencies."""
    seen, result = set(), []
    for row in find_runs(data_dir, types=FULL_SCANS, statuses=("completed",)):  # newest first
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
    """(family, package, version, identifier) of everything the registry already knows, in any state."""
    result = set()
    for entry in registry.load(data_dir, key).get("findings", {}).values():
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


def _repath(value, old: str, new: str):
    """Replaces a path inside plain text, a message's parameters or inline text, keeping the value's shape."""
    if isinstance(value, str):
        return value.replace(old, new)
    if isinstance(value, dict) and isinstance(value.get(MARK), str):
        return {**value, "params": {name: _repath(item, old, new) for name, item in (value.get("params") or {}).items()}}
    if isinstance(value, dict) and isinstance(value.get(INLINE), dict):
        return {INLINE: {locale: _repath(item, old, new) for locale, item in value[INLINE].items()}}
    return value


def match(record: dict, *, data_dir: Path, feeds: dict, run=None) -> list[dict] | None:
    """OSV-Scanner advisories (offline) for a scan's saved dependencies. None if it couldn't run."""
    document = sbom(record.get("dependencies") or [])
    if not document["components"]:
        return []
    if run is None and not engines.engine_ready("osv-scanner"):
        return None
    # Under data/ (a host bind mount): the engine runs as a sibling container and mounts it by its host path.
    work = data_dir / "work"
    work.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="advisory-watch-", dir=work) as folder:
        root = Path(folder)
        (root / "bom.cdx.json").write_text(json.dumps(document), encoding="utf-8")
        cache_dir = engines.writable_cache(data_dir / "osv-cache")
        arguments = ["scan", "source", "-L", "/src/bom.cdx.json", "--format", "json", "--offline-vulnerabilities",
                     "--download-offline-databases", "--no-resolve"]
        try:
            completed = (run or engines._run)("osv-scanner", arguments, root, network=True, timeout=1800,
                                      env={"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": "/cache"},
                                      mounts=["-v", f"{engines.host_path(cache_dir)}:/cache"])
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
    findings = engines.parse_osv_scanner(payload, feeds)
    # The SBOM is a temporary file: each advisory goes back to the manifest that declared the package.
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
                finding["remediation"] = _repath(finding.get("remediation") or "", original, path)
        finding["tool"] = "osv-scanner"
    return findings


def check(data_dir: Path, *, run=None, now: datetime | None = None) -> dict:
    """One pass over every asset. Returns how many were checked and how many new advisories were opened."""
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
            "type": "advisory_watch", "status": "completed", "source": source, "target": record.get("target") or source.get("name"),
            "variant": "advisories", "context": "", "requested_by": "vigilante",
            "trigger": {"kind": "advisories", "base_run": record["id"], "base_at": record.get("created_at")},
            "started_at": now.isoformat(timespec="seconds"), "finished_at": now.isoformat(timespec="seconds"),
            "steps": [{"id": "advisory-watch", "name": msg("intel.watch.step"), "status": "completed",
                       "detail": msg("intel.watch.detail", packages=len(record.get("dependencies") or []),
                                     date=str(record.get("created_at"))[:10], count=len(new))}],
            "findings": new, "owasp_coverage": [],
            "limitations": [msg("intel.watch.limitations.os_packages"), msg("intel.watch.limitations.not_full")],
            "summary": {"candidates": len(new), "sca": len(new), "files": 0, "dependencies": len(record.get("dependencies") or []),
                        "severities": severities, "kev": sum(1 for item in new if item.get("kev"))}})
        _log.info("advisory_watch_new", extra={"reason": f"{source.get('name')}: {len(new)} avisos nuevos"})
    with documents.lock(data_dir, "advisory-watch"):
        state = load_state(data_dir)
        state.update(last_run=now.isoformat(timespec="seconds"), checked=checked, opened=opened, failed=failed)
        _save_state(data_dir, state)
    return {"checked": checked, "opened": opened, "failed": failed}


class Watcher:
    """Thread that checks advisories once every `hours()` hours. After a restart, it honors the last pass."""

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, name="tamandua-advisory-watch", daemon=True)

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
        delay = 600  # after startup, let the panel and the engines settle
        while not self._stop.wait(delay):
            delay = 1800
            if not self.due(datetime.now(timezone.utc)):
                continue
            try:
                result = check(self.data_dir)
                _log.info("advisory_watch_done", extra={"reason": f"{result['checked']} activos, {result['opened']} avisos nuevos, "
                                                                  f"{result['failed']} sin poder contrastar"})
            except Exception:  # noqa: BLE001 — a failure must not kill the watcher
                _log.exception("advisory_watch_failed")
