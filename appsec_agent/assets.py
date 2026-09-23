"""Identidad de los repositorios y limpieza de los que desaparecen.

Un repositorio de GitHub se identifica por su id numérico (`github#123`), que no
cambia al renombrarlo ni al transferirlo: así un rename no parte en dos sus
hallazgos, su triage, sus tickets ni su vigilancia de PRs. Lo demás (workspace
local, GitLab) usa el id de la fuente.

Si un repositorio deja de estar en la instalación —se borró en GitHub o se quitó
del acceso de la App— se marca como retirado y, pasado un margen, se borra todo lo
suyo. El margen existe porque una lista incompleta o un error transitorio de GitHub
no deben destruir datos: solo se reconcilia con una lista leída entera.
"""

from __future__ import annotations

import json
import os
import shutil
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .kinds import FINDING_RUNS, FULL_SCANS
from . import logging_setup

GRACE = timedelta(hours=24)
_log = logging_setup.get("assets")
_lock = threading.Lock()


def asset_key(record: dict) -> str:
    source = record.get("source") or {}
    return source.get("uid") or source.get("id") or source.get("name") or record.get("fixture") or "desconocido"


def _registry_path(data_dir: Path) -> Path:
    return data_dir / "repo-registry.json"


def load_registry(data_dir: Path) -> dict:
    try:
        payload = json.loads(_registry_path(data_dir).read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError, OSError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _write_json(path: Path, payload) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def backfill(data_dir: Path, repositories: list[dict]) -> int:
    """Ejecuciones guardadas antes de la identidad estable: se les pone su `uid` y se mueven triage y tickets."""
    from .store import _run_dir, list_runs, update_index
    uid_of = {item["id"]: item["uid"] for item in repositories if item.get("uid")}
    moved: dict[str, str] = {}
    updated = 0
    for row in list_runs(data_dir):
        source = row.get("source") or {}
        if source.get("uid") or source.get("id") not in uid_of:
            continue
        path = _run_dir(data_dir, row["id"]) / "run.json"
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        record.setdefault("source", {})["uid"] = uid_of[source["id"]]
        _write_json(path, record)
        update_index(data_dir, record)
        moved[source["id"]] = uid_of[source["id"]]
        updated += 1
    for name in ("triage.json", "jira-links.json"):
        target = data_dir / name
        try:
            payload = json.loads(target.read_text(encoding="utf-8"))
        except (FileNotFoundError, ValueError, OSError):
            continue
        changed = False
        for old_key, uid in moved.items():
            if old_key in payload:
                merged = payload.pop(old_key)
                payload[uid] = {**merged, **payload.get(uid, {})}
                changed = True
        if changed:
            _write_json(target, payload)
    if updated:
        _log.info("assets_backfilled", extra={"reason": f"{updated} ejecuciones con identidad estable"})
    return updated


def reconcile(data_dir: Path, repositories: list[dict], *, now: datetime | None = None) -> dict:
    """Compara lo analizado con la lista COMPLETA de la instalación. Devuelve qué se marcó y qué se borró."""
    from .store import list_runs
    now = now or datetime.now(timezone.utc)
    backfill(data_dir, repositories)
    present = {item["uid"]: item for item in repositories if item.get("uid")}
    analysed = {asset_key(row) for row in list_runs(data_dir) if asset_key(row).startswith("github#")}
    purged, marked = [], []
    with _lock:
        registry = load_registry(data_dir)
        for uid in analysed | set(registry):
            entry = registry.setdefault(uid, {})
            if uid in present:
                entry.update(name=present[uid]["name"], source_id=present[uid]["id"], last_seen=now.isoformat(timespec="seconds"))
                entry.pop("removed_at", None)
                continue
            if not entry.get("removed_at"):
                entry["removed_at"] = now.isoformat(timespec="seconds")
                marked.append(uid)
                _log.warning("repo_removed_detected", extra={"reason": f"{entry.get('name', uid)} ya no está en la instalación"})
            elif datetime.fromisoformat(entry["removed_at"]) + GRACE <= now:
                purged.append(uid)
        for uid in purged:
            registry.pop(uid, None)
        _write_json(_registry_path(data_dir), registry)
    for uid in purged:
        purge(data_dir, uid)
    return {"marked": marked, "purged": purged}


def purge(data_dir: Path, uid: str) -> int:
    """Borra ejecuciones, triage, tickets enlazados y vigilancia de un repositorio. Devuelve ejecuciones borradas."""
    from . import jira, pr_watch, triage
    from .store import _run_dir, list_runs, rebuild_index
    removed = 0
    for row in list_runs(data_dir):
        if asset_key(row) == uid:
            shutil.rmtree(_run_dir(data_dir, row["id"]), ignore_errors=True)
            removed += 1
    rebuild_index(data_dir)
    for path in (data_dir / "triage.json", data_dir / "jira-links.json"):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, ValueError, OSError):
            continue
        if payload.pop(uid, None) is not None:
            _write_json(path, payload)
    pr_watch.forget(data_dir, uid)
    _log.warning("repo_purged", extra={"reason": f"{uid}: {removed} ejecuciones borradas"})
    return removed


def overview(data_dir: Path, *, query: str | None = None) -> list[dict]:
    """Un renglón por repositorio analizado: su último escaneo completo, lo pendiente y si GitHub lo retiró."""
    from . import triage
    from .store import list_runs, load_run
    registry = load_registry(data_dir)
    decisions = triage.load(data_dir)
    groups: dict[str, dict] = {}
    for row in list_runs(data_dir):  # del más reciente al más antiguo
        if row["type"] not in FINDING_RUNS:
            continue
        key = asset_key(row)
        entry = groups.setdefault(key, {"key": key, "name": (row.get("source") or {}).get("name"), "provider": (row.get("source") or {}).get("provider"),
                                        "source_id": (row.get("source") or {}).get("id"), "scans": 0, "pr_reviews": 0,
                                        "last_activity": row["created_at"], "latest_scan": None,
                                        "removed_at": (registry.get(key) or {}).get("removed_at")})
        entry["scans" if row["type"] in FULL_SCANS else "pr_reviews"] += 1
        if row["type"] in FULL_SCANS and entry["latest_scan"] is None and row["status"] in ("completed", "incomplete"):
            entry["latest_scan"] = {"run_id": row["id"], "created_at": row["created_at"], "status": row["status"]}
    from .findings_registry import summarize
    for key, entry in groups.items():
        # Lo pendiente sale del registro: escaneos y PRs juntos, menos lo remediado y lo descartado.
        counts = summarize(data_dir, key)
        entry["open"] = {"total": counts["open"], **counts["by_severity"], "from_pr": counts["from_pr"],
                         "fixed": counts["fixed"], "suppressed": counts["suppressed"]}
    rows = sorted(groups.values(), key=lambda item: item["last_activity"], reverse=True)
    if query:
        needle = query.strip().lower()
        rows = [item for item in rows if needle in (item["name"] or "").lower()]
    return rows
