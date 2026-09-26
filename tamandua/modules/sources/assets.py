"""Identidad de los repositorios y su registro (rama de análisis, retirada).

Un repositorio de GitHub se identifica por su id numérico (`github#123`), que no
cambia al renombrarlo ni al transferirlo: así un rename no parte en dos sus
hallazgos, su triage, sus tickets ni su vigilancia de PRs. Lo demás (workspace
local, GitLab) usa el id de la fuente.

Si un repositorio deja de estar en la instalación —se borró en GitHub o se quitó
del acceso de la App— se marca como retirado y, pasado un margen, se borra todo lo
suyo. El margen existe porque una lista incompleta o un error transitorio de GitHub
no deben destruir datos: solo se reconcilia con una lista leída entera. The
reconciliation against the runs and the purge are orchestrated by `runs/assets.py`.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

from tamandua.shared import documents
from tamandua.shared import log as logging_setup

GRACE = timedelta(hours=24)
_log = logging_setup.get("assets")


def asset_key(record: dict) -> str:
    source = record.get("source") or {}
    return source.get("uid") or source.get("id") or source.get("name") or record.get("target") or "desconocido"


def load_registry(data_dir: Path) -> dict:
    payload = documents.load(data_dir, "repo-registry", {})
    return payload if isinstance(payload, dict) else {}


def scan_branch(data_dir: Path, uid: str | None) -> str | None:
    """The branch platform scans read for this repository; None means its default branch."""
    value = (load_registry(data_dir).get(uid) or {}).get("scan_branch") if uid else None
    return value if isinstance(value, str) and value else None


def set_scan_branch(data_dir: Path, uid: str, branch: str | None, *, name: str, source_id: str, by: str) -> None:
    """`branch` already validated against the repository; None goes back to the default branch."""
    with documents.lock(data_dir, "repo-registry"):
        registry = load_registry(data_dir)
        entry = registry.setdefault(uid, {})
        entry.update(name=name, source_id=source_id)
        if branch:
            entry.update(scan_branch=branch, scan_branch_by=by)
        else:
            entry.pop("scan_branch", None)
            entry.pop("scan_branch_by", None)
        documents.save(data_dir, "repo-registry", registry)
    _log.info("scan_branch_configured", extra={"user": by, "reason": f"{uid}: {branch or 'default'}"})


def with_scan_branches(data_dir: Path, rows: list[dict]) -> list[dict]:
    """Repository rows with the branch scans read (`scan_branch`, None = default) and the default one."""
    registry = load_registry(data_dir)
    result = []
    for row in rows:
        stored = (registry.get(row.get("uid")) or {}).get("scan_branch") if row.get("uid") else None
        result.append({**row, "default_branch": row.get("branch"), "scan_branch": stored if isinstance(stored, str) and stored else None})
    return result


def retire(data_dir: Path, repositories: list[dict], analysed: dict[str, str | None], *, now: datetime,
           active_accounts: set[str] | None = None) -> dict:
    """Compares the analysed repositories (uid → name) with the COMPLETE installation list: the missing ones are
    marked removed; those past the grace period leave the registry and are returned in `purged` (the caller purges
    their data). Returns {"marked", "purged"}."""
    present = {item["uid"]: item for item in repositories if item.get("uid")}
    purged, marked = [], []
    with documents.lock(data_dir, "repo-registry"):
        registry = load_registry(data_dir)
        for uid in set(analysed) | set(registry):
            known_name = (registry.get(uid) or {}).get("name") or analysed.get(uid)
            if (active_accounts is not None and isinstance(known_name, str) and "/" in known_name
                    and known_name.split("/", 1)[0].casefold() not in active_accounts):
                # Desconectar una organización no equivale a borrar sus repositorios ni sus hallazgos.
                continue
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
        documents.save(data_dir, "repo-registry", registry)
    return {"marked": marked, "purged": purged}


def forget(data_dir: Path, uid: str) -> None:
    """A purged repository leaves the registry (retirement mark, scan branch)."""
    with documents.edit(data_dir, "repo-registry", {}) as registry:
        registry.pop(uid, None)
