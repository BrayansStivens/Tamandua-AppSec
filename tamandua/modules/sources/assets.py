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

from sqlalchemy import delete, func, select
from sqlalchemy.dialects.postgresql import insert

from tamandua.modules.sources.tables import repo_registry
from tamandua.shared import db, documents
from tamandua.shared import log as logging_setup
from tamandua.shared.db import TENANT

GRACE = timedelta(hours=24)
_log = logging_setup.get("assets")


def asset_key(record: dict) -> str:
    source = record.get("source") or {}
    return source.get("uid") or source.get("id") or source.get("name") or record.get("target") or "desconocido"


def load_registry(data_dir: Path) -> dict:
    """{uid: entry} of every registered repository."""
    with db.transaction(data_dir) as connection:
        return dict(connection.execute(select(repo_registry.c.uid, repo_registry.c.entry).where(repo_registry.c.tenant_id == TENANT)).all())


def _entry(connection, uid: str) -> dict | None:
    return connection.execute(select(repo_registry.c.entry).where(repo_registry.c.tenant_id == TENANT, repo_registry.c.uid == uid)).scalar_one_or_none()


def _put(connection, uid: str, entry: dict) -> None:
    statement = insert(repo_registry).values(tenant_id=TENANT, uid=uid, entry=entry)
    connection.execute(statement.on_conflict_do_update(index_elements=[repo_registry.c.tenant_id, repo_registry.c.uid],
                                                       set_={"entry": entry, "updated_at": func.now()}))


def import_document(data_dir: Path) -> int:
    """The `repo-registry` document of earlier versions → one row per repository (data migration). Returns how many."""
    payload = documents.load(data_dir, "repo-registry", None)
    if not isinstance(payload, dict):
        return 0
    with db.transaction(data_dir) as connection:
        db.lock(connection, "repo-registry")
        for uid, entry in payload.items():
            if isinstance(entry, dict) and _entry(connection, uid) is None:
                _put(connection, uid, entry)
    documents.delete(data_dir, "repo-registry")
    return len(payload)


def scan_branch(data_dir: Path, uid: str | None) -> str | None:
    """The branch platform scans read for this repository; None means its default branch."""
    if not uid:
        return None
    with db.transaction(data_dir) as connection:
        value = (_entry(connection, uid) or {}).get("scan_branch")
    return value if isinstance(value, str) and value else None


def set_scan_branch(data_dir: Path, uid: str, branch: str | None, *, name: str, source_id: str, by: str) -> None:
    """`branch` already validated against the repository; None goes back to the default branch."""
    with db.transaction(data_dir) as connection:
        db.lock(connection, "repo-registry")
        entry = _entry(connection, uid) or {}
        entry.update(name=name, source_id=source_id)
        if branch:
            entry.update(scan_branch=branch, scan_branch_by=by)
        else:
            entry.pop("scan_branch", None)
            entry.pop("scan_branch_by", None)
        _put(connection, uid, entry)
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
    with db.transaction(data_dir) as connection:
        db.lock(connection, "repo-registry")
        registry = dict(connection.execute(select(repo_registry.c.uid, repo_registry.c.entry).where(repo_registry.c.tenant_id == TENANT)).all())
        for uid in set(analysed) | set(registry):
            known_name = (registry.get(uid) or {}).get("name") or analysed.get(uid)
            if (active_accounts is not None and isinstance(known_name, str) and "/" in known_name
                    and known_name.split("/", 1)[0].casefold() not in active_accounts):
                # Desconectar una organización no equivale a borrar sus repositorios ni sus hallazgos.
                continue
            before = registry.get(uid)
            entry = dict(before or {})
            if uid in present:
                entry.update(name=present[uid]["name"], source_id=present[uid]["id"], last_seen=now.isoformat(timespec="seconds"))
                entry.pop("removed_at", None)
            elif not entry.get("removed_at"):
                entry["removed_at"] = now.isoformat(timespec="seconds")
                marked.append(uid)
                _log.warning("repo_removed_detected", extra={"reason": f"{entry.get('name', uid)} ya no está en la instalación"})
            elif datetime.fromisoformat(entry["removed_at"]) + GRACE <= now:
                purged.append(uid)
                continue
            if _changed(before, entry):
                _put(connection, uid, entry)  # only the repositories that changed are written
        if purged:
            connection.execute(delete(repo_registry).where(repo_registry.c.tenant_id == TENANT, repo_registry.c.uid.in_(purged)))
    return {"marked": marked, "purged": purged}


def _changed(before: dict | None, after: dict) -> bool:
    """Whether a registry entry needs writing. `last_seen` only counts when its day changes: every reconciliation
    sees every repository, and rewriting them all each time is what the table replaced."""
    def rest(entry: dict | None) -> dict:
        return {key: value for key, value in (entry or {}).items() if key != "last_seen"}
    return before is None or rest(before) != rest(after) or str(before.get("last_seen") or "")[:10] != str(after.get("last_seen") or "")[:10]


def forget(data_dir: Path, uid: str) -> None:
    """A purged repository leaves the registry (retirement mark, scan branch)."""
    with db.transaction(data_dir) as connection:
        connection.execute(delete(repo_registry).where(repo_registry.c.tenant_id == TENANT, repo_registry.c.uid == uid))
