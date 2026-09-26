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

from datetime import datetime, timedelta, timezone
from pathlib import Path

from tamandua.shared import documents
from tamandua.modules.runs.kinds import FINDING_RUNS, FULL_SCANS
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


def backfill(data_dir: Path, repositories: list[dict]) -> int:
    """Ejecuciones guardadas antes de la identidad estable: se les pone su `uid` y se mueven triage y tickets."""
    from tamandua.modules.findings import triage
    from tamandua.modules.runs.store import list_runs, load_run, save_record
    uid_of = {item["id"]: item["uid"] for item in repositories if item.get("uid")}
    moved: dict[str, str] = {}
    updated = 0
    for row in list_runs(data_dir):
        source = row.get("source") or {}
        if source.get("uid") or source.get("id") not in uid_of:
            continue
        try:
            record = load_run(data_dir, row["id"])
        except (OSError, ValueError):
            continue
        record.setdefault("source", {})["uid"] = uid_of[source["id"]]
        save_record(data_dir, record)
        moved[source["id"]] = uid_of[source["id"]]
        updated += 1
    for old_key, uid in moved.items():
        triage.rename_asset(data_dir, old_key, uid)
    if moved:
        with documents.edit(data_dir, "jira-links", {}) as payload:
            for old_key, uid in moved.items():
                if old_key in payload:
                    merged = payload.pop(old_key)
                    payload[uid] = {**merged, **payload.get(uid, {})}
    if updated:
        _log.info("assets_backfilled", extra={"reason": f"{updated} ejecuciones con identidad estable"})
    return updated


def reconcile(data_dir: Path, repositories: list[dict], *, now: datetime | None = None,
              active_accounts: set[str] | None = None) -> dict:
    """Compara lo analizado con la lista COMPLETA de la instalación. Devuelve qué se marcó y qué se borró."""
    from tamandua.modules.runs.store import list_runs
    now = now or datetime.now(timezone.utc)
    backfill(data_dir, repositories)
    present = {item["uid"]: item for item in repositories if item.get("uid")}
    names = {asset_key(row): (row.get("source") or {}).get("name") for row in list_runs(data_dir)
             if asset_key(row).startswith("github#")}
    analysed = set(names)
    purged, marked = [], []
    with documents.lock(data_dir, "repo-registry"):
        registry = load_registry(data_dir)
        for uid in analysed | set(registry):
            known_name = (registry.get(uid) or {}).get("name") or names.get(uid)
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
    for uid in purged:
        purge(data_dir, uid)
    return {"marked": marked, "purged": purged}


def purge(data_dir: Path, uid: str) -> int:
    """Borra ejecuciones, triage, tickets enlazados, vigilancia, ajustes de rama y de secretos de un repositorio. Devuelve ejecuciones borradas."""
    from tamandua.modules.pullrequests import watch as pr_watch
    from tamandua.modules.findings import triage
    from tamandua.modules.findings import registry as findings_registry
    from tamandua.modules.runs.store import delete_runs, list_runs
    removed = delete_runs(data_dir, [row["id"] for row in list_runs(data_dir) if asset_key(row) == uid])
    triage.forget_asset(data_dir, uid)
    findings_registry.forget_asset(data_dir, uid)
    with documents.edit(data_dir, "jira-links", {}) as payload:
        payload.pop(uid, None)
    pr_watch.forget(data_dir, uid)
    with documents.edit(data_dir, "repo-registry", {}) as registry:
        registry.pop(uid, None)
    from tamandua.modules.findings.exclusions import forget as forget_exclusions
    forget_exclusions(data_dir, uid)
    from tamandua.modules.scanning import secret_rules
    secret_rules.forget(data_dir, uid)
    _log.warning("repo_purged", extra={"reason": f"{uid}: {removed} ejecuciones borradas"})
    return removed


def overview(data_dir: Path, *, query: str | None = None) -> list[dict]:
    """Un renglón por repositorio analizado: su último escaneo completo, lo pendiente y si GitHub lo retiró."""
    from tamandua.modules.runs.store import list_runs
    registry = load_registry(data_dir)
    groups: dict[str, dict] = {}
    for row in list_runs(data_dir):  # del más reciente al más antiguo
        if row["type"] not in FINDING_RUNS:
            continue
        key = asset_key(row)
        entry = groups.setdefault(key, {"key": key, "name": (row.get("source") or {}).get("name"), "provider": (row.get("source") or {}).get("provider"),
                                        "source_id": (row.get("source") or {}).get("id"), "scans": 0, "pr_reviews": 0,
                                        "last_activity": row["created_at"], "latest_scan": None,
                                        "removed_at": (registry.get(key) or {}).get("removed_at")})
        if row["type"] in FULL_SCANS or row["type"] == "pr_review":
            entry["scans" if row["type"] in FULL_SCANS else "pr_reviews"] += 1
        if row["type"] in FULL_SCANS and entry["latest_scan"] is None and row["status"] in ("completed", "incomplete"):
            entry["latest_scan"] = {"run_id": row["id"], "created_at": row["created_at"], "status": row["status"]}
    from tamandua.modules.findings.registry import summarize
    for key, entry in groups.items():
        # Lo pendiente sale del registro: escaneos y PRs juntos, menos lo remediado y lo descartado.
        counts = summarize(data_dir, key)
        entry["open"] = {"total": counts["open"], **counts["by_severity"], "from_pr": counts["from_pr"],
                         "fixed": counts["fixed"], "suppressed": counts["suppressed"], "excluded": counts["excluded"]}
    rows = sorted(groups.values(), key=lambda item: item["last_activity"], reverse=True)
    if query:
        needle = query.strip().lower()
        rows = [item for item in rows if needle in (item["name"] or "").lower()]
    return rows
