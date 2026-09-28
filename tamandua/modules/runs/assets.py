"""Assets seen through their runs: the overview of analysed repositories, reconciling them with the GitHub
installation (stable identity for old runs, retirement, purge) and the full scans a re-verification rides on.

A purge deletes the asset's runs first and then publishes `AssetPurged`, so every context forgets what it keeps about
the asset (subscribed in `tamandua/app/wiring.py`). Runs go first: an interrupted purge leaves registry or triage rows
without runs, which `tamandua integrity` finds and removes.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from tamandua.modules.findings import registry as findings_registry
from tamandua.modules.findings import tickets, triage
from tamandua.modules.findings.kinds import FINDING_RUNS, FULL_SCANS
from tamandua.modules.runs.store import delete_runs, find_runs, load_run, save_record
from tamandua.modules.sources import assets as source_assets
from tamandua.modules.sources.assets import asset_key
from tamandua.shared import events
from tamandua.shared import log as logging_setup

_log = logging_setup.get("assets")


@dataclass(frozen=True)
class AssetPurged:
    """An asset's runs are gone: forget everything else kept about it."""
    data_dir: Path
    key: str


def backfill(data_dir: Path, repositories: list[dict]) -> int:
    """Ejecuciones guardadas antes de la identidad estable: se les pone su `uid` y se mueven triage y tickets."""
    uid_of = {item["id"]: item["uid"] for item in repositories if item.get("uid")}
    moved: dict[str, str] = {}
    updated = 0
    for row in find_runs(data_dir, assets=list(uid_of)):  # still keyed by their old id
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
    tickets.rename_assets(data_dir, moved)
    if updated:
        _log.info("assets_backfilled", extra={"reason": f"{updated} ejecuciones con identidad estable"})
    return updated


def reconcile(data_dir: Path, repositories: list[dict], *, now: datetime | None = None,
              active_accounts: set[str] | None = None) -> dict:
    """Compara lo analizado con la lista COMPLETA de la instalación. Devuelve qué se marcó y qué se borró."""
    now = now or datetime.now(timezone.utc)
    backfill(data_dir, repositories)
    analysed = {asset_key(row): (row.get("source") or {}).get("name") for row in find_runs(data_dir, asset_prefix="github#")}
    result = source_assets.retire(data_dir, repositories, analysed, now=now, active_accounts=active_accounts)
    for uid in result["purged"]:
        purge(data_dir, uid)
    return result


def purge(data_dir: Path, uid: str) -> int:
    """Borra las ejecuciones de un repositorio y avisa para que cada contexto olvide lo suyo. Devuelve ejecuciones borradas."""
    removed = delete_runs(data_dir, [row["id"] for row in find_runs(data_dir, assets=[uid])])
    events.publish(AssetPurged(data_dir, uid))
    _log.warning("repo_purged", extra={"reason": f"{uid}: {removed} ejecuciones borradas"})
    return removed


def overview(data_dir: Path, *, query: str | None = None) -> list[dict]:
    """Un renglón por repositorio analizado: su último escaneo completo, lo pendiente y si GitHub lo retiró."""
    registry = source_assets.load_registry(data_dir)
    groups: dict[str, dict] = {}
    for row in find_runs(data_dir, types=FINDING_RUNS):  # del más reciente al más antiguo
        key = asset_key(row)
        entry = groups.setdefault(key, {"key": key, "name": (row.get("source") or {}).get("name"), "provider": (row.get("source") or {}).get("provider"),
                                        "source_id": (row.get("source") or {}).get("id"), "scans": 0, "pr_reviews": 0,
                                        "last_activity": row["created_at"], "latest_scan": None,
                                        "removed_at": (registry.get(key) or {}).get("removed_at")})
        if row["type"] in FULL_SCANS or row["type"] == "pr_review":
            entry["scans" if row["type"] in FULL_SCANS else "pr_reviews"] += 1
        if row["type"] in FULL_SCANS and entry["latest_scan"] is None and row["status"] in ("completed", "incomplete"):
            entry["latest_scan"] = {"run_id": row["id"], "created_at": row["created_at"], "status": row["status"]}
    for key, entry in groups.items():
        # Lo pendiente sale del registro: escaneos y PRs juntos, menos lo remediado y lo descartado.
        counts = findings_registry.summarize(data_dir, key)
        entry["open"] = {"total": counts["open"], **counts["by_severity"], "from_pr": counts["from_pr"],
                         "fixed": counts["fixed"], "suppressed": counts["suppressed"], "excluded": counts["excluded"]}
    rows = sorted(groups.values(), key=lambda item: item["last_activity"], reverse=True)
    if query:
        needle = query.strip().lower()
        rows = [item for item in rows if needle in (item["name"] or "").lower()]
    return rows


def in_flight(data_dir: Path, key: str) -> dict | None:
    """Un análisis completo de ese activo que aún no terminó, si lo hay."""
    return next(iter(find_runs(data_dir, types=FULL_SCANS, statuses=("queued", "running"), assets=[key], limit=1)), None)


def latest_scan(data_dir: Path, key: str) -> dict | None:
    """El último análisis completo del activo: de él sale cómo volver a analizarlo (repositorio o imagen)."""
    return next(iter(find_runs(data_dir, types=FULL_SCANS, assets=[key], limit=1)), None)
