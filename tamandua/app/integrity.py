"""Relations that can't be foreign keys (see migration 0003), checked on demand by `tamandua doctor`. They span the
runs and findings contexts, so the check lives in the composition layer.

Only a repository purge deletes runs, and it also deletes the repository's registry and triage. A registry asset or a
triage decision whose repository has no run left is what an interrupted purge leaves behind: `fix` deletes it. A
finished run missing from the registry is only reported: rebuilding it from runs would lose what doesn't come from a
run (closed PRs, exclusions), and the repository's next full analysis restores it.
"""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import delete, exists, func, select

from tamandua.modules.findings.tables import registry_assets, triage_decisions
from tamandua.modules.findings.kinds import FINDING_RUNS
from tamandua.modules.runs.tables import runs
from tamandua.shared import db
from tamandua.shared import log as logging_setup
from tamandua.shared.db import TENANT

_log = logging_setup.get("findings")

FIXABLE = ("registry_without_runs", "triage_without_runs")
REPORTED = ("runs_without_registry",)


def _has_runs(table):
    return exists().where(runs.c.tenant_id == table.c.tenant_id, runs.c.asset_key == table.c.asset_key)


def _orphans() -> dict:
    return {
        "registry_without_runs": (registry_assets, (registry_assets.c.tenant_id == TENANT, ~_has_runs(registry_assets))),
        "triage_without_runs": (triage_decisions, (triage_decisions.c.tenant_id == TENANT, ~_has_runs(triage_decisions))),
        "runs_without_registry": (runs, (runs.c.tenant_id == TENANT, runs.c.type.in_(FINDING_RUNS),
                                         runs.c.status.in_(("completed", "incomplete")), runs.c.asset_key.is_not(None),
                                         ~exists().where(registry_assets.c.tenant_id == runs.c.tenant_id,
                                                         registry_assets.c.asset_key == runs.c.asset_key))),
    }


def check(data_dir: Path) -> dict[str, int]:
    """Orphan rows per relation. Reads only."""
    with db.transaction(data_dir) as connection:
        return {name: connection.execute(select(func.count()).select_from(table).where(*conditions)).scalar_one()
                for name, (table, conditions) in _orphans().items()}


def fix(data_dir: Path) -> dict[str, int]:
    """Deletes the orphans that are leftovers (registry first: its findings go with it) and returns how many per relation."""
    orphans = _orphans()
    removed = {}
    with db.transaction(data_dir) as connection:
        for name in FIXABLE:
            table, conditions = orphans[name]
            removed[name] = connection.execute(delete(table).where(*conditions)).rowcount
    if any(removed.values()):
        _log.warning("orphans_removed", extra={"reason": ", ".join(f"{name}: {count}" for name, count in removed.items())})
    return removed
