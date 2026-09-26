"""The findings registry is derived from the runs: rebuilt from them, and read by the same id as a run."""

from __future__ import annotations

from pathlib import Path

from tamandua.modules.findings import registry
from tamandua.modules.runs.store import list_runs, load_run


def rebuild(data_dir: Path) -> int:
    """Reconstruye todos los registros desde las ejecuciones, en orden cronológico."""
    registry.reset(data_dir)
    applied = 0
    for row in sorted(list_runs(data_dir), key=lambda item: item.get("finished_at") or item["created_at"]):
        try:
            registry.apply(data_dir, load_run(data_dir, row["id"]))
            applied += 1
        except (ValueError, OSError):
            continue
    return applied


def resolve(data_dir: Path, run_id: str) -> dict:
    """Una ejecución por su id, o el estado de un repositorio por `asset:<clave>`."""
    if isinstance(run_id, str) and run_id.startswith(registry.VIEW_PREFIX):
        return registry.view(data_dir, run_id[len(registry.VIEW_PREFIX):], status="all")
    return load_run(data_dir, run_id)
