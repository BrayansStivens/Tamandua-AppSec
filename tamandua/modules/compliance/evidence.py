"""Evidence hub: what can be exported for each analyzed asset and for the whole portfolio.

The files themselves come from the existing renderers (SBOM, VEX, technical and audit reports); this module only
says which assets exist, whether each has a complete scan (an SBOM needs one) and gathers a portfolio's findings.
"""

from __future__ import annotations

from pathlib import Path


def catalog(data_dir: Path) -> list[dict]:
    """Analyzed assets, most recent first: key, latest name, kind and when each last finished a complete scan."""
    from tamandua.modules.runs.kinds import FINDING_RUNS, FULL_SCANS
    from tamandua.modules.runs.store import list_runs
    from tamandua.modules.sources.assets import asset_key
    rows: dict[str, dict] = {}
    for row in list_runs(data_dir):  # most recent first
        if row["type"] not in FINDING_RUNS:
            continue
        key = asset_key(row)
        entry = rows.setdefault(key, {"key": key, "name": (row.get("source") or {}).get("name") or key, "kind": None,
                                      "last_complete": None, "last_status": None})
        if row["type"] in FULL_SCANS:
            entry["kind"] = entry["kind"] or ("image" if row["type"] == "image_scan" else "repository")
            entry["last_status"] = entry["last_status"] or row["status"]
            if row["status"] == "completed" and entry["last_complete"] is None:
                entry["last_complete"] = row["created_at"]
    for entry in rows.values():
        entry["kind"] = entry["kind"] or ("image" if entry["key"].startswith("image:") else "repository")
    return list(rows.values())


def assets(data_dir: Path, *, query: str = "") -> list[dict]:
    """The asset picker: analyzed assets filtered by name, with what each can export."""
    needle = query.strip().lower()
    return [{"key": row["key"], "name": row["name"], "kind": row["kind"], "last_complete": row["last_complete"],
             "sbom": row["last_complete"] is not None}
            for row in catalog(data_dir) if not needle or needle in row["name"].lower()]


def overview(data_dir: Path) -> dict:
    rows = catalog(data_dir)
    return {"assets": len(rows), "complete": sum(1 for row in rows if row["last_complete"])}


def portfolio(data_dir: Path, chosen: list[dict], *, status: str = "all") -> list[dict]:
    """Each chosen asset ({"key", "name"}) with its registry findings and latest full scan, for the consolidated report."""
    from tamandua.modules.findings import registry as findings_registry
    scans = {row["key"]: row for row in catalog(data_dir)}
    return [{"name": row.get("name") or row["key"], "findings": findings_registry.view(data_dir, row["key"], status=status)["findings"],
             "last_complete": (scans.get(row["key"]) or {}).get("last_complete"),
             "last_status": (scans.get(row["key"]) or {}).get("last_status")}
            for row in chosen]
