"""Evidence hub: what can be exported for each analyzed asset and for the whole portfolio.

The files themselves come from the existing renderers (SBOM, VEX, technical and audit reports); this module only
says which assets exist, whether each has a complete scan (an SBOM needs one) and gathers a portfolio's findings.
"""

from __future__ import annotations

from pathlib import Path


def catalog(data_dir: Path) -> list[dict]:
    """Analyzed assets, most recent first: key, latest name, kind and when each last finished a complete scan."""
    from tamandua.modules.findings.kinds import FINDING_RUNS, FULL_SCANS
    from tamandua.modules.runs.store import find_runs
    from tamandua.modules.sources.assets import asset_key
    rows: dict[str, dict] = {}
    for row in find_runs(data_dir, types=FINDING_RUNS):  # most recent first
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


def complete_scans(data_dir: Path) -> tuple[list[dict], int]:
    """The latest completed full scan of each asset, most recent first and at most `sbom.PORTFOLIO_ASSETS`, as
    `{"key", "ref", "scan"}` with a ref unique in the portfolio; and how many assets have one."""
    from tamandua.modules.compliance import sbom
    from tamandua.modules.findings.kinds import FULL_SCANS
    from tamandua.modules.runs.store import find_runs, load_run
    from tamandua.modules.sources.assets import asset_key
    latest: dict[str, dict] = {}
    for row in find_runs(data_dir, types=FULL_SCANS, statuses=("completed",)):  # most recent first
        latest.setdefault(asset_key(row), row)
    chosen, used = [], {"urn:tamandua:portfolio"}
    for key, row in list(latest.items())[:sbom.PORTFOLIO_ASSETS]:
        try:
            scan = load_run(data_dir, row["id"])
        except (ValueError, OSError):
            continue
        ref = sbom.root_ref(scan)
        ref = ref if ref not in used else f"{ref}#{key}"
        used.add(ref)
        chosen.append({"key": key, "ref": ref, "scan": scan})
    return chosen, len(latest)


def portfolio_sbom(data_dir: Path, *, name: str, version: str, locale: str) -> dict | None:
    """CycloneDX of every asset with a completed full scan; None when there is none."""
    from tamandua.modules.compliance import sbom
    chosen, total = complete_scans(data_dir)
    return sbom.portfolio(chosen, total=total, name=name, version=version, locale=locale) if total else None


def portfolio_vex(data_dir: Path, *, version: str, locale: str) -> dict | None:
    """OpenVEX of the same assets as the portfolio SBOM (same product refs), from every triage decision."""
    from tamandua.modules.compliance import vex
    from tamandua.modules.findings import registry as findings_registry
    chosen, total = complete_scans(data_dir)
    if not total:
        return None
    records = [(item["ref"], findings_registry.view(data_dir, item["key"], status="all")) for item in chosen]
    return vex.portfolio(records, total=total, version=version, locale=locale)
