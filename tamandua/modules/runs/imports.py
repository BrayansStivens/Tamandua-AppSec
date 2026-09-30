"""Findings from other tools (SARIF) into an asset's findings registry, one `sarif_import` run per tool.

The asset must already be known (a scanned asset, or a repository the GitHub App covers): an import never creates
one. Every run of one document is saved together, or none is. What a full import of a tool no longer reports is
fixed by the registry (`findings/registry.py`); a partial one only opens and updates.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tamandua.modules.findings import registry
from tamandua.modules.integrations.github import valid_branch
from tamandua.modules.runs.store import find_runs, save_and_apply
from tamandua.modules.scanning.sarif_import import ParsedRun, SarifError, parse
from tamandua.modules.sources import assets as source_assets
from tamandua.shared import db
from tamandua.shared import log as logging_setup
from tamandua.shared.i18n import msg
from tamandua.shared.model import RunRecord

SCOPES = ("full", "partial")
ASSET_MAX = 200
COMMIT = re.compile(r"[0-9a-fA-F]{7,64}")
SEVERITIES = ("critical", "high", "medium", "low", "info")
SCANNERS = ("sast", "secrets", "sca", "iac", "cicd")
_log = logging_setup.get("imports")


class ImportRefused(ValueError):
    """An import that can't go ahead: `status` (400, 404, 409) and a catalog `message`."""

    def __init__(self, status: int, message: dict):
        super().__init__(message)
        self.status, self.message = status, message


def resolve_source(data_dir: Path, wanted: str) -> dict:
    """The `source` of the asset named `wanted` (its key or its name), as its own runs carry it."""
    wanted = wanted.strip() if isinstance(wanted, str) else ""
    if not wanted or len(wanted) > ASSET_MAX:
        raise ImportRefused(400, msg("runs.imports.errors.invalid_asset"))
    found = registry.find_assets(data_dir, wanted)
    if len(found) > 1:
        raise ImportRefused(409, msg("runs.imports.errors.ambiguous_asset", asset=wanted))
    if found:
        key, name = found[0]["asset"], found[0]["name"]
        latest = next(iter(find_runs(data_dir, assets=[key], limit=1)), None)
        source = (latest or {}).get("source") or {}
        if source:
            return {field: source[field] for field in ("id", "uid", "name", "provider", "image") if source.get(field)}
        return {"id": key, **({"uid": key} if key.startswith("github#") else {}), "name": name or key,
                "provider": re.split(r"[:#]", key, maxsplit=1)[0] or "local"}
    repositories = source_assets.registered(data_dir, wanted)
    if len(repositories) > 1:
        raise ImportRefused(409, msg("runs.imports.errors.ambiguous_asset", asset=wanted))
    if repositories:
        entry = repositories[0]
        source_id = entry.get("source_id") or f"github:{entry['name']}"
        return {"id": source_id, "uid": entry["uid"], "name": entry["name"], "provider": source_id.partition(":")[0] or "github"}
    raise ImportRefused(404, msg("runs.imports.errors.unknown_asset", asset=wanted))


def _record(parsed: ParsedRun, source: dict, *, scope: str, commit: str | None, branch: str | None,
            requested_by: str, now: str) -> RunRecord:
    tool, findings = parsed["tool"], parsed["findings"]
    full = scope == "full"
    detail = msg("runs.imports.detail_full" if full else "runs.imports.detail_partial", tool=tool, count=len(findings),
                 results=parsed["results"], skipped=parsed["skipped"])
    return {
        "type": "sarif_import", "status": "completed",
        "source": {**source, **({"commit": commit} if commit else {}), **({"branch": branch} if branch else {})},
        "target": str(source.get("name") or ""), "variant": "import", "context": "", "requested_by": requested_by,
        "trigger": {"kind": "import", "format": "sarif", "tool": tool, "scope": scope,
                    **({"commit": commit} if commit else {}), **({"branch": branch} if branch else {})},
        "started_at": now, "finished_at": now,
        "steps": [{"id": "sarif-import", "name": msg("runs.imports.step", tool=tool), "status": "completed" if full else "partial",
                   "detail": detail, "tool": {"name": tool, "version": parsed["version"], "image": None, "duration_s": None}}],
        "findings": findings, "owasp_coverage": [],
        "limitations": [msg("runs.imports.limitations.third_party", tool=tool),
                        *([] if full else [msg("runs.imports.limitations.partial", tool=tool)])],
        "summary": {"files": len({item["path"] for item in findings if item.get("path")}), "dependencies": 0,
                    "candidates": len(findings), **{name: sum(1 for item in findings if item["scanner"] == name) for name in SCANNERS},
                    "severities": {level: sum(1 for item in findings if item["severity"] == level) for level in SEVERITIES},
                    "priorities": {action: sum(1 for item in findings if item["priority"]["action"] == action)
                                   for action in ("act", "attend", "track")},
                    "kev": 0, "fixable": 0, "tools": [{"name": tool, "version": parsed["version"], "status": "completed"}]},
    }


def import_sarif(data_dir: Path, document: Any, *, asset: str, tool: str | None = None, scope: str = "full",
                 commit: str | None = None, branch: str | None = None, requested_by: str) -> dict:
    """Imports a SARIF document into an existing asset. Returns {"asset", "name", "runs": [one summary per tool]}."""
    if scope not in SCOPES:
        raise ImportRefused(400, msg("runs.imports.errors.invalid_scope"))
    if commit is not None and not COMMIT.fullmatch(commit):
        raise ImportRefused(400, msg("runs.imports.errors.invalid_commit"))
    if branch is not None and not valid_branch(branch):
        raise ImportRefused(400, msg("integrations.github.invalid_branch_name", branch=branch[:100]))
    source = resolve_source(data_dir, asset)
    try:
        parsed = parse(document, tool=tool)
    except SarifError as exc:
        raise ImportRefused(400, exc.message) from exc
    now = datetime.now(timezone.utc).isoformat()
    runs = []
    # One document, one outcome: every tool's run lands, or none does.
    with db.transaction(data_dir):
        for item in parsed:
            saved, changes = save_and_apply(data_dir, _record(item, source, scope=scope, commit=commit.lower() if commit else None,
                                                              branch=branch, requested_by=requested_by, now=now))
            runs.append({"id": saved["id"], "tool": item["tool"], "version": item["version"], "scope": scope, "status": saved["status"],
                         "findings": len(saved.get("findings") or []), "excluded": len(saved.get("excluded_findings") or []),
                         "skipped": item["skipped"], "opened": changes.get("opened", 0), "fixed": changes.get("fixed", 0)})
    key = source_assets.asset_key({"source": source})
    _log.info("sarif_imported", extra={"user": requested_by, "reason": f"{key}: " + ", ".join(
        f"{run['tool']} +{run['opened']} -{run['fixed']}" for run in runs)})
    return {"asset": key, "name": source.get("name") or key, "runs": runs}
