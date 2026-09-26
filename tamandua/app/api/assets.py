"""Analyzed assets (repositories and images): the list, the current state of each, its exports and excluded paths."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field

from tamandua.app.api.deps import ApiError, Context, Policy, documented, guard, json_body
from tamandua.app.api.deps import problem
from tamandua.app.api.runs import DOWNLOADS, PROFILE_REPORTS, SBOM_FILE, VEX_FILE, download
from tamandua.modules.findings import exclusions
from tamandua.modules.findings import registry as findings_registry
from tamandua.modules.findings import tickets
from tamandua.modules.runs.assets import overview as assets_overview
from tamandua.shared.i18n import msg

router = APIRouter(tags=["assets"])

STATUSES = ("open", "fixed", "excluded", "all")
EXPORTS = ("tickets.json", "report.md", "report.pdf", "findings.sarif", *PROFILE_REPORTS, "record.json", SBOM_FILE, VEX_FILE)
PAGE_MAX = 200


class AssetPage(BaseModel):
    items: list[dict[str, Any]] = Field(max_length=PAGE_MAX)
    total: int
    limit: int
    offset: int


@router.get("/api/assets", response_model=AssetPage)
def assets(q: str = "", key: str = "", limit: str = "50", offset: str = "0", context: Context = Depends(guard())) -> dict:
    """Analyzed repositories and images, grouped by stable identity, with their current state. `limit` is clamped to 1–200."""
    rows = assets_overview(context.data_dir, query=q[:100] or None)
    if key:
        rows = [row for row in rows if row["key"] == key]
    try:
        size, start = max(1, min(int(limit or "50"), PAGE_MAX)), max(0, int(offset or "0"))
    except ValueError:
        raise ApiError(400, msg("api.invalid_paging")) from None
    return context.render({"items": rows[start:start + size], "total": len(rows), "limit": size, "offset": start})


@router.get("/api/assets/state")
def asset_state(key: str = "", status: str = "open", context: Context = Depends(guard())) -> dict[str, Any]:
    """An asset's findings registry (scans and PRs): open, fixed, excluded or all."""
    key, status = key[:200], status or "open"
    if not key or status not in STATUSES:
        raise ApiError(400, msg("api.invalid_repository_status"))
    view = findings_registry.view(context.data_dir, key, status=status)
    return context.render(tickets.annotate(context.data_dir, view))


@router.get("/api/assets/export", response_class=Response, responses=DOWNLOADS)
def asset_export(key: str = "", status: str = "open", artifact: str = "", title: str = "",
                 context: Context = Depends(guard())) -> Response:
    """An export of the current state (there is no run ID for this view). `artifact` also accepts record.json."""
    status = status or "open"
    if not key or len(key) > 200 or status not in STATUSES:
        raise ApiError(400, msg("api.invalid_asset_status"))
    if artifact not in EXPORTS:
        raise ApiError(404, msg("api.format_unavailable"))
    if not any(row["key"] == key for row in assets_overview(context.data_dir)):
        raise ApiError(404, msg("api.asset_not_found"))
    # The VEX describes every decision (also what was fixed or dismissed), whatever the tab.
    record = tickets.annotate(context.data_dir, findings_registry.view(context.data_dir, key, status="all" if artifact == VEX_FILE else status))
    if artifact == "record.json":
        return JSONResponse(context.render(record))
    try:
        return download(context, record, artifact, title)
    except ValueError as exc:
        raise ApiError(400, problem(exc)) from exc


@router.get("/api/assets/exclusions")
def asset_exclusions(key: str = "", context: Context = Depends(guard())) -> dict[str, Any]:
    """A repository's excluded paths: anyone sees them; only an administrator changes them."""
    if not exclusions.ASSET_KEY.fullmatch(key):
        raise ApiError(400, msg("api.invalid_repository"))
    return context.render(exclusions.get(context.data_dir, key))


class ExclusionsIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    key: str = Field(max_length=200, pattern=f"^{exclusions.ASSET_KEY.pattern}$")
    patterns: list[str] = Field(max_length=exclusions.MAX_PATTERNS)
    reason: str | None = None


EXCLUSION_FIELDS = set(ExclusionsIn.model_fields)


@router.post("/api/assets/exclusions", openapi_extra=documented(ExclusionsIn))
def save_asset_exclusions(context: Context = Depends(guard(Policy(admin=True, action="save-exclusions", body=20_000))),
                          data: Any = Depends(json_body)) -> dict[str, Any]:
    """Replaces the excluded paths; findings under them move to excluded, and the ones no longer covered reopen."""
    if (not isinstance(data, dict) or not {"key", "patterns"} <= set(data) or not set(data) <= EXCLUSION_FIELDS
            or not isinstance(data["key"], str) or not exclusions.ASSET_KEY.fullmatch(data["key"])
            or not isinstance(data.get("reason") or "", str)):
        raise ApiError(400, msg("api.invalid_request"))
    key, user = data["key"], context.user
    # Only repositories or images that exist: no made-up keys in the file.
    if not findings_registry.load(context.data_dir, key)["findings"] and not any(row["key"] == key for row in assets_overview(context.data_dir)):
        raise ApiError(404, msg("api.repository_not_found"))
    try:
        saved = exclusions.save(context.data_dir, key, data["patterns"], reason=data.get("reason"), user=user)
    except exclusions.ExclusionError as exc:
        raise ApiError(400, problem(exc)) from exc
    moved = findings_registry.apply_exclusions(context.data_dir, key, saved["patterns"], when=saved["at"])
    context.state.log.info("exclusions", extra={"user": user["username"], "reason":
                                                f"{key}: {len(saved['patterns'])} rutas, {moved['excluded']} excluidos, {moved['reopened']} reabiertos"})
    return context.render({**saved, "moved": moved})
