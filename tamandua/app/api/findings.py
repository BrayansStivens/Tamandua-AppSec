"""Findings: triage, re-verification of one finding, and the due dates (SLA) per severity."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field, StrictStr, WithJsonSchema

from tamandua.app.api.deps import ApiError, Context, Policy, body, documented, guard
from tamandua.app.api.deps import problem
from tamandua.app.demo import DEMO_SOURCE_ID
from tamandua.modules.findings import registry as findings_registry
from tamandua.modules.findings import sla, triage, verifications
from tamandua.modules.findings.registry import VIEW_PREFIX
from tamandua.modules.integrations import code_tokens
from tamandua.modules.integrations.installations import github_installations
from tamandua.modules.findings.kinds import FINDING_RUNS
from tamandua.modules.runs import assets as run_assets
from tamandua.modules.runs import registry as run_registry
from tamandua.modules.runs.store import load_run
from tamandua.modules.scanning.image import ImageError, parse_reference
from tamandua.modules.sources.assets import asset_key
from tamandua.modules.sources.repositories import find_source
from tamandua.shared.i18n import msg

router = APIRouter(tags=["findings"])


class SlaDays(BaseModel):
    """Days per severity; null means that severity has no due date."""
    critical: int | None
    high: int | None
    medium: int | None
    low: int | None


class SlaDefaults(BaseModel):
    critical: int
    high: int
    medium: int
    low: int


class SlaPolicy(BaseModel):
    days: SlaDays
    defaults: SlaDefaults
    updated_by: str | None
    updated_at: str | None


@router.get("/api/sla", response_model=SlaPolicy)
def policy(context: Context = Depends(guard())) -> dict:
    """Anyone can read them (they explain due dates); an administrator changes them."""
    return context.render(sla.policy(context.data_dir))


def _checked_later(schema: dict):
    """A field the module checks itself (with its own message): any value here, `schema` in the OpenAPI."""
    return Annotated[Any, WithJsonSchema(schema)]


def _text(limit: int):
    return _checked_later({"type": ["string", "null"], "maxLength": limit})


LevelDays = _checked_later({"type": "object", "required": list(sla.LEVELS), "additionalProperties": False,
                            "properties": {level: {"type": ["integer", "null"]} for level in sla.LEVELS}})
Fingerprints = _checked_later({"type": "array", "items": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                               "minItems": 1, "maxItems": triage.MAX_BATCH})
TriageStatus = _checked_later({"type": "string", "enum": list(triage.STATUSES)})
Reason, Note = _text(triage.REASON_MAX), _text(triage.NOTE_MAX)
Expiry = _checked_later({"type": ["string", "null"], "format": "date"})


class SlaIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    days: LevelDays


@router.post("/api/sla", response_model=SlaPolicy, openapi_extra=documented(SlaIn))
def change_policy(context: Context = Depends(guard(Policy(admin=True, action="sla", body=1024))),
                  data: SlaIn = Depends(body(SlaIn, msg("api.invalid_request")))) -> dict:
    """Days per severity (all four; null: no due date). Answers the new policy."""
    try:
        return context.render(sla.save(context.data_dir, data.days, user=context.user))
    except sla.SlaError as exc:
        raise ApiError(400, problem(exc)) from exc


class TriageIn(BaseModel):
    """`run_id`: a run, or an asset's state (asset:<key>); the triage is the same."""
    model_config = ConfigDict(extra="forbid")
    run_id: StrictStr
    fingerprints: Fingerprints
    status: TriageStatus
    reason: Reason = None
    note: Note = None
    expires_at: Expiry = None


class TriageResult(BaseModel):
    summary: dict[str, Any]


@router.post("/api/findings/triage", response_model=TriageResult, openapi_extra=documented(TriageIn))
def triage_findings(context: Context = Depends(guard(Policy(action="triage", body=40_000))),
                    data: TriageIn = Depends(body(TriageIn, msg("api.invalid_triage")))) -> dict:
    try:
        record = run_registry.resolve(context.data_dir, data.run_id)
    except (ValueError, OSError):
        raise ApiError(404, msg("api.run_not_found")) from None
    if record.get("type") not in (*FINDING_RUNS, "asset_state"):
        raise ApiError(400, msg("api.triage_scope"))
    user = context.user
    try:
        updated = triage.decide(context.data_dir, record, data.fingerprints, data.status, reason=data.reason, note=data.note,
                                expires_at=data.expires_at, user=user)
    except PermissionError as exc:
        raise ApiError(403, problem(exc)) from exc
    except triage.TriageError as exc:
        raise ApiError(400, problem(exc)) from exc
    context.state.log.info("triage", extra={"user": user["username"], "run_id": record["id"], "reason":
                                            f"{data.status}: {len(data.fingerprints)} hallazgos"})
    return context.render({"summary": updated["summary"]})


class ReverifyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    run_id: StrictStr
    fingerprint: StrictStr = Field(pattern="^[0-9a-f]{16,64}$")


class Reverification(BaseModel):
    run: dict[str, Any]
    joined: bool  # attached to the asset's scan already in progress


QUEUE_LIMIT = 20


@router.post("/api/findings/reverify", status_code=202, response_model=Reverification, openapi_extra=documented(ReverifyIn))
def reverify_finding(context: Context = Depends(guard(Policy(action="reverify-finding", body=512))),
                     data: ReverifyIn = Depends(body(ReverifyIn, msg("api.invalid_finding")))) -> dict:
    """Scans the finding's asset again (or joins the scan in progress) to see whether it is still there."""
    data_dir, state = context.data_dir, context.state
    if data.run_id.startswith(VIEW_PREFIX):
        key = data.run_id.removeprefix(VIEW_PREFIX)
    else:
        try:
            key = asset_key(load_run(data_dir, data.run_id))
        except (ValueError, OSError):
            raise ApiError(404, msg("api.run_not_found")) from None
    entry = findings_registry.load(data_dir, key).get("findings", {}).get(data.fingerprint)
    if entry is None:
        raise ApiError(404, msg("api.finding_not_in_asset"))
    origin = entry.get("origin") or {}
    if origin.get("kind") == "pr" and not origin.get("merged"):
        raise ApiError(409, msg("api.finding_from_open_pr"))
    if origin.get("kind") == "import":  # only that tool can say whether it is still there
        raise ApiError(409, msg("api.finding_from_import", tool=origin.get("tool") or "SARIF"))
    by = context.user["username"]
    current = run_assets.in_flight(data_dir, key)
    if current:
        verifications.record(data_dir, key, data.fingerprint, current["id"], by=by)
        return context.render({"run": {"id": current["id"], "status": current["status"]}, "joined": True})
    base = run_assets.latest_scan(data_dir, key)
    if base is None:
        raise ApiError(409, msg("api.no_full_scan"))
    if state.jobs.pending() >= QUEUE_LIMIT:
        raise ApiError(429, msg("api.queue_full"))
    source = base.get("source") or {}
    if source.get("id") == DEMO_SOURCE_ID:
        raise ApiError(409, msg("api.demo_reverify"))
    if base["type"] == "image_scan":
        try:
            image = parse_reference(str((source.get("image") or {}).get("reference") or base.get("target") or ""))
        except ImageError as exc:
            raise ApiError(409, msg("api.image_rescan_failed", detail=problem(exc))) from exc
        queued = state.jobs.enqueue_image_scan(image=image, context="", requested_by=by)
    else:
        tokens = code_tokens.current()
        found = find_source(tokens, github_installations(data_dir), source.get("id") or "")
        if found is None:
            raise ApiError(409, msg("api.repository_gone"))
        queued = state.jobs.enqueue_repository_scan(source_id=found["id"], source_name=found["name"], allow_osv_upload=False, context="",
                                                    tokens=tokens, installation_id=found.get("installation_id"), uid=found.get("uid"),
                                                    requested_by=by, trigger={"kind": "reverify"})
    verifications.record(data_dir, key, data.fingerprint, queued["id"], by=by)
    state.log.info("reverify", extra={"user": by, "reason": f"{key} {data.fingerprint[:12]}"})
    return context.render({"run": queued, "joined": False})
