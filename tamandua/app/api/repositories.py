"""Repository scans (one, or several in a batch), what a scan will do, and which branch platform scans read."""

from __future__ import annotations

import re
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictStr

from tamandua.app.api.deps import ApiError, Context, Policy, body, documented, guard, json_body
from tamandua.app.api.deps import problem
from tamandua.modules.integrations import code_tokens
from tamandua.modules.integrations.github import BranchNotFound, GitHubAppError, branch_head, valid_branch
from tamandua.modules.integrations.installations import github_installations
from tamandua.modules.runs import batches
from tamandua.modules.scanning.plan import plan as scan_plan
from tamandua.modules.sources.assets import set_scan_branch
from tamandua.modules.sources.repositories import find_source
from tamandua.shared.i18n import msg, text

router = APIRouter(tags=["repositories"])
UID = re.compile(r"github#[1-9][0-9]{0,15}")


def github_repository(context: Context, uid: str, missing: dict) -> dict:
    """A repository the connected GitHub App covers, by stable identity; 404 with `missing` otherwise."""
    found = find_source(None, github_installations(context.data_dir), uid) if UID.fullmatch(uid) else None
    if found is None or not found.get("installation_id"):
        raise ApiError(404, missing)
    return found


def checked_branch(repository: dict, branch: str) -> str:
    """The branch's latest commit, or a 400 that names the branch (bad name or not in the repository)."""
    if not valid_branch(branch):
        raise ApiError(400, msg("integrations.github.invalid_branch_name", branch=branch))
    try:
        return branch_head(repository["installation_id"], repository["name"], branch)
    except BranchNotFound as exc:
        raise ApiError(400, exc.message) from exc
    except GitHubAppError as exc:
        raise ApiError(502, problem(exc)) from exc


class ScanBranchIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    uid: str = Field(max_length=40)
    branch: str | None = Field(max_length=255)


class ScanBranch(BaseModel):
    uid: str
    branch: str | None
    head_sha: str | None
    default_branch: str | None


@router.post("/api/repositories/branch", response_model=ScanBranch)
def scan_branch(body: ScanBranchIn,
                context: Context = Depends(guard(Policy(admin=True, action="set-scan-branch", body=512)))) -> dict:
    """Sets the branch every platform scan of this repository reads; null goes back to the default branch."""
    repository = github_repository(context, body.uid, msg("sources.errors.not_available"))
    branch = (body.branch or "").strip() or None
    head = checked_branch(repository, branch) if branch else None
    set_scan_branch(context.data_dir, repository["uid"], branch, name=repository["name"], source_id=repository["id"],
                    by=context.user["username"])
    return {"uid": repository["uid"], "branch": branch, "head_sha": head, "default_branch": repository.get("branch")}


QUEUE_LIMIT = 20


@router.get("/api/repositories/plan")
def plan(source_id: str = "", context: Context = Depends(guard())) -> dict[str, Any]:
    """What the scan will do, worked out from the repository's real tree and the available engines."""
    tokens = code_tokens.current()
    source = find_source(tokens, github_installations(context.data_dir), source_id or None)
    if source is None:
        raise ApiError(400, msg("sources.errors.not_available"))
    try:
        return context.render(scan_plan(source["id"], installation_id=source.get("installation_id")))
    except GitHubAppError as exc:
        raise ApiError(502, problem(exc)) from exc


class RepositoryScanIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source_id: StrictStr
    allow_osv_upload: StrictBool  # required: nothing is sent to OSV unless the person said so
    context: StrictStr = ""


class QueuedScan(BaseModel):
    run: dict[str, Any]


@router.post("/api/repositories/scans", status_code=202, response_model=QueuedScan, openapi_extra=documented(RepositoryScanIn))
def repository_scan(context: Context = Depends(guard(Policy(action="scan-repository", body=1024))),
                    data: RepositoryScanIn = Depends(body(RepositoryScanIn, msg("api.invalid_repository")))) -> dict:
    state = context.state
    tokens = code_tokens.current()
    # The repository must exist for this credential before anything is queued.
    source = find_source(tokens, github_installations(context.data_dir), data.source_id)
    if source is None or source["id"] != data.source_id:
        raise ApiError(400, msg("sources.errors.not_available"))
    if state.jobs.pending() >= QUEUE_LIMIT:
        raise ApiError(429, msg("api.queue_full"))
    queued = state.jobs.enqueue_repository_scan(source_id=data.source_id, source_name=source["name"], allow_osv_upload=data.allow_osv_upload,
                                                context=data.context, tokens=tokens, installation_id=source.get("installation_id"),
                                                uid=source.get("uid"))
    return context.render({"run": queued})


FAILED_SHOWN, RECENT_BATCHES = 20, 5


class BatchSummary(BaseModel):
    """Progress worked out from the batch's real runs, with the estimated time left."""
    id: str
    label: str | None
    status: str
    created_at: str
    by: str | None
    total: int
    pending: int
    running: int
    done: int
    failed: int
    critical: int
    high: int
    eta_seconds: int
    failed_items: list[dict[str, Any]] = Field(max_length=FAILED_SHOWN)


class Batches(BaseModel):
    active: BatchSummary | None
    recent: list[BatchSummary] = Field(max_length=RECENT_BATCHES)


class BatchIn(BaseModel):
    """A selection (`source_ids`, any member) or a whole organization (`account`, administrators); one of the two."""
    model_config = ConfigDict(extra="forbid")
    source_ids: list[str] | None = Field(None, min_length=1, max_length=batches.MAX_SELECTED)
    account: str | None = Field(None, max_length=100)
    allow_osv_upload: bool = False
    context: str = ""


@router.post("/api/repositories/batches", status_code=202, response_model=BatchSummary, openapi_extra=documented(BatchIn))
def create_batch(context: Context = Depends(guard(Policy(action="scan-batch", body=64_000))),
                 data: Any = Depends(json_body)) -> dict:
    """Several repositories at once: a selection (up to 100) or a whole organization (administration)."""
    if (not isinstance(data, dict) or not set(data) <= set(BatchIn.model_fields)
            or ("source_ids" in data) == ("account" in data)
            or not isinstance(data.get("allow_osv_upload", False), bool) or not isinstance(data.get("context", ""), str)):
        raise ApiError(400, msg("api.batch_scope"))
    installations = github_installations(context.data_dir)
    if not installations:
        raise ApiError(400, msg("api.batch_needs_app"))
    user = context.user
    if "account" in data:
        # A whole organization keeps the server busy for hours: an administration decision.
        if user.get("role") != "admin":
            raise ApiError(403, msg("api.org_admin_only"))
        from tamandua.modules.integrations.github import installation_info, installation_repositories
        account = data["account"]
        if not isinstance(account, str) or not account or len(account) > 100:
            raise ApiError(400, msg("api.invalid_organization"))
        items = []
        for installation in installations:
            try:
                if (installation_info(installation).get("account") or "").casefold() != account.casefold():
                    continue
                items = [{**row, "source_id": row["id"], "installation_id": installation}
                         for row in installation_repositories(installation) if not row.get("archived")]
            except GitHubAppError as exc:
                raise ApiError(502, problem(exc)) from exc
            break
        if not items:
            raise ApiError(404, msg("api.org_empty"))
        # Batches store their label as text (in the language of whoever started them).
        label = text(msg("api.scope.organization", account=account), context.locale)
    else:
        chosen = data["source_ids"]
        if not isinstance(chosen, list) or not 1 <= len(chosen) <= batches.MAX_SELECTED or not all(isinstance(item, str) for item in chosen):
            raise ApiError(400, msg("api.choose_batch", max=batches.MAX_SELECTED))
        items = []
        for source_id in dict.fromkeys(chosen):
            source = find_source(None, installations, source_id)
            if source is None or source.get("installation_id") is None:
                raise ApiError(400, msg("api.repo_not_in_app", repository=source_id[:120]))
            items.append({**source, "source_id": source["id"]})
        label = text(msg("api.scope.selected", count=len(items)), context.locale)
    try:
        batch = batches.create(context.data_dir, items, by=user["username"], label=label,
                               allow_osv_upload=data.get("allow_osv_upload", False), context=data.get("context", ""))
    except batches.BatchError as exc:
        raise ApiError(409, problem(exc)) from exc
    context.state.log.info("scan_batch", extra={"user": user["username"], "reason": f"{label}: {len(batch['items'])}"})
    return context.render(batches.summary(context.data_dir, batch))


@router.get("/api/repositories/batches", response_model=Batches)
def list_batches(context: Context = Depends(guard())) -> dict:
    """The running batch, if any, and the latest finished ones (repositories and images)."""
    rows = batches.all_batches(context.data_dir)
    current = next((row for row in rows if row["status"] == "running"), None)
    return context.render({"active": batches.summary(context.data_dir, current) if current else None,
                           "recent": [batches.summary(context.data_dir, row) for row in rows if row["status"] != "running"][:RECENT_BATCHES]})


class CancelBatchIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: StrictStr


@router.post("/api/repositories/batches/cancel", response_model=BatchSummary, openapi_extra=documented(CancelBatchIn))
def cancel_batch(context: Context = Depends(guard(Policy(action="cancel-batch", body=256))),
                 data: CancelBatchIn = Depends(body(CancelBatchIn, msg("api.invalid_batch")))) -> dict:
    """Whoever started it, or an administrator."""
    user = context.user
    try:
        batch = batches.load(context.data_dir, data.id)
        if batch.get("by") != user["username"] and user.get("role") != "admin":
            raise ApiError(403, msg("api.cancel_forbidden"))
        batch = batches.cancel(context.data_dir, data.id, by=user["username"])
    except batches.BatchError as exc:
        raise ApiError(404, problem(exc)) from exc
    return context.render(batches.summary(context.data_dir, batch))
