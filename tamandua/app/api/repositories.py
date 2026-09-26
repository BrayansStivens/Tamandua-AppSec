"""Per-repository settings of GitHub App repositories: which branch platform scans read."""

from __future__ import annotations

import re

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field

from tamandua.app.api.deps import ApiError, Context, Policy, guard
from tamandua.app.api.routing import problem
from tamandua.modules.integrations.github import BranchNotFound, GitHubAppError, branch_head, valid_branch
from tamandua.modules.integrations.installations import github_installations
from tamandua.modules.sources.assets import set_scan_branch
from tamandua.modules.sources.repositories import find_source
from tamandua.shared.i18n import msg

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
