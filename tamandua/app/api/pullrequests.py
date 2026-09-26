"""Pull request review settings. The rest of the PR routes (table) are in routes/prs.py."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field

from tamandua.app.api.deps import ApiError, Context, Policy, guard
from tamandua.app.api.repositories import checked_branch, github_repository
from tamandua.modules.pullrequests import watch as pr_watch
from tamandua.shared.i18n import msg

router = APIRouter(tags=["pull-requests"])


class TargetBranchesIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    uid: str = Field(max_length=40)
    branches: list[Annotated[str, Field(max_length=255)]] = Field(max_length=50)


class TargetBranches(BaseModel):
    uid: str
    base_branches: list[str]
    default_branch: str | None


@router.post("/api/pull-requests/branches", response_model=TargetBranches)
def target_branches(body: TargetBranchesIn,
                    context: Context = Depends(guard(Policy(admin=True, action="pr-branches", body=16_000)))) -> dict:
    """Branches whose PRs are reviewed; an empty list means the repository's default branch."""
    repository = github_repository(context, body.uid, msg("pulls.errors.not_in_app"))
    branches = list(dict.fromkeys(name.strip() for name in body.branches if name.strip()))
    if len(branches) > pr_watch.MAX_BASE_BRANCHES:
        raise ApiError(400, msg("pulls.errors.too_many_branches", max=pr_watch.MAX_BASE_BRANCHES))
    for branch in branches:
        checked_branch(repository, branch)
    config = pr_watch.set_base_branches(context.data_dir, repository["uid"], branches, default_branch=repository.get("branch"),
                                        by=context.user["username"])
    return {"uid": repository["uid"], "base_branches": config["base_branches"], "default_branch": repository.get("branch")}
