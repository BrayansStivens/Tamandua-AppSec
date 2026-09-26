"""Pull request review settings and on-demand reviews. The rest of the PR routes (table) are in routes/prs.py."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field, StrictInt

from tamandua.app.api.deps import ApiError, Context, Policy, guard
from tamandua.app.api.repositories import checked_branch, github_repository
from tamandua.app.api.routing import problem
from tamandua.modules.integrations.github import GitHubAppError, installation_repository, pull_request
from tamandua.modules.integrations.installations import github_installations
from tamandua.modules.pullrequests import watch as pr_watch
from tamandua.modules.runs.store import load_run
from tamandua.shared.i18n import msg

router = APIRouter(tags=["pull-requests"])


class TargetBranchesIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    uid: str = Field(max_length=40)
    branches: list[Annotated[str, Field(max_length=255)]] = Field(max_length=50)


class TargetBranches(BaseModel):
    uid: str
    base_branches: list[str] = Field(max_length=pr_watch.MAX_BASE_BRANCHES)
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


SOURCE_ID = r"github:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+"
QUEUE_LIMIT = 20


def installation_entry(data_dir, source_id: str) -> tuple[int, dict] | None:
    """The installation that covers a repository, and its row; None if no connected installation does."""
    for installation in github_installations(data_dir):
        try:
            entry = installation_repository(installation, source_id)
        except GitHubAppError:
            continue
        if entry:
            return installation, entry
    return None


class ReviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source_id: str = Field(max_length=200, pattern=SOURCE_ID)
    number: StrictInt = Field(gt=0, lt=10**9)


class QueuedRun(BaseModel):
    id: str
    status: str


class ReviewQueued(BaseModel):
    run: QueuedRun


def _in_progress(data_dir, uid: str, number: int, head_sha: str) -> bool:
    entry = pr_watch.reviewed(data_dir, uid).get(str(number))
    if not entry or entry.get("head_sha") != head_sha:
        return False
    try:
        return load_run(data_dir, entry["run_id"]).get("status") in ("queued", "running")
    except (OSError, ValueError, KeyError):
        return False


@router.post("/api/pull-requests/review", status_code=202, response_model=ReviewQueued)
def review_now(body: ReviewIn, context: Context = Depends(guard(Policy(action="review-pr", body=256)))) -> dict:
    """Reviews (or reviews again) a pull request's head commit now, whether the repository is watched or not."""
    found = installation_entry(context.data_dir, body.source_id)
    if found is None:
        raise ApiError(400, msg("pulls.errors.repo_not_in_app"))
    installation, entry = found
    try:
        pull = pull_request(installation, entry["name"], body.number)
    except GitHubAppError as exc:
        raise ApiError(400, problem(exc)) from exc
    if not pull["head_sha"]:
        raise ApiError(400, msg("pulls.errors.no_head"))
    if _in_progress(context.data_dir, entry["uid"], body.number, pull["head_sha"]):
        raise ApiError(409, msg("pulls.errors.review_in_progress", number=body.number))
    if context.state.jobs.pending() >= QUEUE_LIMIT:
        raise ApiError(429, msg("api.queue_full"))
    queued = context.state.jobs.enqueue_pr_review(source_id=body.source_id, uid=entry["uid"], pull=pull, installation_id=installation,
                                                  requested_by=context.user["username"], default_branch=entry.get("branch"))
    return {"run": queued}
