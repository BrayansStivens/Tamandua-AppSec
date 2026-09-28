"""Pull request review: watched repositories and their settings, open pull requests, and on-demand reviews."""

from __future__ import annotations

import re
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, WithJsonSchema, model_validator

from tamandua.app.api.deps import ApiError, Context, Policy, body, documented, guard
from tamandua.app.api.repositories import checked_branch, github_repository
from tamandua.app.api.deps import problem
from tamandua.modules.integrations.github import (GitHubAppError, installation_repositories, installation_repository,
                                                  open_pull_requests, pull_request)
from tamandua.modules.integrations.installations import github_installations
from tamandua.modules.pullrequests import watch as pr_watch
from tamandua.modules.pullrequests.review import GATES
from tamandua.modules.runs.store import find_runs, load_run
from tamandua.modules.sources.repositories import source_page
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


MAX_PULLS = 50       # GitHub's page of open pull requests
MAX_WATCH_PAGE = 100
MAX_CHOSEN = 200


class WatchConfig(BaseModel):
    """A repository's watch settings (with who changed them last, once changed)."""
    model_config = ConfigDict(extra="allow")
    enabled: bool
    post_comment: bool
    gate: str
    branch: bool
    base_branches: list[str] = Field(max_length=pr_watch.MAX_BASE_BRANCHES)


class RepositoryWatch(WatchConfig):
    uid: str
    branch_scan: dict[str, Any] | None
    branch_min_minutes: int
    default_branch: str | None


class PullReview(BaseModel):
    run_id: str
    status: str
    head_sha: str
    created_at: str
    current: bool
    new: int
    severities: dict[str, int]


class PullRow(BaseModel):
    model_config = ConfigDict(extra="allow")
    number: int | None
    title: str
    url: str | None
    author: str | None
    draft: bool
    head_sha: str | None
    head_ref: str | None
    base_ref: str | None
    updated_at: str | None
    state: str | None
    merged: bool
    closed_at: str | None
    review: PullReview | None


class PullListing(BaseModel):
    """`pulls_error` (and no pulls) when GitHub doesn't let the App read them: the settings can still be changed."""
    settings: RepositoryWatch
    pulls: list[PullRow] = Field(max_length=MAX_PULLS)
    pulls_error: str | None = None


def _repository(data_dir, source_id) -> tuple[int, dict] | None:
    """Only repositories the installation covers: their installation and row."""
    if not isinstance(source_id, str) or not re.fullmatch(SOURCE_ID, source_id):
        return None
    return installation_entry(data_dir, source_id)


@router.get("/api/pull-requests", response_model=PullListing, response_model_exclude_unset=True)
def pulls(source_id: str | None = None, context: Context = Depends(guard())) -> dict:
    found = _repository(context.data_dir, source_id)
    if found is None:
        raise ApiError(400, msg("pulls.errors.pick_repository"))
    installation, entry = found
    data_dir, repository, uid = context.data_dir, entry["name"], entry["uid"]
    settings = {**pr_watch.settings(data_dir, uid), "branch_scan": pr_watch.branch_state(data_dir, uid),
                "branch_min_minutes": pr_watch.branch_min_seconds() // 60, "uid": uid, "default_branch": entry.get("branch")}
    try:
        rows = open_pull_requests(installation, repository)
    except GitHubAppError as exc:
        # The settings can be left ready even if GitHub doesn't let the App read the pull requests yet.
        return context.render({"settings": settings, "pulls": [], "pulls_error": problem(exc)})
    done = pr_watch.reviewed(data_dir, uid)
    runs = {row["id"]: row for row in find_runs(data_dir, types=("pr_review",), ids=[entry["run_id"] for entry in done.values() if entry.get("run_id")])}
    for row in rows:
        entry = done.get(str(row["number"]))
        run = runs.get(entry["run_id"]) if entry else None
        row["review"] = None if run is None else {
            "run_id": run["id"], "status": run["status"], "head_sha": entry["head_sha"], "created_at": run["created_at"],
            "current": entry["head_sha"] == row["head_sha"], "new": (run.get("summary") or {}).get("candidates", 0),
            "severities": (run.get("summary") or {}).get("severities", {})}
    return context.render({"settings": settings, "pulls": rows})


class WatchRow(WatchConfig):
    id: str
    uid: str
    name: str
    private: bool | None
    reviewed: int
    branch_scan: dict[str, Any] | None
    default_branch: str | None


class WatchPage(BaseModel):
    repositories: list[WatchRow] = Field(max_length=MAX_WATCH_PAGE)
    total: int
    page: int
    per_page: int
    partial: bool
    interval: int
    enabled: int
    branch_min_minutes: int


def _row(item: dict, state: dict) -> dict:
    # Settings saved under the old key (the name) until the watcher moves them to the stable one (pr_watch.migrate):
    # a GET only reads.
    def saved(section: str):
        return state[section].get(item["uid"]) or state[section].get(item["id"]) or {}
    return {"id": item["id"], "uid": item["uid"], "name": item["name"], "private": item.get("private"),
            **pr_watch.DEFAULTS, **saved("repositories"), "reviewed": saved("review_counts") or 0,
            "branch_scan": pr_watch.latest_scan(state["branches"].get(item["uid"])), "default_branch": item.get("branch")}


def _page(page: str | None, per_page: str | None) -> tuple[int, int] | None:
    """`page` (from 1) and `per_page` (1-100); None if they aren't valid. Empty means the default, as it always did."""
    try:
        page_number, size = int(page or "1"), int(per_page or "25")
    except ValueError:
        return None
    return (page_number, size) if 1 <= size <= MAX_WATCH_PAGE and 1 <= page_number and page_number * size <= 10_000 else None


PageNumber = Annotated[str | None, WithJsonSchema({"type": "integer", "minimum": 1})]


@router.get("/api/pull-requests/watch", response_model=WatchPage)
def watch_overview(q: str = "", page: PageNumber = None, per_page: PageNumber = None,
                   only: str | None = Query(None, description="`enabled`: only the watched repositories"),
                   context: Context = Depends(guard())) -> dict:
    """One page (`per_page` 1-100, 25 by default) of the installation's repositories with their watch settings."""
    installations = github_installations(context.data_dir)
    if not installations:
        raise ApiError(400, msg("pulls.errors.connect_app"))
    paged, only = _page(page, per_page), only or None
    if paged is None or len(q) > 100 or only not in (None, "enabled"):
        raise ApiError(400, msg("api.invalid_search"))
    page_number, size = paged
    state = pr_watch.load(context.data_dir, reviews=False)
    enabled = sorted(key for key, value in state["repositories"].items() if value.get("enabled"))
    partial = False
    if only == "enabled":
        # The watched ones come from the saved settings. Their names come from the full list (cached, and kept fresh
        # by the watcher): resolving them one by one would cost one or two GitHub calls per repository and a member
        # could exhaust the installation's rate limit.
        wanted, items = set(enabled), []
        for installation in installations if wanted else []:
            try:
                items.extend({**row, "installation_id": installation} for row in installation_repositories(installation) if row["uid"] in wanted)
            except GitHubAppError:
                continue
        items = [item for item in items if q.strip().casefold() in item["name"].casefold()]
        total, items = len(items), items[(page_number - 1) * size:page_number * size]
    else:
        listing = source_page(None, installations, query=q, provider="github", page=page_number, per_page=size)
        items, total, partial = listing["sources"], listing["total"], listing["partial"]
    state["review_counts"] = pr_watch.review_counts(context.data_dir, [key for item in items for key in (item["uid"], item["id"]) if key])
    return context.render({"repositories": [_row(item, state) for item in items], "total": total, "page": page_number,
                           "per_page": size, "partial": partial, "interval": pr_watch.interval(), "enabled": len(enabled),
                           "branch_min_minutes": pr_watch.branch_min_seconds() // 60})


TARGETS = ("source_id", "source_ids", "all")


class WatchSettingsIn(BaseModel):
    """Exactly one of `source_id`, `source_ids` (1-200) or `all`; with `all`, only `enabled`."""
    model_config = ConfigDict(extra="forbid")
    source_id: Annotated[Any, WithJsonSchema({"type": "string"})] = None
    source_ids: Annotated[Any, WithJsonSchema({"type": "array", "items": {"type": "string"}, "maxItems": MAX_CHOSEN})] = None
    all: StrictBool = None
    enabled: StrictBool = None
    post_comment: StrictBool = None
    gate: Annotated[Any, WithJsonSchema({"type": "string", "enum": list(GATES)})] = None
    branch: StrictBool = None

    @model_validator(mode="before")
    @classmethod
    def _one_target(cls, data):
        if isinstance(data, dict) and sum(key in data for key in TARGETS) != 1:
            raise ValueError("one target")
        return data


class WatchUpdated(BaseModel):
    model_config = ConfigDict(extra="forbid")
    updated: int


@router.post("/api/pull-requests/settings", response_model=WatchUpdated | WatchConfig, openapi_extra=documented(WatchSettingsIn))
def watch_settings(context: Context = Depends(guard(Policy(admin=True, action="pr-settings", body=16_000))),
                   data: WatchSettingsIn = Depends(body(WatchSettingsIn, msg("pulls.errors.invalid_settings")))) -> dict:
    """Configures one repository (and answers its settings), several, or all of them (and answers how many)."""
    payload, data_dir = data.model_dump(exclude_unset=True), context.data_dir
    options = {"enabled": payload.get("enabled"), "post_comment": payload.get("post_comment"), "gate": payload.get("gate"),
               "branch": payload.get("branch"), "by": context.user["username"]}
    if "all" in payload:
        if payload["all"] is not True or set(payload) - {"all", "enabled"} or not isinstance(payload.get("enabled"), bool):
            raise ApiError(400, msg("pulls.errors.invalid_settings"))
        if payload["enabled"]:
            # Enabling all does need the full list; it is a one-off admin action.
            keys = []
            for installation in github_installations(data_dir):
                try:
                    keys.extend(item["uid"] for item in installation_repositories(installation))
                except GitHubAppError as exc:
                    raise ApiError(502, problem(exc)) from exc
        else:
            keys = [key for key, value in pr_watch.load(data_dir, reviews=False)["repositories"].items() if value.get("enabled")]
        results = pr_watch.configure_many(data_dir, keys, **options) if keys else []
        return {"updated": len(results)}
    chosen = [payload["source_id"]] if "source_id" in payload else payload["source_ids"]
    if not isinstance(chosen, list) or not 1 <= len(chosen) <= MAX_CHOSEN or not all(isinstance(item, str) for item in chosen):
        raise ApiError(400, msg("pulls.errors.choose_range", max=MAX_CHOSEN))
    uid_of = {}
    for item in dict.fromkeys(chosen):
        # Each selection is checked on its own; the ones the view just listed cost no extra call.
        found = _repository(data_dir, item)
        if found is None:
            raise ApiError(400, msg("pulls.errors.not_in_app"))
        uid_of[item] = found[1]["uid"]
    try:
        results = pr_watch.configure_many(data_dir, list(uid_of.values()), **options)
    except ValueError as exc:
        raise ApiError(400, problem(exc)) from exc
    return context.render(results[0] if "source_id" in payload else {"updated": len(results)})
