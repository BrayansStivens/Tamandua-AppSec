"""Which repositories are watched (their PRs and main branch), which commits were already reviewed, and the poller.

Settings are stored by stable identity (`github#<id>`): renaming a
repository doesn't turn off its watch.

Without webhooks (the local MVP has no public URL) it polls: every
``TAMANDUA_PR_POLL_SECONDS`` (300 by default, minimum 60) it lists the open PRs
of the enabled repositories and queues a review for each head commit not
reviewed yet. Drafts are skipped.

Only PRs into the repository's target branches are reviewed (`base_branches`; empty means the default branch).
Each target branch is watched too: when its latest commit changes, the repository is rescanned at that commit so
the PR baseline doesn't go stale after a merge. At most once every ``TAMANDUA_BRANCH_MIN_MINUTES`` (60 by default)
per branch, a few per round and only with an almost empty queue: manual scans and PR reviews don't wait behind it.
"""

from __future__ import annotations

import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import delete, func, select, update
from sqlalchemy.dialects.postgresql import insert

from tamandua.modules.pullrequests.tables import pr_reviews, pr_watch
from tamandua.shared import db
from tamandua.shared.db import TENANT
from tamandua.shared import settings as env_settings
from tamandua.shared import events
from tamandua.shared import log as logging_setup
from tamandua.modules.pullrequests.review import GATES
from tamandua.shared.i18n import msg, text

_log = logging_setup.get("pr_watch")
DEFAULTS = {"enabled": False, "post_comment": True, "gate": "high", "branch": True, "base_branches": []}
MAX_BASE_BRANCHES = 10
BRANCH_PER_POLL = 3     # main-branch rescans queued per round, at most
BRANCH_QUEUE_LIMIT = 2  # only if the queue holds fewer than this


@dataclass(frozen=True)
class RepositoriesListed:
    """The COMPLETE repository list of the connected installations was read (a partial one is never published):
    what's missing from it can be retired. `active_accounts`: the accounts still connected (None: all)."""
    data_dir: Path
    repositories: list[dict]
    active_accounts: set[str] | None


class WatchError(ValueError):
    """`message` is what people read (rendered per reader); str() stays English, for logs."""

    def __init__(self, message):
        super().__init__(text(message, "en"))
        self.message = message


@contextmanager
def _locked(data_dir: Path):
    """One transaction under the watch lock: read-modify-write of the settings never loses a concurrent change."""
    with db.transaction(data_dir) as connection:
        db.lock(connection, "pr-watch")
        yield connection


def _configs(connection, keys=None) -> dict[str, dict]:
    statement = select(pr_watch.c.asset_key, pr_watch.c.config).where(pr_watch.c.tenant_id == TENANT, pr_watch.c.config.is_not(None))
    if keys is not None:
        statement = statement.where(pr_watch.c.asset_key.in_(list(keys)))
    return {key: config for key, config in connection.execute(statement).all() if isinstance(config, dict)}


def _branches_of(connection, key: str):
    return connection.execute(select(pr_watch.c.branches).where(pr_watch.c.tenant_id == TENANT, pr_watch.c.asset_key == key)).scalar_one_or_none()


def _put(connection, key: str, **values) -> None:
    statement = insert(pr_watch).values(tenant_id=TENANT, asset_key=key, **values)
    connection.execute(statement.on_conflict_do_update(index_elements=[pr_watch.c.tenant_id, pr_watch.c.asset_key],
                                                       set_={**values, "updated_at": func.now()}))


def _reviews(connection, keys=None) -> dict[str, dict]:
    statement = select(pr_reviews.c.asset_key, pr_reviews.c.number, pr_reviews.c.head_sha, pr_reviews.c.run_id, pr_reviews.c.closed) \
        .where(pr_reviews.c.tenant_id == TENANT)
    if keys is not None:
        statement = statement.where(pr_reviews.c.asset_key.in_(list(keys)))
    result: dict[str, dict] = {}
    for key, number, head_sha, run_id, closed in connection.execute(statement.order_by(pr_reviews.c.number)).all():
        result.setdefault(key, {})[str(number)] = {"head_sha": head_sha, "run_id": run_id, **({"closed": True} if closed else {})}
    return result


def load(data_dir: Path, *, reviews: bool = True) -> dict:
    """{"repositories": {key: settings}, "reviewed": {key: {number: review}}, "branches": {key: heads}}. Without
    `reviews`, "reviewed" stays empty: the reviewed pull requests are what grows."""
    with db.transaction(data_dir) as connection:
        branches = dict(connection.execute(
            select(pr_watch.c.asset_key, pr_watch.c.branches).where(pr_watch.c.tenant_id == TENANT, pr_watch.c.branches.is_not(None))).all())
        return {"repositories": _configs(connection), "reviewed": _reviews(connection) if reviews else {}, "branches": branches}


def review_counts(data_dir: Path, keys: list[str]) -> dict[str, int]:
    """How many pull requests of each repository were reviewed."""
    with db.transaction(data_dir) as connection:
        return dict(connection.execute(select(pr_reviews.c.asset_key, func.count()).where(
            pr_reviews.c.tenant_id == TENANT, pr_reviews.c.asset_key.in_(keys)).group_by(pr_reviews.c.asset_key)).all())


def _save(data_dir: Path, payload: dict) -> None:
    """Replaces the whole watch state with `payload` (the shape `load` returns). For the data migration and tests."""
    with _locked(data_dir) as connection:
        connection.execute(delete(pr_reviews).where(pr_reviews.c.tenant_id == TENANT))
        connection.execute(delete(pr_watch).where(pr_watch.c.tenant_id == TENANT))
        repositories, branches = payload.get("repositories") or {}, payload.get("branches") or {}
        for key in set(repositories) | set(branches):
            _put(connection, key, config=repositories.get(key), branches=branches.get(key))
        rows = [{"tenant_id": TENANT, "asset_key": key, "number": int(number), "head_sha": str(entry.get("head_sha") or ""),
                 "run_id": str(entry.get("run_id") or "")[:32], "closed": bool(entry.get("closed"))}
                for key, done in (payload.get("reviewed") or {}).items() if isinstance(done, dict)
                for number, entry in done.items() if isinstance(entry, dict) and str(number).isdigit()]
        if rows:
            connection.execute(insert(pr_reviews), rows)


def settings(data_dir: Path, source_id: str) -> dict:
    with db.transaction(data_dir) as connection:
        return {**DEFAULTS, **_configs(connection, [source_id]).get(source_id, {})}


def configure(data_dir: Path, source_id: str, *, enabled=None, post_comment=None, gate=None, branch=None, by: str) -> dict:
    return configure_many(data_dir, [source_id], enabled=enabled, post_comment=post_comment, gate=gate, branch=branch, by=by)[0]


def configure_many(data_dir: Path, keys: list[str], *, enabled=None, post_comment=None, gate=None, branch=None, by: str) -> list[dict]:
    """Several repositories in one transaction; each writes only its own row."""
    if gate is not None and gate not in GATES:
        raise WatchError(msg("pulls.watch.invalid_gate"))
    results = []
    with _locked(data_dir) as connection:
        stored = _configs(connection, keys)
        when = datetime.now(timezone.utc).isoformat(timespec="seconds")
        for key in dict.fromkeys(keys):
            current = {**DEFAULTS, **stored.get(key, {})}
            for field, value in (("enabled", enabled), ("post_comment", post_comment), ("gate", gate), ("branch", branch)):
                if value is not None:
                    current[field] = value
            current.update(updated_by=by, updated_at=when)
            _put(connection, key, config=current)
            results.append(current)
    reason = f"{keys[0]}: {results[0]['enabled']}" if len(results) == 1 else f"{len(results)} repositorios: {enabled}"
    _log.info("pr_watch_configured", extra={"user": by, "reason": reason})
    return results


def target_branches(config: dict, default_branch: str | None) -> list[str]:
    """Branches whose PRs are reviewed and whose baseline is kept fresh; empty if nothing is known."""
    configured = [branch for branch in config.get("base_branches") or [] if isinstance(branch, str)]
    return configured or ([default_branch] if default_branch else [])


def set_base_branches(data_dir: Path, key: str, branches: list[str], *, default_branch: str | None, by: str) -> dict:
    """Stores the (already validated) target branches and drops the watch state of branches no longer targeted."""
    with _locked(data_dir) as connection:
        current = {**DEFAULTS, **_configs(connection, [key]).get(key, {})}
        current.update(base_branches=list(branches), updated_by=by,
                       updated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))
        keep = set(target_branches(current, default_branch))
        heads = {name: state for name, state in _heads(_branches_of(connection, key), default_branch).items() if name in keep}
        _put(connection, key, config=current, branches={"heads": heads} if heads else None)
    _log.info("pr_branches_configured", extra={"user": by, "reason": f"{key}: {', '.join(branches) or 'default'}"})
    return current


def forget(data_dir: Path, key: str) -> None:
    with _locked(data_dir) as connection:
        connection.execute(delete(pr_reviews).where(pr_reviews.c.tenant_id == TENANT, pr_reviews.c.asset_key == key))
        connection.execute(delete(pr_watch).where(pr_watch.c.tenant_id == TENANT, pr_watch.c.asset_key == key))


def migrate(data_dir: Path, repositories: list[dict]) -> None:
    """Old settings stored by name (`github:owner/repo`) → stable identity. What the stable key
    already holds wins."""
    by_name = {item["id"]: item["uid"] for item in repositories if item.get("uid")}
    if not by_name:
        return
    with _locked(data_dir) as connection:
        old_keys = set(connection.execute(select(pr_watch.c.asset_key).where(
            pr_watch.c.tenant_id == TENANT, pr_watch.c.asset_key.in_(list(by_name)))).scalars())
        old_keys |= set(connection.execute(select(pr_reviews.c.asset_key).where(
            pr_reviews.c.tenant_id == TENANT, pr_reviews.c.asset_key.in_(list(by_name)))).scalars())
        for old in old_keys:
            new = by_name[old]
            row = connection.execute(select(pr_watch.c.config, pr_watch.c.branches).where(
                pr_watch.c.tenant_id == TENANT, pr_watch.c.asset_key == old)).first()
            target = connection.execute(select(pr_watch.c.config, pr_watch.c.branches).where(
                pr_watch.c.tenant_id == TENANT, pr_watch.c.asset_key == new)).first()
            if row is not None:
                _put(connection, new, config=(target.config if target and target.config is not None else row.config),
                     branches=(target.branches if target and target.branches is not None else row.branches))
                connection.execute(delete(pr_watch).where(pr_watch.c.tenant_id == TENANT, pr_watch.c.asset_key == old))
            taken = select(pr_reviews.c.number).where(pr_reviews.c.tenant_id == TENANT, pr_reviews.c.asset_key == new)
            connection.execute(update(pr_reviews).where(pr_reviews.c.tenant_id == TENANT, pr_reviews.c.asset_key == old,
                                                        pr_reviews.c.number.not_in(taken.scalar_subquery())).values(asset_key=new))
            connection.execute(delete(pr_reviews).where(pr_reviews.c.tenant_id == TENANT, pr_reviews.c.asset_key == old))


def reviewed(data_dir: Path, source_id: str) -> dict:
    with db.transaction(data_dir) as connection:
        return _reviews(connection, [source_id]).get(source_id, {})


def mark(data_dir: Path, source_id: str, number: int, head_sha: str, run_id: str) -> None:
    values = {"head_sha": head_sha, "run_id": run_id, "closed": False}
    statement = insert(pr_reviews).values(tenant_id=TENANT, asset_key=source_id, number=int(number), **values)
    with db.transaction(data_dir) as connection:
        connection.execute(statement.on_conflict_do_update(
            index_elements=[pr_reviews.c.tenant_id, pr_reviews.c.asset_key, pr_reviews.c.number], set_={**values, "updated_at": func.now()}))


def _heads(entry, default_branch: str | None = None) -> dict[str, dict]:
    """Watch state per branch. Older entries hold a single state, which was always the default branch's."""
    if not isinstance(entry, dict):
        return {}
    if isinstance(entry.get("heads"), dict):
        return {name: state for name, state in entry["heads"].items() if isinstance(state, dict)}
    return {default_branch: entry} if default_branch and entry.get("head_sha") else {}


def latest_scan(entry) -> dict | None:
    """The most recent branch rescan of a repository (what the panel shows), with its branch when known."""
    if isinstance(entry, dict) and not isinstance(entry.get("heads"), dict):
        return entry if entry.get("head_sha") else None
    states = [{**state, "branch": name} for name, state in _heads(entry).items()]
    return max(states, key=lambda state: str(state.get("at") or ""), default=None)


def branch_state(data_dir: Path, key: str, branch: str | None = None, *, default_branch: str | None = None) -> dict | None:
    with db.transaction(data_dir) as connection:
        entry = _branches_of(connection, key)
    if branch is None:
        return latest_scan(entry)
    return _heads(entry, default_branch).get(branch)


def mark_branch(data_dir: Path, key: str, head_sha: str, run_id: str, branch: str, *, default_branch: str | None = None) -> None:
    with _locked(data_dir) as connection:
        heads = _heads(_branches_of(connection, key), default_branch)
        heads[branch] = {"head_sha": head_sha, "run_id": run_id, "at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        _put(connection, key, branches={"heads": heads})


def branch_min_seconds() -> int:
    return 60 * env_settings.integer("TAMANDUA_BRANCH_MIN_MINUTES")


def interval() -> int:
    return env_settings.integer("TAMANDUA_PR_POLL_SECONDS")


def mark_closed(data_dir: Path, key: str, number: int) -> None:
    with db.transaction(data_dir) as connection:
        connection.execute(update(pr_reviews).where(pr_reviews.c.tenant_id == TENANT, pr_reviews.c.asset_key == key,
                                                    pr_reviews.c.number == int(number)).values(closed=True, updated_at=func.now()))


class Watcher:
    """Thread that polls the PRs of the enabled repositories. Only `serve` starts it."""

    def __init__(self, data_dir: Path, jobs, installation_for):
        self.data_dir, self.jobs, self.installation_for = data_dir, jobs, installation_for
        self.interval = interval()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, name="tamandua-pr-watch", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        _log.info("pr_watch_started", extra={"reason": f"cada {self.interval} s"})
        # The first round doesn't wait the full interval: after a restart, open PRs are reviewed right away.
        delay = min(15, self.interval)
        while not self._stop.wait(delay):
            delay = self.interval
            try:
                self.poll()
            except Exception:  # noqa: BLE001 — a network failure must not kill the watcher
                _log.exception("pr_watch_failed")

    def _closed(self, installation: int, key: str, repository: str, done: dict, open_numbers: set[int]) -> None:
        """Reviewed PRs that are no longer open: unmerged ones retire their findings; merged ones wait for the scan."""
        from tamandua.modules.findings.registry import pull_closed
        from tamandua.modules.integrations.github import GitHubAppError, pull_request
        for number, entry in done.items():
            if entry.get("closed") or int(number) in open_numbers:
                continue
            try:
                pull = pull_request(installation, repository, int(number))
            except GitHubAppError:
                continue
            if pull.get("state") != "closed":
                continue
            pull_closed(self.data_dir, key, int(number), merged=pull["merged"], when=pull.get("closed_at") or "")
            mark_closed(self.data_dir, key, int(number))
            _log.info("pr_closed", extra={"reason": f"{repository}#{number} {'mergeado' if pull['merged'] else 'cerrado sin merge'}"})

    def poll(self) -> int:
        from tamandua.modules.integrations.github import GitHubAppError, installation_repositories, open_pull_requests
        configured = self.installation_for()
        installations = [configured] if isinstance(configured, int) else configured or []
        if not installations:
            return 0
        repositories = []
        failed = False
        for installation in installations:
            try:
                repositories.extend({**item, "installation_id": installation}
                                    for item in installation_repositories(installation, fresh=True))
            except GitHubAppError as exc:
                _log.warning("pr_repos_failed", extra={"reason": f"{installation}: {exc}"})
                failed = True
        if failed:
            # A partial response doesn't prove that another account's repositories disappeared.
            return 0
        migrate(self.data_dir, repositories)
        # Only accounts still connected can prove that a repository is gone.
        from tamandua.modules.integrations.installations import github_connections
        accounts = {row["account"].casefold() for row in github_connections(self.data_dir)
                    if isinstance(row.get("account"), str)}
        events.publish(RepositoriesListed(self.data_dir, repositories, accounts or None))
        by_uid = {item["uid"]: item for item in repositories}
        queued = 0
        for key, config in load(self.data_dir, reviews=False)["repositories"].items():
            if not config.get("enabled") or key not in by_uid:
                continue
            source_id, repository = by_uid[key]["id"], by_uid[key]["name"]
            installation = by_uid[key]["installation_id"]
            try:
                pulls = open_pull_requests(installation, repository)
            except GitHubAppError as exc:
                _log.warning("pr_list_failed", extra={"reason": f"{repository}: {exc}"})
                continue
            done = reviewed(self.data_dir, key)
            self._closed(installation, key, repository, done, {pull["number"] for pull in pulls})
            targets = set(target_branches(config, by_uid[key].get("branch")))
            for pull in pulls:
                if pull["draft"] or not pull["head_sha"] or done.get(str(pull["number"]), {}).get("head_sha") == pull["head_sha"]:
                    continue
                if targets and pull.get("base_ref") not in targets:
                    continue
                if self.jobs.pending() >= 20:
                    return queued
                self.jobs.enqueue_pr_review(source_id=source_id, uid=key, pull=pull, installation_id=installation, requested_by="vigilante",
                                            default_branch=by_uid[key].get("branch"))
                queued += 1
        rescans = self._branches(by_uid)
        watched = sum(1 for config in load(self.data_dir, reviews=False)["repositories"].values() if config.get("enabled"))
        _log.info("pr_watch_poll", extra={"reason": f"{watched} repositorios vigilados, {queued} revisiones de PR y {rescans} "
                                                    "reanálisis de rama principal encolados"})
        return queued + rescans

    def _branches(self, by_uid: dict) -> int:
        """Rescans each target branch whose latest commit changed, pinned to that commit (with a pause between scans)."""
        from tamandua.modules.integrations.github import GitHubAppError, branch_head
        queued = 0
        now = datetime.now(timezone.utc)
        for key, config in load(self.data_dir, reviews=False)["repositories"].items():
            if not config.get("enabled") or not {**DEFAULTS, **config}.get("branch") or key not in by_uid:
                continue
            item = by_uid[key]
            if item.get("archived"):
                continue
            default = item.get("branch")
            for branch in target_branches(config, default):
                if queued >= BRANCH_PER_POLL or self.jobs.pending() >= BRANCH_QUEUE_LIMIT:
                    return queued
                last = branch_state(self.data_dir, key, branch, default_branch=default) or {}
                try:
                    if last.get("at") and (now - datetime.fromisoformat(last["at"])).total_seconds() < branch_min_seconds():
                        continue
                except ValueError:
                    pass
                try:
                    head = branch_head(item["installation_id"], item["name"], branch)
                except GitHubAppError as exc:
                    _log.warning("branch_head_failed", extra={"reason": f"{item['name']}@{branch}: {exc}"})
                    continue
                if head == last.get("head_sha"):
                    continue
                run = self.jobs.enqueue_repository_scan(
                    source_id=item["id"], source_name=item["name"], allow_osv_upload=False, context="", tokens={},
                    installation_id=item["installation_id"], uid=key, requested_by="vigilante", branch=branch, commit=head,
                    trigger={"kind": "branch", "branch": branch, "head_sha": head, "previous_sha": last.get("head_sha")})
                mark_branch(self.data_dir, key, head, run["id"], branch, default_branch=default)
                queued += 1
                _log.info("branch_rescan", extra={"reason": f"{item['name']}@{branch} {head[:7]}"})
        return queued
