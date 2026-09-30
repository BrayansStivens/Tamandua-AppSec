"""Periodic tasks as rounds that anyone can trigger.

With TAMANDUA_PERIODIC=leader (the default) the leader worker runs them on its own clock (threads started by
`tamandua.app.worker.start_periodic`). With `external`, nothing runs on its own: a scheduler calls `tamandua periodic`
(cron, a Kubernetes CronJob, the platform's scheduler) or `GET /api/cron` with the cron token (Vercel Cron). A round
runs what is due. What needs the engines or takes long (NVD and the advisory watch) is queued for a worker instead of
running inside the API.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from time import monotonic
from typing import Callable

from tamandua.shared import documents, settings
from tamandua.shared import log as logging_setup

_log = logging_setup.get("periodic")
STATE = "periodic"
NVD_BUDGET = 600  # seconds of NVD sync per round: a worker job, never a request
NVD_EVERY = 900   # longer than the budget: rounds never pile up behind each other


@dataclass(frozen=True)
class Task:
    every: Callable[[], int]      # seconds between rounds; 0 means every time it's called, negative means off
    on_worker: bool                # needs the engines or takes long: an API queues it
    run: Callable[[Path, object], object]


def _outbox(data_dir: Path, jobs) -> object:
    from tamandua.modules.integrations import notifications
    from tamandua.modules.runs import jira_sync
    # Each queue on its own: a channel failing doesn't hold Jira's back, nor the other way round.
    sent, failure = 0, None
    for drain in (notifications.drain, jira_sync.drain):
        try:
            sent += drain(data_dir)
        except Exception as exc:  # noqa: BLE001 — re-raised once both queues had their turn
            failure = exc
    if failure is not None:
        raise failure
    return sent


def _pull_requests(data_dir: Path, jobs) -> object:
    from tamandua.modules.integrations.installations import github_installations
    from tamandua.modules.pullrequests.watch import Watcher
    return Watcher(data_dir, jobs, lambda: github_installations(data_dir)).poll()


def _nvd(data_dir: Path, jobs) -> object:
    """Syncs for up to NVD_BUDGET seconds. NVD failing or throttling (it answers 403/503 under load) ends the round
    quietly: the sync is resumable and the next round goes on from where this one stopped."""
    import time
    from urllib.error import URLError
    from sqlalchemy.exc import SQLAlchemyError
    from tamandua.modules.intel import cve_db
    from tamandua.modules.intel.advisories import load_feeds
    started, steps = monotonic(), 0
    try:
        cve_db.load_signals(data_dir, load_feeds(data_dir))
        while monotonic() - started < NVD_BUDGET and cve_db.sync_step(data_dir) != "idle":
            steps += 1
            if monotonic() - started + cve_db.pause() < NVD_BUDGET:
                time.sleep(cve_db.pause())
    except (URLError, TimeoutError, OSError, ValueError, SQLAlchemyError) as error:  # HTTPError is a URLError
        _log.warning("cve_sync_failed", extra={"reason": type(error).__name__})
    return steps


def _advisories(data_dir: Path, jobs) -> object:
    from tamandua.modules.runs import advisory_watch
    return advisory_watch.check(data_dir)


TASKS: dict[str, Task] = {
    "outbox": Task(lambda: 0, False, _outbox),
    "pull_requests": Task(lambda: settings.integer("TAMANDUA_PR_POLL_SECONDS"), False, _pull_requests),
    "nvd": Task(lambda: NVD_EVERY if settings.flag("TAMANDUA_CVE_SYNC") else -1, True, _nvd),
    "advisories": Task(lambda: 3600 * settings.integer("TAMANDUA_ADVISORY_WATCH_HOURS") or -1, True, _advisories),
}


def external() -> bool:
    return settings.text("TAMANDUA_PERIODIC") == "external"


def _claim(data_dir: Path, names: list[str], now: datetime) -> list[str]:
    """The due tasks among `names`, marked as started in the same transaction: two schedulers firing at once never run a
    task twice."""
    claimed = []
    with documents.edit(data_dir, STATE, {}) as state:
        for name in names:
            every = TASKS[name].every()
            last = (state.get(name) or {}).get("started_at")
            if every < 0:
                continue
            if last and every and now - datetime.fromisoformat(last) < timedelta(seconds=every):
                continue
            state[name] = {**(state.get(name) or {}), "started_at": now.isoformat()}
            claimed.append(name)
    return claimed


def run_round(data_dir: Path, jobs, *, here_only: bool, only: list[str] | None = None,
              now: datetime | None = None) -> dict:
    """One round. `here_only` (an API): tasks that belong on a worker are queued, not run. Returns what happened."""
    names = [name for name in (only or TASKS) if name in TASKS]
    outcome: dict[str, list] = {"ran": [], "queued": [], "failed": []}
    for name in _claim(data_dir, names, now or datetime.now(timezone.utc)):
        if here_only and TASKS[name].on_worker:
            jobs.enqueue_periodic(name)
            outcome["queued"].append(name)
            continue
        try:
            TASKS[name].run(data_dir, jobs)
            outcome["ran"].append(name)
        except Exception:  # noqa: BLE001 — one task failing doesn't stop the others
            _log.exception("periodic_task_failed", extra={"reason": name})
            outcome["failed"].append(name)
    return outcome
