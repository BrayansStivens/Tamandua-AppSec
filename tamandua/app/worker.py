"""Worker process: runs the queued scans and the periodic tasks. It is the only one that needs Docker.

* Scans: claims jobs from the PostgreSQL queue (several workers can run at once).
* Periodic tasks (PR and main-branch watching, daily new advisories, NVD sync and the notification outbox): only
  one worker runs them, the one holding the leader lock in PostgreSQL. If that worker dies, its connection closes,
  the lock is released and another worker takes it.
"""

from __future__ import annotations

import hashlib
import signal
import tempfile
import threading
from pathlib import Path

from sqlalchemy import text

from tamandua.app import data_migrations, wiring
from tamandua.modules.runs import periodic
from tamandua.modules.runs.jobs import ScanJobs
from tamandua.shared import db
from tamandua.shared import log as logging_setup
from tamandua.shared.i18n import t

LEADER_KEY = int.from_bytes(hashlib.sha256(b"tamandua:worker-leader").digest()[:8], "big", signed=True)


def start_periodic(data_dir: Path, jobs: ScanJobs) -> list:
    """Starts the periodic tasks (threads). Used by the leader worker and by single-process mode."""
    from tamandua.modules.integrations.installations import github_installations
    from tamandua.modules.runs.advisory_watch import Watcher as AdvisoryWatcher
    from tamandua.modules.intel.cve_db import Syncer
    from tamandua.modules.pullrequests.watch import Watcher
    tasks = [Watcher(data_dir, jobs, lambda: github_installations(data_dir)), Syncer(data_dir),
             # Once a day, the already scanned dependencies against advisories published since (offline).
             AdvisoryWatcher(data_dir), OutboxDrainer(data_dir)]
    for task in tasks:
        task.start()
    return tasks


class OutboxDrainer:
    """Delivers the notification outbox every few seconds (with retries; see notifications.drain)."""

    def __init__(self, data_dir: Path, interval: float = 10.0):
        self.data_dir, self.interval = data_dir, interval
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, name="tamandua-outbox", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        from tamandua.modules.integrations import notifications
        log = logging_setup.get("outbox")
        while not self._stop.wait(self.interval):
            try:
                notifications.drain(self.data_dir)
            except Exception:  # noqa: BLE001 — a channel or the database being down doesn't stop the worker
                log.exception("outbox_drain_failed")


LEADER_CHECK_SECONDS = 30


def _lead(data_dir: Path, jobs: ScanJobs, stop: threading.Event) -> None:
    """Tries to become the leader; while it is, runs the periodic tasks and keeps the connection that holds the lock.

    Every LEADER_CHECK_SECONDS it checks that connection. If it is gone, so is the lock (PostgreSQL frees it with the
    session) and another worker may lead by now: this one stops its periodic tasks and competes again."""
    log = logging_setup.get("worker")
    while not stop.is_set():
        connection = db.engine().connect()
        tasks: list = []
        try:
            if connection.execute(text("SELECT pg_try_advisory_lock(:key)"), {"key": LEADER_KEY}).scalar():
                connection.commit()
                log.info("worker_leader", extra={"reason": "this worker advances the batches" + (
                    "; a scheduler triggers the periodic tasks" if periodic.external() else " and runs the periodic tasks")})
                jobs.leader = True
                if not periodic.external():  # external: a scheduler triggers the rounds (tamandua periodic, /api/cron)
                    tasks = start_periodic(data_dir, jobs)
                while not stop.wait(LEADER_CHECK_SECONDS):
                    connection.execute(text("SELECT 1"))
                    connection.commit()
                return
            connection.rollback()
        except Exception:  # noqa: BLE001 — the database dropped the connection: leadership (and the lock) is lost
            log.exception("worker_leader_lost" if jobs.leader else "worker_leader_failed")
        finally:
            for task in tasks:
                task.stop()
            jobs.leader = False
            # Really closed, never back to the pool: a pooled session would keep the leader lock held for nobody.
            connection.invalidate()
        stop.wait(LEADER_CHECK_SECONDS)


def run(data_dir: Path) -> None:
    # The standalone compose points TMPDIR at data/tmp (disk, not the small in-memory /tmp) for the engines' files.
    (data_dir / "tmp").mkdir(parents=True, exist_ok=True)
    tempfile.tempdir = None  # look at TMPDIR again, now that the folder exists
    wiring.configure()
    data_migrations.upgrade(data_dir)
    logging_setup.configure(data_dir)
    jobs = ScanJobs(data_dir, worker=False)
    jobs.prepare(embedded=False)
    stop = threading.Event()

    def shutdown(*_args) -> None:
        stop.set()
        jobs.stop()
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    threading.Thread(target=_lead, args=(data_dir, jobs, stop), name="tamandua-leader", daemon=True).start()
    print(t("cli.worker.started"), flush=True)
    jobs.run_worker()
    print(t("cli.worker.stopped"), flush=True)


def healthy(data_dir: Path) -> bool:
    """For the container healthcheck: some worker on this machine (hostname) sent a heartbeat recently."""
    import socket
    from tamandua.modules.runs import queue
    host = socket.gethostname()
    return any(worker["id"].startswith(f"{host}:") for worker in queue.workers_alive(data_dir))
