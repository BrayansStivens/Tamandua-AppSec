"""Durable job queue on PostgreSQL (`jobs` table).

The API enqueues and answers right away; one or more workers claim jobs with `FOR UPDATE SKIP LOCKED` (never two
on the same job). While a job runs, its worker renews `locked_at`; if a worker dies, its jobs stop being renewed
and `recover` treats them as interrupted (the run is marked failed with a clear message, as a restart used to do).
Scans are never retried on their own: whoever launched them decides whether to repeat them.
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from pathlib import Path

from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert

from tamandua.modules.runs.tables import jobs, workers
from tamandua.shared import db
from tamandua.shared.db import TENANT

STALE = timedelta(minutes=5)  # not renewed within this time: the worker that held it died


def enqueue(data_dir: Path, kind: str, payload: dict, *, run_id: str | None = None) -> str:
    identifier = uuid.uuid4().hex
    with db.transaction(data_dir) as connection:
        connection.execute(insert(jobs).values(tenant_id=TENANT, id=identifier, kind=kind, run_id=run_id, payload=payload))
    return identifier


def claim(data_dir: Path, worker: str) -> dict | None:
    """The oldest queued job, already marked as this worker's; None if there is none."""
    with db.transaction(data_dir) as connection:
        oldest = (select(jobs.c.id).where(jobs.c.tenant_id == TENANT, jobs.c.status == "queued")
                  .order_by(jobs.c.created_at).limit(1).with_for_update(skip_locked=True).scalar_subquery())
        row = connection.execute(update(jobs).where(jobs.c.tenant_id == TENANT, jobs.c.id == oldest)
                                 .values(status="running", locked_by=worker, locked_at=func.now(), attempts=jobs.c.attempts + 1)
                                 .returning(jobs.c.id, jobs.c.kind, jobs.c.run_id, jobs.c.payload)).first()
    return dict(row._mapping) if row else None


def touch(data_dir: Path, worker: str) -> None:
    """Renews this worker's running jobs (and its heartbeat)."""
    with db.transaction(data_dir) as connection:
        connection.execute(update(jobs).where(jobs.c.tenant_id == TENANT, jobs.c.status == "running", jobs.c.locked_by == worker)
                           .values(locked_at=func.now()))


def finish(data_dir: Path, job_id: str, *, error: str | None = None, worker: str | None = None) -> bool:
    """Closes a job. With `worker`, only while that worker still holds it: a job already recovered as interrupted
    stays failed. False if nothing was closed."""
    conditions = [jobs.c.tenant_id == TENANT, jobs.c.id == job_id]
    if worker is not None:
        conditions += [jobs.c.locked_by == worker, jobs.c.status == "running"]
    with db.transaction(data_dir) as connection:
        closed = connection.execute(update(jobs).where(*conditions)
                                    .values(status="failed" if error else "done", error=(error or None) and error[:500],
                                            finished_at=func.now()).returning(jobs.c.id)).first()
    return closed is not None


def pending(data_dir: Path) -> int:
    """Queued or running (whatever hasn't finished yet)."""
    with db.transaction(data_dir) as connection:
        return connection.execute(select(func.count()).select_from(jobs)
                                  .where(jobs.c.tenant_id == TENANT, jobs.c.status.in_(("queued", "running")))).scalar_one()


def recover(data_dir: Path) -> list[dict]:
    """Running jobs of a worker that stopped renewing them: they are treated as interrupted. Returns which ones."""
    with db.transaction(data_dir) as connection:
        rows = connection.execute(update(jobs).where(jobs.c.tenant_id == TENANT, jobs.c.status == "running",
                                                     jobs.c.locked_at < func.now() - STALE)
                                  .values(status="failed", error="Interrupted: the worker stopped responding", finished_at=func.now())
                                  .returning(jobs.c.id, jobs.c.kind, jobs.c.run_id)).all()
    return [dict(row._mapping) for row in rows]


def heartbeat(data_dir: Path, worker: str, *, docker: bool, version: str) -> None:
    statement = insert(workers).values(id=worker, heartbeat_at=func.now(), docker=docker, version=version)
    with db.transaction(data_dir) as connection:
        connection.execute(statement.on_conflict_do_update(index_elements=[workers.c.id],
                                                           set_={"heartbeat_at": func.now(), "docker": docker, "version": version}))


def workers_alive(data_dir: Path) -> list[dict]:
    with db.transaction(data_dir) as connection:
        return [dict(row._mapping) for row in connection.execute(
            select(workers.c.id, workers.c.docker, workers.c.version).where(workers.c.heartbeat_at > func.now() - STALE))]
