"""Operational figures for the metrics endpoint: queue, workers and recent runs, read in one pass.

Every figure is a gauge computed from the database at scrape time (several API replicas give the same answer).
Windows are bounded (the last 24 hours) so a scrape stays cheap however large the history grows.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from sqlalchemy import DateTime, Float, and_, cast, extract, func, select

from tamandua.modules.runs.queue import STALE
from tamandua.modules.runs.tables import jobs, runs, workers
from tamandua.shared import db
from tamandua.shared.db import TENANT

WINDOW = timedelta(hours=24)
JOB_STATUSES = ("queued", "running", "done", "failed")
QUANTILES = (0.5, 0.95)


def snapshot(data_dir: Path) -> dict:
    """{"jobs": {status: n}, "jobs_failed_window": n, "oldest_queued_seconds": s, "workers": {...}, "runs": [...]}."""
    now = func.now()
    with db.transaction(data_dir) as connection:
        by_status = dict.fromkeys(JOB_STATUSES, 0) | {
            row.status: row.total for row in connection.execute(
                select(jobs.c.status, func.count().label("total")).where(jobs.c.tenant_id == TENANT).group_by(jobs.c.status))}
        failed = connection.execute(select(func.count()).select_from(jobs).where(
            jobs.c.tenant_id == TENANT, jobs.c.status == "failed", jobs.c.finished_at > now - WINDOW)).scalar_one()
        oldest = connection.execute(select(extract("epoch", now - func.min(jobs.c.created_at))).where(
            jobs.c.tenant_id == TENANT, jobs.c.status == "queued")).scalar()
        beats = connection.execute(select(
            func.count().filter(workers.c.heartbeat_at > now - STALE).label("alive"),
            func.count().filter(and_(workers.c.heartbeat_at > now - STALE, workers.c.docker)).label("docker"),
            extract("epoch", now - func.max(workers.c.heartbeat_at)).label("last_beat"))).one()
        runs_rows = _runs(connection, now)
    return {"jobs": by_status, "jobs_failed_window": failed, "oldest_queued_seconds": float(oldest or 0),
            "workers": {"alive": beats.alive, "docker": beats.docker,
                        "last_heartbeat_seconds": None if beats.last_beat is None else float(beats.last_beat)},
            "runs": runs_rows}


def _runs(connection, now) -> list[dict]:
    """Runs created in the window, by type and status, with duration quantiles for the finished ones."""
    started = cast(runs.c.row["started_at"].astext, DateTime(timezone=True))
    finished = cast(runs.c.row["finished_at"].astext, DateTime(timezone=True))
    has_times = and_(runs.c.row.has_key("started_at"), runs.c.row.has_key("finished_at"))
    duration = cast(extract("epoch", finished - started), Float)
    columns = [runs.c.type, runs.c.status, func.count().label("total"),
               func.max(duration).filter(has_times).label("max"),
               func.sum(duration).filter(has_times).label("sum"),
               func.count().filter(has_times).label("timed")]
    columns += [func.percentile_cont(q).within_group(duration).filter(has_times).label(f"q{index}")
                for index, q in enumerate(QUANTILES)]
    rows = connection.execute(select(*columns).where(runs.c.tenant_id == TENANT, runs.c.created_at > now - WINDOW)
                              .group_by(runs.c.type, runs.c.status).order_by(runs.c.type, runs.c.status)).all()
    return [{"type": row.type, "status": row.status, "total": row.total, "timed": row.timed,
             "sum": float(row.sum or 0), "max": None if row.max is None else float(row.max),
             "quantiles": {q: (None if getattr(row, f"q{index}") is None else float(getattr(row, f"q{index}")))
                           for index, q in enumerate(QUANTILES)}}
            for row in rows]
