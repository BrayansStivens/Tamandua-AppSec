"""Cola de trabajos durable sobre PostgreSQL (tabla `jobs`).

El API encola y responde al instante; uno o varios workers reclaman con `FOR UPDATE SKIP LOCKED` (nunca dos el
mismo trabajo). Mientras corre, el worker renueva `locked_at`; si un worker muere, sus trabajos se quedan sin
renovar y `recover` los da por interrumpidos (la ejecución se marca fallida con un mensaje claro, como antes con un
reinicio). Los análisis no se reintentan solos: repetirlos lo decide quien los lanzó.
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

STALE = timedelta(minutes=5)  # sin renovar en este tiempo: el worker que lo tenía murió


def enqueue(data_dir: Path, kind: str, payload: dict, *, run_id: str | None = None) -> str:
    identifier = uuid.uuid4().hex
    with db.transaction(data_dir) as connection:
        connection.execute(insert(jobs).values(tenant_id=TENANT, id=identifier, kind=kind, run_id=run_id, payload=payload))
    return identifier


def claim(data_dir: Path, worker: str) -> dict | None:
    """El trabajo más antiguo en cola, ya marcado como de este worker; None si no hay."""
    with db.transaction(data_dir) as connection:
        oldest = (select(jobs.c.id).where(jobs.c.tenant_id == TENANT, jobs.c.status == "queued")
                  .order_by(jobs.c.created_at).limit(1).with_for_update(skip_locked=True).scalar_subquery())
        row = connection.execute(update(jobs).where(jobs.c.tenant_id == TENANT, jobs.c.id == oldest)
                                 .values(status="running", locked_by=worker, locked_at=func.now(), attempts=jobs.c.attempts + 1)
                                 .returning(jobs.c.id, jobs.c.kind, jobs.c.run_id, jobs.c.payload)).first()
    return dict(row._mapping) if row else None


def touch(data_dir: Path, worker: str) -> None:
    """Renueva los trabajos en curso de este worker (y su latido)."""
    with db.transaction(data_dir) as connection:
        connection.execute(update(jobs).where(jobs.c.tenant_id == TENANT, jobs.c.status == "running", jobs.c.locked_by == worker)
                           .values(locked_at=func.now()))


def finish(data_dir: Path, job_id: str, *, error: str | None = None) -> None:
    with db.transaction(data_dir) as connection:
        connection.execute(update(jobs).where(jobs.c.tenant_id == TENANT, jobs.c.id == job_id)
                           .values(status="failed" if error else "done", error=(error or None) and error[:500], finished_at=func.now()))


def pending(data_dir: Path) -> int:
    """En cola o en curso (lo que aún no ha terminado)."""
    with db.transaction(data_dir) as connection:
        return connection.execute(select(func.count()).select_from(jobs)
                                  .where(jobs.c.tenant_id == TENANT, jobs.c.status.in_(("queued", "running")))).scalar_one()


def recover(data_dir: Path) -> list[dict]:
    """Trabajos en curso de un worker que dejó de renovarlos: se dan por interrumpidos. Devuelve cuáles."""
    with db.transaction(data_dir) as connection:
        rows = connection.execute(update(jobs).where(jobs.c.tenant_id == TENANT, jobs.c.status == "running",
                                                     jobs.c.locked_at < func.now() - STALE)
                                  .values(status="failed", error="Interrumpido: el worker dejó de responder", finished_at=func.now())
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
