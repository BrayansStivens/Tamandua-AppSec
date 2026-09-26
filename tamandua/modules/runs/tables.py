"""Tablas de ejecuciones. La fila del listado (`row`) y el registro completo (`record`) se guardan tal cual en JSONB
(el formato que ya usa la aplicación); las columnas tipadas sirven para filtrar, ordenar y paginar en la base."""

from sqlalchemy import Boolean, Column, DateTime, ForeignKeyConstraint, Index, Integer, String, Table, Text, func
from sqlalchemy.dialects.postgresql import JSONB

from tamandua.shared.db import TENANT, metadata

runs = Table(
    "runs", metadata,
    Column("tenant_id", Text, primary_key=True, server_default=TENANT),
    Column("id", String(32), primary_key=True),
    Column("type", Text, nullable=False),
    Column("status", Text, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    # No foreign key to registry_assets: a queued, failed or non-finding run has no registry row (see migration 0003).
    Column("asset_key", Text),
    Column("row", JSONB, nullable=False),
    Column("record", JSONB, nullable=False),
    Column("report", Text),
    Column("sarif", JSONB),
    Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()),
)
Index("ix_runs_listing", runs.c.tenant_id, runs.c.created_at.desc(), runs.c.id.desc())
Index("ix_runs_asset", runs.c.tenant_id, runs.c.asset_key)
Index("ix_runs_status", runs.c.tenant_id, runs.c.status)

# Cola de trabajos durable: el API encola, el worker reclama con FOR UPDATE SKIP LOCKED. Sin secretos en `payload`
# (los tokens de código viajan por el almacén cifrado y el worker los borra al usarlos).
jobs = Table(
    "jobs", metadata,
    Column("tenant_id", Text, primary_key=True, server_default=TENANT),
    Column("id", String(32), primary_key=True),
    Column("kind", Text, nullable=False),
    Column("run_id", String(32)),
    Column("payload", JSONB, nullable=False),
    Column("status", Text, nullable=False, server_default="queued"),  # queued · running · done · failed
    Column("attempts", Integer, nullable=False, server_default="0"),
    Column("locked_by", Text),
    Column("locked_at", DateTime(timezone=True)),
    Column("error", Text),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("finished_at", DateTime(timezone=True)),
    # A job only exists to fill its run: when the run goes (repository purge), so does the job.
    ForeignKeyConstraint(["tenant_id", "run_id"], ["runs.tenant_id", "runs.id"], name="fk_jobs_run", ondelete="CASCADE"),
)
Index("ix_jobs_claim", jobs.c.tenant_id, jobs.c.status, jobs.c.created_at)
Index("ix_jobs_run", jobs.c.tenant_id, jobs.c.run_id)

# Latido de cada worker: la salud del API dice si hay uno vivo y si puede lanzar los motores (Docker).
workers = Table(
    "workers", metadata,
    Column("id", Text, primary_key=True),
    Column("heartbeat_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("docker", Boolean, nullable=False, server_default="false"),
    Column("version", Text),
)
