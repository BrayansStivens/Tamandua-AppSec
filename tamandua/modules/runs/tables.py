"""Tablas de ejecuciones. La fila del listado (`row`) y el registro completo (`record`) se guardan tal cual en JSONB
(el formato que ya usa la aplicación); las columnas tipadas sirven para filtrar, ordenar y paginar en la base."""

from sqlalchemy import func, Column, DateTime, Index, String, Table, Text
from sqlalchemy.dialects.postgresql import JSONB

from tamandua.shared.db import TENANT, metadata

runs = Table(
    "runs", metadata,
    Column("tenant_id", Text, primary_key=True, server_default=TENANT),
    Column("id", String(32), primary_key=True),
    Column("type", Text, nullable=False),
    Column("status", Text, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
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
