"""The repository registry: one row per repository (its name, scan branch and retirement mark). It replaces the
`repo-registry` document, rewritten whole on every reconciliation."""

from sqlalchemy import Column, DateTime, Table, Text, func
from sqlalchemy.dialects.postgresql import JSONB

from tamandua.shared.db import TENANT, metadata

repo_registry = Table(
    "repo_registry", metadata,
    Column("tenant_id", Text, primary_key=True, server_default=TENANT),
    Column("uid", Text, primary_key=True),
    Column("entry", JSONB, nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
)
