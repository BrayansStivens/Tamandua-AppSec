"""Tables for the findings registry and triage. Each finding keeps its whole entry in JSONB (the usual format) and,
separately, what gets queried: status and CVE (GIN index for "does this CVE affect me?")."""

from sqlalchemy import DateTime, func, ARRAY, Column, ForeignKeyConstraint, Index, Table, Text
from sqlalchemy.dialects.postgresql import JSONB

from tamandua.shared.db import TENANT, metadata

registry_assets = Table(
    "registry_assets", metadata,
    Column("tenant_id", Text, primary_key=True, server_default=TENANT),
    Column("asset_key", Text, primary_key=True),
    Column("name", Text),
    Column("applied", JSONB, nullable=False, server_default="[]"),  # runs already merged in (idempotency)
)

registry_findings = Table(
    "registry_findings", metadata,
    Column("tenant_id", Text, primary_key=True, server_default=TENANT),
    Column("asset_key", Text, primary_key=True),
    Column("fingerprint", Text, primary_key=True),
    Column("status", Text, nullable=False),
    Column("cves", ARRAY(Text), nullable=False, server_default="{}"),
    Column("entry", JSONB, nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()),
    ForeignKeyConstraint(["tenant_id", "asset_key"], ["registry_assets.tenant_id", "registry_assets.asset_key"],
                         name="fk_registry_findings_asset", ondelete="CASCADE"),
)
Index("ix_registry_findings_status", registry_findings.c.tenant_id, registry_findings.c.status)
Index("ix_registry_findings_cves", registry_findings.c.cves, postgresql_using="gin")

# No foreign key to registry_findings: a decision outlives a registry rebuild and moves to a new asset key before the
# registry has it (see migration 0003). `tamandua.app.integrity` reports the ones whose repository is gone.
triage_decisions = Table(
    "triage_decisions", metadata,
    Column("tenant_id", Text, primary_key=True, server_default=TENANT),
    Column("asset_key", Text, primary_key=True),
    Column("fingerprint", Text, primary_key=True),
    Column("status", Text, nullable=False),
    Column("decision", JSONB, nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()),
)
