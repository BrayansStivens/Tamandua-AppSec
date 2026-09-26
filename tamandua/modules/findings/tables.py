"""Tablas del registro de hallazgos y del triage. Cada hallazgo guarda su entrada completa en JSONB (el formato de
siempre) y, aparte, lo que se consulta: estado y CVE (índice GIN para «¿me afecta este CVE?»)."""

from sqlalchemy import DateTime, func, ARRAY, Column, Index, Table, Text
from sqlalchemy.dialects.postgresql import JSONB

from tamandua.shared.db import TENANT, metadata

registry_assets = Table(
    "registry_assets", metadata,
    Column("tenant_id", Text, primary_key=True, server_default=TENANT),
    Column("asset_key", Text, primary_key=True),
    Column("name", Text),
    Column("applied", JSONB, nullable=False, server_default="[]"),  # ejecuciones ya incorporadas (idempotencia)
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
)
Index("ix_registry_findings_status", registry_findings.c.tenant_id, registry_findings.c.status)
Index("ix_registry_findings_cves", registry_findings.c.cves, postgresql_using="gin")

triage_decisions = Table(
    "triage_decisions", metadata,
    Column("tenant_id", Text, primary_key=True, server_default=TENANT),
    Column("asset_key", Text, primary_key=True),
    Column("fingerprint", Text, primary_key=True),
    Column("status", Text, nullable=False),
    Column("decision", JSONB, nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()),
)
