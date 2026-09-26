"""Buzón de salida de avisos (outbox): cada mensaje se guarda antes de enviarse y el worker lo entrega con reintentos.
Si el proceso cae, no se pierde; si el canal falla, se reintenta con espera creciente."""

from sqlalchemy import Column, DateTime, Index, Integer, String, Table, Text, func
from sqlalchemy.dialects.postgresql import JSONB

from tamandua.shared.db import TENANT, metadata

outbox = Table(
    "outbox", metadata,
    Column("tenant_id", Text, primary_key=True, server_default=TENANT),
    Column("id", String(32), primary_key=True),
    Column("channel_id", Text, nullable=False),
    Column("payload", JSONB, nullable=False),
    Column("status", Text, nullable=False, server_default="pending"),  # pending · sent · failed
    Column("attempts", Integer, nullable=False, server_default="0"),
    Column("next_attempt_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("last_error", Text),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
)
Index("ix_outbox_due", outbox.c.tenant_id, outbox.c.status, outbox.c.next_attempt_at)
