"""Outbox: every outgoing message is stored before it is sent, and the worker delivers it with retries.
If the process dies, nothing is lost; if the channel fails, it is retried with a growing backoff.

Notification channels use their channel id; Jira work (issues to create, comments) uses `JIRA_CHANNEL` and is delivered
by `runs/jira_sync.py`."""

from sqlalchemy import Column, DateTime, Index, Integer, String, Table, Text, func
from sqlalchemy.dialects.postgresql import JSONB

from tamandua.shared.db import TENANT, metadata

JIRA_CHANNEL = "jira"

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
