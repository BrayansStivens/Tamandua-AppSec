"""Pull request watch tables: one row per repository (its settings and the heads of its target branches) and one per
reviewed pull request, which is what grows. They replace the `pr-watch` document, rewritten whole on every change."""

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Table, Text, func
from sqlalchemy.dialects.postgresql import JSONB

from tamandua.shared.db import TENANT, metadata

pr_watch = Table(
    "pr_watch", metadata,
    Column("tenant_id", Text, primary_key=True, server_default=TENANT),
    Column("asset_key", Text, primary_key=True),
    Column("config", JSONB),    # watch settings; NULL when none were saved
    Column("branches", JSONB),  # {"heads": {branch: {head_sha, run_id, at}}}; NULL before the first rescan
    Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
)

pr_reviews = Table(
    "pr_reviews", metadata,
    Column("tenant_id", Text, primary_key=True, server_default=TENANT),
    Column("asset_key", Text, primary_key=True),
    Column("number", Integer, primary_key=True),
    Column("head_sha", Text, nullable=False),
    Column("run_id", String(32), nullable=False),
    Column("closed", Boolean, nullable=False, server_default="false"),
    Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
)
