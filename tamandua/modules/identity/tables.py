"""Users, sessions and second-factor challenges. Each user's full record (scrypt hash, encrypted TOTP,
one-time links) goes in JSONB with its usual shape; the columns are for lookup and sorting."""

from sqlalchemy import Column, DateTime, Float, ForeignKeyConstraint, Index, Integer, Table, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB

from tamandua.shared.db import TENANT, metadata

users = Table(
    "users", metadata,
    Column("tenant_id", Text, primary_key=True, server_default=TENANT),
    Column("id", Text, primary_key=True),
    Column("username", Text, nullable=False),
    Column("position", Integer, nullable=False, server_default="0"),  # creation order (the list's usual order)
    Column("record", JSONB, nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    UniqueConstraint("tenant_id", "username", name="uq_users_username"),
)

# The cookie carries the identifier and its signature; this keeps only the identifier's hash (as sessions.json did).
sessions = Table(
    "sessions", metadata,
    Column("tenant_id", Text, primary_key=True, server_default=TENANT),
    Column("id", Text, primary_key=True),
    Column("user_id", Text, nullable=False),
    Column("expires_at", Float, nullable=False),
    Column("record", JSONB, nullable=False),
    ForeignKeyConstraint(["tenant_id", "user_id"], ["users.tenant_id", "users.id"], name="fk_sessions_user", ondelete="CASCADE"),
)
Index("ix_sessions_user", sessions.c.tenant_id, sessions.c.user_id)

# Pending sign-in between the correct password and the TOTP code (was in process memory: broke with several replicas).
auth_challenges = Table(
    "auth_challenges", metadata,
    Column("tenant_id", Text, primary_key=True, server_default=TENANT),
    Column("id", Text, primary_key=True),  # token hash
    Column("user_id", Text, nullable=False),
    Column("client", Text, nullable=False),
    Column("failures", Integer, nullable=False, server_default="0"),
    Column("created_at", Float, nullable=False),
    ForeignKeyConstraint(["tenant_id", "user_id"], ["users.tenant_id", "users.id"], name="fk_auth_challenges_user", ondelete="CASCADE"),
)

# Progressive lock-out per key (user, client address, setup code…), shared by every instance of the API.
auth_throttle = Table(
    "auth_throttle", metadata,
    Column("tenant_id", Text, primary_key=True, server_default=TENANT),
    Column("key", Text, primary_key=True),
    Column("failures", Integer, nullable=False, server_default="0"),
    Column("until", Float, nullable=False, server_default="0"),
    Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
)
# Forgetting idle keys (auth.Throttle) reads by age: without it, each prune would read the whole table.
Index("ix_auth_throttle_updated_at", auth_throttle.c.tenant_id, auth_throttle.c.updated_at)
