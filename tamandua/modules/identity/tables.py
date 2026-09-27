"""Usuarios, sesiones y retos de segundo factor. El registro completo de cada usuario (hash scrypt, TOTP cifrado,
enlaces de un solo uso) va en JSONB con la forma de siempre; las columnas sirven para buscar y ordenar."""

from sqlalchemy import Column, DateTime, Float, ForeignKeyConstraint, Index, Integer, Table, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB

from tamandua.shared.db import TENANT, metadata

users = Table(
    "users", metadata,
    Column("tenant_id", Text, primary_key=True, server_default=TENANT),
    Column("id", Text, primary_key=True),
    Column("username", Text, nullable=False),
    Column("position", Integer, nullable=False, server_default="0"),  # orden de alta (el de la lista de siempre)
    Column("record", JSONB, nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    UniqueConstraint("tenant_id", "username", name="uq_users_username"),
)

# La cookie lleva el identificador y su firma; aquí solo el hash del identificador (como antes en sessions.json).
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

# Retén entre la contraseña correcta y el código TOTP (antes en memoria del proceso: no servía con varias réplicas).
auth_challenges = Table(
    "auth_challenges", metadata,
    Column("tenant_id", Text, primary_key=True, server_default=TENANT),
    Column("id", Text, primary_key=True),  # hash del token
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
