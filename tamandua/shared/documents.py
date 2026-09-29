"""JSON documents in PostgreSQL: the store for configuration and small state (PR watching, exclusions,
deadlines, CRA, batches, threat models…).

Each document keeps the shape its JSON file had, so modules only change how they read and write it.
Read-modify-save runs in a transaction with a per-document lock (`edit`): the API and the worker no longer
overwrite each other's writes, as they did with the files and each process's `threading.Lock`s.
"""

from __future__ import annotations

import copy
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import Column, DateTime, Table, Text, delete as sql_delete, func, select
from sqlalchemy.dialects.postgresql import JSONB, insert

from tamandua.shared import db
from tamandua.shared.db import TENANT, metadata

documents = Table(
    "documents", metadata,
    Column("tenant_id", Text, primary_key=True, server_default=TENANT),
    Column("name", Text, primary_key=True),
    Column("body", JSONB, nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
)


def load(data_dir: Path, name: str, default=None):
    """The document, or a copy of `default` if it doesn't exist."""
    with db.transaction(data_dir) as connection:
        body = connection.execute(select(documents.c.body).where(documents.c.tenant_id == TENANT, documents.c.name == name)).scalar_one_or_none()
    return copy.deepcopy(default) if body is None else body


def save(data_dir: Path, name: str, body) -> None:
    statement = insert(documents).values(tenant_id=TENANT, name=name, body=body)
    with db.transaction(data_dir) as connection:
        connection.execute(statement.on_conflict_do_update(index_elements=[documents.c.tenant_id, documents.c.name],
                                                           set_={"body": statement.excluded.body, "updated_at": func.now()}))


@contextmanager
def lock(data_dir: Path, name: str):
    """Transaction holding a lock on a document (across processes): inside it, load and save are atomic."""
    with db.transaction(data_dir) as connection:
        db.lock(connection, "document", name)
        yield


@contextmanager
def edit(data_dir: Path, name: str, default):
    """Atomic read-modify-save: `with edit(d, "x", {}) as body: body["k"] = 1`."""
    with lock(data_dir, name):
        body = load(data_dir, name, default)
        yield body
        save(data_dir, name, body)


def delete(data_dir: Path, name: str) -> None:
    with db.transaction(data_dir) as connection:
        connection.execute(sql_delete(documents).where(documents.c.tenant_id == TENANT, documents.c.name == name))


def names(data_dir: Path, prefix: str) -> list[str]:
    """Documents whose name starts with `prefix` (e.g. `batches/`), in order."""
    escaped = prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    with db.transaction(data_dir) as connection:
        return list(connection.execute(select(documents.c.name).where(documents.c.tenant_id == TENANT,
                                                                      documents.c.name.like(f"{escaped}%", escape="\\"))
                                       .order_by(documents.c.name)).scalars())


def signature(data_dir: Path, *names_: str) -> tuple:
    """Last modification time of some documents (to invalidate caches)."""
    with db.transaction(data_dir) as connection:
        return tuple(connection.execute(select(documents.c.name, documents.c.updated_at)
                                        .where(documents.c.tenant_id == TENANT, documents.c.name.in_(names_))
                                        .order_by(documents.c.name)).all())
