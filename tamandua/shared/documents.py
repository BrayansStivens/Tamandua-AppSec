"""Documentos JSON en PostgreSQL: el almacén de la configuración y el estado pequeño (vigilancia de PRs, exclusiones,
plazos, CRA, lotes, modelos de amenazas…).

Cada documento conserva la forma que tenía su archivo JSON, así que los módulos cambian solo su lectura y escritura.
Leer-modificar-guardar va en una transacción con cerrojo por documento (`edit`): el API y el worker ya no se pisan
escrituras, como pasaba con los archivos y los `threading.Lock` de cada proceso.
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
    """El documento, o una copia de `default` si no existe."""
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
    """Transacción con cerrojo sobre un documento (entre procesos): dentro, load y save son atómicos."""
    with db.transaction(data_dir) as connection:
        db.lock(connection, "document", name)
        yield


@contextmanager
def edit(data_dir: Path, name: str, default):
    """Leer-modificar-guardar atómico: `with edit(d, "x", {}) as body: body["k"] = 1`."""
    with lock(data_dir, name):
        body = load(data_dir, name, default)
        yield body
        save(data_dir, name, body)


def delete(data_dir: Path, name: str) -> None:
    with db.transaction(data_dir) as connection:
        connection.execute(sql_delete(documents).where(documents.c.tenant_id == TENANT, documents.c.name == name))


def names(data_dir: Path, prefix: str) -> list[str]:
    """Documentos cuyo nombre empieza por `prefix` (p. ej. «batches/»), en orden."""
    escaped = prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    with db.transaction(data_dir) as connection:
        return list(connection.execute(select(documents.c.name).where(documents.c.tenant_id == TENANT,
                                                                      documents.c.name.like(f"{escaped}%", escape="\\"))
                                       .order_by(documents.c.name)).scalars())


def signature(data_dir: Path, *names_: str) -> tuple:
    """Última modificación de unos documentos (para invalidar cachés)."""
    with db.transaction(data_dir) as connection:
        return tuple(connection.execute(select(documents.c.name, documents.c.updated_at)
                                        .where(documents.c.tenant_id == TENANT, documents.c.name.in_(names_))
                                        .order_by(documents.c.name)).all())
