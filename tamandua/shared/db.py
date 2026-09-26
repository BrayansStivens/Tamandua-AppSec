"""Base de datos: PostgreSQL con SQLAlchemy 2 (Core) y psycopg 3.

* `APPSEC_AGENT_DATABASE_URL` (p. ej. `postgresql+psycopg://tamandua:…@postgres:5432/tamandua`) dice dónde está.
* Cada tabla lleva `tenant_id`: hoy siempre `TENANT` («default»); la edición gestionada lo usará con RLS.
* El esquema lo crean las migraciones de Alembic (`tamandua/app/alembic`) al arrancar; `metadata` es su fuente.
* Aislamiento para pruebas: con `APPSEC_AGENT_DB_ISOLATE=data-dir`, cada carpeta de datos usa su propio esquema de
  Postgres (creado al vuelo). Así cada prueba, que usa un directorio temporal, tiene su base limpia sin cambiar la
  firma de las 150 funciones que reciben `data_dir`.

Concurrencia: los cerrojos son de Postgres (`pg_advisory_xact_lock`) y valen entre procesos y réplicas, no solo entre
hilos de un proceso como los `threading.Lock` que sustituyen.
"""

from __future__ import annotations

import contextvars
import hashlib
import os
import threading
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import Connection, Engine, MetaData, create_engine, text

TENANT = "default"
metadata = MetaData(naming_convention={
    "ix": "ix_%(column_0_label)s", "uq": "uq_%(table_name)s_%(column_0_name)s", "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s", "pk": "pk_%(table_name)s"})

_engine: Engine | None = None
_engine_lock = threading.Lock()
_schema_lock = threading.Lock()
_ready: dict[str, frozenset[str]] = {}  # esquema aislado -> tablas ya creadas en él
_current: contextvars.ContextVar[Connection | None] = contextvars.ContextVar("tamandua_db_connection", default=None)


class DatabaseNotConfigured(RuntimeError):
    pass


def url() -> str:
    value = os.environ.get("APPSEC_AGENT_DATABASE_URL", "").strip()
    if not value:
        raise DatabaseNotConfigured("Falta APPSEC_AGENT_DATABASE_URL: Tamandua guarda ejecuciones y hallazgos en PostgreSQL "
                                    "(con `make up` se configura solo).")
    return value


def engine() -> Engine:
    global _engine
    with _engine_lock:
        if _engine is None:
            # Todas las marcas de tiempo en UTC, como las que ya guarda la aplicación en ISO 8601.
            _engine = create_engine(url(), pool_pre_ping=True, pool_size=5, max_overflow=10, connect_args={"options": "-c timezone=UTC"})
        return _engine


def reset() -> None:
    """Olvida el motor (p. ej. tras cambiar la URL en una prueba)."""
    global _engine
    with _engine_lock:
        if _engine is not None:
            _engine.dispose()
        _engine = None
        _ready.clear()


def schema_for(data_dir: Path) -> str | None:
    if os.environ.get("APPSEC_AGENT_DB_ISOLATE") != "data-dir":
        return None
    return "t_" + hashlib.sha256(str(Path(data_dir).resolve()).encode()).hexdigest()[:20]


def _prepare(connection: Connection, schema: str | None) -> Connection:
    if schema is None:
        return connection
    tables = frozenset(metadata.tables)
    if _ready.get(schema) != tables:  # primera vez, o se registraron tablas nuevas al importar otro módulo
        # En una conexión aparte y bajo cerrojo: crear el mismo esquema desde varios hilos a la vez choca en Postgres.
        with _schema_lock:
            if _ready.get(schema) != tables:
                with engine().begin() as setup:
                    setup.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{schema}"'))  # nombre derivado de un hash, no del usuario
                    metadata.create_all(setup.execution_options(schema_translate_map={None: schema}))
                _ready[schema] = tables
    return connection.execution_options(schema_translate_map={None: schema})


@contextmanager
def transaction(data_dir: Path):
    """Una transacción (o la que ya está abierta en este contexto: las operaciones anidadas comparten la de fuera)."""
    current = _current.get()
    if current is not None:
        yield current
        return
    with engine().begin() as connection:
        connection = _prepare(connection, schema_for(data_dir))
        token = _current.set(connection)
        try:
            yield connection
        finally:
            _current.reset(token)


def lock(connection: Connection, *parts: str) -> None:
    """Cerrojo exclusivo hasta el final de la transacción, por clave (entre procesos y réplicas)."""
    digest = hashlib.sha256("\x1f".join((TENANT, *parts)).encode()).digest()
    connection.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": int.from_bytes(digest[:8], "big", signed=True)})
