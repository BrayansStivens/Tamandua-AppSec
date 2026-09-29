"""Database: PostgreSQL with SQLAlchemy 2 (Core) and psycopg 3.

* `TAMANDUA_DATABASE_URL` (e.g. `postgresql+psycopg://tamandua:…@postgres:5432/tamandua`) says where it is.
* Every table has a `tenant_id`: today always `TENANT` ("default"); the managed edition will use it with RLS.
* The schema is created by the Alembic migrations (`tamandua/app/alembic`) at startup; `metadata` is their source.
* Test isolation: with `TAMANDUA_DB_ISOLATE=data-dir`, each data folder uses its own Postgres schema (created on
  the fly). That way each test, which uses a temporary directory, gets a clean database without changing the
  signature of the 150 functions that take `data_dir`.

Concurrency: locks are Postgres locks (`pg_advisory_xact_lock`) and hold across processes and replicas, not only
across the threads of one process like the `threading.Lock`s they replace.
"""

from __future__ import annotations

import contextvars
import hashlib
import threading
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import Connection, Engine, MetaData, create_engine, text

from tamandua.shared import settings

TENANT = "default"
metadata = MetaData(naming_convention={
    "ix": "ix_%(column_0_label)s", "uq": "uq_%(table_name)s_%(column_0_name)s", "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s", "pk": "pk_%(table_name)s"})

_engine: Engine | None = None
_engine_lock = threading.Lock()
_schema_lock = threading.Lock()
_ready: dict[str, frozenset[str]] = {}  # isolated schema -> tables already created in it
_current: contextvars.ContextVar[Connection | None] = contextvars.ContextVar("tamandua_db_connection", default=None)


class DatabaseNotConfigured(RuntimeError):
    pass


def url() -> str:
    value = settings.text("TAMANDUA_DATABASE_URL")
    if not value:
        raise DatabaseNotConfigured("TAMANDUA_DATABASE_URL is missing: Tamandua stores runs and findings in PostgreSQL "
                                    "(`make up` configures it for you).")
    # Managed databases (Neon, Supabase, Railway, Render, Heroku) hand out postgres:// or postgresql://: same database,
    # with the driver Tamandua ships (psycopg 3).
    for prefix in ("postgres://", "postgresql://"):
        if value.startswith(prefix):
            return "postgresql+psycopg://" + value.removeprefix(prefix)
    return value


def engine() -> Engine:
    global _engine
    with _engine_lock:
        if _engine is None:
            # Every timestamp in UTC, like the ISO 8601 ones the application already stores.
            _engine = create_engine(url(), pool_pre_ping=True, pool_size=5, max_overflow=10, connect_args={"options": "-c timezone=UTC"})
        return _engine


def reset() -> None:
    """Forgets the engine (e.g. after a test changes the URL)."""
    global _engine
    with _engine_lock:
        if _engine is not None:
            _engine.dispose()
        _engine = None
        _ready.clear()


def schema_for(data_dir: Path) -> str | None:
    if settings.text("TAMANDUA_DB_ISOLATE") != "data-dir":
        return None
    return "t_" + hashlib.sha256(str(Path(data_dir).resolve()).encode()).hexdigest()[:20]


def _prepare(connection: Connection, schema: str | None) -> Connection:
    if schema is None:
        return connection
    tables = frozenset(metadata.tables)
    if _ready.get(schema) != tables:  # first time, or importing another module registered new tables
        # On its own connection and under a lock: several threads creating the same schema at once clash in Postgres.
        with _schema_lock:
            if _ready.get(schema) != tables:
                with engine().begin() as setup:
                    setup.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{schema}"'))  # hash-derived name, not user input
                    metadata.create_all(setup.execution_options(schema_translate_map={None: schema}))
                _ready[schema] = tables
    return connection.execution_options(schema_translate_map={None: schema})


@contextmanager
def transaction(data_dir: Path):
    """A transaction (or the one already open in this context: nested operations share the outer one)."""
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


@contextmanager
def separate_transaction(data_dir: Path):
    """A transaction of its own that commits on its own, even when called inside another one."""
    with engine().begin() as connection:
        yield _prepare(connection, schema_for(data_dir))


def lock(connection: Connection, *parts: str) -> None:
    """Exclusive lock until the end of the transaction, per key (across processes and replicas)."""
    digest = hashlib.sha256("\x1f".join((TENANT, *parts)).encode()).digest()
    connection.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": int.from_bytes(digest[:8], "big", signed=True)})
