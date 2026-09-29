"""PostgreSQL schema: Alembic migrations at startup (before any read)."""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config

from tamandua.shared import db, settings

SCRIPTS = Path(__file__).resolve().parent / "alembic"


def tables() -> None:
    """Registers every table in `db.metadata` (the source of the migrations)."""
    import tamandua.modules.findings.tables  # noqa: F401
    import tamandua.modules.identity.tables  # noqa: F401
    import tamandua.modules.integrations.tables  # noqa: F401
    import tamandua.modules.intel.tables  # noqa: F401
    import tamandua.modules.pullrequests.tables  # noqa: F401
    import tamandua.modules.runs.tables  # noqa: F401
    import tamandua.modules.sources.tables  # noqa: F401
    import tamandua.shared.documents  # noqa: F401
    import tamandua.shared.vault  # noqa: F401


def config() -> Config:
    alembic = Config()
    alembic.set_main_option("script_location", str(SCRIPTS))
    alembic.set_main_option("sqlalchemy.url", db.url().replace("%", "%%"))
    return alembic


def upgrade() -> None:
    """Brings the schema to the latest version. In tests (one schema per data folder) `db` creates it on the fly."""
    tables()
    if settings.text("TAMANDUA_DB_ISOLATE") == "data-dir":
        return
    with db.engine().begin() as connection:
        # API and worker start together: without a lock both would create the same tables and one would fail.
        # The second one waits here and, once in, Alembic already sees the schema up to date.
        db.lock(connection, "schema-upgrade")
        alembic = config()
        alembic.attributes["connection"] = connection
        command.upgrade(alembic, "head")
