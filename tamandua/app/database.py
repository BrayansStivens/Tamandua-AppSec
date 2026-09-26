"""Esquema de PostgreSQL: migraciones de Alembic al arrancar (antes que cualquier lectura)."""

from __future__ import annotations

import os
from pathlib import Path

from alembic import command
from alembic.config import Config

from tamandua.shared import db

SCRIPTS = Path(__file__).resolve().parent / "alembic"


def tables() -> None:
    """Registra todas las tablas en `db.metadata` (la fuente de las migraciones)."""
    import tamandua.modules.findings.tables  # noqa: F401
    import tamandua.modules.identity.tables  # noqa: F401
    import tamandua.modules.integrations.tables  # noqa: F401
    import tamandua.modules.runs.tables  # noqa: F401
    import tamandua.shared.documents  # noqa: F401


def config() -> Config:
    settings = Config()
    settings.set_main_option("script_location", str(SCRIPTS))
    settings.set_main_option("sqlalchemy.url", db.url().replace("%", "%%"))
    return settings


def upgrade() -> None:
    """Lleva el esquema a la última versión. En pruebas (esquema por carpeta de datos) lo crea `db` al vuelo."""
    tables()
    if os.environ.get("APPSEC_AGENT_DB_ISOLATE") == "data-dir":
        return
    with db.engine().begin() as connection:
        settings = config()
        settings.attributes["connection"] = connection
        command.upgrade(settings, "head")
