"""Esquema de PostgreSQL: las migraciones de Alembic crean exactamente las tablas del código (sin cambios sin migración)."""

import os
import unittest
import uuid
from unittest.mock import patch

from sqlalchemy import create_engine, text

from tamandua.app import database
from tamandua.shared import db


@unittest.skipUnless(os.environ.get("TAMANDUA_DATABASE_URL"), "hace falta PostgreSQL (make test lo arranca)")
class MigrationDriftTests(unittest.TestCase):
    def test_alembic_head_matches_the_tables_in_code(self):
        from alembic.autogenerate import compare_metadata
        from alembic.migration import MigrationContext
        base = os.environ["TAMANDUA_DATABASE_URL"]
        name = f"drift_{uuid.uuid4().hex[:12]}"
        admin = create_engine(base, isolation_level="AUTOCOMMIT")
        with admin.connect() as connection:
            connection.execute(text(f'CREATE DATABASE "{name}"'))
        try:
            url = base.rsplit("/", 1)[0] + f"/{name}"
            with patch.dict(os.environ, {"TAMANDUA_DATABASE_URL": url, "TAMANDUA_DB_ISOLATE": ""}):
                db.reset()
                database.upgrade()
                with db.engine().connect() as connection:
                    differences = compare_metadata(MigrationContext.configure(connection, opts={"compare_type": True}), db.metadata)
                    tables = set(connection.execute(text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")).scalars())
                database.upgrade()  # repetirlo no hace nada
                db.reset()
        finally:
            db.reset()
            with admin.connect() as connection:
                connection.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
            admin.dispose()
        self.assertEqual(differences, [])
        self.assertTrue({"runs", "registry_assets", "registry_findings", "triage_decisions", "alembic_version"} <= tables)


if __name__ == "__main__":
    unittest.main()
