"""Foreign keys (cascades), migration 0003 on a database with orphans, and `tamandua integrity` for the logical relations."""

import io
import os
import tempfile
import unittest
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from sqlalchemy import create_engine, delete, func, insert, inspect, select, text
from sqlalchemy.exc import IntegrityError

from tamandua.app import wiring
from tamandua.app import database
from tamandua.app import integrity
from tamandua.modules.findings import triage
from tamandua.modules.findings import registry as findings_registry
from tamandua.modules.findings.tables import registry_assets, registry_findings, triage_decisions
from tamandua.modules.identity.auth import Sessions, Users
from tamandua.modules.identity.tables import auth_challenges, sessions, users
from tamandua.modules.runs import queue
from tamandua.modules.runs.store import delete_runs, save_record, save_repository_scan
from tamandua.modules.runs.tables import jobs, runs
from tamandua.modules.runs import assets
from tamandua.shared import db
from tamandua.shared.db import TENANT
from test_dashboard import _finding, _scan

wiring.configure()  # like every Tamandua process: domain events and injected readers

PASSWORD = "-".join(("frase", "de", "prueba", "larga", "42"))
NOW = datetime.now(timezone.utc).isoformat()


def count(data_dir, table, *conditions) -> int:
    with db.transaction(data_dir) as connection:
        return connection.execute(select(func.count()).select_from(table).where(*conditions)).scalar_one()


def scan(name, uid, fingerprints):
    record = _scan(name, [_finding(item) for item in fingerprints], NOW)
    record["source"]["uid"] = uid
    return record


@unittest.skipUnless(os.environ.get("TAMANDUA_DATABASE_URL"), "needs PostgreSQL (make test starts it)")
class ForeignKeyTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data_dir = Path(self.directory.name)

    def test_deleting_a_user_deletes_its_sessions_and_challenges(self):
        user_store, session_store = Users(self.data_dir), Sessions(self.data_dir)
        user_store.create("ana", PASSWORD, role="admin")
        user_store.create("luis", PASSWORD)
        ana, luis = user_store.get("ana"), user_store.get("luis")
        session_store.issue(ana, mfa=False)
        session_store.issue(luis, mfa=False)
        session_store.open_challenge(ana["id"], "127.0.0.1")
        with db.transaction(self.data_dir) as connection:
            connection.execute(delete(users).where(users.c.tenant_id == TENANT, users.c.id == ana["id"]))
        self.assertEqual(count(self.data_dir, sessions, sessions.c.user_id == ana["id"]), 0)
        self.assertEqual(count(self.data_dir, auth_challenges), 0)
        self.assertEqual(count(self.data_dir, sessions, sessions.c.user_id == luis["id"]), 1)

    def test_a_session_needs_an_existing_user(self):
        with self.assertRaises(IntegrityError):
            Sessions(self.data_dir).issue({"id": "nobody"}, mfa=False)

    def test_deleting_a_run_deletes_its_jobs_and_a_job_needs_its_run(self):
        record = save_repository_scan(self.data_dir, scan("org/web", "github#1", ["a" * 64]))
        queue.enqueue(self.data_dir, "repository_scan", {}, run_id=record["id"])
        queue.enqueue(self.data_dir, "noop", {})
        with self.assertRaises(IntegrityError):
            queue.enqueue(self.data_dir, "repository_scan", {}, run_id=uuid.uuid4().hex)
        delete_runs(self.data_dir, [record["id"]])
        self.assertEqual(count(self.data_dir, jobs, jobs.c.run_id.is_not(None)), 0)
        self.assertEqual(count(self.data_dir, jobs), 1)

    def test_forgetting_an_asset_deletes_its_findings(self):
        save_repository_scan(self.data_dir, scan("org/web", "github#1", ["a" * 64, "b" * 64]))
        save_repository_scan(self.data_dir, scan("org/api", "github#2", ["c" * 64]))
        with db.transaction(self.data_dir) as connection:
            connection.execute(delete(registry_assets).where(registry_assets.c.asset_key == "github#1"))
        self.assertEqual(count(self.data_dir, registry_findings, registry_findings.c.asset_key == "github#1"), 0)
        self.assertEqual(count(self.data_dir, registry_findings, registry_findings.c.asset_key == "github#2"), 1)

    def test_purging_a_repository_still_works_and_leaves_no_orphans(self):
        record = save_repository_scan(self.data_dir, scan("org/web", "github#1", ["a" * 64]))
        queue.enqueue(self.data_dir, "repository_scan", {}, run_id=record["id"])
        triage.decide(self.data_dir, record, ["a" * 64], "false_positive", reason="Example data in a test",
                      user={"username": "ana", "role": "member"})
        self.assertEqual(assets.purge(self.data_dir, "github#1"), 1)
        for table in (runs, jobs, registry_assets, registry_findings, triage_decisions):
            self.assertEqual(count(self.data_dir, table), 0, table.name)
        self.assertEqual(integrity.check(self.data_dir), dict.fromkeys(integrity.FIXABLE + integrity.REPORTED, 0))


@unittest.skipUnless(os.environ.get("TAMANDUA_DATABASE_URL"), "needs PostgreSQL (make test starts it)")
class MigrationTests(unittest.TestCase):
    """The Alembic path of a production install (not the per-test schema): 0002 with orphans, then head."""

    ORPHANS = """
        INSERT INTO users (id, username, record) VALUES ('u1', 'ana', '{}');
        INSERT INTO sessions (id, user_id, expires_at, record) VALUES ('s1', 'u1', 1, '{}'), ('s2', 'ghost', 1, '{}');
        INSERT INTO auth_challenges (id, user_id, client, created_at) VALUES ('c1', 'ghost', 'x', 1), ('c2', 'u1', 'x', 1);
        INSERT INTO runs (id, type, status, created_at, "row", record) VALUES ('r1', 'repository_scan', 'completed', now(), '{}', '{}');
        INSERT INTO jobs (id, kind, run_id, payload) VALUES ('j1', 'repository_scan', 'r1', '{}'), ('j2', 'repository_scan', 'gone', '{}'),
                                                            ('j3', 'noop', NULL, '{}');
        INSERT INTO registry_assets (asset_key, name) VALUES ('kept', 'org/kept');
        INSERT INTO registry_findings (asset_key, fingerprint, status, entry) VALUES ('kept', 'f1', 'open', '{}'),
                                                                                     ('lost', 'f2', 'open', '{"first_run": "r0"}');
    """

    def test_upgrade_cleans_orphans_then_adds_the_foreign_keys(self):
        from alembic import command
        base = os.environ["TAMANDUA_DATABASE_URL"]
        name = f"fk_{uuid.uuid4().hex[:12]}"
        admin = create_engine(base, isolation_level="AUTOCOMMIT")
        with admin.connect() as connection:
            connection.execute(text(f'CREATE DATABASE "{name}"'))
        try:
            with patch.dict(os.environ, {"TAMANDUA_DATABASE_URL": base.rsplit("/", 1)[0] + f"/{name}", "TAMANDUA_DB_ISOLATE": ""}):
                db.reset()
                database.tables()
                with db.engine().begin() as connection:
                    settings = database.config()
                    settings.attributes["connection"] = connection
                    command.upgrade(settings, "0002")
                    for statement in self.ORPHANS.split(";")[:-1]:
                        connection.execute(text(statement))
                with self.assertLogs("tamandua.database", "INFO") as logs:
                    database.upgrade()
                with db.engine().connect() as connection:
                    left = {table: sorted(connection.execute(text(f"SELECT {column} FROM {table}")).scalars())
                            for table, column in (("sessions", "id"), ("auth_challenges", "id"), ("jobs", "id"),
                                                  ("registry_assets", "asset_key"), ("registry_findings", "fingerprint"))}
                    applied = connection.execute(text("SELECT applied FROM registry_assets WHERE asset_key = 'lost'")).scalar_one()
                    keys = {fk["name"]: fk["options"].get("ondelete") for table in ("sessions", "auth_challenges", "jobs", "registry_findings")
                            for fk in inspect(connection).get_foreign_keys(table)}
                with self.assertRaises(IntegrityError), db.engine().begin() as connection:
                    connection.execute(text("INSERT INTO sessions (id, user_id, expires_at, record) VALUES ('s3', 'ghost', 1, '{}')"))
                with db.engine().begin() as connection:
                    connection.execute(text("DELETE FROM users WHERE id = 'u1'"))
                    connection.execute(text("DELETE FROM runs WHERE id = 'r1'"))
                    after = [connection.execute(text(f"SELECT count(*) FROM {table}")).scalar_one()
                             for table in ("sessions", "auth_challenges", "jobs")]
                db.reset()
        finally:
            db.reset()
            with admin.connect() as connection:
                connection.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
            admin.dispose()
        self.assertEqual(left, {"sessions": ["s1"], "auth_challenges": ["c2"], "jobs": ["j1", "j3"],
                                "registry_assets": ["kept", "lost"], "registry_findings": ["f1", "f2"]})
        self.assertEqual(applied, [])
        self.assertEqual(keys, {"fk_sessions_user": "CASCADE", "fk_auth_challenges_user": "CASCADE", "fk_jobs_run": "CASCADE",
                                "fk_registry_findings_asset": "CASCADE"})
        self.assertEqual(after, [0, 0, 1])
        self.assertEqual([record.reason for record in logs.records],
                         ["sessions without user: 1", "auth_challenges without user: 1", "jobs without run: 1",
                          "registry_assets recreated for orphan findings: 1"])


@unittest.skipUnless(os.environ.get("TAMANDUA_DATABASE_URL"), "needs PostgreSQL (make test starts it)")
class DoctorTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data_dir = Path(self.directory.name)
        self.kept = save_repository_scan(self.data_dir, scan("org/web", "github#1", ["a" * 64]))
        triage.decide(self.data_dir, self.kept, ["a" * 64], "false_positive", reason="Example data in a test",
                      user={"username": "ana", "role": "member"})

    def leave_orphans(self):
        # What an interrupted purge of github#9 leaves, and a finished run of github#5 whose registry update never ran.
        findings_registry._save(self.data_dir, {"asset": "github#9", "name": "org/gone", "applied": [],
                                                "findings": {"b" * 64: {"status": "open"}, "c" * 64: {"status": "open"}}})
        with db.transaction(self.data_dir) as connection:
            connection.execute(insert(triage_decisions).values(tenant_id=TENANT, asset_key="github#9", fingerprint="b" * 64,
                                                               status="false_positive", decision={"status": "false_positive"}))
        save_record(self.data_dir, {**scan("org/api", "github#5", ["d" * 64]), "id": uuid.uuid4().hex, "created_at": NOW})

    def integrity(self, *extra):
        from tamandua.cli.main import main as cli
        with patch("sys.stdout", io.StringIO()) as out, patch("sys.stderr", io.StringIO()):
            code = cli(["--data-dir", str(self.data_dir), "integrity", *extra])
        return code, out.getvalue()

    def test_consistent_database(self):
        self.assertEqual(integrity.check(self.data_dir), {"registry_without_runs": 0, "triage_without_runs": 0, "runs_without_registry": 0})
        code, output = self.integrity()
        self.assertEqual(code, 0)
        self.assertIn("Todo en orden", output)

    def test_reports_orphans_without_deleting_them(self):
        self.leave_orphans()
        self.assertEqual(integrity.check(self.data_dir), {"registry_without_runs": 1, "triage_without_runs": 1, "runs_without_registry": 1})
        code, output = self.integrity()
        self.assertEqual(code, 3)
        self.assertIn("Estado de hallazgos de repositorios sin ejecuciones: 1", output)
        self.assertIn("Decisiones de triage de repositorios sin ejecuciones: 1", output)
        self.assertIn("Ejecuciones terminadas que faltan en el registro de hallazgos: 1", output)
        self.assertIn("Se pueden borrar 2 filas huérfanas: ejecuta tamandua integrity --fix.", output)
        self.assertEqual(count(self.data_dir, registry_findings, registry_findings.c.asset_key == "github#9"), 2)
        self.assertEqual(count(self.data_dir, triage_decisions), 2)

    def test_fix_deletes_the_leftovers_and_keeps_the_rest(self):
        self.leave_orphans()
        code, output = self.integrity("--fix")
        self.assertEqual(code, 3)  # the run missing from the registry is only reported
        self.assertIn("Estado de hallazgos de repositorios sin ejecuciones: 0  (1 borrada)", output)
        self.assertIn("Decisiones de triage de repositorios sin ejecuciones: 0  (1 borrada)", output)
        self.assertIn("Ejecuciones terminadas que faltan en el registro de hallazgos: 1  (no se borran", output)
        self.assertEqual(count(self.data_dir, registry_findings, registry_findings.c.asset_key == "github#9"), 0)
        self.assertEqual(count(self.data_dir, registry_assets), 1)
        self.assertEqual(count(self.data_dir, triage_decisions, triage_decisions.c.asset_key == "github#1"), 1)
        self.assertEqual(count(self.data_dir, runs), 2)
        self.assertEqual(integrity.fix(self.data_dir), {"registry_without_runs": 0, "triage_without_runs": 0})

    def test_output_in_english(self):
        self.leave_orphans()
        with patch.dict(os.environ, {"TAMANDUA_DEFAULT_LOCALE": "en"}):
            _, output = self.integrity()
        self.assertIn("Triage decisions of repositories with no runs left: 1", output)
        self.assertIn("2 orphan rows can be deleted: run tamandua integrity --fix.", output)


if __name__ == "__main__":
    unittest.main()
