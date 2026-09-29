"""Upgrading doesn't break the data of those who already have it: versioned migrations, with a backup, only once."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tamandua.app import data_migrations as migrations
from tamandua.app.data_migrations import Migration
from tamandua.shared import documents, paths


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.directory.name) / "data"

    def tearDown(self):
        self.directory.cleanup()

    def version(self):
        return documents.load(self.data_dir, migrations.VERSION_DOCUMENT)

    def existing_data(self):
        self.data_dir.mkdir(parents=True, exist_ok=True)
        documents.save(self.data_dir, "sla", {"days": {}})

    def test_a_new_install_starts_at_the_latest_version_without_migrating(self):
        self.assertEqual(migrations.upgrade(self.data_dir), [])
        self.assertEqual(self.version()["version"], migrations.LATEST)
        self.assertFalse((self.data_dir / migrations.BACKUPS).exists())

    def test_existing_data_without_version_runs_everything_once_with_a_backup(self):
        findings = self.data_dir / "findings"
        findings.mkdir(parents=True)
        (findings / "x.json").write_text('{"asset": "a", "findings": {}}')
        self.existing_data()
        steps = (Migration("una", ("findings",), lambda data: 1), Migration("otra", (), lambda data: 2))
        with patch.object(migrations, "MIGRATIONS", steps), patch.object(migrations, "LATEST", 2):
            done = migrations.upgrade(self.data_dir)
            self.assertEqual(done, ["una", "otra"])
            self.assertEqual(self.version()["version"], 2)
            self.assertEqual(migrations.upgrade(self.data_dir), [])  # already up to date: no migrating or copying again
        backup = next((self.data_dir / migrations.BACKUPS).iterdir())
        self.assertEqual((backup / "findings" / "x.json").read_text(), '{"asset": "a", "findings": {}}')
        self.assertEqual(len(list((self.data_dir / migrations.BACKUPS).iterdir())), 1)

    def test_only_pending_migrations_run_and_a_failure_resumes_from_there(self):
        calls = []
        steps = (Migration("uno", (), lambda data: calls.append("uno")),
                 Migration("dos", (), lambda data: (_ for _ in ()).throw(OSError("disco lleno"))),
                 Migration("tres", (), lambda data: calls.append("tres")))
        self.existing_data()
        with patch.object(migrations, "MIGRATIONS", steps), patch.object(migrations, "LATEST", 3):
            with self.assertRaises(OSError):
                migrations.upgrade(self.data_dir)
            self.assertEqual((calls, self.version()["version"]), (["uno"], 1))
            fixed = (steps[0], Migration("dos", (), lambda data: calls.append("dos")), steps[2])
            with patch.object(migrations, "MIGRATIONS", fixed):
                self.assertEqual(migrations.upgrade(self.data_dir), ["dos", "tres"])
        self.assertEqual(calls, ["uno", "dos", "tres"])

    def test_data_from_a_newer_version_refuses_to_start(self):
        self.data_dir.mkdir()
        documents.save(self.data_dir, migrations.VERSION_DOCUMENT, {"version": migrations.LATEST + 1, "history": []})
        with self.assertRaises(migrations.DataTooNew):
            migrations.upgrade(self.data_dir)

    def test_the_version_file_of_earlier_releases_is_adopted_into_the_database(self):
        self.existing_data()
        (self.data_dir / migrations.VERSION_FILE).write_text(json.dumps({"version": 1, "history": [{"version": 1, "name": "cra_opt_in"}]}))
        calls = []
        steps = (Migration("uno", (), lambda data: calls.append("uno")), Migration("dos", (), lambda data: calls.append("dos")))
        with patch.object(migrations, "MIGRATIONS", steps), patch.object(migrations, "LATEST", 2):
            self.assertEqual(migrations.upgrade(self.data_dir), ["dos"])
            (self.data_dir / migrations.VERSION_FILE).unlink()  # the database is the source from now on
            self.assertEqual(migrations.upgrade(self.data_dir), [])
        self.assertEqual((calls, self.version()["version"], len(self.version()["history"])), (["dos"], 2, 2))


class SealTotpSeedsMigrationTests(unittest.TestCase):
    """TOTP seeds were stored in the clear: they are sealed, and sign-in with the same authenticator keeps working."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.directory.name) / "data"
        self.data_dir.mkdir()
        config = patch.object(paths, "CONFIG_DIR", Path(self.directory.name) / "config")
        config.start()
        self.addCleanup(config.stop)
        documents.save(self.data_dir, migrations.VERSION_DOCUMENT, {"version": 1, "history": []})

    def tearDown(self):
        self.directory.cleanup()

    def test_clear_seeds_are_sealed_and_still_verify(self):
        import base64
        import time
        from tamandua.modules.identity.auth import Users, totp_code
        users = Users(self.data_dir)
        user = users.create("ana", "una-clave-larga-y-segura-2026", role="admin")
        seed = base64.b32encode(b"0123456789abcdefghij").decode()
        users._update(user["id"], lambda row: row.update(totp={"enabled": True, "secret": seed, "backup_codes": []}))
        self.assertIn("seal_totp_seeds", migrations.upgrade(self.data_dir))
        stored = users.by_id(user["id"])["totp"]
        self.assertNotIn("secret", stored)
        self.assertNotIn(seed, json.dumps(stored))
        self.assertTrue(users.verify_totp(user["id"], totp_code(base64.b32decode(seed), int(time.time()))))
        self.assertEqual(users.seal_clear_totp(), 0)  # idempotent


class CraOptInMigrationTests(unittest.TestCase):
    """The CRA kit became opt-in: a workspace that already marked products keeps it on; the rest start off."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.directory.name) / "data"
        self.data_dir.mkdir()
        (self.data_dir / migrations.VERSION_FILE).write_text(json.dumps({"version": 0}))

    def tearDown(self):
        self.directory.cleanup()

    def test_marked_products_keep_the_kit_on_and_old_events_are_to_assess(self):
        from tamandua.modules.compliance import cra
        from tamandua.shared import documents
        from tamandua.shared.i18n import localize
        old = {"products": {"github#9": {"name": "Portal", "support_until": None, "by": "ana", "at": "2026-09-01T00:00:00+00:00"}},
               "reports": {"github#9|CVE-2026-1111": {}}}
        documents.save(self.data_dir, "cra", old)
        self.assertIn("cra_opt_in", migrations.upgrade(self.data_dir))
        policy = localize(cra.policy(self.data_dir), "en")
        self.assertEqual((policy["enabled"], policy["by"], len(policy["history"])), (True, "tamandua", 1))
        self.assertIn("products were already marked", policy["reason"])
        state = documents.load(self.data_dir, "cra", {})
        self.assertEqual((state["products"], state["reports"]), (old["products"], old["reports"]))  # nothing else rewritten
        self.assertEqual(migrations._cra_opt_in(self.data_dir), 0)  # idempotent

    def test_without_products_the_kit_stays_off(self):
        from tamandua.modules.compliance import cra
        migrations.upgrade(self.data_dir)
        self.assertEqual((cra.enabled(self.data_dir), cra.policy(self.data_dir)["history"]), (False, []))


class VaultToDatabaseMigrationTests(unittest.TestCase):
    """The vault file and the session key of earlier versions move to the database; nobody has to sign in again."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.directory.name) / "data"
        self.config = Path(self.directory.name) / "config"
        (self.data_dir / "auth").mkdir(parents=True)
        patcher = patch.object(paths, "CONFIG_DIR", self.config)
        patcher.start()
        self.addCleanup(patcher.stop)
        documents.save(self.data_dir, migrations.VERSION_DOCUMENT, {"version": 2, "history": []})

    def tearDown(self):
        self.directory.cleanup()

    def test_vault_file_and_session_key_are_imported(self):
        import base64
        from tamandua.modules.identity.auth import SESSION_KEY, Sessions
        from tamandua.shared import vault
        vault.put("jira", {"token": "ATATT3xFfGF0-antiguo"})
        from tamandua.shared import db
        with db.separate_transaction(self.config) as connection:  # as an earlier version left it: only the file
            rows = {row.name: {"nonce": row.nonce, "data": row.data} for row in connection.execute(
                vault.vault_entries.select().with_only_columns(vault.vault_entries.c.name, vault.vault_entries.c.nonce,
                                                               vault.vault_entries.c.data))}
            connection.execute(vault.vault_entries.delete())
        (self.config / "secrets.vault").write_text(json.dumps(rows))
        key = base64.b64encode(b"s" * 32).decode()
        (self.data_dir / "auth" / "session.key").write_text(key)
        self.assertIn("vault_to_database", migrations.upgrade(self.data_dir))
        self.assertEqual(vault.get("jira")["token"], "ATATT3xFfGF0-antiguo")
        self.assertEqual(vault.get(SESSION_KEY)["session_key"], key)
        self.assertEqual(Sessions(self.data_dir)._key, b"s" * 32)  # existing cookies stay valid
        self.assertFalse((self.data_dir / "auth" / "session.key").exists())



class WatchAndRegistryTablesTests(unittest.TestCase):
    """The `pr-watch` and `repo-registry` documents of earlier versions move to their tables."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data_dir = Path(self.directory.name) / "data"
        self.data_dir.mkdir()
        documents.save(self.data_dir, migrations.VERSION_DOCUMENT, {"version": 4, "history": []})

    def test_the_documents_become_rows_once(self):
        from tamandua.modules.pullrequests import watch
        from tamandua.modules.sources import assets
        documents.save(self.data_dir, "pr-watch", {
            "repositories": {"github#1": {"enabled": True, "gate": "critical"}},
            "reviewed": {"github#1": {"7": {"head_sha": "a" * 40, "run_id": "1" * 32}, "8": {"head_sha": "b" * 40, "run_id": "2" * 32, "closed": True}}},
            "branches": {"github#1": {"heads": {"main": {"head_sha": "c" * 40, "run_id": "3" * 32, "at": "2026-09-01T00:00:00+00:00"}}}}})
        documents.save(self.data_dir, "repo-registry", {"github#1": {"name": "org/api", "scan_branch": "develop"},
                                                        "github#2": {"name": "org/old", "removed_at": "2026-09-01T00:00:00+00:00"}})
        self.assertIn("watch_and_registry_to_tables", migrations.upgrade(self.data_dir))
        self.assertEqual(watch.settings(self.data_dir, "github#1")["gate"], "critical")
        self.assertEqual(watch.reviewed(self.data_dir, "github#1"), {"7": {"head_sha": "a" * 40, "run_id": "1" * 32},
                                                                     "8": {"head_sha": "b" * 40, "run_id": "2" * 32, "closed": True}})
        self.assertEqual(watch.branch_state(self.data_dir, "github#1", "main")["head_sha"], "c" * 40)
        self.assertEqual(assets.scan_branch(self.data_dir, "github#1"), "develop")
        self.assertEqual(set(assets.load_registry(self.data_dir)), {"github#1", "github#2"})
        self.assertIsNone(documents.load(self.data_dir, "pr-watch"))
        self.assertIsNone(documents.load(self.data_dir, "repo-registry"))
        self.assertEqual(migrations.upgrade(self.data_dir), [])


if __name__ == "__main__":
    unittest.main()
