"""Actualizar no rompe los datos de quien ya los tiene: migraciones versionadas, con copia y una sola vez."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tamandua.app import data_migrations as migrations
from tamandua.app.data_migrations import Migration


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.directory.name) / "data"

    def tearDown(self):
        self.directory.cleanup()

    def version(self):
        return json.loads((self.data_dir / migrations.VERSION_FILE).read_text())

    def test_a_new_install_starts_at_the_latest_version_without_migrating(self):
        self.assertEqual(migrations.upgrade(self.data_dir), [])
        self.assertEqual(self.version()["version"], migrations.LATEST)
        self.assertFalse((self.data_dir / migrations.BACKUPS).exists())

    def test_existing_data_without_version_runs_everything_once_with_a_backup(self):
        findings = self.data_dir / "findings"
        findings.mkdir(parents=True)
        (findings / "x.json").write_text('{"asset": "a", "findings": {}}')
        (self.data_dir / "runs").mkdir()
        steps = (Migration("una", ("findings",), lambda data: 1), Migration("otra", (), lambda data: 2))
        with patch.object(migrations, "MIGRATIONS", steps), patch.object(migrations, "LATEST", 2):
            done = migrations.upgrade(self.data_dir)
            self.assertEqual(done, ["una", "otra"])
            self.assertEqual(self.version()["version"], 2)
            self.assertEqual(migrations.upgrade(self.data_dir), [])  # ya al día: no vuelve a migrar ni a copiar
        backup = next((self.data_dir / migrations.BACKUPS).iterdir())
        self.assertEqual((backup / "findings" / "x.json").read_text(), '{"asset": "a", "findings": {}}')
        self.assertEqual(len(list((self.data_dir / migrations.BACKUPS).iterdir())), 1)

    def test_only_pending_migrations_run_and_a_failure_resumes_from_there(self):
        calls = []
        steps = (Migration("uno", (), lambda data: calls.append("uno")),
                 Migration("dos", (), lambda data: (_ for _ in ()).throw(OSError("disco lleno"))),
                 Migration("tres", (), lambda data: calls.append("tres")))
        (self.data_dir / "runs").mkdir(parents=True)
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
        (self.data_dir / migrations.VERSION_FILE).write_text(json.dumps({"version": migrations.LATEST + 1}))
        with self.assertRaises(migrations.DataTooNew):
            migrations.upgrade(self.data_dir)


if __name__ == "__main__":
    unittest.main()
