"""Actualizar no rompe los datos de quien ya los tiene: migraciones versionadas, con copia y una sola vez."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from appsec_agent import migrations
from appsec_agent.migrations import Migration


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
        done = migrations.upgrade(self.data_dir)
        self.assertEqual(done, [migration.name for migration in migrations.MIGRATIONS])
        self.assertEqual(self.version()["version"], migrations.LATEST)
        backup = next((self.data_dir / migrations.BACKUPS).iterdir())
        self.assertEqual((backup / "findings" / "x.json").read_text(), '{"asset": "a", "findings": {}}')
        self.assertEqual(migrations.upgrade(self.data_dir), [])  # ya al día: no vuelve a migrar ni a copiar
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

    def test_the_old_incomplete_fix_repair_runs_as_a_migration(self):
        from appsec_agent import findings_registry as registry
        from appsec_agent.store import save_repository_scan
        from test_dashboard import _finding, _scan
        a, b = "a" * 64, "b" * 64

        def save(findings, stamp, status="completed"):
            record = {**_scan("org/api", findings, stamp), "status": status, "finished_at": stamp}
            record["source"]["uid"] = "github#7"
            return save_repository_scan(self.data_dir, record, created_at=stamp)
        save([_finding(a), _finding(b)], "2026-09-01T00:00:00+00:00")
        broken = save([], "2026-09-02T00:00:00+00:00", "incomplete")
        # Un registro anterior al arreglo: aquel escaneo incompleto dio algo por remediado.
        path = next((self.data_dir / "findings").glob("*.json"))
        state = json.loads(path.read_text())
        state["findings"][b].update(status="fixed", fixed={"at": "x", "run_id": broken["id"], "how": "viejo", "auto": True})
        path.write_text(json.dumps(state))
        migrations.upgrade(self.data_dir)
        self.assertEqual(registry.load(self.data_dir, "github#7")["findings"][b]["status"], "open")
        self.assertEqual(self.version()["history"][0]["result"], 1)

if __name__ == "__main__":
    unittest.main()
