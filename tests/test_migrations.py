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

    def test_an_install_from_the_file_era_is_repaired_and_imported_into_postgres(self):
        """Una instalación con los archivos de antes (sin versión): se repara (migración 1) y se importa (3), sin tocar
        los archivos, que quedan para volver atrás."""
        import hashlib
        from test_dashboard import _finding, _scan
        from tamandua.modules.findings import registry, triage
        from tamandua.modules.runs.store import artifact, list_runs
        a, b = "a" * 64, "b" * 64
        good, broken = "1" * 32, "2" * 32
        for run_id, status, findings, stamp in ((good, "completed", [_finding(a), _finding(b)], "2026-09-01T00:00:00+00:00"),
                                                (broken, "incomplete", [], "2026-09-02T00:00:00+00:00")):
            folder = self.data_dir / "runs" / run_id
            folder.mkdir(parents=True)
            record = {**_scan("org/api", findings, stamp), "id": run_id, "status": status, "created_at": stamp, "finished_at": stamp}
            record["source"]["uid"] = "github#7"
            (folder / "run.json").write_text(json.dumps(record))
            (folder / "report.md").write_text(f"# informe {run_id}")
        registry_file = self.data_dir / "findings" / f"{hashlib.sha256(b'github#7').hexdigest()[:32]}.json"
        registry_file.parent.mkdir()
        registry_file.write_text(json.dumps({"asset": "github#7", "name": "org/api", "applied": [good, broken], "findings": {
            a: {"status": "open", "first_seen": "2026-09-01T00:00:00+00:00", "finding": _finding(a)},
            # Un escaneo incompleto lo dio por remediado antes de que eso dejara de ocurrir: hay que reabrirlo.
            b: {"status": "fixed", "first_seen": "2026-09-01T00:00:00+00:00", "finding": _finding(b),
                "fixed": {"at": "x", "run_id": broken, "how": "viejo", "auto": True}}}}))
        (self.data_dir / "triage.json").write_text(json.dumps({"github#7": {a: {"status": "in_progress", "reason": "", "by": "ana"}}}))
        before = sorted(path.read_bytes() for path in self.data_dir.rglob("run.json"))
        done = migrations.upgrade(self.data_dir)
        self.assertEqual(done, [migration.name for migration in migrations.MIGRATIONS])
        self.assertEqual({row["id"] for row in list_runs(self.data_dir)}, {good, broken})
        self.assertEqual(artifact(self.data_dir, good, "report.md").decode(), f"# informe {good}")
        state = registry.load(self.data_dir, "github#7")
        self.assertEqual({digest: entry["status"] for digest, entry in state["findings"].items()}, {a: "open", b: "open"})
        self.assertEqual(state["applied"], [good, broken])  # la idempotencia por ejecución sobrevive a la importación
        self.assertEqual(triage.load_asset(self.data_dir, "github#7")[a]["status"], "in_progress")
        self.assertEqual(sorted(path.read_bytes() for path in self.data_dir.rglob("run.json")), before)  # intactos
        self.assertEqual(self.version()["history"][0]["result"], 1)
        self.assertEqual(migrations.upgrade(self.data_dir), [])  # una sola vez


if __name__ == "__main__":
    unittest.main()
