"""La cola de escaneos: responde al instante, informa del progreso y falla sin filtrar el servidor."""

import json
import os
import tempfile
import time
import unittest

from tamandua.modules.runs.store import artifact as store_artifact
from pathlib import Path
from unittest.mock import patch

from tamandua.modules.runs.jobs import ScanJobs
from tamandua.modules.sources.repositories import SourceError
from tamandua.modules.scanning.engines import host_path
from tamandua.modules.runs.store import load_run
from tamandua.shared.i18n import text


def _wait(data_dir, run_id, timeout=15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        record = load_run(data_dir, run_id)
        if record["status"] not in ("queued", "running"):
            return record
        time.sleep(0.05)
    raise AssertionError("el trabajo no terminó")


class JobsTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.directory.name)
        engines = patch.dict("tamandua.modules.scanning.engines._docker_state", {"ok": False})
        engines.start()
        self.addCleanup(engines.stop)
        self.addCleanup(self.directory.cleanup)

    def test_enqueue_returns_immediately_and_records_progress(self):
        jobs = ScanJobs(self.data_dir)
        with patch("tamandua.modules.runs.jobs.snapshot_source") as snapshot:
            def fake(source_id, destination, tokens, installation, ref=None, progress=None):
                (destination / "app.py").write_text('db.execute(f"SELECT {user_id}")\n')
                return destination, {"id": source_id, "name": "demo", "provider": "local", "files": 1}
            snapshot.side_effect = fake
            queued = jobs.enqueue_repository_scan(source_id="local:demo", source_name="demo", allow_osv_upload=False,
                                                  context="prueba", tokens={}, installation_id=None)
            self.assertEqual(queued["status"], "queued")
            # Antes de terminar, el registro ya existe y es legible por el panel.
            self.assertIn(load_run(self.data_dir, queued["id"])["status"], ("queued", "running", "completed"))
            record = _wait(self.data_dir, queued["id"])
        self.assertEqual(record["status"], "incomplete")  # sin Docker en las pruebas no corre ningún motor: nunca «completed»
        self.assertEqual(record["context"], "prueba")
        self.assertGreaterEqual(record["summary"]["sast"], 1)
        levels = [event["level"] for event in record["progress"]]
        self.assertEqual(levels[0], "info")
        self.assertIn("ok", levels)
        self.assertTrue(bool(store_artifact(self.data_dir, queued["id"], "report.md")))
        self.assertFalse(any((self.data_dir / "work").iterdir()), "el snapshot temporal se limpia")

    def test_source_failure_is_reported_without_server_internals(self):
        jobs = ScanJobs(self.data_dir)
        with patch("tamandua.modules.runs.jobs.snapshot_source", side_effect=SourceError("Repositorio no disponible para la credencial configurada")):
            queued = jobs.enqueue_repository_scan(source_id="github:x/y", source_name="x/y", allow_osv_upload=False,
                                                  context="", tokens={}, installation_id=None)
            record = _wait(self.data_dir, queued["id"])
        self.assertEqual(record["status"], "failed")
        self.assertIn("No se pudo obtener el repositorio", text(record["progress"][-1]["message"]))

    def test_unexpected_error_never_leaks_a_traceback_to_the_user(self):
        jobs = ScanJobs(self.data_dir)
        with patch("tamandua.modules.runs.jobs.snapshot_source", side_effect=RuntimeError("/srv/secret/path exploded")):
            queued = jobs.enqueue_repository_scan(source_id="github:x/y", source_name="x/y", allow_osv_upload=False,
                                                  context="", tokens={}, installation_id=None)
            record = _wait(self.data_dir, queued["id"])
        self.assertEqual(record["status"], "failed")
        serialized = json.dumps(record["progress"])
        self.assertNotIn("/srv/secret", serialized)
        self.assertNotIn("Traceback", serialized)
        self.assertIn("error interno", text(record["progress"][-1]["message"]))


class HostPathTests(unittest.TestCase):
    def test_paths_inside_the_data_dir_are_translated_for_the_docker_daemon(self):
        with tempfile.TemporaryDirectory() as temporary:
            inside = Path(temporary)
            with patch.dict(os.environ, {"TAMANDUA_DATA_DIR": str(inside), "TAMANDUA_HOST_DATA_DIR": "/Users/dev/appsec/data"}):
                self.assertEqual(host_path(inside / "work" / "snap"), "/Users/dev/appsec/data/work/snap")
                # Fuera del directorio de datos no se toca la ruta.
                self.assertEqual(host_path(Path("/etc/hosts")), str(Path("/etc/hosts").resolve()))
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(host_path(Path("/tmp/x")), str(Path("/tmp/x").resolve()))


if __name__ == "__main__":
    unittest.main()
