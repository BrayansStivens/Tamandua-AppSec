"""What lets Tamandua run beyond one server with Compose: managed database URLs, platform health checks and the ASGI
entry point that Vercel (or any ASGI server) imports."""

import importlib
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tamandua.shared import db, paths

from tests.test_auth import HttpCase


class DatabaseUrlTests(unittest.TestCase):
    def test_managed_database_urls_get_the_shipped_driver(self):
        for given in ("postgres://u:p@host:5432/db", "postgresql://u:p@host:5432/db", "postgresql+psycopg://u:p@host:5432/db"):
            with self.subTest(given=given), patch.dict(os.environ, {"TAMANDUA_DATABASE_URL": given}):
                self.assertEqual(db.url(), "postgresql+psycopg://u:p@host:5432/db")


class PlatformHealthTests(HttpCase):
    def test_a_foreign_host_gets_the_anonymous_health_and_nothing_else(self):
        status, body, _ = self.call("GET", "/api/health", headers={"Host": "10.0.0.7:8766"})
        self.assertEqual((status, set(body)), (200, {"status", "version"}))
        self.assertEqual(self.call("GET", "/api/runs", headers={"Host": "10.0.0.7:8766"})[0], 403)
        self.assertEqual(self.call("POST", "/api/health", headers={"Host": "10.0.0.7:8766"})[0], 403)


class AsgiEntryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        config = patch.object(paths, "CONFIG_DIR", Path(self.directory.name) / "config")
        config.start()
        self.addCleanup(config.stop)
        self.addCleanup(sys.modules.pop, "tamandua.app.asgi", None)

    def load(self, **environment):
        base = {"TAMANDUA_DATA_DIR": str(Path(self.directory.name) / "data"), "TAMANDUA_EMBEDDED_WORKER": "1",
                "TAMANDUA_MASTER_KEY": "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="}
        with patch.dict(os.environ, {**base, **environment}):
            sys.modules.pop("tamandua.app.asgi", None)
            return importlib.import_module("tamandua.app.asgi")

    def test_it_refuses_to_start_without_a_public_https_url(self):
        with self.assertRaises(RuntimeError) as raised:
            self.load()
        self.assertIn("TAMANDUA_PUBLIC_URL", str(raised.exception))
        with self.assertRaises(RuntimeError):
            self.load(TAMANDUA_PUBLIC_URL="http://tamandua.example.com")

    def test_it_serves_without_running_scans_or_periodic_tasks(self):
        module = self.load(TAMANDUA_PUBLIC_URL="https://tamandua.example.com", TAMANDUA_ALLOWED_ORIGINS="https://tamandua.example.com")
        state = module.app.state.core
        self.assertIsNone(state.jobs._thread)  # no embedded worker, whatever TAMANDUA_EMBEDDED_WORKER says
        from starlette.testclient import TestClient
        response = TestClient(module.app, base_url="https://tamandua.example.com").get("/api/health")
        self.assertEqual((response.status_code, response.json()["status"]), (200, "ok"))


if __name__ == "__main__":
    unittest.main()
