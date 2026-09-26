"""Community lista para otros: datos de demostración y primeros pasos deducidos del estado real."""

import base64
import os
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from tamandua.app import demo
from tamandua.modules.pullrequests import watch as pr_watch
from tamandua.modules.threats import model as tm
from tamandua.modules.identity.auth import Users, totp_code
from tamandua.modules.runs.store import list_runs, save_repository_scan
from test_auth import PASSWORD, HttpCase
from test_dashboard import _finding, _scan

ROOT = Path(__file__).resolve().parents[1]


class DemoTests(unittest.TestCase):
    def test_demo_analyses_the_bundled_examples_and_imports_the_model_once(self):
        seen = []

        def scan(root, source, **kwargs):
            seen.append((source["id"], sorted(path.name for path in Path(root).iterdir())))
            return {**_scan("demo · ejemplos vulnerables", [_finding("a" * 64)], datetime.now(timezone.utc).isoformat()),
                    "source": {**source, "sha256": "x"}, "context": kwargs.get("context", "")}

        with tempfile.TemporaryDirectory() as folder, patch("tamandua.modules.scanning.repository.scan_repository", side_effect=scan):
            data = Path(folder)
            first = demo.seed(data, fixtures=ROOT / "fixtures", models=ROOT / "web/src/examples/threat-models", report=lambda message: None)
            second = demo.seed(data, fixtures=ROOT / "fixtures", models=ROOT / "web/src/examples/threat-models", report=lambda message: None)
            self.assertEqual(seen[0], ("local:demo-ejemplos", ["sast-samples", "scanner-samples"]))
            self.assertEqual((first["code"]["status"], "threat_model" in first, "threat_model" in second), ("completed", True, False))
            self.assertEqual([model["name"] for model in tm.list_models(data)], [demo.MODEL_NAME])  # no se duplica
            self.assertEqual({row["source"]["id"] for row in list_runs(data)}, {"local:demo-ejemplos"})
            with self.assertRaises(FileNotFoundError):
                demo.seed(data, fixtures=data / "no-existe", report=lambda message: None)


class OnboardingTests(HttpCase):
    def test_steps_follow_the_real_state(self):
        with patch.dict(os.environ, {"TAMANDUA_REQUIRE_TOTP": "none"}):
            Users(self.data_dir).create("admin", PASSWORD, role="admin")
            cookie = self.post("/api/auth/login", "login", {"username": "admin", "password": PASSWORD})[2][0].split("; ")[0]
            _, state, _ = self.call("GET", "/api/onboarding", headers={"Cookie": cookie})
            self.assertEqual({key: state[key] for key in ("github", "analyzed", "demo", "watching", "alerts", "admin")},
                             {"github": False, "analyzed": False, "demo": False, "watching": False, "alerts": False, "admin": True})
            demo_scan = _scan("demo · ejemplos vulnerables", [], datetime.now(timezone.utc).isoformat())
            save_repository_scan(self.data_dir, {**demo_scan, "source": {**demo_scan["source"], "id": "local:demo-ejemplos"}})
            _, state, _ = self.call("GET", "/api/onboarding", headers={"Cookie": cookie})
            self.assertEqual((state["demo"], state["analyzed"]), (True, False))  # la demo no es «tu primer análisis»
            # Activar el segundo factor por el flujo real: confirmar reemite la sesión.
            _, body, _ = self.post("/api/auth/totp/setup", "totp-setup", {}, cookie)
            code = totp_code(base64.b32decode(body["secret"]), int(time.time()))
            cookie = self.post("/api/auth/totp/confirm", "totp-confirm", {"code": code}, cookie)[2][0].split("; ")[0]
            save_repository_scan(self.data_dir, _scan("acme/api", [], datetime.now(timezone.utc).isoformat()))
            pr_watch.configure(self.data_dir, "github#1", enabled=True, by="admin")
            _, state, _ = self.call("GET", "/api/onboarding", headers={"Cookie": cookie})
            self.assertEqual((state["analyzed"], state["watching"], state["mfa"]), (True, True, True))


if __name__ == "__main__":
    unittest.main()
