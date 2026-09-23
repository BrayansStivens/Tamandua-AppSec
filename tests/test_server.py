"""Pruebas sin socket del límite de acción del panel local."""

import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from appsec_agent.auth import Users
from appsec_agent.integrations import github_installation
from appsec_agent.server import make_handler
from appsec_agent.store import list_runs


class ServerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.directory.name)
        # El almacén de credenciales del proveedor se aísla: si no, las pruebas
        # verían la App real de quien las ejecuta y dejarían de ser deterministas.
        store = patch("appsec_agent.github_app.CONFIG_DIR", self.data_dir / "config")
        store.start()
        self.addCleanup(store.stop)
        # El camino con motores en contenedor se prueba en test_scanners; aquí no se lanza Docker.
        engines = patch.dict("appsec_agent.scanners._docker_state", {"ok": False})
        engines.start()
        self.addCleanup(engines.stop)
        # Estas pruebas cubren otras cosas; la política de TOTP tiene las suyas.
        policy = patch.dict(os.environ, {"APPSEC_AGENT_REQUIRE_TOTP": "none"})
        policy.start()
        self.addCleanup(policy.stop)
        self.handler_class = make_handler(self.data_dir)
        self.origin = "http://127.0.0.1:8766"
        # Todas las rutas exigen sesión: las pruebas entran como un administrador creado por la CLI.
        Users(self.data_dir).create("operadora", "correcto-caballo-bateria", role="admin")
        self.cookie = self.login("operadora", "correcto-caballo-bateria")

    def login(self, username, password):
        handler_headers = {"Origin": self.origin, "X-AppSec-Agent-Action": "login"}
        raw = self.raw_request("POST", "/api/auth/login", json.dumps({"username": username, "password": password}),
                               handler_headers, cookie=None)
        for line in raw.split(b"\r\n\r\n", 1)[0].split(b"\r\n"):
            if line.lower().startswith(b"set-cookie:"):
                return line.split(b":", 1)[1].strip().split(b";", 1)[0].decode("ascii")
        raise AssertionError(raw)

    def tearDown(self):
        self.directory.cleanup()

    def request(self, method, path, body=None, headers=None, cookie="default"):
        raw = self.raw_request(method, path, body, headers, cookie=cookie)
        status = int(raw.split(b" ", 2)[1])
        return status, raw.split(b"\r\n\r\n", 1)[1]

    def raw_request(self, method, path, body=None, headers=None, cookie="default"):
        cookie = self.cookie if cookie == "default" else cookie
        handler = self.handler_class.__new__(self.handler_class)
        handler.server = type("Server", (), {"server_port": 8766})()
        handler.client_address = ("127.0.0.1", 10000)
        handler.request_version = "HTTP/1.1"
        handler.command = method
        handler.path = path
        handler.requestline = f"{method} {path} HTTP/1.1"
        handler.rfile = io.BytesIO((body or "").encode("utf-8"))
        handler.wfile = io.BytesIO()
        handler.log_message = lambda *_args: None
        handler.headers = {"Host": "127.0.0.1:8766", "Content-Length": str(len(body or "")),
                           **({"Cookie": cookie} if cookie else {}), **(headers or {})}
        getattr(handler, f"do_{method}")()
        return handler.wfile.getvalue()

    def test_rejects_cross_origin_and_arbitrary_targets(self):
        body = json.dumps({"source_id": "local:x", "allow_osv_upload": False})
        status, _ = self.request("POST", "/api/repositories/scans", body, {"Origin": "http://evil.test", "X-AppSec-Agent-Action": "scan-repository"})
        self.assertEqual(status, 403)
        status, _ = self.request("POST", "/api/images/scans", json.dumps({"reference": "https://example.com/x"}),
                                 {"Origin": self.origin, "X-AppSec-Agent-Action": "scan-image"})
        self.assertEqual(status, 400)
        status, _ = self.request("GET", "/assets/../store.py")
        self.assertEqual(status, 404)
        self.assertEqual(list_runs(self.data_dir), [])

    def test_lab_is_no_longer_reachable_from_the_api(self):
        status, _ = self.request("POST", "/api/lab/scans", json.dumps({"variant": "fixed"}),
                                 {"Origin": self.origin, "X-AppSec-Agent-Action": "scan-lab"})
        self.assertEqual(status, 404)
        self.assertEqual(list_runs(self.data_dir), [])

    def test_user_supplies_own_ai_key_and_it_never_returns_to_the_browser(self):
        secret = "sk-user-owned-key-000111222333"
        headers = {"Origin": self.origin, "X-AppSec-Agent-Action": "save-ai-key"}
        # Una clave que el proveedor rechaza no se guarda.
        with patch("appsec_agent.providers.check_provider",
                   return_value={"provider": "openai", "status": "invalid_credentials",
                                 "message": "El proveedor rechazó la comprobación"}):
            status, payload = self.request("POST", "/api/providers/keys",
                                           json.dumps({"provider": "openai", "action": "save",
                                                       "api_key": secret}), headers)
        self.assertEqual(status, 400)
        self.assertIn(b"rechaz", payload)
        status, listing = self.request("GET", "/api/providers")
        self.assertFalse(json.loads(listing)[0]["configured"])

        # Aceptada: se guarda, y ni el guardado ni el listado devuelven la clave.
        with patch("appsec_agent.providers.check_provider",
                   return_value={"provider": "openai", "status": "connected", "message": "ok"}):
            status, payload = self.request("POST", "/api/providers/keys",
                                           json.dumps({"provider": "openai", "action": "save",
                                                       "api_key": secret}), headers)
        self.assertEqual(status, 200)
        self.assertNotIn(secret.encode(), payload)
        status, listing = self.request("GET", "/api/providers")
        self.assertNotIn(secret.encode(), listing)
        openai = json.loads(listing)[0]
        self.assertTrue(openai["configured"])
        self.assertEqual(openai["owner"], "usuario")
        self.assertEqual(openai["last4"], "2333")

        # Retirarla la borra del almacén.
        status, _ = self.request("POST", "/api/providers/keys",
                                 json.dumps({"provider": "openai", "action": "remove"}), headers)
        self.assertEqual(status, 200)
        status, listing = self.request("GET", "/api/providers")
        self.assertFalse(json.loads(listing)[0]["configured"])

    def test_provider_endpoint_never_starts_a_lab_scan_or_exposes_keys(self):
        with patch.dict("os.environ", {"OPENAI_API_KEY": "server-secret", "ANTHROPIC_API_KEY": "",
                                       "APPSEC_AGENT_BOOTSTRAP": "1"}), \
                patch("appsec_agent.api.routes_sources.check_provider", return_value={"status": "connected"}) as check:
            status, payload = self.request("GET", "/api/providers")
            self.assertEqual(status, 200)
            self.assertNotIn(b"server-secret", payload)
            status, _ = self.request("POST", "/api/providers/check", json.dumps({"variant": "fixed"}),
                                     {"Origin": self.origin, "X-AppSec-Agent-Action": "check-provider"})
            self.assertEqual(status, 400)
            status, payload = self.request("POST", "/api/providers/check", json.dumps({"provider": "openai"}),
                                           {"Origin": self.origin, "X-AppSec-Agent-Action": "check-provider"})
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(payload)["status"], "connected")
            check.assert_called_once_with("openai")
            self.assertEqual(list_runs(self.data_dir), [])

    def test_soc2_export_is_explicitly_non_certifying(self):
        # El laboratorio ya no tiene ruta en la API: la ejecución se crea como lo hace la CLI (scan-fixture).
        from appsec_agent.cli import DEFAULT_FIXTURE
        from appsec_agent.engine import scan_fixture
        from appsec_agent.store import save_scan
        run_id = save_scan(self.data_dir, scan_fixture(DEFAULT_FIXTURE, "fixed"))["id"]
        status, report = self.request("GET", f"/api/runs/{run_id}/report-soc2.md")
        self.assertEqual(status, 200)
        self.assertIn(b"SOC 2 Tipo II", report)
        self.assertIn(b"no demuestra", report)

    def test_repository_scan_is_queued_and_never_opts_in_to_osv_implicitly(self):
        headers = {"Origin": self.origin, "X-AppSec-Agent-Action": "scan-repository"}
        status, _ = self.request("POST", "/api/repositories/scans",
                                 json.dumps({"source_id": "https://example.com", "allow_osv_upload": False}), headers)
        self.assertEqual(status, 400)
        status, _ = self.request("POST", "/api/repositories/scans",
                                 json.dumps({"source_id": "local:appsec-agent"}), headers)
        self.assertEqual(status, 400)
        with tempfile.TemporaryDirectory() as temporary, \
                patch("appsec_agent.jobs.snapshot_source") as snapshot, \
                patch("appsec_agent.repository_scan._query_osv", side_effect=AssertionError("OSV llamado")):
            root = Path(temporary)
            (root / "app.py").write_text('db.execute(f"SELECT {user_id}")\n')
            snapshot.return_value = root, {"id": "local:appsec-agent", "name": "Código propio", "provider": "local", "files": 1}
            # La petición vuelve al instante con el identificador; el trabajo corre en segundo plano.
            status, payload = self.request("POST", "/api/repositories/scans",
                                           json.dumps({"source_id": "local:appsec-agent", "allow_osv_upload": False}), headers)
            self.assertEqual(status, 202)
            queued = json.loads(payload)["run"]
            self.assertEqual(queued["status"], "queued")
            record = self._wait_for_run(queued["id"])
        self.assertEqual(record["status"], "completed")
        self.assertEqual(record["summary"]["sast"], 1)
        # El progreso es para el usuario: sin rutas del servidor ni salidas crudas.
        messages = [event["message"] for event in record["progress"]]
        self.assertTrue(any("Terminado" in message for message in messages), messages)
        self.assertFalse(any("/var/" in message or "Traceback" in message for message in messages))

    def _wait_for_run(self, run_id, timeout=20.0):
        import time as _time
        deadline = _time.time() + timeout
        while _time.time() < deadline:
            status, payload = self.request("GET", f"/api/runs/{run_id}")
            record = json.loads(payload)
            if record["status"] not in ("queued", "running"):
                return record
            _time.sleep(0.05)
        self.fail("el escaneo no terminó a tiempo")

    def test_health_and_allowed_origins_follow_configuration(self):
        status, payload = self.request("GET", "/api/health")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(payload)["status"], "ok")
        # Otro Host o Origin distinto de los permitidos se rechaza aunque el puerto coincida.
        status, _ = self.request("GET", "/api/health", headers={"Host": "evil.test:8766"})
        self.assertEqual(status, 403)
        with patch.dict(os.environ, {"APPSEC_AGENT_ALLOWED_ORIGINS": "http://appsec.local:8766"}):
            status, _ = self.request("GET", "/api/health", headers={"Host": "appsec.local:8766"})
            self.assertEqual(status, 200)
            status, _ = self.request("GET", "/api/health")   # 127.0.0.1 deja de estar permitido
            self.assertEqual(status, 403)

    def test_code_connection_from_ui_validates_lists_and_forgets_token(self):
        secret = "ghp_test_read_only_secret_123"
        headers = {"Origin": self.origin, "X-AppSec-Agent-Action": "connect-code"}
        with patch("appsec_agent.repository_sources._request", return_value=json.dumps([
            {"full_name": "example/private", "private": True, "default_branch": "main"}
        ]).encode()) as request:
            status, payload = self.request("POST", "/api/integrations/code", json.dumps({"provider": "github", "token": secret}), headers)
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(payload)["repositories"], 1)
            status, listing = self.request("GET", "/api/sources")
            self.assertEqual(status, 200)
            self.assertIn(b"github:example/private", listing)
            self.assertEqual(json.loads(listing)["providers"]["github"]["origin"], "session")
            self.assertNotIn(secret.encode(), listing + payload)
            self.assertEqual(request.call_args.args[1], secret)
            status, _ = self.request("POST", "/api/integrations/code", json.dumps({"provider": "github", "disconnect": True}), headers)
            self.assertEqual(status, 200)
            status, listing = self.request("GET", "/api/sources")
            self.assertEqual(status, 200)
            self.assertNotIn(b"github:example/private", listing)

    def test_code_connection_rejects_cross_origin_and_invalid_token(self):
        body = json.dumps({"provider": "github", "token": "test-token-123"})
        status, _ = self.request("POST", "/api/integrations/code", body,
                                 {"Origin": "http://evil.test", "X-AppSec-Agent-Action": "connect-code"})
        self.assertEqual(status, 403)
        with patch("appsec_agent.repository_sources._request", side_effect=Exception("should not call")):
            status, _ = self.request("POST", "/api/integrations/code", json.dumps({"provider": "github", "token": "bad token"}),
                                     {"Origin": self.origin, "X-AppSec-Agent-Action": "connect-code"})
            self.assertEqual(status, 400)


if __name__ == "__main__":
    unittest.main()
