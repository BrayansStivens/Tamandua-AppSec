import os

import asgi
from unittest.mock import patch

from tamandua.app.http import transport_check

from tests.test_auth import PASSWORD, HttpCase


class FirstRunTests(HttpCase):
    def setup_body(self, code, username="brayan"):
        return {"code": code, "username": username, "password": PASSWORD, "display_name": "Brayan"}

    def test_first_admin_needs_the_console_code_and_only_once(self):
        auth = self.handler_class.state.auth
        code = auth.setup_code()
        self.assertRegex(code, r"^[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$")
        self.assertEqual(auth.setup_code(), code)  # estable mientras no se use
        status, body, _ = self.post("/api/auth/setup", "setup-admin", self.setup_body("AAAA-BBBB-CCCC"))
        self.assertEqual(status, 400)
        self.assertIn("consola", body["error"])
        status, body, cookies = self.post("/api/auth/setup", "setup-admin", self.setup_body(code.lower()))
        self.assertEqual((status, body["user"]["role"]), (200, "admin"))
        self.assertIn("HttpOnly", cookies[0])
        # Ya hay administrador: el código muere y no se puede crear otro por esta vía.
        self.assertIsNone(auth.setup_code())
        status, _, _ = self.post("/api/auth/setup", "setup-admin", self.setup_body(code, "otro"))
        self.assertEqual(status, 400)
        self.assertFalse(self.call("GET", "/api/auth/session")[1]["setup_required"])

    def test_setup_is_throttled_and_needs_csrf_header(self):
        self.handler_class.state.auth.setup_code()
        self.assertEqual(self.call("POST", "/api/auth/setup", self.setup_body("X"), {"Origin": "http://127.0.0.1:8766"})[0], 403)
        statuses = [self.post("/api/auth/setup", "setup-admin", self.setup_body("AAAA-BBBB-CCCC"))[0] for _ in range(7)]
        self.assertEqual(statuses[-1], 429)

    def test_plain_http_is_refused_outside_loopback(self):
        for url, allowed in (("http://127.0.0.1:8766", True), ("http://localhost:8766", True), ("https://appsec.acme.io", True),
                             ("http://192.168.1.20:8766", False), ("http://appsec.acme.io", False)):
            with self.subTest(url=url), patch.dict(os.environ, {"APPSEC_AGENT_PUBLIC_URL": url}):
                self.assertEqual(transport_check(8766) is None, allowed)
        with patch.dict(os.environ, {"APPSEC_AGENT_PUBLIC_URL": "http://192.168.1.20:8766", "APPSEC_AGENT_ALLOW_INSECURE_HTTP": "1"}):
            self.assertIsNone(transport_check(8766))

    def test_security_headers(self):
        with patch.dict(os.environ, {"APPSEC_AGENT_PUBLIC_URL": "https://appsec.acme.io", "APPSEC_AGENT_ALLOWED_ORIGINS": "https://appsec.acme.io"}):
            raw = self.raw("GET", "/api/health", {"Host": "appsec.acme.io"})
        self.assertIn(b"Strict-Transport-Security: max-age=31536000", raw)
        self.assertIn(b"Referrer-Policy: no-referrer", raw)

    def raw(self, method, path, headers):
        return asgi.raw(self.client, method, path, None, headers)
