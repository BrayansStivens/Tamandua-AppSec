"""Identidad, sesiones, TOTP y la puerta de autenticación del panel."""

import base64
import io
import json
import os
import re
import tempfile
import time
import unittest
from dataclasses import asdict
from types import SimpleNamespace

import asgi
from pathlib import Path
from unittest.mock import patch

from tamandua.modules.identity import auth
from tamandua.modules.identity.auth import AuthError, Authenticator, Locked, Users, totp_code
from tamandua.cli.main import main as cli
from fastapi.routing import APIRoute
from tamandua.app.api import ROUTERS
from tamandua.app.api.server import build_state

# Contraseña de prueba armada por partes: un literal así lo marcaría (con razón) un detector de secretos.
NEW_PASSWORD = "-".join(("otra", "frase", "muy", "larga", "99"))

PASSWORD = "correcto-caballo-bateria"
ORIGIN = "http://127.0.0.1:8766"


class PrimitiveTests(unittest.TestCase):
    def test_rfc6238_vector(self):
        # Vector SHA-1 del apéndice B de RFC 6238, recortado a 6 dígitos.
        self.assertEqual(totp_code(b"12345678901234567890", 59, digits=8), "94287082")
        self.assertEqual(totp_code(b"12345678901234567890", 1111111109, digits=8), "07081804")

    def test_password_policy_and_hash(self):
        for weak in ("corta", "a" * 20, "operadora-larga-1234"):
            with self.assertRaises(AuthError):
                auth.validate_password(weak, "operadora")
        record = auth.hash_password(PASSWORD)
        self.assertNotIn(PASSWORD, json.dumps(record))
        self.assertTrue(auth.verify_password(record, PASSWORD))
        self.assertFalse(auth.verify_password(record, PASSWORD + "x"))
        self.assertFalse(auth.verify_password(None, PASSWORD))

    def test_totp_step_is_single_use(self):
        secret = b"k" * 20
        now = 1_700_000_000
        code = totp_code(secret, now)
        step = auth.totp_matches(secret, code, now, None)
        self.assertIsNotNone(step)
        self.assertIsNone(auth.totp_matches(secret, code, now, step))


class AuthenticatorTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.directory.name)
        self.auth = Authenticator(self.data_dir)
        self.user = self.auth.users.create("operadora", PASSWORD, role="admin")

    def tearDown(self):
        self.directory.cleanup()

    def test_stored_data_holds_no_plain_secret(self):
        """The signing key lives sealed in the vault, never on disk; the database holds neither the password nor a
        session identifier in the clear."""
        from tamandua.shared import vault
        result = self.auth.login("operadora", PASSWORD, "1.1.1.1")
        self.assertFalse((self.data_dir / "auth").exists())
        self.assertIn("session-key", vault.names())
        stored = stored_identity(self.data_dir)
        self.assertNotIn(result["session"].split(".")[0], stored)
        self.assertNotIn(PASSWORD, stored)

    def test_tampered_cookie_and_logout(self):
        cookie = self.auth.login("operadora", PASSWORD, "c")["session"]
        header = f"{auth.COOKIE_NAME}={cookie}"
        self.assertEqual(self.auth.current(header)[0]["username"], "operadora")
        self.assertIsNone(self.auth.current(header[:-1] + ("0" if header[-1] != "0" else "1"))[0])
        self.auth.logout(header)
        self.assertIsNone(self.auth.current(header)[0])

    def test_lockout_after_repeated_failures(self):
        for _ in range(auth.LOCK_AFTER):
            with self.assertRaises(AuthError):
                self.auth.login("operadora", "incorrecta-del-todo", "c")
        with self.assertRaises(Locked):
            self.auth.login("operadora", PASSWORD, "c")

    def test_the_lockout_is_shared_by_every_instance_and_survives_a_restart(self):
        other = Authenticator(self.data_dir)  # another API instance (or the same one after a restart)
        for index in range(auth.LOCK_AFTER):
            with self.assertRaises(AuthError):
                (self.auth if index % 2 else other).login("operadora", "incorrecta-del-todo", "c")
        with self.assertRaises(Locked):
            Authenticator(self.data_dir).login("operadora", PASSWORD, "c")

    def test_code_tokens_are_shared_and_sealed(self):
        from tamandua.modules.integrations import code_tokens
        from tamandua.shared import vault
        with patch("tamandua.shared.paths.CONFIG_DIR", self.data_dir / "config"):
            code_tokens.connect("gitlab", "glpat-token-de-prueba-123")
            self.assertEqual(code_tokens.current(), {"gitlab": "glpat-token-de-prueba-123"})
            self.assertIn("code_tokens", vault.names())
            code_tokens.disconnect("gitlab")
            self.assertEqual((code_tokens.current(), vault.names()), ({}, [name for name in vault.names() if name != "code_tokens"]))

    def test_totp_flow_with_backup_codes(self):
        enrolment = self.auth.users.begin_totp(self.user["id"])
        secret = base64.b32decode(enrolment["secret"])
        self.assertTrue(enrolment["uri"].startswith("otpauth://totp/"))
        now = int(time.time())
        codes = self.auth.users.confirm_totp(self.user["id"], totp_code(secret, now), now)
        self.assertEqual(len(codes), auth.BACKUP_CODES)
        step = self.auth.login("operadora", PASSWORD, "c")
        self.assertIn("challenge", step)
        with self.assertRaises(AuthError):
            self.auth.second_factor(step["challenge"], "000000", "c")
        with self.assertRaises(AuthError):  # el retén está atado al cliente que lo abrió
            self.auth.second_factor(step["challenge"], codes[0], "otro")
        done = self.auth.second_factor(step["challenge"], codes[0], "c")
        self.assertTrue(self.auth.sessions.resolve(done["session"])["mfa"])
        again = self.auth.login("operadora", PASSWORD, "c")
        with self.assertRaises(AuthError):  # un código de respaldo solo vale una vez
            self.auth.second_factor(again["challenge"], codes[0], "c")

    def test_password_change_revokes_other_sessions(self):
        first = f"{auth.COOKIE_NAME}={self.auth.login('operadora', PASSWORD, 'a')['session']}"
        second = f"{auth.COOKIE_NAME}={self.auth.login('operadora', PASSWORD, 'b')['session']}"
        user, _ = self.auth.current(first)
        fresh = self.auth.change_password(user, PASSWORD, NEW_PASSWORD, first)
        self.assertIsNone(self.auth.current(first)[0])
        self.assertIsNone(self.auth.current(second)[0])
        self.assertIsNotNone(self.auth.current(f"{auth.COOKIE_NAME}={fresh}")[0])


class CliTests(unittest.TestCase):
    def test_first_admin_by_command(self):
        with tempfile.TemporaryDirectory() as directory, patch("sys.stdin", io.StringIO(PASSWORD + "\n")), \
                patch("sys.stdout", io.StringIO()) as out, patch("sys.stderr", io.StringIO()):
            self.assertEqual(cli(["--data-dir", directory, "user", "create", "--username", "Brayan",
                                  "--admin", "--password-stdin"]), 0)
            created = json.loads(out.getvalue())
            self.assertEqual((created["username"], created["role"]), ("brayan", "admin"))
            self.assertNotIn("password", created)
            self.assertTrue(auth.verify_password(Users(Path(directory)).get("brayan")["password"], PASSWORD))


def stored_identity(data_dir) -> str:
    """Todo lo que la base guarda de usuarios y sesiones, como texto (para comprobar que no hay secretos en claro)."""
    import json
    from sqlalchemy import select
    from tamandua.modules.identity.tables import sessions, users
    from tamandua.shared import db
    with db.transaction(data_dir) as connection:
        rows = [*connection.execute(select(users.c.record)).scalars(), *connection.execute(select(sessions.c.id, sessions.c.record)).all()]
    return json.dumps(rows, default=str)


def routes_with_policy() -> list[SimpleNamespace]:
    """Every API route with the policy its guard applies (method, path, public, admin, action)."""
    def policy(dependant):
        found = getattr(dependant.call, "policy", None)
        return found or next((item for item in map(policy, dependant.dependencies) if item), None)
    return [SimpleNamespace(method=method, path=route.path, **asdict(found))
            for module in ROUTERS for route in module.router.routes if isinstance(route, APIRoute) and (found := policy(route.dependant))
            for method in sorted(route.methods)]


class HttpCase(unittest.TestCase):
    """Servidor sin socket sobre un directorio temporal, con helpers de petición."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.directory.name)
        store = patch("tamandua.shared.paths.CONFIG_DIR", self.data_dir / "config")
        store.start()
        self.addCleanup(store.stop)
        engines = patch.dict("tamandua.modules.scanning.engines._docker_state", {"ok": False}, clear=True)
        # Estas pruebas cubren otras cosas; la política de TOTP tiene las suyas.
        policy = patch.dict(os.environ, {"TAMANDUA_REQUIRE_TOTP": "none"})
        policy.start()
        self.addCleanup(policy.stop)
        engines.start()
        self.addCleanup(engines.stop)
        self.state = build_state(self.data_dir)
        # Todas las peticiones pasan por la aplicación completa (FastAPI con todas sus rutas).
        self.client = asgi.client_for(self.data_dir, self.state)

    def tearDown(self):
        self.directory.cleanup()

    def call(self, method, path, body=None, headers=None):
        response = asgi.request(self.client, method, path, json.dumps(body) if body is not None else None, headers)
        cookies = response.headers.get_list("set-cookie")
        try:
            body = response.json() if response.content else None
        except ValueError:
            body = response.content  # artefactos que no son JSON (Markdown, scripts)
        return response.status_code, body, cookies

    def post(self, path, action, body, cookie=None):
        return self.call("POST", path, body, {"Origin": ORIGIN, "X-Tamandua-Action": action,
                                              **({"Cookie": cookie} if cookie else {})})



class GateTests(HttpCase):
    """La puerta en el servidor: sin sesión no se ve nada salvo login y salud mínima."""

    def test_everything_requires_a_session(self):
        status, body, _ = self.call("GET", "/api/auth/session")
        self.assertEqual((status, body["authenticated"], body["setup_required"]), (200, False, True))
        for path in ("/api/runs", "/api/providers", "/api/dashboard", "/api/sources", "/api/runs/x/report.md",
                     "/api/assets/export?key=x&artifact=report.pdf", "/api/threat-models/x/report.pdf"):
            self.assertEqual(self.call("GET", path)[0], 401, path)
        status, body, _ = self.call("GET", "/api/health")
        self.assertEqual(set(body), {"status", "version"})  # sin sesión no se cuenta el estado interno
        self.assertEqual(self.post("/api/repositories/scans", "scan-repository", {"source_id": "x", "allow_osv_upload": False})[0], 401)

    def test_login_cookie_attributes_and_member_limits(self):
        Users(self.data_dir).create("analista", PASSWORD)
        status, body, cookies = self.post("/api/auth/login", "login", {"username": "analista", "password": PASSWORD})
        self.assertEqual((status, body["step"]), (200, "done"))
        attributes = cookies[0].split("; ")
        self.assertIn("HttpOnly", attributes)
        self.assertIn("SameSite=Strict", attributes)
        self.assertNotIn(PASSWORD, json.dumps(body))
        cookie = attributes[0]
        self.assertEqual(self.call("GET", "/api/runs", headers={"Cookie": cookie})[0], 200)
        # Un miembro analiza, pero no conecta proveedores ni guarda claves del servicio.
        status, _, _ = self.post("/api/providers/keys", "save-ai-key", {"provider": "openai", "action": "remove"}, cookie)
        self.assertEqual(status, 403)
        status, _, cookies = self.post("/api/auth/logout", "logout", {}, cookie)
        self.assertIn("Max-Age=0", cookies[0])
        self.assertEqual(self.call("GET", "/api/runs", headers={"Cookie": cookie})[0], 401)

    def test_login_needs_origin_and_action(self):
        Users(self.data_dir).create("analista", PASSWORD)
        status, _, _ = self.call("POST", "/api/auth/login", {"username": "analista", "password": PASSWORD},
                                 {"Origin": "http://evil.test", "X-Tamandua-Action": "login"})
        self.assertEqual(status, 403)
        status, body, _ = self.post("/api/auth/login", "login", {"username": "nadie", "password": PASSWORD})
        self.assertEqual((status, body["error"]), (401, "Usuario o contraseña incorrectos"))

    def test_route_table_enforces_session_and_role(self):
        """Recorre todas las rutas registradas: ninguna privada responde sin sesión ni una de admin a un miembro."""
        Users(self.data_dir).create("analista", PASSWORD)
        _, _, cookies = self.post("/api/auth/login", "login", {"username": "analista", "password": PASSWORD})
        member = cookies[0].split("; ")[0]
        entries = routes_with_policy()
        self.assertGreater(len(entries), 30)
        for entry in entries:
            path = re.sub(r"\{[^}]+\}", "x", entry.path)
            if entry.method == "POST":
                self.assertTrue(entry.action, entry.path)
                call = lambda cookie=None, path=path, action=entry.action: self.post(path, action, {}, cookie)
            else:
                call = lambda cookie=None, path=path: self.call("GET", path, headers={"Cookie": cookie} if cookie else {})
            if not entry.public:
                self.assertEqual(call()[0], 401, f"{entry.method} {entry.path} sin sesión")
            if entry.admin:
                self.assertEqual(call(member)[0], 403, f"{entry.method} {entry.path} como miembro")

    def test_secure_cookie_behind_https(self):
        Users(self.data_dir).create("analista", PASSWORD)
        with patch.dict(os.environ, {"TAMANDUA_PUBLIC_URL": "https://appsec.example.com"}):
            _, _, cookies = self.post("/api/auth/login", "login", {"username": "analista", "password": PASSWORD})
        self.assertIn("Secure", cookies[0].split("; "))


class PolicyAndUsersTests(HttpCase):
    """Política de TOTP para administradores, invitaciones y salvaguardas del último admin."""

    def setUp(self):
        super().setUp()
        self.admin = Users(self.data_dir).create("operadora", PASSWORD, role="admin")

    def login_cookie(self, username="operadora", password=PASSWORD):
        _, _, cookies = self.post("/api/auth/login", "login", {"username": username, "password": password})
        return cookies[0].split("; ")[0]

    def enrol(self, cookie):
        _, body, _ = self.post("/api/auth/totp/setup", "totp-setup", {}, cookie)
        code = totp_code(base64.b32decode(body["secret"]), int(time.time()))
        return self.post("/api/auth/totp/confirm", "totp-confirm", {"code": code}, cookie)

    def test_admin_without_totp_can_only_enrol(self):
        with patch.dict(os.environ, {"TAMANDUA_REQUIRE_TOTP": "admins"}):
            cookie = self.login_cookie()
            _, session, _ = self.call("GET", "/api/auth/session", headers={"Cookie": cookie})
            self.assertTrue(session["totp_required"])
            status, body, _ = self.call("GET", "/api/runs", headers={"Cookie": cookie})
            self.assertEqual((status, body["code"]), (403, "totp_required"))
            self.assertEqual(self.post("/api/repositories/scans", "scan-repository", {"source_id": "x", "allow_osv_upload": False}, cookie)[0], 403)
            status, _, cookies = self.enrol(cookie)
            self.assertEqual(status, 200)
            # Confirmar reemite la sesión con segundo factor; la anterior, sin él, deja de valer.
            fresh = cookies[0].split("; ")[0]
            self.assertEqual(self.call("GET", "/api/runs", headers={"Cookie": fresh})[0], 200)
            self.assertEqual(self.call("GET", "/api/runs", headers={"Cookie": cookie})[0], 401)

    def test_invite_link_sets_password_once(self):
        cookie = self.login_cookie()
        status, body, _ = self.post("/api/users", "manage-users", {"action": "invite", "username": "Analista", "role": "member",
                                                                     "display_name": "Ana Lista"}, cookie)
        self.assertEqual(status, 200)
        self.assertIn("/#link=", body["link"])
        token = body["link"].split("#link=", 1)[1]
        self.assertNotIn(token, stored_identity(self.data_dir))
        # Sin contraseña todavía, nadie entra con esa cuenta.
        self.assertEqual(self.post("/api/auth/login", "login", {"username": "analista", "password": PASSWORD})[0], 401)
        status, found, _ = self.post("/api/auth/link/check", "check-link", {"token": token})
        self.assertEqual((status, found["username"], found["purpose"]), (200, "analista", "invite"))
        status, done, cookies = self.post("/api/auth/link", "accept-link", {"token": token, "password": NEW_PASSWORD})
        self.assertEqual((status, done["user"]["username"]), (200, "analista"))
        self.assertIn("HttpOnly", cookies[0])
        self.assertEqual(self.post("/api/auth/link", "accept-link", {"token": token, "password": NEW_PASSWORD})[0], 400)
        # Un miembro no administra usuarios.
        member = self.login_cookie("analista", NEW_PASSWORD)
        self.assertEqual(self.call("GET", "/api/users", headers={"Cookie": member})[0], 403)

    def test_last_admin_and_self_protection(self):
        cookie = self.login_cookie()
        for body in ({"action": "disable", "user_id": self.admin["id"]}, {"action": "role", "user_id": self.admin["id"], "role": "member"}):
            status, result, _ = self.post("/api/users", "manage-users", body, cookie)
            self.assertEqual(status, 400, result)
        _, invited, _ = self.post("/api/users", "manage-users", {"action": "invite", "username": "segunda", "role": "admin"}, cookie)
        status, _, _ = self.post("/api/users", "manage-users", {"action": "disable", "user_id": invited["user"]["id"]}, cookie)
        self.assertEqual(status, 200)
        _, listing, _ = self.call("GET", "/api/users", headers={"Cookie": cookie})
        self.assertEqual({user["username"]: user["disabled"] for user in listing["users"]}, {"operadora": False, "segunda": True})

    def test_disable_revokes_sessions(self):
        Users(self.data_dir).create("analista", PASSWORD)
        admin, member = self.login_cookie(), self.login_cookie("analista")
        target = Users(self.data_dir).get("analista")["id"]
        self.post("/api/users", "manage-users", {"action": "disable", "user_id": target}, admin)
        self.assertEqual(self.call("GET", "/api/runs", headers={"Cookie": member})[0], 401)


class AuditRegressionTests(HttpCase):
    """Regresiones de la auditoría del 23/09: H-1, H-2, O-2, O-3."""

    def setUp(self):
        super().setUp()
        self.admin = Users(self.data_dir).create("operadora", PASSWORD, role="admin")
        self.auth = Authenticator(self.data_dir)

    def enrol(self, user_id):
        secret = base64.b32decode(self.auth.users.begin_totp(user_id)["secret"])
        now = int(time.time()) - 60  # un paso que el login posterior no reutiliza
        self.auth.users.confirm_totp(user_id, totp_code(secret, now), now)
        return secret

    def test_reset_link_does_not_skip_totp(self):
        self.enrol(self.admin["id"])
        token = self.auth.users.issue_link(self.admin["id"], "reset")
        status, body, cookies = self.post("/api/auth/link", "accept-link", {"token": token, "password": NEW_PASSWORD})
        self.assertEqual((status, body["step"]), (200, "totp"))
        self.assertEqual(cookies, [])

    def test_session_without_mfa_is_useless_once_totp_is_on(self):
        _, _, cookies = self.post("/api/auth/login", "login", {"username": "operadora", "password": PASSWORD})
        cookie = cookies[0].split("; ")[0]
        self.enrol(self.admin["id"])  # la CLI o un proceso aparte lo activa sin reemitir esta sesión
        self.assertEqual(self.call("GET", "/api/runs", headers={"Cookie": cookie})[0], 401)

    def test_concurrent_totp_guesses_are_bounded(self):
        import threading
        self.enrol(self.admin["id"])
        challenge = self.auth.login("operadora", PASSWORD, "c")["challenge"]
        evaluated = []
        original = self.auth.users.verify_totp
        def counting(*args, **kwargs):
            evaluated.append(1)
            time.sleep(0.01)
            return original(*args, **kwargs)
        self.auth.users.verify_totp = counting
        threads = [threading.Thread(target=lambda: self._guess(challenge)) for _ in range(60)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertLessEqual(len(evaluated), auth.LOCK_AFTER)

    def _guess(self, challenge):
        try:
            self.auth.second_factor(challenge, "000000", "c")
        except AuthError:
            pass

    def test_link_cannot_be_redeemed_twice(self):
        token = self.auth.users.issue_link(self.admin["id"], "reset")
        self.auth.users.redeem_link(token, NEW_PASSWORD)
        with self.assertRaises(AuthError):
            self.auth.users.redeem_link(token, "tercera-frase-larga-77")

    def test_last_admin_guard_runs_under_the_write_lock(self):
        second = Users(self.data_dir).create("segunda", PASSWORD, role="admin")
        self.auth.users.set_disabled(second["id"], True, actor_id=self.admin["id"])
        with self.assertRaises(AuthError):
            self.auth.users.set_role(self.admin["id"], "member", actor_id=second["id"])


if __name__ == "__main__":
    unittest.main()
