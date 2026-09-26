"""API FastAPI: rutas tipadas y rutas de tabla (@route), un solo control de seguridad."""

import json
import unittest
from pathlib import Path

import asgi
from tamandua.app.api import openapi_document
from tamandua.modules.identity.auth import Users
from test_auth import ORIGIN, PASSWORD, HttpCase

ROOT = Path(__file__).resolve().parents[1]


class OpenApiTests(unittest.TestCase):
    def test_document_lists_the_migrated_routes_and_matches_the_committed_copy(self):
        document = json.loads(openapi_document())
        self.assertTrue({"/api/health", "/api/dashboard", "/api/cve-db", "/api/cve-db/item", "/api/cve-db/affected", "/api/sla", "/api/cra",
                         "/api/cra/products", "/api/cra/events", "/api/cra/assets", "/api/policies/cra", "/api/evidence",
                         "/api/evidence/assets", "/api/evidence/portfolio"} <= set(document["paths"]))
        # El panel se genera de esta copia: si la API cambia, `make openapi` (el CI lo comprueba).
        self.assertEqual(openapi_document(), (ROOT / "web/src/shared/api/openapi.json").read_text())

    def test_every_array_in_the_committed_copy_declares_its_maximum(self):
        # Checkov CKV_OPENAPI_21: an array without maxItems is an unbounded response; each bound is enforced by the server.
        unbounded = []

        def walk(node, path):
            if isinstance(node, dict):
                if node.get("type") == "array" and not isinstance(node.get("maxItems"), int):
                    unbounded.append(path)
                for key, value in node.items():
                    walk(value, f"{path}/{key}")
            elif isinstance(node, list):
                for index, value in enumerate(node):
                    walk(value, f"{path}/{index}")
        walk(json.loads((ROOT / "web/src/shared/api/openapi.json").read_text()), "")
        self.assertEqual(unbounded, [])

    def test_invalid_input_is_documented_as_the_400_the_api_answers(self):
        document = json.loads(openapi_document())
        self.assertNotIn("HTTPValidationError", document["components"]["schemas"])
        responses = document["paths"]["/api/cra/events"]["get"]["responses"]
        self.assertEqual((set(responses), responses["400"]["content"]["application/json"]["schema"]),
                         ({"200", "400"}, {"$ref": "#/components/schemas/Error"}))


class OpenApiSecurityTests(unittest.TestCase):
    def test_document_declares_the_session_cookie_and_the_public_health_route(self):
        from tamandua.modules.identity.auth import COOKIE_NAME
        document = json.loads(openapi_document())
        self.assertEqual(document["components"]["securitySchemes"]["session"], {
            "type": "apiKey", "in": "cookie", "name": COOKIE_NAME, "description": "Session signed in to the panel."})
        self.assertEqual(document["security"], [{"session": []}])
        self.assertEqual(document["paths"]["/api/health"]["get"]["security"], [{}, {"session": []}])


class StackTests(HttpCase):
    def test_same_security_for_typed_and_table_routes(self):
        # Ruta migrada (FastAPI) y ruta clásica (adaptador): mismo 401, mismas cabeceras.
        for path in ("/api/sla", "/api/runs"):
            raw = asgi.raw(self.client, "GET", path)
            self.assertIn(b" 401 ", raw.split(b"\r\n", 1)[0], path)
            self.assertIn(b"X-Frame-Options: DENY", raw, path)
            self.assertIn(b"Content-Security-Policy: default-src 'none'", raw, path)
        self.assertEqual(asgi.request(self.client, "GET", "/api/sla", headers={"Host": "evil.test"}).json(), {"error": "Host no permitido"})
        Users(self.data_dir).create("ana", PASSWORD)
        status, _, cookies = self.post("/api/auth/login", "login", {"username": "ana", "password": PASSWORD})  # POST clásico
        self.assertEqual((status, len(cookies)), (200, 1))
        cookie = {"Cookie": cookies[0].split("; ")[0]}
        self.assertIn("HttpOnly", cookies[0])  # la cookie del clásico cruza el adaptador intacta
        self.assertEqual(self.call("GET", "/api/sla", headers=cookie)[0], 200)
        self.assertEqual(self.call("GET", "/api/dashboard?days=12", headers=cookie), (400, {"error": "Ventana inválida"}, []))
        # Los valores válidos llegan como texto en la URL (el panel siempre manda days y tz).
        for days in (7, 30, 90, 365):
            status, body, _ = self.call("GET", f"/api/dashboard?days={days}&tz=America/Bogota", headers=cookie)
            self.assertEqual((status, body["window_days"]), (200, days))
        self.assertEqual(self.call("GET", "/api/no-existe", headers=cookie)[0], 404)
        # CSRF: un POST sin la cabecera de acción no pasa, venga de donde venga.
        self.assertEqual(self.call("POST", "/api/sla", {"days": {}}, {**cookie, "Origin": ORIGIN})[0], 403)


if __name__ == "__main__":
    unittest.main()


class BodyLimitTests(unittest.TestCase):
    def test_oversized_or_unbounded_bodies_are_refused_before_reading(self):
        import tempfile
        from pathlib import Path
        from tamandua.app.api.server import build_state
        with tempfile.TemporaryDirectory() as temporary:
            client = asgi.client_for(Path(temporary), build_state(Path(temporary)))
            big = asgi.request(client, "POST", "/api/repositories/branch", b"{" + b" " * 1_000_001 + b"}",
                               {"Content-Type": "application/json", "Origin": ORIGIN, "X-Tamandua-Action": "set-scan-branch"})
            self.assertEqual(big.status_code, 413)
            chunked = asgi.request(client, "POST", "/api/repositories/branch", iter([b"{}"]),
                                   {"Content-Type": "application/json", "Origin": ORIGIN, "X-Tamandua-Action": "set-scan-branch"})
            self.assertEqual(chunked.status_code, 411)
