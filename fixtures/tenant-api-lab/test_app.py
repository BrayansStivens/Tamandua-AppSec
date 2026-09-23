"""Ground truth del fixture; prueba pares vulnerable/corregido sin abrir puertos."""

import io
import json
import unittest
from urllib.parse import quote

from app import TenantLab


def request(app, method, path, token="token-alice", body=None):
    raw = json.dumps(body).encode() if body is not None else b""
    route, _, query = path.partition("?")
    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": route,
        "QUERY_STRING": query,
        "HTTP_AUTHORIZATION": f"Bearer {token}",
        "CONTENT_LENGTH": str(len(raw)),
        "wsgi.input": io.BytesIO(raw),
    }
    result = {}

    def start_response(status, headers):
        result["status"] = int(status.split()[0])

    result["body"] = json.loads(b"".join(app(environ, start_response)))
    return result["status"], result["body"]


class GroundTruth(unittest.TestCase):
    def test_bola_vulnerable_and_fixed(self):
        vulnerable = TenantLab(True)
        fixed = TenantLab(False)
        self.assertEqual(request(vulnerable, "GET", "/api/documents/2")[0], 200)
        self.assertEqual(request(fixed, "GET", "/api/documents/2")[0], 404)
        self.assertEqual(request(fixed, "GET", "/api/documents/1")[0], 200)

    def test_admin_permission_vulnerable_and_fixed(self):
        self.assertEqual(request(TenantLab(True), "POST", "/api/admin/reports")[0], 200)
        self.assertEqual(request(TenantLab(False), "POST", "/api/admin/reports")[0], 403)
        self.assertEqual(request(TenantLab(False), "POST", "/api/admin/reports", "token-admin")[0], 200)

    def test_sensitive_field_vulnerable_and_fixed(self):
        self.assertIn("support_pin", request(TenantLab(True), "GET", "/api/me")[1])
        self.assertNotIn("support_pin", request(TenantLab(False), "GET", "/api/me")[1])

    def test_mass_assignment_vulnerable_and_fixed(self):
        vulnerable = TenantLab(True)
        fixed = TenantLab(False)
        self.assertEqual(request(vulnerable, "PATCH", "/api/me", body={"role": "admin"})[1]["role"], "admin")
        self.assertEqual(request(fixed, "PATCH", "/api/me", body={"role": "admin"})[1]["role"], "member")

    def test_sql_injection_vulnerable_and_fixed(self):
        payload = quote("%' OR 1=1 --", safe="")
        vulnerable = request(TenantLab(True), "GET", f"/api/search?q={payload}")[1]["documents"]
        fixed = request(TenantLab(False), "GET", f"/api/search?q={payload}")[1]["documents"]
        self.assertEqual({row["tenant"] for row in vulnerable}, {"tenant-a", "tenant-b"})
        self.assertEqual(fixed, [])

    def test_unauthenticated_is_rejected_in_both_variants(self):
        for variant in (True, False):
            self.assertEqual(request(TenantLab(variant), "GET", "/api/me", token="unknown")[0], 401)


if __name__ == "__main__":
    unittest.main()
