import json
from unittest.mock import patch

from appsec_agent.auth import Users
from appsec_agent.github_app import GitHubAppError
from appsec_agent.integrations import github_installation

from tests.test_auth import PASSWORD, HttpCase

VERIFIED = {"app_id": "4242", "pem": "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----\n", "slug": "appsec-de-acme",
            "name": "AppSec de Acme", "owner": "acme", "owner_type": "Organization", "html_url": "https://github.com/apps/appsec-de-acme",
            "permissions": {}, "events": []}


class GitHubRoutesTests(HttpCase):
    def setUp(self):
        super().setUp()
        Users(self.data_dir).create("admin", PASSWORD, role="admin")
        Users(self.data_dir).create("miembro", PASSWORD)
        self.admin, self.member = self.cookie("admin"), self.cookie("miembro")

    def cookie(self, username):
        _, _, cookies = self.post("/api/auth/login", "login", {"username": username, "password": PASSWORD})
        return cookies[0].split("; ")[0]

    def test_only_admins_save_the_app_and_the_key_never_comes_back(self):
        body = {"app_id": "4242", "private_key": VERIFIED["pem"]}
        self.assertEqual(self.post("/api/integrations/github/app", "save-github-app", body, self.member)[0], 403)
        with patch("appsec_agent.api.routes_sources.verify_app", return_value=dict(VERIFIED)), \
                patch("appsec_agent.api.routes_sources.app_installations", return_value=[]), \
                patch("appsec_agent.api.routes_sources.app_permissions", return_value={}):
            status, answer, _ = self.post("/api/integrations/github/app", "save-github-app", body, self.admin)
        self.assertEqual((status, answer["configured"], answer["slug"], answer["connected"]), (200, True, "appsec-de-acme", False))
        self.assertNotIn("PRIVATE KEY", json.dumps(answer))
        self.assertNotIn("MIIE", json.dumps(answer))
        with patch("appsec_agent.api.routes_sources.verify_app", side_effect=GitHubAppError("GitHub no reconoce ese App ID")):
            status, answer, _ = self.post("/api/integrations/github/app", "save-github-app", body, self.admin)
        self.assertEqual((status, answer["error"]), (400, "GitHub no reconoce ese App ID"))

    def test_installation_is_accepted_only_if_it_belongs_to_our_app(self):
        with patch("appsec_agent.api.routes_sources.app_installations", return_value=[{"installation_id": 77, "account": "acme"}]), \
                patch("appsec_agent.api.routes_sources.installation_details", return_value={"account": "acme", "permissions": {}}):
            status, _, _ = self.call("GET", "/oauth/callback?installation_id=999&setup_action=install")
            self.assertEqual(status, 200)  # página de aviso, no se guarda nada
            self.assertIsNone(github_installation(self.data_dir))
            status, _, _ = self.call("GET", "/oauth/callback?installation_id=77&setup_action=install")
            self.assertEqual(status, 302)
            self.assertEqual(github_installation(self.data_dir), 77)
            statuses = [self.call("GET", "/oauth/callback?installation_id=999")[1] for _ in range(6)]
            self.assertIn(b"Demasiados intentos", statuses[-1])

    def test_detect_explains_when_the_app_is_not_installed_yet(self):
        with patch("appsec_agent.api.routes_sources.app_installations", return_value=[]):
            status, answer, _ = self.post("/api/integrations/github", "connect-github", {"action": "detect"}, self.admin)
        self.assertEqual(status, 404)
        self.assertIn("Instalar en GitHub", answer["error"])
        self.assertEqual(self.post("/api/integrations/github", "connect-github", {"action": "create"}, self.admin)[0], 400)
