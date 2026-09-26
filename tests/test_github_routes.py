import json
from unittest.mock import patch

from tamandua.modules.identity.auth import Users
from tamandua.modules.integrations.github import GitHubAppError
from tamandua.modules.integrations.installations import github_installation, github_installations

from fake_github import fake_github
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
        with patch("tamandua.app.api.routes.sources.verify_app", return_value=dict(VERIFIED)), \
                patch("tamandua.app.api.routes.sources.app_installations", return_value=[]), \
                patch("tamandua.app.api.routes.sources.app_permissions", return_value={}):
            status, answer, _ = self.post("/api/integrations/github/app", "save-github-app", body, self.admin)
        self.assertEqual((status, answer["configured"], answer["slug"], answer["connected"]), (200, True, "appsec-de-acme", False))
        self.assertNotIn("PRIVATE KEY", json.dumps(answer))
        self.assertNotIn("MIIE", json.dumps(answer))
        with patch("tamandua.app.api.routes.sources.verify_app", side_effect=GitHubAppError("GitHub no reconoce ese App ID")):
            status, answer, _ = self.post("/api/integrations/github/app", "save-github-app", body, self.admin)
        self.assertEqual((status, answer["error"]), (400, "GitHub no reconoce ese App ID"))

    def test_installation_is_accepted_only_if_it_belongs_to_our_app(self):
        with patch("tamandua.app.api.routes.sources.app_installations", return_value=[{"installation_id": 77, "account": "acme"}]), \
                patch("tamandua.app.api.routes.sources.installation_details", return_value={"account": "acme", "permissions": {}}):
            status, _, _ = self.call("GET", "/oauth/callback?installation_id=999&setup_action=install")
            self.assertEqual(status, 200)  # página de aviso, no se guarda nada
            self.assertIsNone(github_installation(self.data_dir))
            status, _, _ = self.call("GET", "/oauth/callback?installation_id=77&setup_action=install")
            self.assertEqual(status, 200)
            self.assertIsNone(github_installation(self.data_dir))
            status, _, _ = self.post("/api/integrations/github", "connect-github", {"action": "connect", "installation_id": 77}, self.admin)
            self.assertEqual(status, 200)
            self.assertEqual(github_installation(self.data_dir), 77)
            statuses = [self.call("GET", "/oauth/callback?installation_id=999")[1] for _ in range(6)]
            self.assertIn(b"Demasiados intentos", statuses[-1])

    def test_detect_explains_when_the_app_is_not_installed_yet(self):
        with patch("tamandua.app.api.routes.sources.app_installations", return_value=[]):
            status, answer, _ = self.post("/api/integrations/github", "connect-github", {"action": "detect"}, self.admin)
        self.assertEqual(status, 404)
        self.assertIn("Instalar en GitHub", answer["error"])
        self.assertEqual(self.post("/api/integrations/github", "connect-github", {"action": "create"}, self.admin)[0], 400)

    def test_two_organizations_are_listed_and_each_scan_uses_its_installation(self):
        accounts = [{"installation_id": 77, "account": "acme"}, {"installation_id": 88, "account": "beta"}]
        with patch("tamandua.app.api.routes.sources.app_installations", return_value=accounts), \
                patch("tamandua.app.api.routes.sources.installation_details", side_effect=lambda installation: {
                    "account": "acme" if installation == 77 else "beta", "permissions": {}}), \
                fake_github({77: [(1, "acme/api")], 88: [(2, "beta/web")]}, {77: ("acme", "selected"), 88: ("beta", "selected")}):
            status, body, _ = self.post("/api/integrations/github", "connect-github", {"action": "detect"}, self.admin)
            self.assertEqual((status, body["connected"]), (200, False))
            self.assertEqual([item["account"] for item in body["available_installations"]], ["acme", "beta"])
            self.assertNotIn("available_installations", self.call("GET", "/api/integrations/github", headers={"Cookie": self.member})[1])
            self.assertEqual(self.post("/api/integrations/github", "connect-github", {"action": "connect", "installation_id": 999}, self.admin)[0], 404)
            self.assertEqual(github_installations(self.data_dir), [])
            for installation in (77, 88):
                status, body, _ = self.post("/api/integrations/github", "connect-github",
                                            {"action": "connect", "installation_id": installation}, self.admin)
            self.assertEqual((status, github_installations(self.data_dir)), (200, [77, 88]))
            self.assertEqual([item["account"] for item in body["installations"]], ["acme", "beta"])
            _, listing, _ = self.call("GET", "/api/sources", headers={"Cookie": self.member})
            self.assertEqual({item["name"]: item["installation_id"] for item in listing["sources"]},
                             {"acme/api": 77, "beta/web": 88})
            with patch("tamandua.app.api.routes.runs.scan_plan", side_effect=lambda source, installation_id: {
                    "source": source, "installation_id": installation_id}):
                _, plan, _ = self.call("GET", "/api/repositories/plan?source_id=github:beta/web", headers={"Cookie": self.member})
                self.assertEqual(plan["installation_id"], 88)
            with patch("tamandua.modules.runs.jobs.ScanJobs.enqueue_repository_scan", return_value={"id": "queued"}) as enqueue:
                status, _, _ = self.post("/api/repositories/scans", "scan-repository",
                                          {"source_id": "github:beta/web", "allow_osv_upload": False}, self.member)
                self.assertEqual(status, 202)
                self.assertEqual(enqueue.call_args.kwargs["installation_id"], 88)
            _, watch, _ = self.call("GET", "/api/pull-requests/watch", headers={"Cookie": self.member})
            self.assertEqual({item["name"] for item in watch["repositories"]}, {"acme/api", "beta/web"})
            self.assertEqual(self.post("/api/integrations/github", "connect-github", {"action": "disconnect", "installation_id": 77}, self.admin)[0], 200)
            self.assertEqual(github_installations(self.data_dir), [88])
            _, listing, _ = self.call("GET", "/api/sources", headers={"Cookie": self.member})
            self.assertEqual([item["name"] for item in listing["sources"]], ["beta/web"])
