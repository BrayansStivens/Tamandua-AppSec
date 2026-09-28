"""Routes whose answers had no other HTTP test: they go through their response model, and it keeps what they said."""

import subprocess
import unittest
from unittest.mock import patch

from tamandua.modules.identity.auth import Users
from test_auth import PASSWORD, HttpCase


class RouteResponseTests(HttpCase):
    def setUp(self):
        super().setUp()
        Users(self.data_dir).create("administradora", PASSWORD, role="admin")
        _, _, cookies = self.post("/api/auth/login", "login", {"username": "administradora", "password": PASSWORD})
        self.admin = cookies[0].split("; ")[0]

    def test_domains_are_registered_checked_and_verified(self):
        status, domain, _ = self.post("/api/domains", "register-domain", {"url": "https://app.example.com", "kind": "api",
                                                                          "context": "Public API"}, self.admin)
        self.assertEqual((status, domain["host"], domain["kind"], domain["verified"]), (200, "app.example.com", "api", False))
        self.assertEqual(domain["txt_name"], "_tamandua.app.example.com")
        status, listed, _ = self.call("GET", "/api/domains", headers={"Cookie": self.admin})
        self.assertEqual((status, [item["id"] for item in listed]), (200, [domain["id"]]))
        with patch("tamandua.modules.sources.domains.socket.getaddrinfo", return_value=[(2, 1, 6, "", ("10.0.0.5", 443))]):
            status, checked, _ = self.post("/api/domains/check", "check-domain", {"url": "https://app.example.com"}, self.admin)
        self.assertEqual((status, checked["reachable"], checked["status"]), (200, False, "private_address"))
        answer = subprocess.CompletedProcess([], 0, f'"{domain["txt_value"]}"\n', "")
        with patch("tamandua.modules.sources.domains.subprocess.run", return_value=answer):
            status, verified, _ = self.post("/api/domains/verify", "verify-domain", {"domain_id": domain["id"]}, self.admin)
        self.assertEqual((status, verified["verified"]), (200, True))
        self.assertIsNotNone(verified["verified_at"])

    def test_jira_without_a_connection_says_so_and_nothing_more(self):
        status, body, _ = self.call("GET", "/api/integrations/jira", headers={"Cookie": self.admin})
        self.assertEqual((status, body), (200, {"configured": False}))  # no field added as null
        status, body, _ = self.post("/api/integrations/jira", "connect-jira", {"action": "remove"}, self.admin)
        self.assertEqual((status, body), (200, {"configured": False}))

    def test_each_notification_operation_answers_its_own_shape(self):
        from test_notifications import PUBLIC
        with patch("socket.getaddrinfo", return_value=PUBLIC):
            status, saved, _ = self.post("/api/notifications", "notifications", {"op": "save", "kind": "webhook", "name": "SIEM",
                                         "url": "https://siem.example.com/hook", "events": ["findings"], "threshold": "high"}, self.admin)
            self.assertEqual((status, set(saved)), (200, {"channel", "secret"}))
            self.assertTrue(saved["secret"])  # a webhook's signing secret, shown once
            with patch("tamandua.app.api.notifications.notifications.test", return_value=(False, "Connection refused")):
                status, tested, _ = self.post("/api/notifications", "notifications", {"op": "test", "id": saved["channel"]["id"]}, self.admin)
            self.assertEqual((status, tested["ok"], tested["detail"], len(tested["channels"])), (200, False, "Connection refused", 1))
            status, left, _ = self.post("/api/notifications", "notifications", {"op": "remove", "id": saved["channel"]["id"]}, self.admin)
            self.assertEqual((status, left), (200, {"channels": []}))


if __name__ == "__main__":
    unittest.main()
