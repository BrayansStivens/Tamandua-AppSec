"""Avisos a Slack, Teams o un webhook: solo lo nuevo que importa, sin filtrar URLs ni bloquear análisis."""

import hashlib
import hmac
import json
import os
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tamandua.modules.runs import batches
from tamandua.shared import paths
from tamandua.modules.integrations import github as github_app
from tamandua.modules.integrations import notifications
from tamandua.modules.runs.store import save_repository_scan
from test_dashboard import _finding, _scan

PUBLIC = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
PRIVATE = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 443))]
SLACK = "https://hooks.slack.com/services/" + "/".join(("T000", "B000", "x" * 24))


class NotificationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        for patcher in (patch.object(paths, "CONFIG_DIR", Path(self.directory.name) / "config"),
                        patch.dict(os.environ, {"APPSEC_AGENT_PUBLIC_URL": "https://tamandua.example.com"}),
                        patch("socket.getaddrinfo", return_value=PUBLIC)):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.sent = []

    def sender(self, url, body, headers):
        self.sent.append((url, json.loads(body), headers, body))
        return True, "HTTP 200"

    def test_urls_are_checked_before_saving(self):
        for kind, url in (("slack", "http://hooks.slack.com/x"), ("slack", "https://example.com/hook"),
                          ("teams", "https://hooks.slack.com/x"), ("webhook", "https://user:pass@example.com/")):
            with self.subTest(url=url), self.assertRaises(notifications.NotificationError):
                notifications.check_url(kind, url)
        with patch("socket.getaddrinfo", return_value=PRIVATE), self.assertRaises(notifications.NotificationError):
            notifications.check_url("webhook", "https://interno.example.com/hook")  # SSRF
        notifications.check_url("teams", "https://prod-12.westus.logic.azure.com/workflows/abc")

    def test_the_list_never_returns_the_url_or_the_secret(self):
        row, secret = notifications.save("webhook", "Receptor", "https://receiver.example.com/hook/" + "s" * 20, ["findings"], "high", by="ana")
        self.assertTrue(secret)
        self.assertNotIn("s" * 20, json.dumps(notifications.channels()))
        self.assertNotIn(secret, json.dumps(notifications.channels()))
        self.assertEqual((row["host"], row["signed"]), ("receiver.example.com", True))

    def test_only_new_findings_above_the_threshold_reach_each_channel(self):
        notifications.save("slack", "#seguridad", SLACK, ["findings"], "critical", by="ana")
        _, secret = notifications.save("webhook", "SIEM", "https://siem.example.com/in", ["findings", "batches"], "medium", by="ana")
        record = {"id": "r" * 32, "type": "repository_scan", "source": {"name": "acme/api"}}
        notifications.on_run(record, [_finding("a" * 64, "high"), _finding("b" * 64, "medium")], sender=self.sender, wait=True)
        self.assertEqual([item[0] for item in self.sent], ["https://siem.example.com/in"])  # nada crítico: Slack no recibe
        _, payload, headers, body = self.sent[0]
        self.assertEqual(headers["X-Tamandua-Signature"], "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest())
        self.assertEqual((payload["event"], payload["asset"], payload["counts"]["high"]), ("findings", "acme/api", 1))
        self.assertEqual(payload["link"], f"https://tamandua.example.com/#/hallazgos?run={'r' * 32}")
        self.sent.clear()
        notifications.on_run(record, [_finding("c" * 64, "critical"), *(_finding(str(index) * 64, "low") for index in range(6))], sender=self.sender, wait=True)
        slack = next(payload for url, payload, _, _ in self.sent if url == SLACK)
        self.assertIn("1 hallazgo nuevo en acme/api", slack["text"])  # el canal de críticos cuenta solo lo suyo
        self.sent.clear()
        notifications.on_run({**record, "type": "pr_review"}, [_finding("d" * 64, "critical")], sender=self.sender, wait=True)
        self.assertEqual(self.sent, [])  # los PRs avisan en el propio PR

    def test_teams_gets_an_adaptive_card_and_a_test_message(self):
        row, _ = notifications.save("teams", "Equipo", "https://prod-1.westus.logic.azure.com/workflows/abc", ["batches"], "high", by="ana")
        notifications.on_batch({"label": "3 repositorios", "done": 3, "failed": 0, "critical": 1, "high": 2}, sender=self.sender, wait=True)
        card = self.sent[0][1]["attachments"][0]["content"]
        self.assertEqual((card["type"], card["body"][0]["text"]), ("AdaptiveCard", "Lote terminado · 3 repositorios"))
        self.assertEqual(notifications.test(row["id"], sender=self.sender), (True, "HTTP 200"))
        self.assertTrue(notifications.channels()[0]["last"]["ok"])

    def test_a_saved_scan_notifies_what_is_new_and_a_finished_batch_notifies_once(self):
        notifications.save("webhook", "SIEM", "https://siem.example.com/in", ["findings", "batches"], "high", by="ana")
        calls = []
        with tempfile.TemporaryDirectory() as folder, patch.object(notifications, "on_run", side_effect=lambda record, opened: calls.append(len(opened))), \
                patch.object(notifications, "on_batch", side_effect=lambda summary: calls.append(summary["label"])):
            data = Path(folder)
            save_repository_scan(data, _scan("acme/api", [_finding("a" * 64, "high")], "2026-09-25"))
            save_repository_scan(data, _scan("acme/api", [_finding("a" * 64, "high")], "2026-09-26"))  # nada nuevo: sin aviso
            save_repository_scan(data, _scan("acme/api", [_finding("a" * 64, "high"), _finding("b" * 64, "critical")], "2026-09-27"))
            batch = batches.create(data, [{"source_id": "github:acme/a", "name": "acme/a", "installation_id": 7}], by="ana", label="uno")
            current, index = batches.take_next(data)
            batches.attach(data, current["id"], index, run_id="1" * 32)
            self.assertIsNone(batches.take_next(data))
            self.assertIsNone(batches.take_next(data))
        self.assertEqual(calls, [1, 1, "uno"])


if __name__ == "__main__":
    unittest.main()


from tamandua.modules.identity.auth import Users  # noqa: E402
from test_auth import PASSWORD, HttpCase  # noqa: E402


class RouteTests(HttpCase):
    def test_only_an_admin_sees_or_changes_the_channels(self):
        with patch.dict(os.environ, {"APPSEC_AGENT_REQUIRE_TOTP": "none"}):
            Users(self.data_dir).create("admin", PASSWORD, role="admin")
            Users(self.data_dir).create("miembro", PASSWORD)
            admin = self.post("/api/auth/login", "login", {"username": "admin", "password": PASSWORD})[2][0].split("; ")[0]
            member = self.post("/api/auth/login", "login", {"username": "miembro", "password": PASSWORD})[2][0].split("; ")[0]
            self.assertEqual(self.call("GET", "/api/notifications", headers={"Cookie": member})[0], 403)
            with patch("socket.getaddrinfo", return_value=PUBLIC):
                status, body, _ = self.post("/api/notifications", "notifications",
                                            {"op": "save", "kind": "slack", "name": "#sec", "url": SLACK, "events": ["findings"], "threshold": "high"}, admin)
                self.assertEqual((status, body["secret"]), (200, None))
                self.assertEqual(self.post("/api/notifications", "notifications", {"op": "remove", "id": body["channel"]["id"]}, member)[0], 403)
                self.assertEqual(self.post("/api/notifications", "notifications", {"op": "save", "kind": "slack", "name": "x", "url": "http://x", "events": ["findings"],
                                                                                   "threshold": "high"}, admin)[0], 400)
            _, listing, _ = self.call("GET", "/api/notifications", headers={"Cookie": admin})
            self.assertNotIn("hooks.slack.com/services", json.dumps(listing))
