"""Conector de Jira contra un Jira simulado: nunca sale a la red."""

import json
import os
import stat
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from tamandua.modules.integrations import jira
from tamandua.modules.findings import triage
from tamandua.modules.runs.store import render_tickets, save_repository_scan
from test_dashboard import _finding, _scan

TOKEN = "ATATT3xFfGF0-token-de-prueba-1234"
FP_A, FP_B = "a" * 64, "b" * 64


class FakeJira:
    def __init__(self, *, priority_field=True, existing_label=None):
        self.calls, self.created = [], 0
        self.priority_field, self.existing_label = priority_field, existing_label

    def __call__(self, credentials, method, path, body=None):
        self.calls.append((method, path, body))
        if path == "/rest/api/3/myself":
            return {"accountId": "abc"}
        if path.startswith("/rest/api/3/project/"):
            return {"name": "Seguridad", "issueTypes": [{"name": "Task"}, {"name": "Bug"}]}
        if path == "/rest/api/3/search/jql":
            hit = self.existing_label and self.existing_label in body["jql"]
            return {"issues": [{"key": "SEC-7"}] if hit else []}
        if path == "/rest/api/3/issue":
            if "priority" in body["fields"] and not self.priority_field:
                raise jira.JiraError("Jira respondió 400: priority: Field 'priority' cannot be set")
            self.created += 1
            return {"key": f"SEC-{100 + self.created}"}
        raise AssertionError(path)


class JiraTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.directory.name)
        store = patch("tamandua.shared.paths.CONFIG_DIR", self.data_dir / "config")
        store.start()
        self.addCleanup(store.stop)
        now = datetime.now(timezone.utc).isoformat()
        self.record = save_repository_scan(self.data_dir, _scan("org/api", [_finding(FP_A), _finding(FP_B, "critical", package="lodash")], now))

    def tearDown(self):
        self.directory.cleanup()

    def configure(self, fake=None):
        return jira.configure("https://acme.atlassian.net/", "sec@acme.io", TOKEN, "sec", "Task", by="operadora", http=fake or FakeJira())

    def test_only_jira_cloud_hosts_are_accepted(self):
        for site in ("http://acme.atlassian.net", "https://169.254.169.254", "https://acme.atlassian.net.evil.io",
                     "https://evil.io/acme.atlassian.net", "https://acme.atlassian.net:8443", "https://user@acme.atlassian.net"):
            with self.assertRaises(jira.JiraError, msg=site):
                jira.normalize_site(site)
        self.assertEqual(jira.normalize_site("Acme.atlassian.net"), "acme.atlassian.net")

    def test_token_is_private_and_never_returned(self):
        state = self.configure()
        self.assertEqual((state["project"], state["last4"], state["project_name"]), ("SEC", "1234", "Seguridad"))
        self.assertNotIn(TOKEN, json.dumps(state))
        # Cifrado en el almacén: el token no aparece en ningún fichero de configuración.
        for path in (self.data_dir / "config").iterdir():
            self.assertNotIn(TOKEN.encode(), path.read_bytes(), path.name)
        mode = stat.S_IMODE(os.stat(self.data_dir / "config" / "secrets.vault").st_mode)
        self.assertEqual(mode, 0o600)
        with self.assertRaises(jira.JiraError):
            jira.configure("acme.atlassian.net", "sec@acme.io", TOKEN, "SEC", "Epic", by="x", http=FakeJira())

    def test_export_is_idempotent_and_skips_what_exists(self):
        self.configure()
        fake = FakeJira(existing_label=jira.label_for(FP_B))
        tickets = render_tickets(triage.annotate(self.data_dir, self.record))
        result = jira.export(self.data_dir, self.record, tickets, [FP_A, FP_B], by="analista", http=fake)
        self.assertEqual([item["key"] for item in result["created"]], ["SEC-101"])
        self.assertEqual([item["key"] for item in result["existing"]], ["SEC-7"])
        issue = next(body for method, path, body in fake.calls if path == "/rest/api/3/issue")
        self.assertIn(jira.label_for(FP_A), issue["fields"]["labels"])
        self.assertEqual(issue["fields"]["description"]["type"], "doc")
        again = jira.export(self.data_dir, self.record, tickets, [FP_A, FP_B], by="analista", http=fake)
        self.assertEqual((len(again["created"]), len(again["existing"]), fake.created), (0, 2, 1))
        annotated = jira.annotate(self.data_dir, self.record)
        self.assertEqual({item["ticket"]["key"] for item in annotated["findings"]}, {"SEC-101", "SEC-7"})

    def test_priority_is_dropped_when_the_project_does_not_accept_it(self):
        self.configure()
        fake = FakeJira(priority_field=False)
        tickets = render_tickets(self.record)
        result = jira.export(self.data_dir, self.record, tickets, [FP_A, FP_B], by="analista", http=fake)
        self.assertEqual(len(result["created"]), 2)
        self.assertEqual(result["failed"], [])

    def test_suppressed_findings_are_not_exportable(self):
        self.configure()
        triage.decide(self.data_dir, self.record, [FP_A], "false_positive", reason="Contenido estático del repositorio",
                      user={"username": "analista", "role": "member"})
        tickets = render_tickets(triage.annotate(self.data_dir, self.record))
        with self.assertRaises(jira.JiraError):
            jira.export(self.data_dir, self.record, tickets, [FP_A], by="analista", http=FakeJira())

    def test_advisories_of_one_package_become_one_issue(self):
        self.configure()
        second = {**_finding("c" * 64, "critical"), "rule_id": "CVE-2026-2", "cve": ["CVE-2026-2"]}
        second["package"] = {**second["package"], "fixed_version": "1.2.0"}
        record = save_repository_scan(self.data_dir, _scan("org/web", [_finding(FP_A), second], datetime.now(timezone.utc).isoformat()))
        fake = FakeJira()
        result = jira.export(self.data_dir, record, render_tickets(record), [FP_A, "c" * 64], by="analista", http=fake)
        self.assertEqual((fake.created, {item["key"] for item in result["created"]}), (1, {"SEC-101"}))
        issue = next(body for method, path, body in fake.calls if path == "/rest/api/3/issue")["fields"]
        self.assertEqual(issue["summary"], "[CRITICAL] Actualizar axios 1.0.0 a 1.2.0 · 2 avisos")
        self.assertEqual(issue["priority"], {"name": "High"})
        self.assertTrue({jira.label_for(FP_A), jira.label_for("c" * 64)} <= set(issue["labels"]))


if __name__ == "__main__":
    unittest.main()
