"""Triage persistente: la decisión sobrevive entre escaneos y cambia lo que cuenta como pendiente."""

import json
import tempfile
import unittest
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from tamandua.modules.reporting import dashboard
from tamandua.modules.findings import triage
from tamandua.modules.runs.store import load_run, render_repository_report, render_repository_sarif, render_tickets
from tamandua.modules.runs.store import save_repository_scan
from test_dashboard import _finding, _scan

ADMIN = {"username": "operadora", "role": "admin"}
MEMBER = {"username": "analista", "role": "member"}
FP = "a" * 64
OTHER = "b" * 64


class TriageTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.directory.name)
        now = datetime.now(timezone.utc)
        self.first = save_repository_scan(self.data_dir, _scan("org/api", [_finding(FP), _finding(OTHER, "critical")], now.isoformat()),
                                          created_at=(now - timedelta(days=1)).isoformat())

    def tearDown(self):
        self.directory.cleanup()

    def test_decision_follows_the_fingerprint_into_the_next_scan(self):
        triage.decide(self.data_dir, self.first, [FP], "false_positive", reason="Contenido saneado por DOMPurify", user=MEMBER)
        second = save_repository_scan(self.data_dir, _scan("org/api", [_finding(FP), _finding(OTHER, "critical")],
                                                           datetime.now(timezone.utc).isoformat()))
        annotated = triage.annotate(self.data_dir, load_run(self.data_dir, second["id"]))
        states = {item["fingerprint"]: item["triage"] for item in annotated["findings"]}
        self.assertEqual(states[FP]["status"], "false_positive")
        self.assertEqual(states[FP]["by"], "analista")
        self.assertEqual(states[OTHER]["status"], "open")
        self.assertEqual(annotated["summary"]["actionable"], 1)

    def test_rules_for_reason_role_expiry_and_scope(self):
        with self.assertRaises(triage.TriageError):
            triage.decide(self.data_dir, self.first, [FP], "false_positive", reason="no", user=MEMBER)
        with self.assertRaises(PermissionError):
            triage.decide(self.data_dir, self.first, [FP], "accepted", reason="Mitigado por el WAF corporativo", user=MEMBER)
        with self.assertRaises(triage.TriageError):
            triage.decide(self.data_dir, self.first, ["c" * 64], "in_progress", user=MEMBER)
        too_far = (date.today() + timedelta(days=400)).isoformat()
        with self.assertRaises(triage.TriageError):
            triage.decide(self.data_dir, self.first, [FP], "accepted", reason="Mitigado por el WAF corporativo",
                          expires_at=too_far, user=ADMIN)
        record = triage.decide(self.data_dir, self.first, [FP], "accepted", reason="Mitigado por el WAF corporativo", user=ADMIN)
        state = next(item["triage"] for item in record["findings"] if item["fingerprint"] == FP)
        self.assertEqual(state["expires_at"], (datetime.now(timezone.utc).date() + timedelta(days=90)).isoformat())

    def test_expired_acceptance_counts_as_open_again(self):
        entry = {"status": "accepted", "reason": "x" * 12, "expires_at": "2026-01-01", "history": []}
        state = triage.effective(entry, today=date(2026, 2, 1))
        self.assertEqual((state["status"], state["expired"]), ("open", True))

    def test_history_keeps_who_and_why(self):
        triage.decide(self.data_dir, self.first, [FP], "in_progress", note="PR #12", user=MEMBER)
        triage.decide(self.data_dir, self.first, [FP], "open", user=ADMIN)
        history = triage.load(self.data_dir)["github:org/api"][FP]["history"]
        self.assertEqual([(item["status"], item["by"]) for item in history], [("in_progress", "analista"), ("open", "operadora")])

    def test_outputs_respect_triage(self):
        record = triage.decide(self.data_dir, self.first, [FP], "false_positive", reason="Contenido saneado por DOMPurify", user=MEMBER)
        self.assertEqual([ticket["fingerprint"] for ticket in render_tickets(record)], [OTHER])
        sarif = render_repository_sarif(record)["runs"][0]["results"]
        suppressed = [item for item in sarif if item.get("suppressions")]
        self.assertEqual(len(suppressed), 1)
        self.assertEqual(suppressed[0]["suppressions"][0]["kind"], "external")
        report = render_repository_report(record)
        self.assertIn("## Descartados en triage", report)
        self.assertIn("Contenido saneado por DOMPurify", report)
        with patch("tamandua.modules.reporting.dashboard.load_recent_cves", return_value={"__meta__": {}, "items": []}):
            kpis = dashboard.compute(self.data_dir, 30)["kpis"]
        self.assertEqual((kpis["open"]["total"], kpis["triage"]["false_positive"]), (1, 1))


if __name__ == "__main__":
    unittest.main()
