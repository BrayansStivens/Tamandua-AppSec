"""Plazos de corrección: política tolerante, reloj desde la primera detección, API, Resumen e informe."""

import json
import os
import tempfile
import unittest
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from tamandua.modules.reporting import dashboard
from tamandua.modules.findings import registry as findings_registry
from tamandua.modules.findings import sla
from tamandua.modules.findings import triage
from tamandua.modules.reporting.audit import render_audit_pdf, validate_options
from tamandua.modules.identity.auth import Users
from tamandua.modules.runs.store import save_repository_scan
from test_auth import PASSWORD, HttpCase
from test_dashboard import _finding, _scan
from test_report_design import text as pdf_text

ADMIN = {"username": "ana", "role": "admin"}


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.directory.name)

    def tearDown(self):
        self.directory.cleanup()

    def test_defaults_without_file_and_tolerant_with_broken_values(self):
        self.assertEqual(sla.policy(self.data_dir)["days"], sla.DEFAULTS)
        (self.data_dir / "sla.json").write_text(json.dumps({"days": {"critical": 3, "high": "treinta", "low": None}}))
        self.assertEqual(sla.policy(self.data_dir)["days"], {"critical": 3, "high": 30, "medium": 90, "low": None})
        (self.data_dir / "sla.json").write_text("{roto")
        self.assertEqual(sla.policy(self.data_dir)["days"], sla.DEFAULTS)

    def test_save_validates_every_level(self):
        saved = sla.save(self.data_dir, {"critical": 5, "high": 15, "medium": 60, "low": None}, user=ADMIN)
        self.assertEqual((saved["days"]["critical"], saved["days"]["low"], saved["updated_by"]), (5, None, "ana"))
        for bad in ({"critical": 5}, {"critical": 0, "high": 1, "medium": 1, "low": 1}, {"critical": True, "high": 1, "medium": 1, "low": 1},
                    {"critical": 9999, "high": 1, "medium": 1, "low": 1}, {"critical": "7", "high": 1, "medium": 1, "low": 1}, [7, 30]):
            with self.assertRaises(sla.SlaError, msg=bad):
                sla.save(self.data_dir, bad, user=ADMIN)

    def test_deadline_counts_from_first_detection(self):
        today = date(2026, 10, 10)
        self.assertEqual(sla.deadline("critical", "2026-10-01T23:00:00+00:00", sla.DEFAULTS, today=today),
                         {"days": 7, "due": "2026-10-08", "days_left": -2, "state": "overdue"})
        self.assertEqual(sla.deadline("high", "2026-10-01T00:00:00+00:00", sla.DEFAULTS, today=today)["state"], "ok")
        self.assertEqual(sla.deadline("high", "2026-09-12T00:00:00+00:00", sla.DEFAULTS, today=today)["state"], "soon")
        self.assertIsNone(sla.deadline("info", "2026-10-01", sla.DEFAULTS, today=today))  # sin plazo para su severidad
        self.assertIsNone(sla.deadline("low", "2026-10-01", {**sla.DEFAULTS, "low": None}, today=today))
        self.assertIsNone(sla.deadline("high", "no es fecha", sla.DEFAULTS, today=today))

    def test_only_pending_findings_run_the_clock(self):
        base = {"severity": "critical", "lifecycle": {"status": "open", "first_seen": "2026-01-01T00:00:00+00:00"}}
        findings = [dict(base), {**base, "triage": {"status": "in_progress"}}, {**base, "triage": {"status": "accepted"}},
                    {**base, "lifecycle": {**base["lifecycle"], "status": "fixed"}}, {"severity": "critical"}]
        sla.annotate(findings, sla.DEFAULTS, today=date(2026, 2, 1))
        self.assertEqual([(item.get("sla") or {}).get("state") for item in findings], ["overdue", "overdue", None, None, None])
        self.assertNotIn("sla", findings[4])  # sin ciclo de vida (una ejecución suelta): no se inventa un plazo
        self.assertEqual(sla.counts(findings)["overdue_by_severity"]["critical"], 2)


class IntegrationTests(unittest.TestCase):
    """El reloj lo marca la primera detección en el registro, en Hallazgos, en el Resumen y en el informe."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.directory.name)
        long_ago = (datetime.now(timezone.utc) - timedelta(days=40)).isoformat()
        now = datetime.now(timezone.utc).isoformat()
        first = {**_scan("org/api", [_finding("a" * 64, "critical"), _finding("b" * 64, "high", package="lodash")], long_ago), "finished_at": long_ago}
        save_repository_scan(self.data_dir, first, created_at=long_ago)
        # Reaparece hoy con uno nuevo: el viejo sigue contando desde hace 40 días.
        again = {**_scan("org/api", [_finding("a" * 64, "critical"), _finding("b" * 64, "high", package="lodash"),
                                     _finding("c" * 64, "critical", package="axios2")], now), "finished_at": now}
        self.run = save_repository_scan(self.data_dir, again, created_at=now)
        self.key = "github:org/api"

    def tearDown(self):
        self.directory.cleanup()

    def test_view_summary_dashboard_and_report_agree(self):
        state = findings_registry.view(self.data_dir, self.key)
        by_print = {item["fingerprint"]: item["sla"]["state"] for item in state["findings"]}
        self.assertEqual(by_print, {"a" * 64: "overdue", "b" * 64: "overdue", "c" * 64: "soon"})
        self.assertEqual((state["summary"]["sla"]["overdue"], state["summary"]["sla"]["days"]["critical"]), (2, 7))
        kpis = dashboard.compute(self.data_dir)["kpis"]["sla"]
        self.assertEqual((kpis["overdue"], kpis["soon"], kpis["overdue_by_severity"]["critical"]), (2, 1, 1))
        # Un riesgo aceptado deja de vencer.
        triage.decide(self.data_dir, self.run, ["b" * 64], "accepted", reason="compensado por el WAF", user=ADMIN)
        self.assertEqual(findings_registry.view(self.data_dir, self.key)["summary"]["sla"]["overdue"], 1)
        options = validate_options({}, default_by="ana")
        state = findings_registry.view(self.data_dir, self.key, status="all")
        content = pdf_text(render_audit_pdf(state, state["findings"], options, version="0.9"))
        self.assertIn("\\(1 aviso fuera de plazo\\)", content)  # texto del PDF: acentos y paréntesis escapados
        self.assertIn("cr\\355tica 7 d\\355as", content)
        self.assertIn("(33 d\\355as)", content)  # retraso: detectado hace 40 días con plazo de 7

    def test_changing_the_policy_moves_the_deadlines(self):
        sla.save(self.data_dir, {"critical": 60, "high": 60, "medium": 90, "low": 180}, user=ADMIN)
        state = findings_registry.view(self.data_dir, self.key)
        self.assertEqual(state["summary"]["sla"]["overdue"], 0)
        self.assertEqual(dashboard.cached(self.data_dir)["kpis"]["sla"]["overdue"], 0)
        sla.save(self.data_dir, {"critical": 1, "high": 60, "medium": 90, "low": 180}, user=ADMIN)
        self.assertEqual(dashboard.cached(self.data_dir)["kpis"]["sla"]["overdue"], 1)  # la caché del Resumen se invalida


class RouteTests(HttpCase):
    def setUp(self):
        super().setUp()
        with patch.dict(os.environ, {"APPSEC_AGENT_REQUIRE_TOTP": "none"}):
            Users(self.data_dir).create("jefa", PASSWORD, role="admin")
            Users(self.data_dir).create("miembro", PASSWORD)
            self.admin = self.post("/api/auth/login", "login", {"username": "jefa", "password": PASSWORD})[2][0].split("; ")[0]
            self.member = self.post("/api/auth/login", "login", {"username": "miembro", "password": PASSWORD})[2][0].split("; ")[0]

    def test_everyone_reads_only_admins_change(self):
        with patch.dict(os.environ, {"APPSEC_AGENT_REQUIRE_TOTP": "none"}):
            self.assertEqual(self.call("GET", "/api/sla")[0], 401)
            status, body, _ = self.call("GET", "/api/sla", headers={"Cookie": self.member})
            self.assertEqual((status, body["days"]), (200, sla.DEFAULTS))
            days = {"critical": 3, "high": 14, "medium": 60, "low": None}
            self.assertEqual(self.post("/api/sla", "sla", {"days": days}, self.member)[0], 403)
            status, body, _ = self.post("/api/sla", "sla", {"days": days}, self.admin)
            self.assertEqual((status, body["days"], body["updated_by"]), (200, days, "jefa"))
            for bad in ({"days": {**days, "critical": -1}}, {"days": days, "extra": 1}, {"dias": days}, [1]):
                self.assertEqual(self.post("/api/sla", "sla", bad, self.admin)[0], 400, bad)
            self.assertEqual(self.post("/api/sla", "otra-accion", {"days": days}, self.admin)[0], 403)


if __name__ == "__main__":
    unittest.main()
