"""Informe de evidencia para auditoría: formulario, alcance elegido, escape de datos y acceso."""

import os
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from appsec_agent.audit_report import ReportError, render_audit_pdf, validate_options
from appsec_agent.auth import Users
from appsec_agent.store import save_repository_scan
from test_auth import PASSWORD, HttpCase
from test_dashboard import _finding, _scan


class OptionsTests(unittest.TestCase):
    def test_defaults_let_the_report_be_generated_without_touching_anything(self):
        options = validate_options({}, default_by="Brayan")
        self.assertEqual((options["framework"], options["detail"], options["include_exceptions"], options["prepared_by"]),
                         ("general", "high", True, "Brayan"))

    def test_invalid_options_are_rejected(self):
        for raw in ({"framework": "pci"}, {"detail": "some"}, {"title": "x" * 121}, {"organization": "a\nb"},
                    {"period_from": "2026-13-01"}, {"period_from": "2026-09-10", "period_to": "2026-09-01"}, {"extra": 1}):
            with self.assertRaises(ReportError, msg=raw):
                validate_options(raw, default_by="x")

    def test_text_from_the_form_or_the_repository_is_data(self):
        """Marcado de ReportLab en el título o en un hallazgo no rompe el PDF ni se interpreta."""
        hostile = '<font color="red">x</font><img src="http://evil/x.png"/>&'
        options = validate_options({"title": hostile, "organization": hostile, "framework": "iso27001"}, default_by="x")
        findings = [{**_finding("a" * 64, "critical"), "title": hostile, "path": hostile, "reason": hostile, "remediation": hostile,
                     "package": None, "triage": {"status": "accepted", "reason": hostile, "by": hostile, "at": "2026-09-01T00:00:00"}}]
        pdf = render_audit_pdf({"id": "r", "type": "repository_scan", "created_at": "2026-09-25", "source": {"name": hostile}}, findings, options, version="0.9")
        self.assertTrue(pdf.startswith(b"%PDF-"))


class RouteTests(HttpCase):
    def setUp(self):
        super().setUp()
        with patch.dict(os.environ, {"APPSEC_AGENT_REQUIRE_TOTP": "none"}):
            Users(self.data_dir).create("miembro", PASSWORD)
            _, _, cookies = self.post("/api/auth/login", "login", {"username": "miembro", "password": PASSWORD})
        self.cookie = cookies[0].split("; ")[0]
        findings = [_finding("a" * 64, "critical"), _finding("b" * 64, "high", package="lodash"), _finding("c" * 64, "low", package="left-pad")]
        self.run = save_repository_scan(self.data_dir, _scan("org/api", findings, datetime.now(timezone.utc).isoformat()))

    def report(self, body):
        with patch.dict(os.environ, {"APPSEC_AGENT_REQUIRE_TOTP": "none"}):
            return self.post("/api/reports/audit", "audit-report", body, self.cookie)

    def test_a_member_generates_one_document_with_the_chosen_findings(self):
        status, pdf, _ = self.report({"run_id": self.run["id"], "fingerprints": ["a" * 64, "b" * 64],
                                      "options": {"framework": "soc2", "organization": "Acme"}})
        self.assertEqual(status, 200)
        self.assertTrue(pdf.startswith(b"%PDF-"))
        status, pdf_all, _ = self.report({"run_id": self.run["id"]})
        self.assertEqual(status, 200)
        self.assertGreater(len(pdf_all), 0)

    def test_the_asset_state_can_be_reported_too(self):
        from appsec_agent.assets import asset_key
        status, pdf, _ = self.report({"asset": asset_key(self.run), "status": "all", "fingerprints": ["a" * 64]})
        self.assertEqual(status, 200, pdf)
        self.assertTrue(pdf.startswith(b"%PDF-"))

    def test_bad_requests(self):
        cases = [{"run_id": self.run["id"], "asset": "x"}, {}, {"run_id": "../../etc/passwd"}, {"run_id": "f" * 32},
                 {"run_id": self.run["id"], "fingerprints": "a"}, {"run_id": self.run["id"], "options": {"framework": "pci"}},
                 {"asset": "no-existe"}]
        for body in cases:
            status, _, _ = self.report(body)
            self.assertIn(status, (400, 404), body)

    def test_a_session_is_required(self):
        status, _, _ = self.post("/api/reports/audit", "audit-report", {"run_id": self.run["id"]})
        self.assertEqual(status, 401)


if __name__ == "__main__":
    unittest.main()
