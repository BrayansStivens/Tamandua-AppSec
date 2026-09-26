"""Fase de cumplimiento: paquetes maliciosos, SBOM CycloneDX, VEX desde el triage, EUVD y marcos del informe."""

import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from tamandua.modules.compliance import cra
from tamandua.modules.intel import cve_db
from tamandua.modules.intel import euvd
from tamandua.modules.findings import fix_guide
from tamandua.modules.compliance import sbom
from tamandua.modules.findings import triage
from tamandua.modules.compliance import vex
from tamandua.modules.intel.advisories import dependency_finding
from tamandua.modules.reporting.audit import FRAMEWORKS, render_audit_pdf, validate_options
from tamandua.modules.identity.auth import Users
from tamandua.modules.runs.store import save_repository_scan
from test_auth import PASSWORD, HttpCase
from test_cve_db import nvd_entry
from test_dashboard import _finding, _scan

ADMIN = {"username": "ana", "role": "admin"}
NOW = datetime(2026, 9, 26, tzinfo=timezone.utc)


def dependency(name="event-stream", version="3.3.6", **extra):
    return {"ecosystem": "npm", "name": name, "version": version, "path": "package-lock.json", **extra}


class MaliciousTests(unittest.TestCase):
    def test_a_mal_advisory_is_hostile_code_to_remove_not_update(self):
        finding = dependency_finding(dependency(), {"id": "MAL-2025-100", "summary": "Malicious code in event-stream",
                                                    "aliases": ["GHSA-mh6f-8j2x-4483"],
                                                    "affected": [{"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.0.0"}]}]}]}, {})
        self.assertEqual((finding["severity"], finding["malicious"], finding["priority"]["action"], finding["package"]["fixed_version"]),
                         ("critical", True, "act", None))
        self.assertEqual(finding["source"]["id"], "ossf-malicious")
        self.assertIn("rota sus tokens", finding["remediation"])
        # Otro aviso del mismo paquete tampoco propone «actualiza a…».
        other = {**_finding("b" * 64, "high", package="event-stream"), "path": "package-lock.json",
                 "package": {"ecosystem": "npm", "name": "event-stream", "version": "3.3.6", "fixed_version": "4.0.0"}}
        fix_guide.attach([finding, other])
        self.assertIn("paquete malicioso", other["fix"]["steps"][0])
        self.assertFalse(any("Actualiza" in step for step in finding["fix"]["steps"]))
        # Los informes (tabla y «qué hacer primero») dicen lo mismo que el panel, y lo malicioso va primero.
        from tamandua.modules.findings.remediation import action, fix_groups
        groups = fix_groups([_finding("c" * 64, "critical", package="axios"), finding, other])
        self.assertTrue(groups[0]["malicious"])
        self.assertTrue(action(groups[0], short=True).startswith("Eliminar event-stream 3.3.6"))


class SbomAndVexTests(unittest.TestCase):
    def record(self):
        findings = [_finding("a" * 64, "critical", package="lodash"), _finding("b" * 64, "high", package="minimist")]
        return {"id": "r1", "type": "repository_scan", "created_at": "2026-09-20T00:00:00+00:00",
                "source": {"id": "github:acme/api", "name": "acme/api", "provider": "github", "sha256": "f" * 64},
                "dependencies": [dependency("lodash", "4.17.20", purl="pkg:npm/lodash@4.17.20", licenses=["MIT"], direct=True),
                                 dependency("left-pad", "1.3.0", direct=False)],
                "findings": findings}

    def test_cyclonedx_uses_inventory_and_fills_gaps_from_findings(self):
        document = sbom.cyclonedx(self.record(), version="0.9", now=NOW)
        self.assertEqual((document["bomFormat"], document["specVersion"]), ("CycloneDX", "1.6"))
        refs = {component["bom-ref"]: component for component in document["components"]}
        # Los paquetes de los hallazgos que no estaban en el inventario (otra versión de lodash, minimist) entran igual.
        self.assertEqual(set(refs), {"pkg:npm/lodash@4.17.20", "pkg:npm/left-pad@1.3.0", "pkg:npm/lodash@1.0.0", "pkg:npm/minimist@1.0.0"})
        self.assertEqual(refs["pkg:npm/lodash@4.17.20"]["licenses"], [{"license": {"name": "MIT"}}])
        root = document["metadata"]["component"]
        self.assertEqual((root["bom-ref"], root["hashes"][0]["content"]), ("pkg:github/acme/api", "f" * 64))
        # Relación conocida: el producto depende directamente de lodash, no de left-pad (transitiva).
        self.assertIn("pkg:npm/lodash@4.17.20", document["dependencies"][0]["dependsOn"])
        self.assertNotIn("pkg:npm/left-pad@1.3.0", document["dependencies"][0]["dependsOn"])

    def test_images_include_system_packages_with_distro_purl(self):
        record = {"id": "i1", "type": "image_scan", "source": {"id": "image:nginx", "name": "nginx", "image": {"reference": "nginx:1.21", "resolved_digest": "sha256:abc"}},
                  "dependencies": [], "system_packages": [{"ecosystem": "debian", "name": "libc6", "version": "2.31-13"}], "findings": []}
        document = sbom.cyclonedx(record, version="0.9", now=NOW)
        self.assertEqual(document["components"][0]["purl"], "pkg:deb/debian/libc6@2.31-13")
        self.assertEqual((document["metadata"]["component"]["type"], document["metadata"]["lifecycles"][0]["phase"]), ("container", "post-build"))

    def test_an_incomplete_inventory_is_declared_not_presented_as_complete(self):
        record = {**self.record(), "steps": [{"name": "Trivy", "status": "inconclusive", "tool": {"name": "trivy"}}]}
        document = sbom.cyclonedx(record, version="0.9", now=NOW)
        self.assertEqual(document["compositions"], [{"aggregate": "incomplete", "assemblies": ["pkg:github/acme/api"]}])
        self.assertNotIn("compositions", sbom.cyclonedx(self.record(), version="0.9", now=NOW))

    def test_an_old_scan_without_inventory_still_gives_a_valid_document(self):
        document = sbom.cyclonedx({"id": "x", "source": {"name": "viejo"}}, version="0.9", now=NOW)
        self.assertEqual((document["components"], document["dependencies"][0]["dependsOn"]), ([], []))

    def test_vex_translates_triage_without_inventing(self):
        record = self.record()
        findings = record["findings"]
        findings[0]["triage"] = {"status": "false_positive", "reason": "La función vulnerable no se usa", "at": "2026-09-21T00:00:00+00:00"}
        findings[1]["triage"] = {"status": "accepted", "reason": "Compensado por el WAF", "expires_at": "2026-12-01"}
        extra = {**_finding("c" * 64, "low", package="qs"), "lifecycle": {"status": "fixed"}}
        code = {**_finding("d" * 64, "high"), "scanner": "sast", "package": None}
        record["findings"] = findings + [extra, code, _finding("e" * 64, "medium", package="ms")]
        document = vex.openvex(record, version="0.9", now=NOW)
        statuses = [statement["status"] for statement in document["statements"]]
        self.assertEqual(statuses, ["not_affected", "affected", "fixed", "under_investigation"])  # el hallazgo de código no entra
        first, second = document["statements"][:2]
        self.assertEqual(first["impact_statement"], "La función vulnerable no se usa")
        self.assertIn("hasta 2026-12-01", second["action_statement"])
        self.assertEqual(first["products"][0]["subcomponents"][0]["@id"], "pkg:npm/lodash@1.0.0")


class ExportRouteTests(HttpCase):
    def setUp(self):
        super().setUp()
        with patch.dict(os.environ, {"APPSEC_AGENT_REQUIRE_TOTP": "none"}):
            Users(self.data_dir).create("miembro", PASSWORD)
            self.cookie = {"Cookie": self.post("/api/auth/login", "login", {"username": "miembro", "password": PASSWORD})[2][0].split("; ")[0]}
        scan = {**_scan("org/api", [_finding("a" * 64, "critical")], datetime.now(timezone.utc).isoformat()),
                "dependencies": [dependency("axios", "1.0.0", direct=True)]}
        self.run = save_repository_scan(self.data_dir, scan)
        self.key = "github:org/api"

    def get(self, path):
        with patch.dict(os.environ, {"APPSEC_AGENT_REQUIRE_TOTP": "none"}):
            return self.call("GET", path, headers=self.cookie)

    def test_sbom_and_vex_from_a_run_and_from_the_asset_state(self):
        for path in (f"/api/runs/{self.run['id']}/sbom.cdx.json", f"/api/assets/export?key={self.key}&artifact=sbom.cdx.json"):
            status, body, _ = self.get(path)
            self.assertEqual(status, 200, path)
            self.assertEqual(body["components"][0]["purl"], "pkg:npm/axios@1.0.0")
        triage.decide(self.data_dir, self.run, ["a" * 64], "false_positive", reason="No se alcanza desde el código", user=ADMIN)
        status, body, _ = self.get(f"/api/assets/export?key={self.key}&artifact=vex.openvex.json&status=open")
        self.assertEqual((status, body["statements"][0]["status"]), (200, "not_affected"))  # también lo descartado
        self.assertEqual(self.get(f"/api/assets/export?key={self.key}&artifact=sbom.xml")[0], 404)
        broken = save_repository_scan(self.data_dir, {**_scan("org/api", [], datetime.now(timezone.utc).isoformat()), "status": "incomplete"})
        self.assertEqual(self.get(f"/api/runs/{broken['id']}/sbom.cdx.json")[0], 404)  # no se exporta como si hubiera terminado


class EuvdTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.directory.name)

    def tearDown(self):
        self.directory.cleanup()

    def test_lookup_caches_and_survives_the_network_going_down(self):
        calls = []
        payload = {"items": [{"id": "EUVD-2026-9", "aliases": "GHSA-x\nCVE-2026-7777\n", "baseScore": 9.1, "baseScoreVersion": "4.0",
                              "exploitedSince": "Sep 2, 2026, 10:00:00 AM"}, {"id": "EUVD-otro", "aliases": "CVE-2026-77770"}]}

        def fetch(cve):
            calls.append(cve)
            return euvd.parse(payload, cve)
        item = euvd.lookup(self.data_dir, "CVE-2026-7777", fetch=fetch, now=NOW)
        self.assertEqual((item["id"], item["severity"], item["exploited_since"]), ("EUVD-2026-9", "critical", "2026-09-02"))
        euvd.lookup(self.data_dir, "CVE-2026-7777", fetch=fetch, now=NOW + timedelta(days=1))
        self.assertEqual(len(calls), 1)  # de la caché

        def down(cve):
            raise OSError("sin red")
        self.assertEqual(euvd.lookup(self.data_dir, "CVE-2026-7777", fetch=down, now=NOW + timedelta(days=30))["id"], "EUVD-2026-9")
        self.assertIsNone(euvd.lookup(self.data_dir, "no-es-un-cve", fetch=fetch))
        with patch.dict(os.environ, {"APPSEC_AGENT_EUVD": "off"}):
            self.assertIsNone(euvd.lookup(self.data_dir, "CVE-2026-8888", fetch=fetch))


class EuvdRouteTests(HttpCase):
    def test_unscored_in_nvd_takes_the_score_from_euvd(self):
        Users(self.data_dir).create("analista", PASSWORD)
        cookie = {"Cookie": self.post("/api/auth/login", "login", {"username": "analista", "password": PASSWORD})[2][0].split("; ")[0]}
        entry = nvd_entry("CVE-2026-55555", "2026-09-19T00:00:00.000")
        entry["cve"]["metrics"] = {}  # NVD ya no lo enriquece
        connection = cve_db.connect(self.data_dir)
        with connection:
            cve_db.upsert(connection, [entry])
        connection.close()
        payload = {"items": [{"id": "EUVD-2026-5", "aliases": "CVE-2026-55555", "baseScore": 7.5, "baseScoreVersion": "3.1",
                              "baseScoreVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}]}
        with patch("tamandua.modules.intel.euvd._fetch", side_effect=lambda cve: euvd.parse(payload, cve)):
            status, body, _ = self.call("GET", "/api/cve-db/item?id=CVE-2026-55555", headers=cookie)
        self.assertEqual((status, body["score"], body["severity"], body["score_source"]), (200, 7.5, "high", "euvd"))


class CraTests(unittest.TestCase):
    """Relojes del art. 14: desde que se sabe que se explota; el informe final, 14 días tras la corrección."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.directory.name)
        kev = {"date_added": "2026-09-20", "due_date": None, "ransomware": True, "name": "Lodash prototype pollution"}
        first = {**_scan("org/api", [{**_finding("a" * 64, "critical", kev=kev, package="lodash"), "cve": ["CVE-2026-1111"]},
                                     {**_finding("b" * 64, "high", package="qs"), "cve": ["CVE-2026-2222"]}], "2026-09-18T10:00:00+00:00"),
                 "finished_at": "2026-09-18T10:00:00+00:00"}
        first["source"]["uid"] = "github#9"
        self.run = save_repository_scan(self.data_dir, first, created_at="2026-09-18T10:00:00+00:00")
        cra.set_product(self.data_dir, "github#9", name="Portal ACME", support_until="2031-12-31", user=ADMIN)

    def tearDown(self):
        self.directory.cleanup()

    def test_clocks_start_when_both_facts_are_known(self):
        now = datetime(2026, 9, 21, 12, tzinfo=timezone.utc)
        (event,) = cra.events(self.data_dir, now=now)  # el hallazgo sin KEV no abre evento
        self.assertEqual((event["cve"], event["product"], event["aware_at"][:10]), ("CVE-2026-1111", "Portal ACME", "2026-09-20"))
        self.assertEqual([(stage["id"], stage["state"]) for stage in event["stages"]],
                         [("early_warning", "overdue"), ("notification", "pending"), ("final_report", "waiting")])
        cra.mark(self.data_dir, event["id"], "early_warning", sent=True, user=ADMIN)
        (event,) = cra.events(self.data_dir, now=now)
        self.assertEqual((event["stages"][0]["state"], event["stages"][0]["sent"]["by"]), ("sent", "ana"))
        self.assertIn("ransomware", cra.draft(event))
        with self.assertRaises(cra.CraError):
            cra.mark(self.data_dir, event["id"], "otra", sent=True, user=ADMIN)

    def test_fixed_starts_the_final_report_and_false_positive_closes_it(self):
        fixed = {**_scan("org/api", [], "2026-09-23T10:00:00+00:00"), "finished_at": "2026-09-23T10:00:00+00:00"}
        fixed["source"]["uid"] = "github#9"
        save_repository_scan(self.data_dir, fixed, created_at="2026-09-23T10:00:00+00:00")
        (event,) = cra.events(self.data_dir, now=datetime(2026, 9, 24, tzinfo=timezone.utc))
        self.assertEqual((event["status"], event["stages"][2]["due"][:10], event["stages"][2]["state"]), ("fixed", "2026-10-07", "pending"))
        triage.decide(self.data_dir, self.run, ["a" * 64], "false_positive", reason="No usamos la función afectada", user=ADMIN)
        self.assertEqual(cra.events(self.data_dir), [])
        with self.assertRaises(cra.CraError):
            cra.set_product(self.data_dir, "github#9", name=" ", support_until=None, user=ADMIN)


class CraRouteTests(HttpCase):
    def test_members_read_only_admins_change(self):
        with patch.dict(os.environ, {"APPSEC_AGENT_REQUIRE_TOTP": "none"}):
            Users(self.data_dir).create("jefa", PASSWORD, role="admin")
            Users(self.data_dir).create("miembro", PASSWORD)
            admin = self.post("/api/auth/login", "login", {"username": "jefa", "password": PASSWORD})[2][0].split("; ")[0]
            member = self.post("/api/auth/login", "login", {"username": "miembro", "password": PASSWORD})[2][0].split("; ")[0]
            save_repository_scan(self.data_dir, _scan("org/api", [], datetime.now(timezone.utc).isoformat()))
            body = {"op": "product", "key": "github:org/api", "name": "API", "support_until": None}
            self.assertEqual(self.call("GET", "/api/cra")[0], 401)
            self.assertEqual(self.call("GET", "/api/cra", headers={"Cookie": member})[0], 200)
            self.assertEqual(self.post("/api/cra", "cra", body, member)[0], 403)
            status, state, _ = self.post("/api/cra", "cra", body, admin)
            self.assertEqual((status, state["products"][0]["name"], bool(state["products"][0]["last_complete"])), (200, "API", True))
            for bad in ({**body, "key": "github:otro"}, {**body, "extra": 1}, {"op": "mark", "event": "x|y", "stage": "early_warning", "sent": "si"},
                        {**body, "support_until": "mañana"}):
                self.assertEqual(self.post("/api/cra", "cra", bad, admin)[0], 400, bad)


class FrameworkTests(unittest.TestCase):
    def test_controls_that_rely_on_deadlines_say_whether_the_report_has_them(self):
        from test_report_design import text as pdf_text
        findings = [{**_finding("a" * 64, "critical"), "triage": {"status": "open"}}]
        record = {"id": "r", "type": "repository_scan", "created_at": "2026-09-25", "source": {"name": "acme/api"}}
        content = pdf_text(render_audit_pdf(record, findings, validate_options({"framework": "pci"}, default_by="ana"), version="0.9"))
        self.assertIn("no incluye los plazos", content)

    def test_every_framework_renders(self):
        findings = [{**_finding("a" * 64, "critical"), "triage": {"status": "open"}}]
        record = {"id": "r", "type": "repository_scan", "created_at": "2026-09-25", "source": {"name": "acme/api"}}
        for framework in FRAMEWORKS:
            options = validate_options({"framework": framework}, default_by="ana")
            self.assertTrue(render_audit_pdf(record, findings, options, version="0.9").startswith(b"%PDF-"), framework)


if __name__ == "__main__":
    unittest.main()
