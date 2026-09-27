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
from tamandua.shared.i18n import localize, text
from tamandua.modules.reporting.audit import FRAMEWORKS, render_audit_pdf, validate_options
from tamandua.modules.identity.auth import Users
from tamandua.modules.runs.store import list_runs, load_run, save_repository_scan
import asgi
from test_auth import ORIGIN, PASSWORD, HttpCase
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
        self.assertIn("rota sus tokens", text(finding["remediation"]))
        # Otro aviso del mismo paquete tampoco propone «actualiza a…».
        other = {**_finding("b" * 64, "high", package="event-stream"), "path": "package-lock.json",
                 "package": {"ecosystem": "npm", "name": "event-stream", "version": "3.3.6", "fixed_version": "4.0.0"}}
        fix_guide.attach([finding, other])
        self.assertIn("paquete malicioso", text(other["fix"]["steps"][0]))
        self.assertFalse(any("Actualiza" in step for step in localize(finding["fix"]["steps"])))
        # Los informes (tabla y «qué hacer primero») dicen lo mismo que el panel, y lo malicioso va primero.
        from tamandua.modules.findings.remediation import action, fix_groups
        groups = fix_groups([_finding("c" * 64, "critical", package="axios"), finding, other])
        self.assertTrue(groups[0]["malicious"])
        self.assertTrue(action(groups[0], short=True).startswith("Eliminar event-stream 3.3.6"))


def acme_record():
    findings = [_finding("a" * 64, "critical", package="lodash"), _finding("b" * 64, "high", package="minimist")]
    return {"id": "r1", "type": "repository_scan", "created_at": "2026-09-20T00:00:00+00:00",
            "source": {"id": "github:acme/api", "name": "acme/api", "provider": "github", "sha256": "f" * 64},
            "dependencies": [dependency("lodash", "4.17.20", purl="pkg:npm/lodash@4.17.20", licenses=["MIT"], direct=True),
                             dependency("left-pad", "1.3.0", direct=False)],
            "findings": findings}


class SbomAndVexTests(unittest.TestCase):
    def record(self):
        return acme_record()

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


def assert_cyclonedx(case, document):
    """The CycloneDX 1.6 JSON shape Tamandua relies on (no schema validator in the test dependencies): required
    fields, unique bom-refs across nested components, and every dependency or composition ref pointing to one."""
    case.assertEqual((document["bomFormat"], document["specVersion"], document["version"]), ("CycloneDX", "1.6", 1))
    case.assertRegex(document["serialNumber"], r"^urn:uuid:[0-9a-f-]{36}$")
    refs = [document["metadata"]["component"]["bom-ref"]]

    def walk(components):
        for component in components:
            case.assertIn(component["type"], ("application", "container", "library"))
            case.assertTrue(component["name"])
            refs.append(component["bom-ref"])
            walk(component.get("components") or [])
    walk(document["components"])
    case.assertEqual(len(refs), len(set(refs)), "bom-refs must be unique")
    for entry in document["dependencies"]:
        case.assertIn(entry["ref"], refs)
        case.assertTrue(set(entry["dependsOn"]) <= set(refs), entry)
    for composition in document.get("compositions") or []:
        case.assertTrue(set(composition["assemblies"]) <= set(refs))
    for prop in [*document["metadata"].get("properties", []), *(p for c in document["components"] for p in c.get("properties", []))]:
        case.assertEqual(set(prop), {"name", "value"})
        case.assertIsInstance(prop["value"], str)


def assert_openvex(case, document):
    case.assertEqual(document["@context"], "https://openvex.dev/ns/v0.2.0")
    case.assertRegex(document["@id"], r"^urn:uuid:")
    for statement in document["statements"]:
        case.assertIn(statement["status"], ("not_affected", "affected", "fixed", "under_investigation"))
        case.assertTrue(statement["vulnerability"]["name"] and statement["products"][0]["@id"])
        if statement["status"] == "not_affected":
            case.assertTrue(statement.get("impact_statement") or statement.get("justification"))
        if statement["status"] == "affected":
            case.assertTrue(statement.get("action_statement"))


class PortfolioSbomAndVexTests(unittest.TestCase):
    def assets(self):
        api = acme_record()
        api["source"] = {**api["source"], "uid": "github#1", "branch": "main", "commit": "c" * 40}
        image = {"id": "i1", "type": "image_scan", "source": {"id": "image:nginx", "name": "nginx", "provider": "registry",
                                                             "image": {"reference": "nginx:1.21", "resolved_digest": "sha256:abc"}},
                 "dependencies": [dependency("lodash", "4.17.20", purl="pkg:npm/lodash@4.17.20")],
                 "system_packages": [{"ecosystem": "debian", "name": "libc6", "version": "2.31-13"}], "findings": [],
                 "steps": [{"name": "Grype", "status": "failed", "tool": {"name": "grype"}}]}
        return [{"key": "github#1", "ref": sbom.root_ref(api), "scan": api}, {"key": "image:nginx", "ref": sbom.root_ref(image), "scan": image}]

    def test_each_asset_is_a_parent_with_its_own_packages_and_nothing_is_deduplicated(self):
        document = sbom.portfolio(self.assets(), total=2, name="Acme", version="0.9", now=NOW, locale="en")
        assert_cyclonedx(self, document)
        self.assertEqual(document["metadata"]["component"]["name"], "Acme")
        self.assertEqual(document["metadata"]["tools"]["components"][0]["version"], "0.9")
        api, image = document["components"]
        self.assertEqual((api["type"], api["bom-ref"], api["version"]), ("application", "pkg:github/acme/api", "c" * 40))
        identity = {prop["name"]: prop["value"] for prop in api["properties"]}
        self.assertEqual((identity["tamandua:uid"], identity["tamandua:branch"], identity["tamandua:asset"], identity["tamandua:run"]),
                         ("github#1", "main", "github#1", "r1"))
        self.assertEqual((image["type"], image["bom-ref"], image["version"]), ("container", "oci:nginx:1.21", "sha256:abc"))
        # The same package in two assets is two entries, each under its parent, with the plain purl kept.
        lodash = [(parent["bom-ref"], child) for parent in (api, image) for child in parent["components"] if child["purl"] == "pkg:npm/lodash@4.17.20"]
        self.assertEqual([child["bom-ref"] for _, child in lodash], ["pkg:github/acme/api|pkg:npm/lodash@4.17.20", "oci:nginx:1.21|pkg:npm/lodash@4.17.20"])
        graph = {entry["ref"]: entry["dependsOn"] for entry in document["dependencies"]}
        self.assertEqual(graph["urn:tamandua:portfolio"], ["pkg:github/acme/api", "oci:nginx:1.21"])
        self.assertIn("pkg:github/acme/api|pkg:npm/lodash@4.17.20", graph["pkg:github/acme/api"])
        self.assertNotIn("pkg:github/acme/api|pkg:npm/left-pad@1.3.0", graph["pkg:github/acme/api"])  # transitive, as in the per-asset SBOM
        self.assertEqual(set(graph["oci:nginx:1.21"]), {child["bom-ref"] for child in image["components"]})
        # The image scan had an engine fail: that asset (only) is declared incomplete; nothing was truncated.
        self.assertEqual(document["compositions"], [{"aggregate": "incomplete", "assemblies": ["oci:nginx:1.21"]}])
        self.assertNotIn("tamandua:truncated", {prop["name"] for prop in document["metadata"]["properties"]})
        self.assertEqual({phase["phase"] for phase in document["metadata"]["lifecycles"]}, {"pre-build", "post-build"})

    def test_past_the_limits_the_document_says_what_was_left_out(self):
        with patch.object(sbom, "PORTFOLIO_COMPONENTS", 3):
            document = sbom.portfolio(self.assets(), total=5, name="Acme", version="0.9", now=NOW, locale="en")
        assert_cyclonedx(self, document)
        (api,) = document["components"]  # the image didn't fit
        self.assertEqual(len(api["components"]), 3)
        self.assertIn("Only 3 of 4 components", {prop["name"]: prop["value"] for prop in api["properties"]}["tamandua:truncated"])
        notes = {prop["name"]: prop["value"] for prop in document["metadata"]["properties"]}
        self.assertEqual((notes["tamandua:assets"], notes["tamandua:components"]), ("1", "3"))
        self.assertIn("1 of 5 assets", notes["tamandua:truncated"])
        self.assertEqual(document["compositions"], [{"aggregate": "incomplete", "assemblies": ["pkg:github/acme/api", "urn:tamandua:portfolio"]}])

    def test_portfolio_vex_keeps_each_statement_on_its_asset(self):
        first, second = acme_record(), {**acme_record(), "findings": [_finding("c" * 64, "high", package="qs")]}
        first["findings"][0]["triage"] = {"status": "false_positive", "reason": "No se usa", "at": "2026-09-21T00:00:00+00:00"}
        document = vex.portfolio([("pkg:github/acme/api", first), ("oci:nginx:1.21", second)], total=2, version="0.9", now=NOW, locale="en")
        assert_openvex(self, document)
        products = [(statement["products"][0]["@id"], statement["products"][0]["subcomponents"][0]["@id"]) for statement in document["statements"]]
        self.assertEqual(products, [("pkg:github/acme/api", "pkg:npm/lodash@1.0.0"), ("pkg:github/acme/api", "pkg:npm/minimist@1.0.0"),
                                    ("oci:nginx:1.21", "pkg:npm/qs@1.0.0")])
        self.assertEqual(document["statements"][0]["products"][0]["identifiers"], {"purl": "pkg:github/acme/api"})
        self.assertNotIn("identifiers", document["statements"][2]["products"][0])
        self.assertEqual(document["tooling"], "Tamandua 0.9")
        partial = vex.portfolio([("pkg:github/acme/api", first)], total=3, version="0.9", now=NOW, locale="en")
        self.assertIn("1 of 3 assets", partial["tooling"])
        with patch.object(vex, "PORTFOLIO_STATEMENTS", 1):
            capped = vex.portfolio([("pkg:github/acme/api", first)], total=1, version="0.9", now=NOW, locale="en")
        self.assertEqual((len(capped["statements"]), "partial" in capped["tooling"]), (1, True))


class ExportRouteTests(HttpCase):
    def setUp(self):
        super().setUp()
        with patch.dict(os.environ, {"TAMANDUA_REQUIRE_TOTP": "none"}):
            Users(self.data_dir).create("miembro", PASSWORD)
            self.cookie = {"Cookie": self.post("/api/auth/login", "login", {"username": "miembro", "password": PASSWORD})[2][0].split("; ")[0]}
        scan = {**_scan("org/api", [_finding("a" * 64, "critical")], datetime.now(timezone.utc).isoformat()),
                "dependencies": [dependency("axios", "1.0.0", direct=True)]}
        self.run = save_repository_scan(self.data_dir, scan)
        self.key = "github:org/api"

    def get(self, path):
        with patch.dict(os.environ, {"TAMANDUA_REQUIRE_TOTP": "none"}):
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
        with patch.dict(os.environ, {"TAMANDUA_EUVD": "off"}):
            self.assertIsNone(euvd.lookup(self.data_dir, "CVE-2026-8888", fetch=fetch))


class EuvdRouteTests(HttpCase):
    def test_unscored_in_nvd_takes_the_score_from_euvd(self):
        Users(self.data_dir).create("analista", PASSWORD)
        cookie = {"Cookie": self.post("/api/auth/login", "login", {"username": "analista", "password": PASSWORD})[2][0].split("; ")[0]}
        entry = nvd_entry("CVE-2026-55555", "2026-09-19T00:00:00.000")
        entry["cve"]["metrics"] = {}  # NVD ya no lo enriquece
        cve_db.upsert(self.data_dir, [entry])
        payload = {"items": [{"id": "EUVD-2026-5", "aliases": "CVE-2026-55555", "baseScore": 7.5, "baseScoreVersion": "3.1",
                              "baseScoreVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}]}
        with patch("tamandua.modules.intel.euvd._fetch", side_effect=lambda cve: euvd.parse(payload, cve)):
            status, body, _ = self.call("GET", "/api/cve-db/item?id=CVE-2026-55555", headers=cookie)
        self.assertEqual((status, body["score"], body["severity"], body["score_source"]), (200, 7.5, "high", "euvd"))


class CraTests(unittest.TestCase):
    """Art. 14: a KEV match is only a signal; the clocks start when an admin records it is exploited in the product."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.directory.name)
        kev = {"date_added": "2026-09-20", "due_date": None, "ransomware": True, "name": "Lodash prototype pollution"}
        first = {**_scan("org/api", [{**_finding("a" * 64, "critical", kev=kev, package="lodash"), "cve": ["CVE-2026-1111"]},
                                     {**_finding("b" * 64, "high", package="qs"), "cve": ["CVE-2026-2222"]}], "2026-09-18T10:00:00+00:00"),
                 "finished_at": "2026-09-18T10:00:00+00:00"}
        first["source"]["uid"] = "github#9"
        self.run = save_repository_scan(self.data_dir, first, created_at="2026-09-18T10:00:00+00:00")
        cra.set_policy(self.data_dir, True, reason="Vendemos el portal en la UE", user=ADMIN)
        cra.set_product(self.data_dir, "github#9", name="Portal ACME", support_until="2031-12-31", user=ADMIN)
        self.event_id = "github#9|CVE-2026-1111"

    def tearDown(self):
        self.directory.cleanup()

    def exploited(self, at: datetime):
        with patch.object(cra, "_now", return_value=at.isoformat()):
            cra.assess(self.data_dir, self.event_id, "exploited", reason=None, user=ADMIN)

    def test_off_by_default_opens_nothing_and_turning_it_off_keeps_the_data(self):
        with tempfile.TemporaryDirectory() as other:
            self.assertEqual((cra.policy(Path(other))["enabled"], cra.events(Path(other))), (False, []))
        self.exploited(datetime(2026, 9, 21, tzinfo=timezone.utc))
        with self.assertRaises(cra.CraError):  # the change needs a reason, like the other policies
            cra.set_policy(self.data_dir, False, reason=" ", user=ADMIN)
        policy = cra.set_policy(self.data_dir, False, reason="Ya no vendemos en la UE", user=ADMIN)
        self.assertEqual((policy["enabled"], [entry["enabled"] for entry in policy["history"]], policy["history"][0]["by"]), (False, [False, True], "ana"))
        self.assertEqual(cra.events(self.data_dir), [])
        self.assertIn("github#9", cra.load(self.data_dir)["products"])
        cra.set_policy(self.data_dir, True, reason="Volvemos a vender en la UE", user=ADMIN)
        (event,) = cra.events(self.data_dir)
        self.assertEqual(event["state"], "exploited")  # the assessment survived

    def test_a_kev_match_is_to_assess_with_no_clock_running(self):
        (event,) = cra.events(self.data_dir, now=datetime(2026, 9, 30, tzinfo=timezone.utc))  # the finding without KEV opens nothing
        self.assertEqual((event["cve"], event["product"], event["state"], event["signal_at"][:10]), ("CVE-2026-1111", "Portal ACME", "to_assess", "2026-09-20"))
        self.assertEqual((event["stages"], event["aware_at"], event["assessment"], event["done"]), ([], None, None, False))
        self.assertIsNone(cra.with_draft(event)["draft"])
        self.assertEqual(cra.overview(self.data_dir)["counts"]["to_assess"], 1)
        with self.assertRaises(cra.CraError):  # nothing to mark as sent before the assessment
            cra.mark(self.data_dir, self.event_id, "early_warning", sent=True, user=ADMIN)

    def test_exploited_starts_the_clocks_from_the_awareness_time(self):
        aware = datetime(2026, 9, 25, 9, tzinfo=timezone.utc)
        self.exploited(aware)
        (event,) = cra.events(self.data_dir, now=aware + timedelta(hours=25))
        self.assertEqual((event["state"], event["aware_at"], event["assessment"]["by"]), ("exploited", aware.isoformat(), "ana"))
        self.assertEqual([(stage["id"], stage["due"], stage["state"]) for stage in event["stages"]],
                         [("early_warning", (aware + timedelta(hours=24)).isoformat(), "overdue"),
                          ("notification", (aware + timedelta(hours=72)).isoformat(), "pending"), ("final_report", None, "waiting")])
        cra.mark(self.data_dir, event["id"], "early_warning", sent=True, user=ADMIN)
        (event,) = cra.events(self.data_dir, now=aware + timedelta(hours=25))
        self.assertEqual((event["stages"][0]["state"], event["stages"][0]["sent"]["by"]), ("sent", "ana"))
        self.assertIn("ransomware", cra.draft(event))
        self.assertIn("2026-09-25 09:00", cra.draft(event))
        with self.assertRaises(cra.CraError):
            cra.mark(self.data_dir, event["id"], "otra", sent=True, user=ADMIN)
        with self.assertRaises(cra.CraError):  # exploited can't be undone: its clocks stay on record
            cra.reopen(self.data_dir, self.event_id, user=ADMIN)
        with self.assertRaises(cra.CraError):
            cra.assess(self.data_dir, self.event_id, "not_affected", reason="Nos equivocamos", user=ADMIN)

    def test_not_affected_needs_a_reason_closes_the_event_and_can_be_reopened(self):
        for reason in (None, "  no ", "x" * 501, "Motivo\x00oculto"):
            with self.assertRaises(cra.CraError, msg=reason):
                cra.assess(self.data_dir, self.event_id, "not_affected", reason=reason, user=ADMIN)
        cra.assess(self.data_dir, self.event_id, "not_affected", reason="No usamos la función afectada de lodash", user=ADMIN)
        (event,) = cra.events(self.data_dir)
        self.assertEqual((event["state"], event["done"], event["stages"], event["assessment"]["reason"]),
                         ("not_affected", True, [], "No usamos la función afectada de lodash"))
        self.assertEqual(cra.overview(self.data_dir)["counts"]["pending"], 0)
        with self.assertRaises(cra.CraError):
            cra.assess(self.data_dir, self.event_id, "exploited", reason=None, user=ADMIN)
        cra.reopen(self.data_dir, self.event_id, user=ADMIN)
        (event,) = cra.events(self.data_dir)
        self.assertEqual(event["state"], "to_assess")
        history = cra.load(self.data_dir)["reports"][self.event_id]["history"]
        self.assertEqual([entry["state"] for entry in history], ["not_affected", "reopened"])
        for bad in ("github#9|CVE-2026-2222", "github#1|CVE-2026-1111", "x", "a" * 400):  # not a KEV event of a product
            with self.assertRaises(cra.CraError, msg=bad):
                cra.assess(self.data_dir, bad, "exploited", reason=None, user=ADMIN)

    def test_events_reported_before_assessments_read_as_exploited_from_the_signal(self):
        from tamandua.shared import documents
        state = documents.load(self.data_dir, "cra", {})
        state["reports"] = {self.event_id: {"early_warning": {"at": "2026-09-20T12:00:00+00:00", "by": "luis"}}}
        documents.save(self.data_dir, "cra", state)
        noon = datetime(2026, 9, 21, 12, tzinfo=timezone.utc)
        (event,) = cra.events(self.data_dir, now=noon)
        self.assertEqual((event["state"], event["assessment"]["legacy"], event["assessment"]["by"], event["aware_at"][:10]),
                         ("exploited", True, "luis", "2026-09-20"))
        self.assertEqual([stage["state"] for stage in event["stages"]], ["sent", "pending", "waiting"])
        cra.mark(self.data_dir, self.event_id, "early_warning", sent=False, user=ADMIN)
        (event,) = cra.events(self.data_dir, now=noon)
        self.assertEqual((event["state"], event["stages"][0]["state"]), ("exploited", "overdue"))  # unmarking doesn't reopen it

    def test_fixed_starts_the_final_report_and_false_positive_closes_it(self):
        self.exploited(datetime(2026, 9, 21, tzinfo=timezone.utc))
        fixed = {**_scan("org/api", [], "2026-09-23T10:00:00+00:00"), "finished_at": "2026-09-23T10:00:00+00:00"}
        fixed["source"]["uid"] = "github#9"
        save_repository_scan(self.data_dir, fixed, created_at="2026-09-23T10:00:00+00:00")
        (event,) = cra.events(self.data_dir, now=datetime(2026, 9, 24, tzinfo=timezone.utc))
        self.assertEqual((event["status"], event["stages"][2]["due"][:10], event["stages"][2]["state"]), ("fixed", "2026-10-07", "pending"))
        triage.decide(self.data_dir, self.run, ["a" * 64], "false_positive", reason="No usamos la función afectada", user=ADMIN)
        self.assertEqual(cra.events(self.data_dir), [])
        with self.assertRaises(cra.CraError):
            cra.set_product(self.data_dir, "github#9", name=" ", support_until=None, user=ADMIN)


JSON = {"Content-Type": "application/json"}


def _send(case, path, action, body, cookie):
    """A POST to a typed route, as the panel sends it."""
    return case.call("POST", path, body, {"Origin": ORIGIN, "X-Tamandua-Action": action, "Cookie": cookie, **JSON})


def _login(case, username, role="member"):
    Users(case.data_dir).create(username, PASSWORD, role=role)
    return case.post("/api/auth/login", "login", {"username": username, "password": PASSWORD})[2][0].split("; ")[0]


class CraRouteTests(HttpCase):
    def test_off_answers_404_and_only_admins_turn_it_on_with_a_reason(self):
        admin, member = _login(self, "jefa", "admin"), _login(self, "miembro")
        save_repository_scan(self.data_dir, _scan("org/api", [], datetime.now(timezone.utc).isoformat()))
        status, policy, _ = self.call("GET", "/api/policies/cra", headers={"Cookie": member})
        self.assertEqual((status, policy["enabled"], policy["history"]), (200, False, []))
        for path in ("/api/cra", "/api/cra/products", "/api/cra/events", "/api/cra/assets"):
            status, body, _ = self.call("GET", path, headers={"Cookie": member, "Accept-Language": "en"})
            self.assertEqual((status, body["error"]), (404, "CRA reporting is off. An admin can turn it on in Policies."), path)
        product = {"op": "product", "key": "github:org/api", "name": "API", "support_until": None}
        self.assertEqual(_send(self, "/api/cra", "cra", product, admin)[0], 404)
        self.assertEqual(self.call("GET", "/api/policies/cra")[0], 401)
        on = {"enabled": True, "reason": "Vendemos la API en la UE"}
        self.assertEqual(_send(self, "/api/policies/cra", "cra-policy", on, member)[0], 403)
        self.assertEqual(self.call("POST", "/api/policies/cra", on, {"Cookie": admin, "Origin": ORIGIN, **JSON})[0], 403)  # CSRF
        for bad in ({**on, "reason": "no"}, {**on, "extra": 1}, {"enabled": "si", "reason": on["reason"]}, {"enabled": True}):
            self.assertEqual(_send(self, "/api/policies/cra", "cra-policy", bad, admin)[0], 400, bad)
        status, policy, _ = _send(self, "/api/policies/cra", "cra-policy", on, admin)
        self.assertEqual((status, policy["enabled"], policy["by"], policy["reason"], len(policy["history"])), (200, True, "jefa", on["reason"], 1))
        self.assertEqual(self.call("GET", "/api/cra", headers={"Cookie": member})[0], 200)

    def test_members_read_only_admins_change_and_assess(self):
        admin, member = _login(self, "jefa", "admin"), _login(self, "miembro")
        cra.set_policy(self.data_dir, True, reason="Vendemos en la UE", user=ADMIN)
        kev = {"date_added": "2026-09-20", "due_date": None, "ransomware": False, "name": "Exploited"}
        save_repository_scan(self.data_dir, _scan("org/api", [{**_finding("a" * 64, "critical", kev=kev), "cve": ["CVE-2026-1111"]}],
                                                  datetime.now(timezone.utc).isoformat()))
        body = {"op": "product", "key": "github:org/api", "name": "API", "support_until": None}
        self.assertEqual(self.call("GET", "/api/cra")[0], 401)
        self.assertEqual(self.call("GET", "/api/cra", headers={"Cookie": member})[0], 200)
        self.assertEqual(_send(self, "/api/cra", "cra", body, member)[0], 403)
        self.assertEqual(self.call("POST", "/api/cra", body, {"Cookie": admin, "Origin": ORIGIN, **JSON})[0], 403)  # CSRF
        status, state, _ = _send(self, "/api/cra", "cra", body, admin)
        self.assertEqual((status, state["counts"]["products"], state["counts"]["candidates"], state["counts"]["to_assess"]), (200, 1, 0, 1))
        _, page, _ = self.call("GET", "/api/cra/products", headers={"Cookie": member})
        self.assertEqual((page["total"], page["items"][0]["name"], bool(page["items"][0]["last_complete"])), (1, "API", True))
        event_id = "github:org/api|CVE-2026-1111"
        for bad in ({**body, "key": "github:otro"}, {**body, "extra": 1}, {"op": "mark", "event": event_id, "stage": "early_warning", "sent": "si"},
                    {**body, "support_until": "mañana"}, {"op": "borrar"},
                    {"op": "mark", "event": event_id, "stage": "early_warning", "sent": True},  # not assessed yet
                    {"op": "assess", "event": event_id, "verdict": "not_affected"},  # a reason is required
                    {"op": "assess", "event": event_id, "verdict": "quizas", "reason": "No sabemos aún"},
                    {"op": "assess", "event": "github:org/api|CVE-2026-9", "verdict": "exploited"}):
            self.assertEqual(_send(self, "/api/cra", "cra", bad, admin)[0], 400, bad)
        assess = {"op": "assess", "event": event_id, "verdict": "exploited"}
        self.assertEqual(_send(self, "/api/cra", "cra", assess, member)[0], 403)
        self.assertEqual(_send(self, "/api/cra", "cra", assess, admin)[0], 200)
        _, events, _ = self.call("GET", "/api/cra/events", headers={"Cookie": member})
        (event,) = events["items"]
        self.assertEqual((event["state"], event["assessment"]["by"], len(event["stages"]), event["aware_at"] is not None), ("exploited", "jefa", 3, True))
        self.assertIn("CVE-2026-1111", event["draft"])
        self.assertEqual(_send(self, "/api/cra", "cra", {"op": "mark", "event": event_id, "stage": "early_warning", "sent": True}, admin)[0], 200)


class CraPagingTests(HttpCase):
    def test_products_events_and_assets_are_paged_on_the_server(self):
        Users(self.data_dir).create("miembro", PASSWORD)
        cookie = {"Cookie": self.post("/api/auth/login", "login", {"username": "miembro", "password": PASSWORD})[2][0].split("; ")[0]}
        cra.set_policy(self.data_dir, True, reason="Vendemos en la UE", user=ADMIN)
        kev = {"date_added": "2026-09-20", "due_date": None, "ransomware": False, "name": "Exploited"}
        stamp = datetime.now(timezone.utc).isoformat()
        findings = {"org/a": [{**_finding("a" * 64, "critical", kev=kev, package="lodash"), "cve": ["CVE-2026-1111"]},
                              {**_finding("b" * 64, "high", kev=kev, package="qs"), "cve": ["CVE-2026-3333"]}],
                    "org/b": [{**_finding("c" * 64, "critical", kev=kev, package="axios"), "cve": ["CVE-2026-4444"]}], "org/c": []}
        for name, items in findings.items():
            save_repository_scan(self.data_dir, _scan(name, items, stamp), created_at=stamp)
        for name in ("org/a", "org/b"):
            cra.set_product(self.data_dir, f"github:{name}", name=name.upper(), support_until=None, user=ADMIN)

        status, overview, _ = self.call("GET", "/api/cra", headers=cookie)
        self.assertEqual((status, overview["counts"]), (200, {"products": 2, "unscanned": 0, "events": 3, "pending": 3, "to_assess": 3,
                                                              "assets": 3, "candidates": 1}))
        _, first, _ = self.call("GET", "/api/cra/products?limit=1", headers=cookie)
        _, second, _ = self.call("GET", "/api/cra/products?limit=1&offset=1", headers=cookie)
        self.assertEqual((first["total"], first["limit"], [item["name"] for item in first["items"] + second["items"]]), (2, 1, ["ORG/A", "ORG/B"]))
        _, events, _ = self.call("GET", "/api/cra/events?limit=2", headers=cookie)
        self.assertEqual((events["total"], len(events["items"]), events["offset"]), (3, 2, 0))
        self.assertEqual({(event["state"], event["draft"]) for event in events["items"]}, {("to_assess", None)})  # no draft before the assessment
        _, rest, _ = self.call("GET", "/api/cra/events?limit=2&offset=2", headers=cookie)
        self.assertEqual(len(rest["items"]), 1)
        self.assertEqual({event["cve"] for event in events["items"] + rest["items"]}, {"CVE-2026-1111", "CVE-2026-3333", "CVE-2026-4444"})
        _, assets, _ = self.call("GET", "/api/cra/assets", headers=cookie)
        self.assertEqual((assets["total"], assets["items"]), (1, [{"key": "github:org/c", "name": "org/c"}]))
        self.assertEqual(self.call("GET", "/api/cra/assets?q=ORG/C", headers=cookie)[1]["total"], 1)
        self.assertEqual(self.call("GET", "/api/cra/assets?q=nada", headers=cookie)[1]["total"], 0)
        for path in ("/api/cra/products", "/api/cra/events", "/api/cra/assets"):
            for bad in ("limit=0", "limit=101", "offset=-1", "offset=10001", "limit=diez"):
                self.assertEqual(self.call("GET", f"{path}?{bad}", headers=cookie), (400, {"error": "Parámetros inválidos"}, []), (path, bad))
            self.assertEqual(self.call("GET", f"{path}?limit=500")[0], 401, path)
        self.assertEqual(self.call("GET", "/api/cra/assets?q=" + "a" * 101, headers=cookie)[0], 400)


class EvidenceHubTests(HttpCase):
    """The hub links to the existing exports; only the portfolio audit evidence has its own route."""

    def test_asset_picker_existing_exports_and_portfolio_evidence(self):
        member = _login(self, "miembro")
        cookie = {"Cookie": member}
        stamp = datetime.now(timezone.utc).isoformat()
        save_repository_scan(self.data_dir, _scan("org/api", [_finding("a" * 64, "critical", package="lodash")], stamp), created_at=stamp)
        incomplete = {**_scan("org/web", [], stamp), "status": "failed"}
        save_repository_scan(self.data_dir, incomplete, created_at=stamp)

        self.assertEqual(self.call("GET", "/api/evidence")[0], 401)
        self.assertEqual(self.call("GET", "/api/evidence", headers=cookie)[1], {"assets": 2, "complete": 1})
        status, page, _ = self.call("GET", "/api/evidence/assets", headers=cookie)
        self.assertEqual((status, page["total"], {item["name"]: item["sbom"] for item in page["items"]}), (200, 2, {"org/api": True, "org/web": False}))
        self.assertEqual({item["kind"] for item in page["items"]}, {"repository"})
        self.assertEqual(self.call("GET", "/api/evidence/assets?q=API", headers=cookie)[1]["total"], 1)
        for bad in ("limit=0", "limit=101", "q=" + "a" * 101):
            self.assertEqual(self.call("GET", f"/api/evidence/assets?{bad}", headers=cookie)[0], 400, bad)

        # The per-asset buttons are the existing exports, called exactly as the hub does.
        for artifact, status_arg, kind in (("sbom.cdx.json", "all", "bomFormat"), ("vex.openvex.json", "all", "statements")):
            status, body, _ = self.call("GET", f"/api/assets/export?key=github:org/api&status={status_arg}&artifact={artifact}", headers=cookie)
            self.assertEqual(status, 200, artifact)
            self.assertIn(kind, body)
        status, body, _ = self.call("GET", "/api/assets/export?key=github:org/api&status=open&artifact=report.pdf", headers=cookie)
        self.assertTrue((status, body[:5]) == (200, b"%PDF-"))
        self.assertEqual(self.call("GET", "/api/assets/export?key=github:org/web&status=all&artifact=sbom.cdx.json", headers=cookie)[0], 404)
        status, body, _ = self.post("/api/reports/audit", "audit-report", {"asset": "github:org/api", "status": "all", "options": {"framework": "iso27001"}}, member)
        self.assertEqual((status, body[:5]), (200, b"%PDF-"))

        for framework in set(FRAMEWORKS) - {"cra"}:
            status, body, _ = _send(self, "/api/evidence/portfolio", "audit-report", {"framework": framework}, member)
            self.assertEqual((status, body[:5]), (200, b"%PDF-"), framework)
        self.assertEqual(self.call("POST", "/api/evidence/portfolio", {"framework": "soc2"}, {"Cookie": member, "Origin": ORIGIN, **JSON})[0], 403)  # CSRF
        self.assertEqual(self.call("POST", "/api/evidence/portfolio", {"framework": "soc2"}, {"Origin": ORIGIN, "X-Tamandua-Action": "audit-report", **JSON})[0], 401)
        for bad in ({"framework": "hipaa"}, {"framework": "soc2", "title": "x"}, {}):
            self.assertEqual(_send(self, "/api/evidence/portfolio", "audit-report", bad, member)[0], 400, bad)

    def test_portfolio_without_analyzed_assets_is_404(self):
        member = _login(self, "miembro")
        self.assertEqual(_send(self, "/api/evidence/portfolio", "audit-report", {"framework": "soc2"}, member)[0], 404)

    def test_portfolio_sbom_and_vex(self):
        member = _login(self, "miembro")
        stamp = datetime.now(timezone.utc).isoformat()
        for path in ("/api/evidence/portfolio/sbom", "/api/evidence/portfolio/vex"):
            self.assertEqual(self.call("GET", path)[0], 401, path)
        # Only a failed scan: nothing to export yet.
        save_repository_scan(self.data_dir, {**_scan("org/web", [], stamp), "status": "failed"}, created_at=stamp)
        for path in ("/api/evidence/portfolio/sbom", "/api/evidence/portfolio/vex"):
            status, body, _ = self.call("GET", path, headers={"Cookie": member, "Accept-Language": "en"})
            self.assertEqual((status, body["error"]), (404, "No asset has a completed full scan yet: the portfolio SBOM and VEX need at least one."), path)

        for name, package in (("org/api", "lodash"), ("org/ui", "lodash")):
            scan = {**_scan(name, [_finding("a" * 64, "critical", package=package)], stamp), "dependencies": [dependency(package, "1.0.0", direct=True)]}
            save_repository_scan(self.data_dir, scan, created_at=stamp)
        run = triage.annotate(self.data_dir, load_run(self.data_dir, next(row["id"] for row in list_runs(self.data_dir) if row["target"] == "org/api")))
        triage.decide(self.data_dir, run, ["a" * 64], "false_positive", reason="No se alcanza desde el código", user=ADMIN)

        response = asgi.request(self.client, "GET", "/api/evidence/portfolio/sbom?organization=Acme%20%20Corp", None, {"Cookie": member})
        self.assertEqual((response.status_code, response.headers["content-type"]), (200, "application/vnd.cyclonedx+json"))
        self.assertIn('filename="portfolio.cdx.json"', response.headers["content-disposition"])
        document = response.json()
        assert_cyclonedx(self, document)
        self.assertEqual(document["metadata"]["component"]["name"], "Acme Corp")
        self.assertEqual({component["name"] for component in document["components"]}, {"org/api", "org/ui"})  # not the failed one
        self.assertEqual([len(component["components"]) for component in document["components"]], [1, 1])  # lodash twice
        _, default, _ = self.call("GET", "/api/evidence/portfolio/sbom", headers={"Cookie": member})
        self.assertEqual(default["metadata"]["component"]["name"], "Tamandua portfolio")  # machine-readable: never localized
        self.assertEqual(self.call("GET", "/api/evidence/portfolio/sbom?organization=" + "a" * 121, headers={"Cookie": member})[0], 400)
        _, control, _ = self.call("GET", "/api/evidence/portfolio/sbom?organization=%07x", headers={"Cookie": member})
        self.assertEqual(control["metadata"]["component"]["name"], "Tamandua portfolio")

        response = asgi.request(self.client, "GET", "/api/evidence/portfolio/vex", None, {"Cookie": member})
        self.assertEqual((response.status_code, response.headers["content-type"]), (200, "application/json"))
        self.assertIn('filename="portfolio.openvex.json"', response.headers["content-disposition"])
        statements = response.json()["statements"]
        assert_openvex(self, response.json())
        # One statement per asset, each about the same product ref as the asset's component in the SBOM.
        self.assertEqual({(item["products"][0]["@id"], item["status"]) for item in statements},
                         {("pkg:github/org/api", "not_affected"), ("pkg:github/org/ui", "under_investigation")})
        self.assertEqual({item["products"][0]["@id"] for item in statements}, {component["bom-ref"] for component in document["components"]})


class CraFrameworkGateTests(HttpCase):
    """The CRA mapping of the audit evidence only exists while the CRA policy is on."""

    def test_cra_framework_is_rejected_when_off_and_accepted_when_on(self):
        member = _login(self, "miembro")
        stamp = datetime.now(timezone.utc).isoformat()
        save_repository_scan(self.data_dir, _scan("org/api", [_finding("a" * 64, "critical")], stamp), created_at=stamp)
        options = {"framework": "cra"}
        requests = (("/api/reports/audit", {"asset": "github:org/api", "status": "all", "options": options}),
                    ("/api/reports/audit", {"assets": ["github:org/api"], "options": options}),
                    ("/api/evidence/portfolio", options))
        message = "The CRA mapping is only available while CRA reporting is on. An admin can turn it on in Policies."
        for path, body in requests:
            status, answer, _ = self.call("POST", path, body, {"Origin": ORIGIN, "X-Tamandua-Action": "audit-report", "Cookie": member,
                                                             "Accept-Language": "en", **JSON})
            self.assertEqual((status, answer["error"]), (400, message), (path, body))
        cra.set_policy(self.data_dir, True, reason="Vendemos en la UE", user=ADMIN)
        for path, body in requests:
            status, answer, _ = _send(self, path, "audit-report", body, member)
            self.assertEqual((status, answer[:5]), (200, b"%PDF-"), (path, body))


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
