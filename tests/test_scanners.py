"""Contrato de los motores en contenedor: parsers contra salidas reales, sin secretos y sin fingir."""

import json
import unittest
from pathlib import Path
from unittest.mock import patch

from tamandua.modules.scanning import engines as scanners
from tamandua.modules.scanning.engines import _pick_fixed, merge_secrets, parse_gitleaks, parse_opengrep, parse_trivy

FIXTURES = Path(__file__).parent / "fixtures"


class TrivyParserTests(unittest.TestCase):
    def setUp(self):
        self.payload = json.loads((FIXTURES / "trivy.json").read_text(encoding="utf-8"))

    def test_three_fronts_from_one_run(self):
        findings = parse_trivy(self.payload, {"kev": {}, "epss": {}})
        kinds = {kind: sum(1 for item in findings if item["scanner"] == kind) for kind in ("sca", "iac", "secrets")}
        self.assertEqual(kinds, {"sca": 9, "iac": 5, "secrets": 1})
        self.assertTrue(all(item["tool"] == "trivy" for item in findings))

    def test_dependency_finding_carries_fix_cvss_and_stable_fingerprint(self):
        lodash = next(item for item in parse_trivy(self.payload, {"kev": {}, "epss": {}})
                      if item["package"] and item["package"]["name"] == "lodash" and item["rule_id"] == "CVE-2021-23337")
        self.assertEqual(lodash["package"]["fixed_version"], "4.17.21")
        self.assertEqual(lodash["advisory"]["cvss_score"], 7.2)
        self.assertEqual(lodash["severity"], "high")
        self.assertIn("de 4.17.20 a 4.17.21", lodash["remediation"])
        self.assertEqual(lodash["cve"], ["CVE-2021-23337"])
        # Misma huella que produciría el camino OSV para el mismo aviso: no duplica tickets entre motores.
        from tamandua.modules.intel.advisories import fingerprint
        self.assertEqual(lodash["fingerprint"], fingerprint("sca", "CVE-2021-23337", "npm", "lodash", "4.17.20"))

    def test_kev_and_epss_enrich_priority(self):
        feeds = {"kev": {"CVE-2021-23337": {"date_added": "2021-12-01", "ransomware": False}}, "epss": {"CVE-2021-23337": (0.42, 0.97)}}
        lodash = next(item for item in parse_trivy(self.payload, feeds) if item["rule_id"] == "CVE-2021-23337")
        self.assertEqual(lodash["priority"]["action"], "act")
        self.assertEqual(lodash["epss"], {"score": 0.42, "percentile": 0.97})

    def test_misconfiguration_has_line_and_resolution(self):
        latest = next(item for item in parse_trivy(self.payload, {}) if item["scanner"] == "iac" and item["rule_id"] == "DS-0001")
        self.assertEqual(latest["path"], "Dockerfile")
        self.assertEqual(latest["line"], 1)
        self.assertIn("tag", latest["remediation"].lower())
        self.assertEqual(latest["owasp"], ["A02:2025"])

    def test_secret_value_is_never_stored(self):
        secret = next(item for item in parse_trivy(self.payload, {}) if item["scanner"] == "secrets")
        serialized = json.dumps(secret)
        self.assertNotIn("ghp_", serialized)
        self.assertNotIn("Match", serialized)
        self.assertEqual(secret["path"], "config.py")
        self.assertEqual(secret["cwe"], [798])

    def test_pick_fixed_chooses_the_next_version_above_installed(self):
        self.assertEqual(_pick_fixed("1.16.0, 0.30.2", "1.9.0"), "1.16.0")
        self.assertEqual(_pick_fixed("4.17.21", "4.17.20"), "4.17.21")
        self.assertIsNone(_pick_fixed("", "1.0.0"))


class GitleaksParserTests(unittest.TestCase):
    def test_finding_keeps_location_and_drops_the_value(self):
        payload = json.loads((FIXTURES / "gitleaks.json").read_text(encoding="utf-8"))
        findings = parse_gitleaks(payload)
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual((finding["rule_id"], finding["path"], finding["line"]), ("slack-bot-token", "config.py", 4))
        self.assertEqual(finding["severity"], "high")
        # El valor no viaja: ni las claves crudas de gitleaks ni el token, ni siquiera redactado.
        self.assertFalse({"Secret", "Match", "Fingerprint"} & set(finding))
        serialized = json.dumps(finding)
        for forbidden in ("REDACTED", "xoxb"):
            self.assertNotIn(forbidden, serialized)

    def test_same_secret_from_two_engines_is_one_finding(self):
        a = parse_gitleaks(json.loads((FIXTURES / "gitleaks.json").read_text(encoding="utf-8")))
        b = [{**a[0], "tool": "trivy", "fingerprint": "otra"}]
        merged = merge_secrets(a, b)
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["also_detected_by"], ["trivy"])


class OpengrepParserTests(unittest.TestCase):
    def setUp(self):
        self.payload = json.loads((FIXTURES / "opengrep.json").read_text(encoding="utf-8"))

    def test_all_seven_languages_yield_findings_with_metadata(self):
        findings = parse_opengrep(self.payload)
        languages = {item["rule_id"].split(".")[1] for item in findings}
        self.assertEqual(languages, {"js", "py", "java", "go", "php", "rb", "cs"})
        self.assertTrue(all(item["rule_id"].startswith("appsec.") for item in findings))
        self.assertTrue(all(item["cwe"] for item in findings), "toda regla propia declara CWE")

    def test_severity_mapping_and_critical_override(self):
        findings = parse_opengrep(self.payload)
        eval_js = next(item for item in findings if item["rule_id"] == "appsec.js.eval-non-literal")
        self.assertEqual(eval_js["severity"], "critical")
        self.assertEqual(eval_js["priority"]["action"], "act")
        weak = next(item for item in findings if item["rule_id"] == "appsec.js.weak-hash")
        self.assertEqual(weak["severity"], "low")
        self.assertEqual(eval_js["path"], "app.js")

    def test_fingerprint_follows_the_snippet_not_the_line(self):
        result = next(item for item in self.payload["results"] if item["check_id"].endswith("js.eval-non-literal"))
        moved = {**result, "start": {**result["start"], "line": result["start"]["line"] + 40}}
        original = parse_opengrep({"results": [result]})[0]["fingerprint"]
        shifted = parse_opengrep({"results": [moved]})[0]["fingerprint"]
        self.assertEqual(original, shifted)


class RunnerTests(unittest.TestCase):
    def test_without_docker_each_engine_declares_not_tested_and_never_runs(self):
        with patch.dict(scanners._docker_state, {"ok": False}), \
                patch("tamandua.modules.scanning.engines._run", side_effect=AssertionError("lanzó un contenedor")):
            for runner in (lambda: scanners.run_opengrep(Path(".")), lambda: scanners.run_gitleaks(Path(".")),
                           lambda: scanners.run_trivy(Path("."), Path("/tmp/x"), {})):
                result = runner()
                self.assertEqual(result["status"], "not_tested")
                self.assertIn("Docker", result["detail"])
                self.assertEqual(result["findings"], [])


if __name__ == "__main__":
    unittest.main()


class DevDependencyTests(unittest.TestCase):
    def test_dev_dependencies_are_included_marked_and_deprioritized(self):
        from tamandua.modules.scanning.engines import parse_trivy
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        def vuln(name, pkg_id):
            return {"VulnerabilityID": f"CVE-2026-{len(name)}000", "PkgID": pkg_id, "PkgName": name, "InstalledVersion": "1.0.0",
                    "FixedVersion": "1.0.1", "Severity": "CRITICAL", "CVSS": {"nvd": {"V3Vector": vector}}, "Title": name}
        payload = {"Results": [{"Target": "pnpm-lock.yaml", "Type": "pnpm", "Class": "lang-pkgs",
                                "Packages": [{"ID": "postcss@1.0.0", "Name": "postcss", "Dev": True, "Relationship": "indirect"},
                                             {"ID": "express@1.0.0", "Name": "express", "Relationship": "direct"}],
                                "Vulnerabilities": [vuln("postcss", "postcss@1.0.0"), vuln("express", "express@1.0.0")]}]}
        by_name = {item["package"]["name"]: item for item in parse_trivy(payload, {})}
        self.assertTrue(by_name["postcss"]["package"]["dev"])
        # Crítica sin KEV ni EPSS alto: «atender» en producción, un nivel menos por ser de desarrollo.
        self.assertEqual((by_name["express"]["priority"]["action"], by_name["postcss"]["priority"]["action"]), ("attend", "track"))
        self.assertIn("desarrollo", " ".join(by_name["postcss"]["priority"]["factors"]))
        self.assertFalse(by_name["express"]["package"]["dev"])
        self.assertTrue(by_name["express"]["package"]["direct"])
        # Con EPSS alto, «actuar ya» baja a «atender»; en CISA KEV no se rebaja aunque sea de desarrollo.
        epss = {"epss": {"CVE-2026-7000": (0.5, 0.99)}}
        self.assertEqual({item["package"]["name"]: item for item in parse_trivy(payload, epss)}["postcss"]["priority"]["action"], "attend")
        kev = {"kev": {"CVE-2026-7000": {"date_added": "2026-09-01"}}}
        self.assertEqual({item["package"]["name"]: item for item in parse_trivy(payload, kev)}["postcss"]["priority"]["action"], "act")
