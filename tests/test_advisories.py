"""Contrato del enriquecimiento de avisos: CVSS calculado, fix correcto, prioridad explicable."""

import gzip
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from appsec_agent import advisories
from appsec_agent.advisories import (affected_range, compare_versions, cvss3_base_score, dependency_finding,
                                      fetch_advisory, prioritize, severity_from_score)

MINIMATCH = {
    "id": "GHSA-23c5-xmqv-rm74", "aliases": ["CVE-2026-27904"],
    "summary": "minimatch ReDoS: nested *() extglobs generate catastrophically backtracking regular expressions",
    "details": "Detalle largo del aviso.",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
    "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-1333"]},
    "affected": [
        {"package": {"ecosystem": "npm", "name": "minimatch"},
         "ranges": [{"type": "SEMVER", "events": [{"introduced": "9.0.0"}, {"fixed": "9.0.6"}]}]},
        {"package": {"ecosystem": "npm", "name": "minimatch"},
         "ranges": [{"type": "SEMVER", "events": [{"introduced": "10.0.0"}, {"fixed": "10.2.3"}]}]},
        {"package": {"ecosystem": "PyPI", "name": "minimatch"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "99.0"}]}]},
    ],
    "references": [{"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-23c5-xmqv-rm74"},
                   {"type": "WEB", "url": "http://inseguro.example"}],
    "published": "2026-02-26T22:07:15Z", "modified": "2026-03-01T00:00:00Z",
}


class CvssTests(unittest.TestCase):
    def test_base_score_matches_the_specification(self):
        # Valores publicados por NVD para estos vectores.
        cases = {"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H": 7.5,
                 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
                 "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N": 6.4,
                 "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
                 "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N": 1.8,
                 "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0.0}
        for vector, expected in cases.items():
            with self.subTest(vector=vector):
                self.assertEqual(cvss3_base_score(vector), expected)
        for bad in ("CVSS:4.0/AV:N/AC:L", "AV:N/AC:L", "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"):
            with self.subTest(vector=bad):
                self.assertIsNone(cvss3_base_score(bad))

    def test_severity_uses_the_score_and_falls_back_to_the_label(self):
        self.assertEqual(severity_from_score(9.8), "critical")
        self.assertEqual(severity_from_score(7.0), "high")
        self.assertEqual(severity_from_score(4.0), "medium")
        self.assertEqual(severity_from_score(0.1), "low")
        self.assertEqual(severity_from_score(None, "MODERATE"), "medium")
        self.assertEqual(severity_from_score(None, "CRITICAL"), "critical")
        self.assertEqual(severity_from_score(None, None), "medium")


class VersionTests(unittest.TestCase):
    def test_lenient_comparison_handles_semver_and_pep440(self):
        self.assertLess(compare_versions("9.0.5", "9.0.6"), 0)
        self.assertLess(compare_versions("9.0.5", "10.2.3"), 0)
        self.assertLess(compare_versions("1.0.0-rc1", "1.0.0"), 0)
        self.assertGreater(compare_versions("1.0.0.post1", "1.0.0"), 0)
        self.assertEqual(compare_versions("v2.1", "2.1.0"), 0)

    def test_fixed_version_comes_from_the_installed_version_line(self):
        # Quien usa 9.0.5 debe oír "9.0.6", no "10.2.3".
        self.assertEqual(affected_range(MINIMATCH, "npm", "minimatch", "9.0.5"), {"introduced": "9.0.0", "fixed": "9.0.6"})
        self.assertEqual(affected_range(MINIMATCH, "npm", "minimatch", "10.1.0")["fixed"], "10.2.3")
        # Sin rango que contenga la versión, se ofrece la siguiente corrección disponible.
        self.assertEqual(affected_range(MINIMATCH, "npm", "minimatch", "8.0.0")["fixed"], "9.0.6")
        # Otro ecosistema con el mismo nombre no contamina.
        self.assertEqual(affected_range(MINIMATCH, "npm", "otro", "9.0.5"), {"introduced": "0", "fixed": None})


class PriorityTests(unittest.TestCase):
    def test_kev_forces_action_and_factors_are_visible(self):
        result = prioritize("medium", 5.0, {"ransomware": True}, (0.01, 0.5), "1.2.3")
        self.assertEqual(result["action"], "act")
        self.assertTrue(any("KEV" in factor and "ransomware" in factor for factor in result["factors"]))
        self.assertTrue(any("Corrección publicada: 1.2.3" in factor for factor in result["factors"]))

    def test_thresholds_without_kev(self):
        self.assertEqual(prioritize("critical", 9.8, None, (0.5, 0.99), None)["action"], "act")
        self.assertEqual(prioritize("high", 7.5, None, (0.007, 0.5), "1.0")["action"], "attend")
        self.assertEqual(prioritize("medium", 5.0, None, (0.08, 0.9), "1.0")["action"], "attend")
        result = prioritize("low", 3.1, None, None, None)
        self.assertEqual(result["action"], "track")
        self.assertIn("Sin versión corregida publicada", result["factors"])


class FindingTests(unittest.TestCase):
    def test_dependency_finding_is_actionable_and_stable_across_paths(self):
        dependency = {"ecosystem": "npm", "name": "minimatch", "version": "9.0.5", "path": "package-lock.json"}
        feeds = {"kev": {}, "epss": {"CVE-2026-27904": (0.0067, 0.51)}}
        finding = dependency_finding(dependency, MINIMATCH, feeds)
        self.assertEqual(finding["severity"], "high")
        self.assertEqual(finding["package"]["fixed_version"], "9.0.6")
        self.assertIn("minimatch 9.0.5:", finding["title"])
        self.assertIn("de 9.0.5 a 9.0.6", finding["remediation"])
        self.assertEqual(finding["cve"], ["CVE-2026-27904"])
        self.assertEqual(finding["ghsa"], ["GHSA-23c5-xmqv-rm74"])
        self.assertEqual(finding["cwe"], [1333])
        self.assertEqual(finding["epss"], {"score": 0.0067, "percentile": 0.51})
        self.assertEqual(finding["priority"]["action"], "attend")
        # Solo referencias https: una URL http no entra en el reporte.
        self.assertEqual(finding["advisory"]["references"], ["https://github.com/advisories/GHSA-23c5-xmqv-rm74"])
        moved = dependency_finding({**dependency, "path": "apps/web/package-lock.json"}, MINIMATCH, feeds)
        # Mover el lockfile no debe abrir un ticket nuevo en Jira.
        self.assertEqual(moved["fingerprint"], finding["fingerprint"])
        other = dependency_finding({**dependency, "version": "9.0.4"}, MINIMATCH, feeds)
        self.assertNotEqual(other["fingerprint"], finding["fingerprint"])

    def test_kev_match_uses_the_cve_alias(self):
        dependency = {"ecosystem": "npm", "name": "minimatch", "version": "9.0.5", "path": "package-lock.json"}
        feeds = {"kev": {"CVE-2026-27904": {"date_added": "2026-03-01", "ransomware": False}}, "epss": {}}
        finding = dependency_finding(dependency, MINIMATCH, feeds)
        self.assertEqual(finding["priority"]["action"], "act")
        self.assertEqual(finding["kev"]["date_added"], "2026-03-01")


class FeedTests(unittest.TestCase):
    def test_feeds_parse_and_are_served_from_cache_without_network(self):
        kev = {"catalogVersion": "2026.09.22", "count": 1,
               "vulnerabilities": [{"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10", "dueDate": "2021-12-24",
                                    "knownRansomwareCampaignUse": "Known", "vulnerabilityName": "Log4Shell"}]}
        epss = gzip.compress(b"#model_version:v2026.06.15,score_date:2026-09-22\ncve,epss,percentile\nCVE-2021-44228,0.99999,1.0\n")
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary)
            (data_dir / "feeds").mkdir()
            (data_dir / "feeds" / "kev.json").write_text(json.dumps(kev), encoding="utf-8")
            (data_dir / "feeds" / "epss.csv.gz").write_bytes(epss)
            advisories._feed_cache.clear()
            with patch("appsec_agent.advisories.urlopen", side_effect=AssertionError("salió a la red con caché fresca")):
                feeds = advisories.load_feeds(data_dir)
        self.assertTrue(feeds["kev"]["CVE-2021-44228"]["ransomware"])
        self.assertEqual(feeds["kev"]["__meta__"]["version"], "2026.09.22")
        self.assertEqual(feeds["epss"]["CVE-2021-44228"], (0.99999, 1.0))

    def test_invalid_identifier_never_reaches_the_network(self):
        with patch("appsec_agent.advisories.urlopen", side_effect=AssertionError("consultó OSV")):
            self.assertIsNone(fetch_advisory("../etc/passwd"))
            self.assertIsNone(fetch_advisory("x"))


if __name__ == "__main__":
    unittest.main()
