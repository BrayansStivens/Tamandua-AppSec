"""Cada aviso de dependencias lleva su fuente y su licencia, y los informes la atribuyen."""

import json
import unittest
from pathlib import Path

from appsec_agent import data_sources
from appsec_agent.dependency_merge import merge_dependencies
from appsec_agent.scanners import parse_osv_scanner, parse_trivy
from appsec_agent.store import _sources_section

OUTPUTS = Path(__file__).resolve().parent / "engine-outputs"


class DataSourceTests(unittest.TestCase):
    def test_each_engine_names_its_source(self):
        trivy = [item for item in parse_trivy(json.loads((OUTPUTS / "trivy-deps.json").read_text()), {}) if item["scanner"] == "sca"]
        self.assertTrue(trivy and all(item["source"]["id"] == "ghsa" and item["source"]["license"] == "CC BY 4.0" for item in trivy))
        self.assertTrue(trivy[0]["source"]["url"].startswith("https://github.com/advisories"))  # el enlace concreto que da Trivy
        osv = parse_osv_scanner(json.loads((OUTPUTS / "osv-scanner.json").read_text()), {})
        self.assertTrue(osv and all(item["source"]["id"] == "ghsa" for item in osv))
        self.assertEqual(data_sources.from_osv("PYSEC-2024-1")["id"], "pypa")
        self.assertEqual(data_sources.from_osv("RUSTSEC-2024-0001")["license"], "CC0 1.0")
        self.assertEqual(data_sources.from_osv("MAL-2024-1")["id"], "ossf-malicious")

    def test_non_commercial_and_unknown_sources_are_flagged(self):
        wolfi = data_sources.from_grype({"namespace": "wolfi:distro:wolfi:rolling", "dataSource": "https://packages.wolfi.dev/os/security.json"})
        self.assertEqual((wolfi["id"], wolfi["terms"], wolfi["license"]), ("wolfi", "non-commercial", "CC BY-NC-ND 4.0"))
        self.assertEqual(data_sources.from_grype({"namespace": "sles:distro:sles:15"})["id"], "suse-cvrf")
        self.assertEqual(data_sources.from_trivy({"DataSource": {"ID": "redhat-csaf-vex"}})["name"], "Red Hat Security Data")
        unknown = data_sources.describe("nueva-fuente", url="javascript:alert(1)", name="Nueva")
        self.assertEqual((unknown["terms"], unknown["url"]), ("unclear", ""))  # solo enlaces https
        self.assertIsNone(data_sources.from_trivy({}))

    def test_merging_engines_keeps_a_source(self):
        primary = {"scanner": "sca", "tool": "trivy", "rule_id": "CVE-1", "cve": ["CVE-1"], "ghsa": [], "confidence": 6,
                   "package": {"ecosystem": "npm", "name": "a", "version": "1.0"}, "advisory": {"id": "CVE-1", "aliases": []}}
        other = {**primary, "tool": "osv-scanner", "source": data_sources.describe("ghsa"), "package": dict(primary["package"])}
        merged, _ = merge_dependencies([dict(primary)], ("osv-scanner", [other]))
        self.assertEqual(merged[0]["source"]["id"], "ghsa")

    def test_reports_attribute_every_source_used(self):
        findings = [{"scanner": "sca", "source": data_sources.describe("ghsa"), "kev": {"date_added": "2026-01-01"}, "epss": {"score": 0.1}},
                    {"scanner": "sca", "source": data_sources.describe("ghsa")},
                    {"scanner": "sca", "source": data_sources.describe("alpine")}]
        lines = data_sources.attribution(findings)
        self.assertIn("GitHub Advisory Database: CC BY 4.0 (requiere atribución) · 2 avisos · https://github.com/advisories", lines)
        self.assertTrue(any(line.startswith("Alpine secdb: CC BY-SA 4.0") for line in lines))
        self.assertIn("This product uses the NVD API but is not endorsed or certified by the NVD.", lines)
        self.assertTrue(any("KEV" in line for line in lines) and any("EPSS" in line for line in lines))
        self.assertEqual(_sources_section([]), [])  # sin avisos, nada que atribuir
        self.assertIn("- Alpine secdb: CC BY-SA 4.0 (atribución y compartir igual) · 1 aviso · https://secdb.alpinelinux.org",
                      _sources_section(findings))


if __name__ == "__main__":
    unittest.main()
