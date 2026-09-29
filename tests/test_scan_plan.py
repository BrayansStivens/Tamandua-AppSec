"""The "Review and launch" step comes from real data: the tree's languages, the available engines and manifests."""

import unittest
from unittest.mock import patch

from tamandua.modules.scanning import plan as scan_plan
from tamandua.shared.i18n import localize

FILES = ["app/main.py", "app/models.py", "web/src/App.tsx", "crates/core/src/lib.rs", "node_modules/x/index.js",
         "pyproject.toml", "uv.lock", "web/package-lock.json", "Dockerfile", "infra/main.tf", "README.md"]


class PlanTests(unittest.TestCase):
    def plan(self, available: bool):
        with patch("tamandua.modules.scanning.plan.files_of", return_value=FILES), \
                patch("tamandua.modules.scanning.plan.engine_ready", return_value=available):
            return localize(scan_plan.plan("github:o/r", installation_id=7))

    def test_languages_rules_manifests_and_iac(self):
        result = self.plan(True)
        languages = {item["name"]: item for item in result["languages"]}
        self.assertEqual(languages["Python"]["files"], 2)
        self.assertGreater(languages["TypeScript"]["rules"], 0)
        self.assertEqual(languages["Rust"]["rules"], 0)
        self.assertNotIn("JavaScript", languages)  # node_modules doesn't count
        self.assertEqual(result["manifests"], ["pyproject.toml", "uv.lock", "web/package-lock.json"])
        self.assertEqual(result["iac"], ["Dockerfile", "infra/main.tf"])
        self.assertTrue(any("Opengrep" in item and "Python (14 reglas, 2 archivos)" in item for item in result["runs"]))
        self.assertTrue(any(item.startswith("Sin reglas SAST de Tamandua para Rust (1 archivo)") for item in result["skips"]))
        self.assertFalse(result["osv_needed"])

    def test_without_engines_it_says_so_and_offers_osv(self):
        result = self.plan(False)
        self.assertTrue(result["osv_needed"])
        self.assertTrue(any("solo para Python" in item for item in result["runs"]))
        self.assertTrue(any("TypeScript" in item for item in result["skips"]))


if __name__ == "__main__":
    unittest.main()
