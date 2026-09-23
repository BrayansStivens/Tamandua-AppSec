"""El paso «Revisar y lanzar» sale de datos reales: lenguajes del árbol, motores disponibles y manifiestos."""

import unittest
from unittest.mock import patch

from appsec_agent import scan_plan

FILES = ["app/main.py", "app/models.py", "web/src/App.tsx", "crates/core/src/lib.rs", "node_modules/x/index.js",
         "pyproject.toml", "uv.lock", "web/package-lock.json", "Dockerfile", "infra/main.tf", "README.md"]


class PlanTests(unittest.TestCase):
    def plan(self, available: bool):
        with patch("appsec_agent.scan_plan.files_of", return_value=FILES), \
                patch("appsec_agent.scan_plan.docker_available", return_value=available), \
                patch("appsec_agent.scan_plan.image_available", return_value=available):
            return scan_plan.plan("github:o/r", installation_id=7)

    def test_languages_rules_manifests_and_iac(self):
        result = self.plan(True)
        languages = {item["name"]: item for item in result["languages"]}
        self.assertEqual(languages["Python"]["files"], 2)
        self.assertGreater(languages["TypeScript"]["rules"], 0)
        self.assertEqual(languages["Rust"]["rules"], 0)
        self.assertNotIn("JavaScript", languages)  # node_modules no cuenta
        self.assertEqual(result["manifests"], ["uv.lock", "web/package-lock.json"])
        self.assertEqual(result["iac"], ["Dockerfile", "infra/main.tf"])
        self.assertTrue(any("Opengrep" in item and "Python (14 reglas, 2 ficheros)" in item for item in result["runs"]))
        self.assertTrue(any(item.startswith("Sin reglas SAST propias para Rust (1 fichero)") for item in result["skips"]))
        self.assertFalse(result["osv_needed"])

    def test_without_engines_it_says_so_and_offers_osv(self):
        result = self.plan(False)
        self.assertTrue(result["osv_needed"])
        self.assertTrue(any("solo para Python" in item for item in result["runs"]))
        self.assertTrue(any("TypeScript" in item for item in result["skips"]))


if __name__ == "__main__":
    unittest.main()
