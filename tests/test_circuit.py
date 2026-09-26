import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from tamandua.cli.main import main as cli_main
from tamandua.modules.lab.engine import ProbeError, scan_fixture
from tamandua.modules.lab.fixture import FixtureError, verify_fixture
from tamandua.modules.lab.runs import save_run, save_scan
from tamandua.modules.runs.store import list_runs, load_run


FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "tenant-api-lab"


class CircuitTests(unittest.TestCase):
    def test_ground_truth_and_persistence(self):
        evaluation = verify_fixture(FIXTURE)
        self.assertEqual(len(evaluation["cases"]), 10)
        self.assertTrue(all(case["passed"] for case in evaluation["cases"]))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            saved = save_run(root, evaluation)
            self.assertEqual(saved["status"], "completed")
            self.assertEqual(saved["summary"]["vulnerable_variants"], 5)
            self.assertEqual(saved["summary"]["fixed_controls"], 5)
            self.assertEqual(load_run(root, saved["id"]), saved)
            self.assertEqual(len(list_runs(root)), 1)
            report = (root / "runs" / saved["id"] / "report.md").read_text()
            self.assertIn("no se descubrieron hallazgos nuevos", report)
            self.assertIn("SQLI-F", report)

    def test_modified_fixture_is_rejected_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("app.py", "cases.json"):
                (root / name).write_bytes((FIXTURE / name).read_bytes())
            (root / "app.py").write_text("raise RuntimeError('no ejecutar')\n")
            with self.assertRaisesRegex(FixtureError, "app.py"):
                verify_fixture(root)

    def test_run_id_does_not_escape_data_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                load_run(Path(directory), "../../etc/passwd")

    def test_scan_detects_five_and_reproduces_in_fresh_process(self):
        vulnerable = scan_fixture(FIXTURE, "vulnerable")
        fixed = scan_fixture(FIXTURE, "fixed")
        self.assertEqual(vulnerable["summary"]["confirmed"], 5)
        self.assertEqual(vulnerable["summary"]["executed"], 5)
        self.assertEqual(fixed["summary"]["confirmed"], 0)
        self.assertEqual(fixed["summary"]["no_issue_observed"], 5)
        self.assertEqual(len(vulnerable["owasp_coverage"]), 10)
        self.assertEqual({item["id"] for item in vulnerable["owasp_coverage"] if item["status"] == "partial"}, {"A01", "A05"})
        self.assertEqual({finding["rule_id"] for finding in vulnerable["findings"]},
                         {"BOLA", "BFLA", "EXPOSURE", "MASS", "SQLI"})
        for finding in vulnerable["findings"]:
            self.assertEqual([attempt["phase"] for attempt in finding["evidence"]],
                             ["discovery", "verification"])
        self.assertNotIn("1111", json.dumps(vulnerable))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            saved = save_scan(root, vulnerable)
            sarif = json.loads((root / "runs" / saved["id"] / "findings.sarif").read_text())
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertEqual(len(sarif["runs"][0]["results"]), 5)
            self.assertEqual(load_run(root, saved["id"])["summary"]["confirmed"], 5)
            self.assertEqual(list_runs(root)[0]["variant"], "vulnerable")
            self.assertIn("BOLA", (root / "runs" / saved["id"] / "report.md").read_text())
            self.assertIn("A10 · Mishandling of Exceptional Conditions", (root / "runs" / saved["id"] / "report.md").read_text())

    def test_scan_does_not_need_ground_truth_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "tenant-api-lab"
            root.mkdir()
            (root / "app.py").write_bytes((FIXTURE / "app.py").read_bytes())
            self.assertEqual(scan_fixture(root, "fixed")["summary"]["no_issue_observed"], 5)

    def test_worker_error_marks_coverage_incomplete(self):
        with patch("tamandua.modules.lab.engine._run_probe", side_effect=ProbeError("fallo controlado")):
            result = scan_fixture(FIXTURE, "fixed")
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["summary"]["needs_follow_up"], 5)
        self.assertEqual(result["summary"]["confirmed"], 0)
        self.assertEqual({item["status"] for item in result["owasp_coverage"] if item["id"] in ("A01", "A05")}, {"inconclusive"})
        with tempfile.TemporaryDirectory() as directory:
            saved = save_scan(Path(directory), result)
            report = (Path(directory) / "runs" / saved["id"] / "report.md").read_text()
            self.assertIn("pruebas pendientes de completar", report)

    def test_cli_returns_distinct_codes_for_findings_and_clean_control(self):
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(StringIO()):
            root = Path(directory)
            self.assertEqual(cli_main(["--data-dir", str(root), "scan-fixture", "--variant", "fixed"]), 0)
            self.assertEqual(cli_main(["--data-dir", str(root), "scan-fixture", "--variant", "vulnerable"]), 2)
            self.assertEqual([run["variant"] for run in list_runs(root)], ["vulnerable", "fixed"])


if __name__ == "__main__":
    unittest.main()
