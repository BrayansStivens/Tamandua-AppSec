"""Avisos publicados después de un análisis: se detectan a diario, sin reanalizar y sin duplicar."""

import json
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from appsec_agent import advisory_watch, findings_registry
from appsec_agent.store import list_runs, save_repository_scan
from test_dashboard import _finding, _scan

OSV_OUTPUT = (Path(__file__).resolve().parent / "engine-outputs" / "osv-scanner.json").read_text()
DEPENDENCIES = [{"ecosystem": "nuget", "name": "Newtonsoft.Json", "version": "12.0.1", "path": "api/packages.lock.json"},
                {"ecosystem": "pip", "name": "requests", "version": "2.25.0", "path": "py/requirements.txt"},
                {"ecosystem": "pip", "name": "starlette", "version": "0.27.0", "path": "py/requirements.txt"},
                {"ecosystem": "npm", "name": "@scope/lib", "version": "1.0.0", "path": "web/package-lock.json"},
                {"ecosystem": "jar", "name": "org.acme:core", "version": "2.1", "path": "pom.xml"}]


def engine(calls):
    def run(key, arguments, snapshot, **kwargs):
        calls.append((key, arguments, json.loads((Path(snapshot) / "bom.cdx.json").read_text())))
        return subprocess.CompletedProcess(arguments, 1, OSV_OUTPUT, "")
    return run


class AdvisoryWatchTests(unittest.TestCase):
    def test_purls_cover_each_ecosystem(self):
        self.assertEqual([advisory_watch.purl(item) for item in DEPENDENCIES],
                         ["pkg:nuget/Newtonsoft.Json@12.0.1", "pkg:pypi/requests@2.25.0", "pkg:pypi/starlette@0.27.0",
                          "pkg:npm/%40scope/lib@1.0.0", "pkg:maven/org.acme/core@2.1"])
        self.assertIsNone(advisory_watch.purl({"ecosystem": "debian", "name": "openssl", "version": "1.1"}))  # SO: no entra

    def test_new_advisories_are_opened_once_and_the_next_full_scan_decides(self):
        with tempfile.TemporaryDirectory() as folder:
            data = Path(folder)
            # Un análisis completo que ya conocía un aviso de requests (con otro identificador, el CVE).
            known = {**_finding("k" * 64, "medium", package="requests"), "rule_id": "CVE-2023-32681", "cve": ["CVE-2023-32681"],
                     "path": "py/requirements.txt", "package": {"ecosystem": "pip", "name": "requests", "version": "2.25.0", "fixed_version": "2.31.0"},
                     "advisory": {"id": "CVE-2023-32681", "aliases": ["GHSA-j8r2-6x86-q33q"]}}
            base = save_repository_scan(data, {**_scan("acme/api", [known], "2026-09-20"), "dependencies": DEPENDENCIES,
                                               "created_at": "2026-09-20T10:00:00+00:00"})
            calls = []
            result = advisory_watch.check(data, run=engine(calls), now=datetime(2026, 9, 25, tzinfo=timezone.utc))
            self.assertEqual(calls[0][0], "osv-scanner")
            self.assertIn("--offline-vulnerabilities", calls[0][1])  # la lista de dependencias no sale de aquí
            self.assertEqual(len(calls[0][2]["components"]), 5)
            watch = [row for row in list_runs(data) if row["type"] == "advisory_watch"]
            self.assertEqual(len(watch), 1)
            opened = result["opened"]
            self.assertEqual(opened, 11)  # 12 avisos del motor menos el que ya estaba (GHSA-j8r2 = CVE-2023-32681)
            state = findings_registry.load(data, "github:acme/api")["findings"]
            fresh = [entry for entry in state.values() if entry["origin"].get("kind") == "advisory"]
            self.assertEqual(len(fresh), 11)
            self.assertFalse(any("GHSA-j8r2-6x86-q33q" in {entry["finding"]["rule_id"], *entry["finding"]["advisory"]["aliases"]} for entry in fresh))
            self.assertTrue(all(entry["finding"]["path"] in ("py/requirements.txt", "api/packages.lock.json") for entry in fresh))
            # Otra pasada con la misma base: nada nuevo.
            self.assertEqual(advisory_watch.check(data, run=engine(calls))["opened"], 0)
            self.assertEqual(len([row for row in list_runs(data) if row["type"] == "advisory_watch"]), 1)
            # El siguiente análisis completo manda: lo que ya no aparece (se actualizó la dependencia) queda remediado.
            save_repository_scan(data, {**_scan("acme/api", [], "2026-09-26"), "dependencies": [], "created_at": "2026-09-26T10:00:00+00:00"})
            state = findings_registry.load(data, "github:acme/api")["findings"]
            self.assertTrue(all(entry["status"] == "fixed" for entry in state.values()))
            self.assertEqual(base["type"], "repository_scan")

    def test_nothing_runs_without_saved_dependencies_or_when_the_engine_fails(self):
        with tempfile.TemporaryDirectory() as folder:
            data = Path(folder)
            save_repository_scan(data, _scan("acme/old", [], "2026-09-01"))  # análisis anterior a la lista de paquetes
            calls = []
            self.assertEqual(advisory_watch.check(data, run=engine(calls)), {"checked": 0, "opened": 0, "failed": 0})
            self.assertEqual(calls, [])
            save_repository_scan(data, {**_scan("acme/new", [], "2026-09-02"), "dependencies": DEPENDENCIES})
            broken = lambda *args, **kwargs: subprocess.CompletedProcess(args, 2, "", "boom")
            self.assertEqual(advisory_watch.check(data, run=broken)["failed"], 1)
            self.assertIsNotNone(advisory_watch.load_state(data).get("last_run"))


if __name__ == "__main__":
    unittest.main()
