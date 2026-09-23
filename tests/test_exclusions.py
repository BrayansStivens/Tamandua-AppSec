"""Rutas excluidas por repositorio: patrones, efecto en ejecuciones y registro, y quién puede cambiarlas."""

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from appsec_agent import exclusions, findings_registry
from appsec_agent.auth import Users
from appsec_agent.store import save_repository_scan
from test_auth import PASSWORD, HttpCase
from test_dashboard import _finding, _scan

ADMIN = {"username": "operadora", "role": "admin"}
KEY = "github#7"
QUERY_KEY = "github%237"  # «#» empezaría el fragmento de la URL


def located(fingerprint, path, severity="high"):
    return {**_finding(fingerprint, severity), "path": path, "scanner": "sast"}


def scan(findings, when):
    record = _scan("org/app", findings, when)
    record["source"].update(uid=KEY)
    record["summary"]["sast"] = len(findings)
    return record


class PatternTests(unittest.TestCase):
    def test_hostile_or_overbroad_patterns_are_rejected(self):
        for bad in (["../etc"], ["/abs"], ["**"], ["*"], ["*/**"], ["a;b"], ["x" * 300], ["fixtures", 3], "fixtures/**",
                    ["./a"], [f"d{index}/**" for index in range(51)]):
            with self.subTest(bad=bad), self.assertRaises(exclusions.ExclusionError):
                exclusions.normalize(bad)
        self.assertEqual(exclusions.normalize(["fixtures/", " docs/*.md ", "fixtures/**", ""]), ["fixtures/**", "docs/*.md"])
        self.assertEqual(exclusions.normalize(["a/**/**/**/b", "c/****"]), ["a/**/b", "c/**"])

    def test_glob_semantics(self):
        active = ["fixtures/**", "docs/*.md", "**/testdata/**"]
        self.assertEqual(exclusions.excluded("fixtures/sast-samples/app.py", active), "fixtures/**")
        self.assertEqual(exclusions.excluded("docs/intro.md", active), "docs/*.md")
        self.assertIsNone(exclusions.excluded("docs/deep/intro.md", active))  # «*» no cruza «/»
        self.assertEqual(exclusions.excluded("pkg/api/testdata/x.json", active), "**/testdata/**")
        self.assertEqual(exclusions.excluded("testdata/x.json", active), "**/testdata/**")
        self.assertIsNone(exclusions.excluded("src/fixtures/app.py", active))
        self.assertEqual(exclusions.excluded(".github/workflows/ci.yml", [".github/**"]), ".github/**")

    def test_reason_is_mandatory_and_history_is_kept(self):
        with tempfile.TemporaryDirectory() as folder:
            data_dir = Path(folder)
            with self.assertRaises(exclusions.ExclusionError):
                exclusions.save(data_dir, KEY, ["fixtures/**"], reason="", user=ADMIN)
            exclusions.save(data_dir, KEY, ["fixtures/**"], reason="Ejemplos vulnerables a propósito", user=ADMIN)
            saved = exclusions.save(data_dir, KEY, [], reason=None, user=ADMIN)
            self.assertEqual(saved["patterns"], [])
            self.assertEqual([item["patterns"] for item in saved["history"]], [["fixtures/**"], []])


class RecordAndRegistryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.directory.name)
        self.now = datetime.now(timezone.utc)
        self.findings = [located("a" * 64, "fixtures/vuln.py", "critical"), located("b" * 64, "app/main.py")]

    def tearDown(self):
        self.directory.cleanup()

    def save(self, minutes):
        return save_repository_scan(self.data_dir, scan([dict(item) for item in self.findings], self.now.isoformat()),
                                    created_at=(self.now + timedelta(minutes=minutes)).isoformat())

    def test_excluded_paths_leave_the_run_but_are_counted(self):
        exclusions.save(self.data_dir, KEY, ["fixtures/**"], reason="Ejemplos vulnerables a propósito", user=ADMIN)
        record = self.save(0)
        self.assertEqual([item["path"] for item in record["findings"]], ["app/main.py"])
        self.assertEqual((record["summary"]["candidates"], record["summary"]["excluded"], record["summary"]["severities"]["critical"]), (1, 1, 0))
        self.assertEqual(record["excluded"]["by_pattern"], {"fixtures/**": 1})
        self.assertTrue(any("fixtures/**" in line for line in record["limitations"]))
        state = findings_registry.summarize(self.data_dir, KEY)
        self.assertEqual((state["open"], state["excluded"], state["fixed"]), (1, 1, 0))
        view = findings_registry.view(self.data_dir, KEY, status="excluded")
        self.assertEqual([item["path"] for item in view["findings"]], ["fixtures/vuln.py"])

    def test_excluding_later_is_not_a_fix_and_including_again_reopens(self):
        self.save(0)
        self.assertEqual(findings_registry.summarize(self.data_dir, KEY)["open"], 2)
        saved = exclusions.save(self.data_dir, KEY, ["fixtures/**"], reason="Ejemplos vulnerables a propósito", user=ADMIN)
        moved = findings_registry.apply_exclusions(self.data_dir, KEY, saved["patterns"], when=saved["at"])
        self.assertEqual(moved, {"excluded": 1, "reopened": 0})
        self.save(5)  # el siguiente escaneo no lo da por remediado
        state = findings_registry.summarize(self.data_dir, KEY)
        self.assertEqual((state["open"], state["excluded"], state["fixed"]), (1, 1, 0))
        exclusions.save(self.data_dir, KEY, [], reason=None, user=ADMIN)
        self.save(10)
        state = findings_registry.summarize(self.data_dir, KEY)
        self.assertEqual((state["open"], state["excluded"], state["fixed"]), (2, 0, 0))

    def test_applying_twice_changes_nothing(self):
        exclusions.save(self.data_dir, KEY, ["fixtures/**"], reason="Ejemplos vulnerables a propósito", user=ADMIN)
        once = exclusions.apply_to_record(self.data_dir, scan(self.findings, self.now.isoformat()), KEY)
        self.assertIs(exclusions.apply_to_record(self.data_dir, once, KEY), once)


class ExclusionApiTests(HttpCase):
    def setUp(self):
        super().setUp()
        Users(self.data_dir).create("operadora", PASSWORD, role="admin")
        Users(self.data_dir).create("analista", PASSWORD)
        save_repository_scan(self.data_dir, scan([located("a" * 64, "fixtures/vuln.py"), located("b" * 64, "app/main.py")],
                                                 datetime.now(timezone.utc).isoformat()))

    def cookie(self, username):
        _, _, cookies = self.post("/api/auth/login", "login", {"username": username, "password": PASSWORD})
        return cookies[0].split("; ")[0]

    def test_only_admins_change_exclusions_and_only_for_real_assets(self):
        body = {"key": KEY, "patterns": ["fixtures/**"], "reason": "Ejemplos vulnerables a propósito"}
        member = self.cookie("analista")
        self.assertEqual(self.post("/api/assets/exclusions", "save-exclusions", body, member)[0], 403)
        self.assertEqual(self.call("GET", f"/api/assets/exclusions?key={QUERY_KEY}", headers={"Cookie": member})[0], 200)
        admin = self.cookie("operadora")
        self.assertEqual(self.post("/api/assets/exclusions", "wrong-action", body, admin)[0], 403)
        self.assertEqual(self.post("/api/assets/exclusions", "save-exclusions", {**body, "key": "github#999"}, admin)[0], 404)
        self.assertEqual(self.post("/api/assets/exclusions", "save-exclusions", {**body, "patterns": ["**"]}, admin)[0], 400)
        self.assertEqual(self.post("/api/assets/exclusions", "save-exclusions", {**body, "extra": 1}, admin)[0], 400)
        self.assertEqual(self.post("/api/assets/exclusions", "save-exclusions", {**body, "key": "github#7\nfalso log"}, admin)[0], 400)
        status, saved, _ = self.post("/api/assets/exclusions", "save-exclusions", body, admin)
        self.assertEqual((status, saved["patterns"], saved["moved"]), (200, ["fixtures/**"], {"excluded": 1, "reopened": 0}))
        status, view, _ = self.call("GET", f"/api/assets/state?key={QUERY_KEY}&status=excluded", headers={"Cookie": admin})
        self.assertEqual((status, len(view["findings"]), view["summary"]["lifecycle"]["excluded"]), (200, 1, 1))


if __name__ == "__main__":
    unittest.main()
