"""`appsec-agent scan`: carpeta local, comparación con la rama base, umbral y códigos de salida."""

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from appsec_agent import local_scan
from appsec_agent.local_scan import EXIT_BLOCKED, EXIT_INCOMPLETE, EXIT_OK, LocalScanError, merge_base, parse_diff, run

GIT = shutil.which("git")


def finding(fingerprint, path, line, severity="high", scanner="sast", package=None):
    return {"fingerprint": fingerprint, "path": path, "line": line, "severity": severity, "scanner": scanner,
            "title": f"Regla {fingerprint}", "rule_id": fingerprint, "reason": "motivo", "cwe": [], "owasp": [],
            "package": package}


def scan_result(findings, status="completed", failed=()):
    steps = [{"id": tool, "name": tool, "status": "inconclusive" if tool in failed else "completed", "detail": "",
              "tool": {"name": tool}} for tool in ("opengrep", "gitleaks", "trivy", "osv-scanner")]
    return {"status": status, "findings": findings, "steps": steps}


@unittest.skipUnless(GIT, "hace falta git")
class GitTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.repo = Path(self.directory.name) / "repo"
        self.repo.mkdir()
        for args in (("init", "-q", "-b", "main"), ("config", "user.email", "t@t"), ("config", "user.name", "t")):
            self.git(*args)
        (self.repo / "app.py").write_text("a = 1\nb = 2\n")
        (self.repo / "requirements.txt").write_text("requests==2.25.0\n")
        self.git("add", "-A")
        self.git("commit", "-qm", "base")
        self.git("checkout", "-qb", "feature")
        (self.repo / "app.py").write_text("a = 1\nb = eval(x)\nc = 3\n")
        (self.repo / "requirements.txt").write_text("requests==2.25.0\nurllib3==1.26.4\n")
        self.git("commit", "-qam", "feature")
        (self.repo / "nuevo.py").write_text("x = 1\n")  # sin commit ni add: también cuenta

    def tearDown(self):
        self.directory.cleanup()

    def git(self, *args):
        subprocess.run(["git", "-C", str(self.repo), *args], check=True, capture_output=True)

    def test_changes_include_commits_uncommitted_and_new_files(self):
        commit = merge_base(self.repo, "main")
        files = {item["filename"]: item for item in local_scan.diff_files(self.repo, commit)}
        self.assertEqual(set(files), {"app.py", "requirements.txt", "nuevo.py"})
        from appsec_agent.pr_review import changed_lines
        changed = changed_lines(list(files.values()))
        self.assertEqual((changed["app.py"], changed["nuevo.py"]), ({2, 3}, None))

    def test_refs_that_look_like_options_or_commands_are_rejected(self):
        for ref in ("--upload-pack=x", "-v", "main;rm -rf /", "a b", "", "main$(id)"):
            with self.assertRaises(LocalScanError, msg=ref):
                merge_base(self.repo, ref)
        with self.assertRaises(LocalScanError):
            merge_base(self.repo, "no-existe")

    def test_only_what_the_change_introduces_is_reported(self):
        head = [finding("eval", "app.py", 2, "critical"), finding("old-sca", "requirements.txt", 1, scanner="sca"),
                finding("new-sca", "requirements.txt", 1, scanner="sca"), finding("elsewhere", "otro.py", 9)]
        base = [finding("old-sca", "requirements.txt", 1, scanner="sca")]
        scans = iter([scan_result(head), scan_result(base)])
        with tempfile.TemporaryDirectory() as data, \
                patch.object(local_scan, "scan_repository", side_effect=lambda *args, **kwargs: next(scans)), \
                patch("appsec_agent.scanners.docker_available", return_value=True):
            result = run(self.repo, data_dir=Path(data), base="main")
        self.assertEqual([item["fingerprint"] for item in result["findings"]], ["eval", "new-sca"])
        self.assertEqual((result["comparison"]["preexisting_in_changed_code"], result["exit_code"]), (1, EXIT_BLOCKED))
        # El punto de partida se analiza de verdad: su copia sale de git, no del árbol de trabajo.
        self.assertTrue(result["comparison"]["baseline"])

    def test_the_base_snapshot_is_the_merge_base_tree(self):
        with tempfile.TemporaryDirectory() as out:
            local_scan.snapshot_commit(self.repo, merge_base(self.repo, "main"), Path(out) / "base")
            self.assertEqual((Path(out) / "base" / "app.py").read_text(), "a = 1\nb = 2\n")
            self.assertFalse((Path(out) / "base" / "nuevo.py").exists())


class GateTests(unittest.TestCase):
    def run_with(self, findings, *, status="completed", failed=(), docker=True, fail_on="high", exclude=None):
        with tempfile.TemporaryDirectory() as folder, tempfile.TemporaryDirectory() as data, \
                patch.object(local_scan, "scan_repository", return_value=scan_result(findings, status, failed)), \
                patch("appsec_agent.scanners.docker_available", return_value=docker), \
                patch("appsec_agent.scanners.docker_problem", return_value="Docker no responde."):
            return run(Path(folder), data_dir=Path(data), fail_on=fail_on, exclude=exclude)

    def test_exit_codes(self):
        self.assertEqual(self.run_with([])["exit_code"], EXIT_OK)
        self.assertEqual(self.run_with([finding("a", "x.py", 1, "medium")])["exit_code"], EXIT_OK)
        self.assertEqual(self.run_with([finding("a", "x.py", 1, "medium")], fail_on="medium")["exit_code"], EXIT_BLOCKED)
        self.assertEqual(self.run_with([finding("a", "x.py", 1, "critical")], fail_on="never")["exit_code"], EXIT_OK)

    def test_an_incomplete_scan_never_passes_as_clean(self):
        self.assertEqual(self.run_with([], failed=("trivy",))["exit_code"], EXIT_INCOMPLETE)
        self.assertEqual(self.run_with([], docker=False)["exit_code"], EXIT_INCOMPLETE)
        # Lo que sí se encontró bloquea igual aunque falte un motor.
        self.assertEqual(self.run_with([finding("a", "x.py", 1, "critical")], failed=("trivy",))["exit_code"], EXIT_BLOCKED)

    def test_text_groups_advisories_of_a_package_into_one_fix(self):
        package = lambda fixed: {"name": "urllib3", "version": "1.26.4", "fixed_version": fixed, "ecosystem": "PyPI"}
        result = self.run_with([finding("u1", "requirements.txt", 1, "high", "sca", package("1.26.5")),
                                finding("u2", "requirements.txt", 1, "medium", "sca", package("2.7.0")),
                                finding("u3", "requirements.txt", 1, "high", "sca", package("1.26.17"))])
        text = local_scan.render_text(result)
        self.assertIn("urllib3 1.26.4: 3 avisos (2 alta, 1 media) → actualiza a 2.7.0", text)
        self.assertEqual(text.count("urllib3"), 1)

    def test_names_from_the_repository_cannot_inject_terminal_escapes(self):
        result = self.run_with([finding("a", "evil\x1b[2K\x1b[1A.py", 1, "critical")])
        text = local_scan.render_text(result)
        self.assertNotIn("\x1b", text)
        self.assertIn("evil?[2K?[1A.py:1", text)

    def test_excluded_paths_do_not_count_but_are_reported(self):
        result = self.run_with([finding("a", "fixtures/vuln/app.py", 1, "critical"), finding("b", "tests/data/x.py", 2, "critical"),
                                finding("c", "src/app.py", 3, "medium")], exclude=["fixtures/", "**/data/**"])
        self.assertEqual(([item["fingerprint"] for item in result["findings"]], result["exit_code"]), (["c"], EXIT_OK))
        self.assertEqual(result["excluded"], {"patterns": ["fixtures/**", "**/data/**"], "findings": 2})
        self.assertIn("2 en rutas excluidas (fixtures/**, **/data/**): no cuentan.", local_scan.render_text(result))
        self.assertEqual(json.loads(local_scan.render_json(result))["excluded"]["findings"], 2)
        for bad in (["../fuera"], ["**"], ["/abs"], ["a;rm"]):
            with self.assertRaises(LocalScanError):
                self.run_with([], exclude=bad)

    def test_json_and_sarif_are_machine_readable(self):
        result = self.run_with([finding("a", "x.py", 3, "critical")])
        payload = json.loads(local_scan.render_json(result))
        self.assertEqual((payload["exit_code"], payload["findings"][0]["path"]), (EXIT_BLOCKED, "x.py"))
        sarif = json.loads(local_scan.render_sarif(result))
        self.assertEqual(sarif["runs"][0]["results"][0]["level"], "error")
        self.assertEqual(sarif["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["security-severity"], "9.5")

    def test_parse_diff_handles_renames_deletions_and_binaries(self):
        text = "\n".join([
            "diff --git a/old.py b/new.py", "similarity index 90%", "rename from old.py", "rename to new.py",
            "--- a/old.py", "+++ b/new.py", "@@ -1 +1 @@", "-a", "+b",
            "diff --git a/gone.py b/gone.py", "deleted file mode 100644", "--- a/gone.py", "+++ /dev/null", "@@ -1 +0,0 @@", "-x",
            "diff --git a/logo.png b/logo.png", "Binary files a/logo.png and b/logo.png differ"])
        files = {item["filename"]: item for item in parse_diff(text)}
        self.assertEqual((files["new.py"]["status"], files["gone.py"]["status"], files["logo.png"]["patch"]), ("modified", "removed", None))


if __name__ == "__main__":
    unittest.main()
