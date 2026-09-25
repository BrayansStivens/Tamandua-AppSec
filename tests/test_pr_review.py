"""Revisión de PRs: diff, línea base, veredicto, comentario y el trabajo completo con GitHub simulado."""

import json
import os
import shutil
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from appsec_agent import pr_review, pr_watch
from appsec_agent.jobs import ScanJobs
from appsec_agent.auth import Users
from appsec_agent.github_app import GitHubAppError, PULLS_FORBIDDEN
from appsec_agent.store import load_run, save_repository_scan, render_profile_report
from appsec_agent.pdf_reports import render_pdf
from fake_github import fake_github
from test_auth import PASSWORD, HttpCase

SHA = "c" * 40
APP = "import subprocess\n\ndef old(cmd):\n    return subprocess.run(cmd, shell=True)\n\n\ndef new(user):\n    return eval(user)\n"
# El PR añade la función `new` (líneas 7-8); `old` ya estaba en la rama principal.
PATCH = "@@ -3,2 +3,6 @@\n def old(cmd):\n     return subprocess.run(cmd, shell=True)\n+\n+\n+def new(user):\n+    return eval(user)\n"


def finding(fingerprint, path="app.py", line=8, severity="high", scanner="sast", package=None):
    return {"fingerprint": fingerprint, "path": path, "line": line, "severity": severity, "scanner": scanner,
            "title": "Regla | con barra", "remediation": "Arreglarlo", "package": package, "rule_id": "R"}


class LogicTests(unittest.TestCase):
    def test_changed_lines_follow_hunks(self):
        changed = pr_review.changed_lines([
            {"filename": "app.py", "status": "modified", "patch": PATCH + "\\ No newline at end of file"},
            {"filename": "logo.png", "status": "added"}, {"filename": "gone.py", "status": "removed", "patch": "@@ -1 +0,0 @@\n-x"}])
        self.assertEqual(changed, {"app.py": {5, 6, 7, 8}, "logo.png": None})

    def test_classify_against_baseline_and_diff(self):
        changed = {"app.py": {7, 8}, "package-lock.json": {10}}
        findings = [finding("new"), finding("old", line=4), finding("moved", line=7), finding("elsewhere", path="lib.py"),
                    finding("dep", path="package-lock.json", line=1, scanner="sca", package={"name": "axios"})]
        result = pr_review.classify(findings, changed, baseline={"old", "moved"})
        self.assertEqual([item["fingerprint"] for item in result["introduced"]], ["new", "dep"])
        self.assertEqual([item["fingerprint"] for item in result["preexisting"]], ["moved"])
        # Sin línea base cuenta todo lo que cae en el diff.
        self.assertEqual(len(pr_review.classify(findings, changed, baseline=None)["introduced"]), 3)

    def test_verdict_gate(self):
        items = [finding("a", severity="medium")]
        self.assertEqual(pr_review.verdict(items, "high")["state"], "success")
        self.assertEqual(pr_review.verdict(items, "medium")["state"], "failure")
        self.assertEqual(pr_review.verdict([finding("b", severity="critical")], "never")["state"], "success")

    def test_unused_dependencies_comment_is_informative(self):
        new = [{"name": "left-pad", "ecosystem": "npm", "manifest": "package.json", "line": 9}]
        before = [{"name": "moment", "ecosystem": "npm", "manifest": "package.json", "line": 7}]
        body = pr_review.render_unused_comment(new, before, ["npm"])
        self.assertIn("> [!WARNING]", body)
        self.assertIn("`left-pad`", body)
        self.assertIn("<summary>1 dependencia preexistente sin uso", body)
        self.assertIn("no bloquea el merge", body)
        self.assertIn("> [!TIP]", pr_review.render_unused_comment([], before, ["npm"]))

    def test_unused_dependency_detection(self):
        import tempfile
        from appsec_agent.unused_deps import analyze, split_by_pr
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "package.json").write_text(json.dumps({"dependencies": {"react": "19", "left-pad": "1", "tailwindcss": "4", "@scope/ui": "1", "prisma": "5"},
                                                           "scripts": {"migrate": "prisma migrate deploy"}}, indent=2))
            (root / "src").mkdir()
            (root / "src" / "App.tsx").write_text("import React from 'react'\nimport { Button } from '@scope/ui/button'\n")
            (root / "requirements.txt").write_text("fastapi==0.110\npython-dotenv==1.0\nrequests==2.31\ngunicorn==22\n")
            (root / "main.py").write_text("from fastapi import FastAPI\nfrom dotenv import load_dotenv\n")
            result = analyze(root)
        names = {item["name"] for item in result["unused"]}
        self.assertEqual(names, {"left-pad", "requests"})  # prisma va por script, gunicorn es implícito
        new, before = split_by_pr(result["unused"], {"package.json": {4}})
        self.assertEqual(([item["name"] for item in new], sorted(item["name"] for item in before)), (["left-pad"], ["requests"]))

    def test_long_titles_are_cut_at_a_word(self):
        self.assertEqual(pr_review._cell("Uncovered a JSON Web Token, which may lead to unauthorized access", 40), "Uncovered a JSON Web Token, which may…")

    def test_file_names_cannot_inject_markdown(self):
        hostile = finding("a", path="a`|x\n[click](https://evil)|.py")
        outcome = {"introduced": [hostile], "preexisting": [], "verdict": pr_review.verdict([hostile])}
        body = pr_review.render_comment({"head_sha": SHA}, outcome, run_id="r" * 32, baseline_run="b", panel_url=None)
        row = next(line for line in body.splitlines() if "click" in line)
        self.assertEqual(row.count("`"), 2)       # solo los del propio código
        self.assertNotIn("\n[click]", body)
        self.assertIn("el panel de Tamandua", body)

    def test_comment_escapes_tables_and_mentions_preexisting(self):
        outcome = {"introduced": [finding("a")], "preexisting": [finding("b")], "verdict": pr_review.verdict([finding("a")])}
        body = pr_review.render_comment({"head_sha": SHA}, outcome, run_id="r" * 32, baseline_run="base", panel_url="https://panel")
        self.assertIn("Regla / con barra", body)
        self.assertIn("> [!CAUTION]", body)
        self.assertIn("1 hallazgo preexistente", body)
        self.assertIn("`app.py:8`", body)


class JobTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.directory.name)
        self.repo = self.data_dir / "repo"
        self.repo.mkdir()
        (self.repo / "app.py").write_text(APP, encoding="utf-8")
        for target, value in (("appsec_agent.scanners._docker_state", {"ok": False}),):
            engines = patch.dict(target, value)
            engines.start()
            self.addCleanup(engines.stop)
        self.posted = []

    def tearDown(self):
        self.directory.cleanup()

    def run_review(self, permissions, *, baseline=True):
        if baseline:
            # La rama principal ya tenía `old`, con su huella.
            main = self.data_dir / "main"
            main.mkdir(exist_ok=True)
            (main / "app.py").write_text(APP.split("\n\n\ndef new")[0] + "\n", encoding="utf-8")
            from appsec_agent.repository_scan import scan_repository
            scan = scan_repository(main, {"id": "github:org/api", "name": "org/api", "provider": "github", "files": 1})
            save_repository_scan(self.data_dir, scan)

        def snapshot(source_id, destination, tokens, installation, ref=None, progress=None):
            self.assertEqual(ref, SHA)
            shutil.copytree(self.repo, destination, dirs_exist_ok=True)
            return destination, {"id": source_id, "name": "org/api", "provider": "github", "files": 1, "sha256": "x"}

        pull = {"number": 12, "title": "Nueva función", "url": "https://github.com/org/api/pull/12", "author": "ana",
                "head_sha": SHA, "head_ref": "feat", "base_ref": "main", "draft": False}
        with patch("appsec_agent.jobs.snapshot_source", snapshot), \
                patch("appsec_agent.github_app.pull_files", return_value=[{"filename": "app.py", "status": "modified", "patch": PATCH}]), \
                patch("appsec_agent.github_app.installation_details", return_value={"permissions": permissions}), \
                patch("appsec_agent.github_app.upsert_pr_comment", side_effect=lambda *args: self.posted.append(("comment", args)) or "created"), \
                patch("appsec_agent.github_app.set_commit_status", side_effect=lambda *args: self.posted.append(("status", args))):
            jobs = ScanJobs(self.data_dir)
            queued = jobs.enqueue_pr_review(source_id="github:org/api", pull=pull, installation_id=7, requested_by="ana")
            for _ in range(200):
                record = load_run(self.data_dir, queued["id"])
                if record["status"] not in ("queued", "running"):
                    break
                time.sleep(0.05)
        return record

    def test_review_counts_only_what_the_pr_introduces_and_reports_it(self):
        record = self.run_review({"pull_requests": "write", "statuses": "write", "contents": "read"})
        self.assertEqual(record["type"], "pr_review")
        self.assertEqual([item["rule_id"] for item in record["findings"]], ["PY-DYNAMIC-CODE"])
        self.assertEqual(record["summary"]["candidates"], 1)
        self.assertIsNotNone(record["review"]["baseline_run"])
        self.assertEqual(record["review"]["verdict"]["state"], "success")  # media, por debajo del umbral alto
        kinds = [kind for kind, _ in self.posted]
        self.assertEqual(kinds, ["comment", "status"])
        body = self.posted[0][1][3]
        self.assertIn("> [!WARNING]", body)
        self.assertIn("**1 hallazgo nuevo**", body)
        self.assertEqual(pr_watch.reviewed(self.data_dir, "github:org/api")["12"]["head_sha"], SHA)
        report = render_profile_report(record, "soc2")
        self.assertIn("una ejecución puntual", report)
        self.assertTrue(render_pdf(report, title="SOC 2 Tipo II", kind="Revisión de PR").startswith(b"%PDF-"))

    def test_without_write_permission_the_review_still_happens(self):
        record = self.run_review({"contents": "read", "metadata": "read"})
        self.assertEqual(record["status"], "incomplete")  # sin Docker en las pruebas no corre ningún motor: nunca «completed»
        self.assertEqual(self.posted, [])
        self.assertIn("sin permiso", record["review"]["delivery"]["comment"])

    def test_without_baseline_everything_in_the_diff_counts(self):
        record = self.run_review({}, baseline=False)
        self.assertEqual([item["rule_id"] for item in record["findings"]], ["PY-DYNAMIC-CODE"])
        self.assertIsNone(record["review"]["baseline_run"])


class SecretInDocsTests(unittest.TestCase):
    """Regresión: un JWT añadido en README.md se ignoraba porque la documentación no entraba en el snapshot."""

    setUp, tearDown = JobTests.setUp, JobTests.tearDown

    # El JWT de ejemplo de jwt.io, armado por partes para que el repositorio no lleve el literal.
    JWT = ".".join(("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0",
                    "KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30"))

    def test_jwt_added_to_readme_is_introduced_and_blocks(self):
        from appsec_agent.repository_sources import _analyzable
        self.assertTrue(_analyzable(Path("README.md")))
        self.assertTrue(_analyzable(Path("docs/.npmrc")))
        self.assertFalse(_analyzable(Path("public/logo.png")))
        readme = "# Safari\n\nGetting started\n\n![img](a.png)\n" + self.JWT + "\nFirst, run the development server:\n"
        (self.repo / "README.md").write_text(readme, encoding="utf-8")
        patch_text = "@@ -3,3 +3,5 @@\n Getting started\n \n+![img](a.png)\n+" + self.JWT + "\n First, run the development server:\n"
        with patch("appsec_agent.github_app.pull_files", return_value=[{"filename": "README.md", "status": "modified", "patch": patch_text}]):
            record = self._review_only({"pull_requests": "write", "statuses": "write"})
        secrets = [item for item in record["findings"] if item["scanner"] == "secrets"]
        self.assertEqual([(item["path"], item["line"]) for item in secrets], [("README.md", 6)])
        self.assertEqual(record["review"]["verdict"]["state"], "failure")
        self.assertNotIn(self.JWT, json.dumps(record))
        comment = next(args for kind, args in self.posted if kind == "comment")[3]
        self.assertNotIn(self.JWT, comment)
        self.assertIn("README.md:6", comment)

    def _review_only(self, permissions):
        # Mismo camino que run_review, sin línea base y con el parche que fije la prueba.
        def snapshot(source_id, destination, tokens, installation, ref=None, progress=None):
            import shutil
            shutil.copytree(self.repo, destination, dirs_exist_ok=True)
            return destination, {"id": source_id, "name": "org/api", "provider": "github", "files": 2, "sha256": "x"}
        pull = {"number": 4, "title": "README", "url": "u", "author": "ana", "head_sha": SHA, "head_ref": "p", "base_ref": "main", "draft": False}
        with patch("appsec_agent.jobs.snapshot_source", snapshot), \
                patch("appsec_agent.github_app.installation_details", return_value={"permissions": permissions}), \
                patch("appsec_agent.github_app.upsert_pr_comment", side_effect=lambda *args: self.posted.append(("comment", args)) or "created"), \
                patch("appsec_agent.github_app.set_commit_status", side_effect=lambda *args: self.posted.append(("status", args))):
            jobs = ScanJobs(self.data_dir)
            queued = jobs.enqueue_pr_review(source_id="github:org/api", pull=pull, installation_id=7, requested_by="ana")
            for _ in range(200):
                record = load_run(self.data_dir, queued["id"])
                if record["status"] not in ("queued", "running"):
                    return record
                time.sleep(0.05)
        return record


class WatcherTests(unittest.TestCase):
    def test_poll_routes_each_organization_to_its_own_installation(self):
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory)
            pr_watch.configure(data_dir, "github#1", enabled=True, by="operadora")
            pr_watch.configure(data_dir, "github#2", enabled=True, by="operadora")
            queued = []

            class Jobs:
                def pending(self):
                    return 0

                def enqueue_pr_review(self, **kwargs):
                    queued.append((kwargs["source_id"], kwargs["installation_id"]))

            def repositories(installation, *, fresh):
                name = "acme/api" if installation == 77 else "beta/web"
                return [{"id": f"github:{name}", "uid": "github#1" if installation == 77 else "github#2", "name": name}]

            pulls = [{"number": 1, "head_sha": "a" * 40, "draft": False}]
            with patch("appsec_agent.github_app.installation_repositories", side_effect=repositories), \
                    patch("appsec_agent.github_app.open_pull_requests", return_value=pulls):
                self.assertEqual(pr_watch.Watcher(data_dir, Jobs(), lambda: [77, 88]).poll(), 2)
            self.assertEqual(queued, [("github:acme/api", 77), ("github:beta/web", 88)])

    def test_poll_enqueues_each_head_once_and_skips_drafts(self):
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory)
            pr_watch.configure(data_dir, "github:org/api", enabled=True, by="operadora")
            pr_watch.configure(data_dir, "github:org/off", enabled=False, by="operadora")
            queued = []

            class Jobs:
                def pending(self):
                    return 0

                def enqueue_pr_review(self, **kwargs):
                    queued.append(kwargs["pull"]["number"])
                    pr_watch.mark(data_dir, kwargs["uid"], kwargs["pull"]["number"], kwargs["pull"]["head_sha"], "run")

            pulls = [{"number": 1, "head_sha": "a" * 40, "draft": False}, {"number": 2, "head_sha": "b" * 40, "draft": True}]
            watcher = pr_watch.Watcher(data_dir, Jobs(), lambda: 7)
            installed = [{"id": "github:org/api", "uid": "github#1", "name": "org/api"}, {"id": "github:org/off", "uid": "github#2", "name": "org/off"}]
            with patch("appsec_agent.github_app.open_pull_requests", return_value=pulls) as listing, \
                    patch("appsec_agent.github_app.installation_repositories", return_value=installed):
                self.assertEqual(watcher.poll(), 1)
                self.assertEqual(watcher.poll(), 0)  # mismo commit: no se repite
                pulls[0]["head_sha"] = "d" * 40      # nuevo push
                self.assertEqual(watcher.poll(), 1)
            self.assertEqual(queued, [1, 1])
            # La configuración guardada por nombre se migró a la identidad estable.
            self.assertEqual(set(pr_watch.load(data_dir)["repositories"]), {"github#1", "github#2"})
            self.assertEqual({call.args[1] for call in listing.call_args_list}, {"org/api"})


class BranchWatchTests(unittest.TestCase):
    def test_the_default_branch_is_rescanned_when_it_changes(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"APPSEC_AGENT_BRANCH_MIN_MINUTES": "60"}):
            data_dir = Path(directory)
            for index in range(1, 6):
                pr_watch.configure(data_dir, f"github#{index}", enabled=True, by="operadora")
            pr_watch.configure(data_dir, "github#5", branch=False, by="operadora")  # solo PRs
            queued = []

            class Jobs:
                pending_count = 0

                def pending(self):
                    return self.pending_count

                def enqueue_repository_scan(self, **kwargs):
                    queued.append((kwargs["source_id"], kwargs["trigger"]["head_sha"], kwargs["requested_by"]))
                    return {"id": f"{len(queued):032d}"}

            installed = [{"id": f"github:org/r{index}", "uid": f"github#{index}", "name": f"org/r{index}", "branch": "main"} for index in range(1, 6)]
            heads = {f"org/r{index}": "a" * 40 for index in range(1, 6)}
            jobs = Jobs()
            watcher = pr_watch.Watcher(data_dir, jobs, lambda: 7)
            with patch("appsec_agent.github_app.installation_repositories", return_value=installed), \
                    patch("appsec_agent.github_app.open_pull_requests", return_value=[]), \
                    patch("appsec_agent.github_app.branch_head", side_effect=lambda installation, name, branch: heads[name]):
                self.assertEqual(watcher.poll(), 3)            # como mucho tres por vuelta
                self.assertEqual(watcher.poll(), 1)            # el cuarto; el quinto solo vigila PRs
                self.assertEqual(watcher.poll(), 0)            # sin commits nuevos no se repite
                heads["org/r1"] = "b" * 40                     # un merge, pero dentro de la pausa mínima
                self.assertEqual(watcher.poll(), 0)
                state = pr_watch.load(data_dir)
                state["branches"]["github#1"]["at"] = "2020-01-01T00:00:00+00:00"
                pr_watch._save(data_dir, state)
                jobs.pending_count = 5                         # cola llena: espera
                self.assertEqual(watcher.poll(), 0)
                jobs.pending_count = 0
                self.assertEqual(watcher.poll(), 1)
            self.assertEqual(queued[-1], ("github:org/r1", "b" * 40, "vigilante"))
            self.assertNotIn("github:org/r5", {item[0] for item in queued})
            self.assertEqual(pr_watch.branch_state(data_dir, "github#1")["head_sha"], "b" * 40)


class RouteTests(HttpCase):
    def test_settings_survive_when_github_denies_reading_pulls(self):
        with patch.dict(os.environ, {"APPSEC_AGENT_REQUIRE_TOTP": "none"}):
            Users(self.data_dir).create("operadora", PASSWORD, role="admin")
            _, _, cookies = self.post("/api/auth/login", "login", {"username": "operadora", "password": PASSWORD})
            cookie = cookies[0].split("; ")[0]
            with patch("appsec_agent.api.routes_prs.github_installations", return_value=[7]), \
                    fake_github({7: [(1, "org/api"), (2, "org/web")]}, {7: ("org", "selected")}), \
                    patch("appsec_agent.api.routes_prs.open_pull_requests", side_effect=GitHubAppError(PULLS_FORBIDDEN)):
                status, body, _ = self.call("GET", "/api/pull-requests?source_id=github:org/api", headers={"Cookie": cookie})
                self.assertEqual((status, body["pulls"], body["settings"]["gate"]), (200, [], "high"))
                self.assertIn("Pull requests", body["pulls_error"])
                # Varios repositorios a la vez, y la vista general los refleja.
                status, body, _ = self.post("/api/pull-requests/settings", "pr-settings", {"source_ids": ["github:org/api", "github:org/web"], "enabled": True}, cookie)
                self.assertEqual((status, body["updated"]), (200, 2))
                _, overview, _ = self.call("GET", "/api/pull-requests/watch", headers={"Cookie": cookie})
                self.assertEqual((overview["enabled"], {row["name"]: row["enabled"] for row in overview["repositories"]}), (2, {"org/api": True, "org/web": True}))
                _, active, _ = self.call("GET", "/api/pull-requests/watch?only=enabled&q=web", headers={"Cookie": cookie})
                self.assertEqual(([row["name"] for row in active["repositories"]], active["total"]), (["org/web"], 1))
                status, _, _ = self.post("/api/pull-requests/settings", "pr-settings", {"source_ids": ["github:org/api", "github:otra/x"], "enabled": False}, cookie)
                self.assertEqual(status, 400)
                # Desactivar todos no necesita recorrer el catálogo.
                status, body, _ = self.post("/api/pull-requests/settings", "pr-settings", {"all": True, "enabled": False}, cookie)
                self.assertEqual((status, body["updated"]), (200, 2))
                self.assertEqual(self.call("GET", "/api/pull-requests/watch", headers={"Cookie": cookie})[1]["enabled"], 0)
                # Un repositorio fuera de la instalación no se acepta.
                status, _, _ = self.call("GET", "/api/pull-requests?source_id=github:otra/cosa", headers={"Cookie": cookie})
                self.assertEqual(status, 400)
                status, _, _ = self.call("GET", "/api/pull-requests?source_id=github:org/fantasma", headers={"Cookie": cookie})
                self.assertEqual(status, 400)

if __name__ == "__main__":
    unittest.main()
