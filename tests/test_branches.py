"""Branch selection: PR target branches, the scan branch per repository, pinned scans and the per-branch baseline."""

import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError

from tamandua.app import wiring
from tamandua.modules.identity.auth import Users
from tamandua.modules.integrations import github
from tamandua.modules.integrations.github import BranchNotFound, branch_head, valid_branch
from tamandua.modules.integrations.installations import save_github
from tamandua.modules.pullrequests import watch as pr_watch
from tamandua.modules.runs.jobs import ScanJobs
from tamandua.modules.runs.store import save_repository_scan
from tamandua.modules.scanning.repository import scan_repository
from tamandua.modules.runs import assets as run_assets
from tamandua.modules.sources import assets
from tamandua.shared.i18n import msg, text

from fake_github import fake_github
from test_auth import ORIGIN, PASSWORD, HttpCase
from test_jobs import _wait

wiring.configure()  # like every Tamandua process: domain events and injected readers

REPOS = {7: [(1, "acme/api"), (2, "acme/web")]}
ACCOUNTS = {7: ("acme", "selected")}
BRANCHES = {"acme/api": {"main": "a" * 40, "develop": "d" * 40, "release/2.0": "e" * 40}}


class BranchNameTests(unittest.TestCase):
    def test_one_rule_for_every_branch_name(self):
        for name in ("main", "develop", "release/2.0", "feature/JIRA-12_x", "v1.2.3"):
            self.assertTrue(valid_branch(name), name)
        for name in ("", "-rf", "/main", "a..b", "a//b", "has space", "feat;rm", "x" * 201, None, 3, "ñandú", "a\nb"):
            self.assertFalse(valid_branch(name), name)

    def test_a_missing_branch_is_reported_by_name(self):
        def refuse(*args, **kwargs):
            raise HTTPError("https://api.github.com/x", 404, "Not Found", {}, None)

        class Opener:
            open = staticmethod(refuse)

        with patch("tamandua.modules.integrations.github.installation_token", return_value="token"), \
                patch("tamandua.shared.http.build_opener", return_value=Opener()):
            with self.assertRaises(BranchNotFound) as caught:
                branch_head(7, "acme/api", "develop")
        self.assertIn("develop", text(caught.exception.message, "en"))
        self.assertIn("develop", text(caught.exception.message, "es"))
        with self.assertRaises(github.GitHubAppError):
            branch_head(7, "acme/api", "../x")


def _scan(data_dir: Path, created_at: str, *, branch: str | None, uid: str = "github#1") -> str:
    """A saved full scan of org/api, optionally on a branch."""
    root = data_dir / f"repo-{created_at[:19].replace(':', '')}"
    root.mkdir()
    (root / "app.py").write_text("print('hi')\n", encoding="utf-8")
    source = {"id": "github:org/api", "uid": uid, "name": "org/api", "provider": "github", "files": 1}
    if branch:
        source["branch"] = branch
    return save_repository_scan(data_dir, scan_repository(root, source), created_at=created_at)["id"]


class BaselineTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data_dir = Path(self.directory.name)
        engines = patch.dict("tamandua.modules.scanning.engines._docker_state", {"ok": False}, clear=True)
        engines.start()
        self.addCleanup(engines.stop)

    def test_the_baseline_is_the_latest_scan_of_the_pr_base_branch(self):
        now = datetime.now(timezone.utc)
        main = _scan(self.data_dir, (now - timedelta(hours=3)).isoformat(), branch="main")
        develop = _scan(self.data_dir, (now - timedelta(hours=2)).isoformat(), branch="develop")
        jobs = ScanJobs(self.data_dir, worker=False)
        self.assertEqual(jobs._baseline("github:org/api", "github#1", branch="main", default_branch="main")["id"], main)
        self.assertEqual(jobs._baseline("github:org/api", "github#1", branch="develop", default_branch="main")["id"], develop)
        self.assertIsNone(jobs._baseline("github:org/api", "github#1", branch="release/2.0", default_branch="main"))
        # A scan that doesn't record its branch read the default branch.
        legacy = _scan(self.data_dir, (now - timedelta(hours=1)).isoformat(), branch=None)
        self.assertEqual(jobs._baseline("github:org/api", "github#1", branch="main", default_branch="main")["id"], legacy)
        self.assertEqual(jobs._baseline("github:org/api", "github#1", branch="develop", default_branch="main")["id"], develop)


class PinnedScanTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data_dir = Path(self.directory.name)
        engines = patch.dict("tamandua.modules.scanning.engines._docker_state", {"ok": False}, clear=True)
        engines.start()
        self.addCleanup(engines.stop)
        self.refs = []

    def snapshot(self, source_id, destination, tokens, installation, ref=None, progress=None):
        self.refs.append(ref)
        (destination / "app.py").write_text("print('hi')\n", encoding="utf-8")
        return destination, {"id": source_id, "uid": "github#1", "name": "org/api", "provider": "github", "files": 1, "branch": "main"}

    def run_scan(self, **kwargs):
        with patch("tamandua.modules.runs.jobs.snapshot_source", side_effect=self.snapshot):
            jobs = ScanJobs(self.data_dir)
            self.addCleanup(jobs.stop)
            queued = jobs.enqueue_repository_scan(source_id="github:org/api", source_name="org/api", allow_osv_upload=False, context="",
                                                  tokens={}, installation_id=7, uid="github#1", **kwargs)
            return _wait(self.data_dir, queued["id"])

    def test_the_configured_branch_is_scanned_at_its_latest_commit(self):
        assets.set_scan_branch(self.data_dir, "github#1", "develop", name="org/api", source_id="github:org/api", by="admin")
        with patch("tamandua.modules.integrations.github.branch_head", return_value="d" * 40) as head:
            record = self.run_scan()
        head.assert_called_once_with(7, "org/api", "develop")
        self.assertEqual(self.refs, ["d" * 40])
        self.assertEqual((record["status"], record["source"]["branch"], record["source"]["commit"]), ("incomplete", "develop", "d" * 40))

    def test_without_a_setting_the_default_branch_is_pinned(self):
        with patch("tamandua.modules.integrations.github.installation_repository", return_value={"branch": "main"}), \
                patch("tamandua.modules.integrations.github.branch_head", return_value="a" * 40):
            record = self.run_scan()
        self.assertEqual(self.refs, ["a" * 40])
        self.assertEqual((record["source"]["branch"], record["source"]["commit"]), ("main", "a" * 40))

    def test_a_pinned_commit_is_not_resolved_again(self):
        with patch("tamandua.modules.integrations.github.branch_head") as head:
            record = self.run_scan(branch="release/2.0", commit="e" * 40)
        head.assert_not_called()
        self.assertEqual((self.refs, record["source"]["branch"]), (["e" * 40], "release/2.0"))

    def test_a_deleted_scan_branch_fails_the_run_naming_it(self):
        assets.set_scan_branch(self.data_dir, "github#1", "gone", name="org/api", source_id="github:org/api", by="admin")
        missing = msg("integrations.github.branch_not_found", branch="gone")
        with patch("tamandua.modules.integrations.github.branch_head", side_effect=BranchNotFound(missing)):
            record = self.run_scan()
        self.assertEqual((record["status"], self.refs), ("failed", []))
        self.assertIn("gone", text(record["limitations"][0], "en"))


class Jobs:
    def __init__(self):
        self.reviews, self.scans = [], []

    def pending(self):
        return 0

    def enqueue_pr_review(self, **kwargs):
        self.reviews.append(kwargs["pull"]["number"])

    def enqueue_repository_scan(self, **kwargs):
        self.scans.append(kwargs)
        return {"id": f"{len(self.scans):032d}"}


class WatcherTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data_dir = Path(self.directory.name)
        self.installed = [{"id": "github:acme/api", "uid": "github#1", "name": "acme/api", "branch": "main"}]

    def poll(self, jobs, pulls, heads=None):
        heads = heads or {"main": "a" * 40}
        with patch("tamandua.modules.integrations.github.installation_repositories", return_value=self.installed), \
                patch("tamandua.modules.integrations.github.open_pull_requests", return_value=pulls), \
                patch("tamandua.modules.integrations.github.branch_head", side_effect=lambda installation, name, branch: heads[branch]):
            return pr_watch.Watcher(self.data_dir, jobs, lambda: 7).poll()

    def test_only_prs_into_the_target_branches_are_reviewed(self):
        pr_watch.configure(self.data_dir, "github#1", enabled=True, branch=False, by="admin")
        pulls = [{"number": 1, "head_sha": "1" * 40, "draft": False, "base_ref": "main"},
                 {"number": 2, "head_sha": "2" * 40, "draft": False, "base_ref": "develop"},
                 {"number": 3, "head_sha": "3" * 40, "draft": False, "base_ref": "release/2.0"}]
        jobs = Jobs()
        self.poll(jobs, pulls)
        self.assertEqual(jobs.reviews, [1])  # no setting: the default branch
        pr_watch.set_base_branches(self.data_dir, "github#1", ["develop", "release/2.0"], default_branch="main", by="admin")
        jobs = Jobs()
        self.poll(jobs, pulls)
        self.assertEqual(jobs.reviews, [2, 3])

    def test_each_target_branch_is_rescanned_pinned_to_the_commit_it_saw(self):
        pr_watch.configure(self.data_dir, "github#1", enabled=True, by="admin")
        pr_watch.set_base_branches(self.data_dir, "github#1", ["main", "develop"], default_branch="main", by="admin")
        # State written before branches were tracked one by one: it was the default branch's.
        state = pr_watch.load(self.data_dir)
        state["branches"]["github#1"] = {"head_sha": "a" * 40, "run_id": "0" * 32, "at": "2020-01-01T00:00:00+00:00"}
        pr_watch._save(self.data_dir, state)
        jobs = Jobs()
        self.assertEqual(self.poll(jobs, [], {"main": "a" * 40, "develop": "d" * 40}), 1)
        self.assertEqual([(scan["branch"], scan["commit"], scan["trigger"]["branch"]) for scan in jobs.scans], [("develop", "d" * 40, "develop")])
        self.assertEqual(pr_watch.branch_state(self.data_dir, "github#1", "develop")["head_sha"], "d" * 40)
        self.assertEqual(pr_watch.branch_state(self.data_dir, "github#1", "main")["head_sha"], "a" * 40)
        self.assertEqual(pr_watch.branch_state(self.data_dir, "github#1")["branch"], "develop")  # latest, for the panel
        self.assertEqual(self.poll(jobs, [], {"main": "a" * 40, "develop": "d" * 40}), 0)  # nothing new
        # Dropping a target branch forgets its watch state.
        pr_watch.set_base_branches(self.data_dir, "github#1", ["main"], default_branch="main", by="admin")
        self.assertIsNone(pr_watch.branch_state(self.data_dir, "github#1", "develop"))


class PurgeTests(unittest.TestCase):
    def test_purging_a_repository_forgets_its_branch_settings(self):
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory)
            assets.set_scan_branch(data_dir, "github#1", "develop", name="acme/api", source_id="github:acme/api", by="admin")
            pr_watch.set_base_branches(data_dir, "github#1", ["develop"], default_branch="main", by="admin")
            pr_watch.mark_branch(data_dir, "github#1", "d" * 40, "0" * 32, "develop")
            run_assets.purge(data_dir, "github#1")
            self.assertIsNone(assets.scan_branch(data_dir, "github#1"))
            self.assertNotIn("github#1", assets.load_registry(data_dir))
            self.assertEqual(pr_watch.settings(data_dir, "github#1")["base_branches"], [])
            self.assertIsNone(pr_watch.branch_state(data_dir, "github#1"))


class RouteTests(HttpCase):
    def setUp(self):
        super().setUp()
        with patch.dict(os.environ, {"TAMANDUA_REQUIRE_TOTP": "none"}):
            Users(self.data_dir).create("admin", PASSWORD, role="admin")
            Users(self.data_dir).create("miembro", PASSWORD)
            self.admin = self.post("/api/auth/login", "login", {"username": "admin", "password": PASSWORD})[2][0].split("; ")[0]
            self.member = self.post("/api/auth/login", "login", {"username": "miembro", "password": PASSWORD})[2][0].split("; ")[0]
        save_github(self.data_dir, 7, {"account": "acme", "repository_selection": "selected"}, "admin")

    def send(self, path, action, body, cookie, locale=None):
        headers = {"Origin": ORIGIN, "X-Tamandua-Action": action, "Cookie": cookie, "Content-Type": "application/json",
                   **({"Accept-Language": locale} if locale else {})}
        with fake_github(REPOS, ACCOUNTS, BRANCHES):
            return self.call("POST", path, body, headers)[:2]

    def test_target_branches_are_normalized_checked_on_github_and_stored(self):
        status, body = self.send("/api/pull-requests/branches", "pr-branches", {"uid": "github#1", "branches": [" develop", "develop", "release/2.0", ""]}, self.admin)
        self.assertEqual((status, body), (200, {"uid": "github#1", "base_branches": ["develop", "release/2.0"], "default_branch": "main"}))
        self.assertEqual(pr_watch.settings(self.data_dir, "github#1")["base_branches"], ["develop", "release/2.0"])
        status, body = self.send("/api/pull-requests/branches", "pr-branches", {"uid": "github#1", "branches": []}, self.admin)
        self.assertEqual((status, body["base_branches"]), (200, []))

    def test_an_unknown_branch_is_rejected_by_name_in_the_readers_language(self):
        status, body = self.send("/api/pull-requests/branches", "pr-branches", {"uid": "github#1", "branches": ["develop", "nope"]}, self.admin, "en")
        self.assertEqual(status, 400)
        self.assertEqual(body["error"], "Branch nope doesn't exist in this repository")
        status, body = self.send("/api/pull-requests/branches", "pr-branches", {"uid": "github#1", "branches": ["nope"]}, self.admin)
        self.assertEqual((status, body["error"]), (400, "La rama nope no existe en este repositorio"))
        self.assertEqual(pr_watch.settings(self.data_dir, "github#1")["base_branches"], [])  # nothing half-saved
        status, body = self.send("/api/repositories/branch", "set-scan-branch", {"uid": "github#1", "branch": "nope"}, self.admin, "en")
        self.assertEqual((status, body["error"]), (400, "Branch nope doesn't exist in this repository"))
        status, body = self.send("/api/pull-requests/branches", "pr-branches", {"uid": "github#1", "branches": ["a..b"]}, self.admin)
        self.assertEqual(status, 400)
        self.assertIn("a..b", body["error"])
        status, _ = self.send("/api/pull-requests/branches", "pr-branches", {"uid": "github#1", "branches": [f"b{index}" for index in range(11)]}, self.admin)
        self.assertEqual(status, 400)

    def test_the_new_routes_are_admin_only_and_need_their_csrf_action(self):
        for path, action, body in (("/api/pull-requests/branches", "pr-branches", {"uid": "github#1", "branches": ["develop"]}),
                                   ("/api/repositories/branch", "set-scan-branch", {"uid": "github#1", "branch": "develop"})):
            self.assertEqual(self.send(path, action, body, self.member)[0], 403, path)
            self.assertEqual(self.send(path, "pr-settings", body, self.admin)[0], 403, path)
            with fake_github(REPOS, ACCOUNTS, BRANCHES):
                json = {"Content-Type": "application/json"}
                self.assertEqual(self.call("POST", path, body, {**json, "X-Tamandua-Action": action, "Cookie": self.admin})[0], 403, path)
                self.assertEqual(self.call("POST", path, body, {**json, "Origin": ORIGIN, "X-Tamandua-Action": action})[0], 401, path)
            self.assertEqual(self.send(path, action, {**body, "uid": "github#99"}, self.admin)[0], 404, path)  # not in the App
            self.assertEqual(self.send(path, action, {**body, "extra": 1}, self.admin)[0], 400, path)
        self.assertIsNone(assets.scan_branch(self.data_dir, "github#1"))
        self.assertEqual(pr_watch.settings(self.data_dir, "github#1")["base_branches"], [])

    def test_the_scan_branch_is_set_shown_and_reset(self):
        status, body = self.send("/api/repositories/branch", "set-scan-branch", {"uid": "github#1", "branch": "release/2.0"}, self.admin)
        self.assertEqual((status, body), (200, {"uid": "github#1", "branch": "release/2.0", "head_sha": "e" * 40, "default_branch": "main"}))
        self.assertEqual(assets.scan_branch(self.data_dir, "github#1"), "release/2.0")
        with fake_github(REPOS, ACCOUNTS, BRANCHES):
            _, listing, _ = self.call("GET", "/api/sources?provider=github", headers={"Cookie": self.member})
        rows = {row["uid"]: (row["scan_branch"], row["default_branch"]) for row in listing["sources"]}
        self.assertEqual(rows, {"github#1": ("release/2.0", "main"), "github#2": (None, "main")})
        status, body = self.send("/api/repositories/branch", "set-scan-branch", {"uid": "github#1", "branch": None}, self.admin)
        self.assertEqual((status, body["branch"], body["head_sha"]), (200, None, None))
        self.assertIsNone(assets.scan_branch(self.data_dir, "github#1"))


if __name__ == "__main__":
    unittest.main()
