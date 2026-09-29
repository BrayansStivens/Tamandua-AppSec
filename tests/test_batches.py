"""Scan batches: several repositories or an organization, without going one by one."""

import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from tamandua.modules.runs import batches
from tamandua.modules.identity.auth import Users
from tamandua.modules.integrations.installations import save_github
from fake_github import fake_github
from test_auth import PASSWORD, HttpCase

REPOS = {7: [(index + 1, f"acme/servicio-{index:02d}") for index in range(12)]}
ACCOUNTS = {7: ("acme", "all")}


def item(name):
    return {"source_id": f"github:{name}", "name": name, "uid": None, "installation_id": 7}


class BatchLogicTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.data = Path(self.directory.name)

    def tearDown(self):
        self.directory.cleanup()

    def test_items_are_taken_one_by_one_and_the_batch_finishes(self):
        batch = batches.create(self.data, [item("acme/a"), item("acme/b"), item("acme/a")], by="ana", label="dos")
        self.assertEqual(len(batch["items"]), 2)  # no duplicates
        taken = [batches.take_next(self.data) for _ in range(2)]
        for (current, index), run_id in zip(taken, ("1" * 32, "2" * 32)):
            batches.attach(self.data, current["id"], index, run_id=run_id)
        self.assertIsNone(batches.take_next(self.data))
        self.assertEqual(batches.load(self.data, batch["id"])["status"], "done")

    def test_only_one_active_batch_and_cancel_stops_it(self):
        batch = batches.create(self.data, [item("acme/a")], by="ana", label="uno")
        with self.assertRaises(batches.BatchError):
            batches.create(self.data, [item("acme/b")], by="ana", label="otro")
        batches.cancel(self.data, batch["id"], by="ana")
        self.assertIsNone(batches.take_next(self.data))
        batches.create(self.data, [item("acme/b")], by="ana", label="otro")  # a cancelled batch no longer blocks

    def test_a_restart_releases_what_was_taken_but_not_queued(self):
        batch = batches.create(self.data, [item("acme/a")], by="ana", label="uno")
        batches.take_next(self.data)  # the process dies before queuing it
        batches.release_taken(self.data)
        current, index = batches.take_next(self.data)
        self.assertEqual((current["id"], index), (batch["id"], 0))

    def test_progress_comes_from_the_real_runs(self):
        from tamandua.modules.runs.store import save_repository_scan
        from test_dashboard import _finding, _scan
        batch = batches.create(self.data, [item("acme/a"), item("acme/b"), item("acme/c")], by="ana", label="tres")
        run = save_repository_scan(self.data, {**_scan("acme/a", [_finding("a" * 64, "critical")], datetime.now(timezone.utc).isoformat()),
                                               "started_at": "2026-09-25T10:00:00+00:00", "finished_at": "2026-09-25T10:01:00+00:00"})
        current, index = batches.take_next(self.data)
        batches.attach(self.data, current["id"], index, run_id=run["id"])
        current, index = batches.take_next(self.data)
        batches.attach(self.data, current["id"], index, error="Repositorio no disponible")
        state = batches.summary(self.data, batches.load(self.data, batch["id"]))
        self.assertEqual((state["done"], state["failed"], state["pending"], state["critical"]), (1, 1, 1, 1))
        self.assertEqual(state["eta_seconds"], 60)  # one pending × the real average duration (60 s)


class ImageBatchTests(unittest.TestCase):
    def test_images_are_batched_by_full_reference_and_fed_to_the_image_scanner(self):
        from tamandua.modules.scanning.image import parse_reference
        from tamandua.modules.runs.jobs import ScanJobs
        with tempfile.TemporaryDirectory() as folder:
            data = Path(folder)
            items = [{"kind": "image", "image": parse_reference(reference)} for reference in ("nginx:1.21", "nginx:1.27-alpine", "nginx:1.21")]
            batch = batches.create(data, items, by="ana", label="imágenes")
            self.assertEqual([item["name"] for item in batch["items"]], ["docker.io/library/nginx:1.21", "docker.io/library/nginx:1.27-alpine"])  # two tags, two scans
            with patch.object(ScanJobs, "__init__", lambda self, data_dir: setattr(self, "data_dir", data_dir)), \
                    patch.object(ScanJobs, "enqueue_image_scan", return_value={"id": "3" * 32}) as enqueue:
                jobs = ScanJobs(data)
                jobs._feed_batch()
            self.assertEqual(enqueue.call_args.kwargs["image"]["reference"], "docker.io/library/nginx:1.21")
            self.assertEqual(enqueue.call_args.kwargs["requested_by"], "ana")
            self.assertEqual(batches.load(data, batch["id"])["items"][0]["run_id"], "3" * 32)


class WorkerTests(unittest.TestCase):
    def test_the_real_worker_goes_through_the_whole_batch(self):
        """The worker takes the batch's repositories one by one when it has nothing else to do, until it is done."""
        import time
        from tamandua.modules.runs.jobs import ScanJobs
        from test_dashboard import _finding, _scan

        def snapshot(source_id, destination, tokens, installation, ref=None, progress=None):
            destination.mkdir(parents=True, exist_ok=True)
            return destination, {"id": source_id, "name": source_id.removeprefix("github:"), "provider": "github", "files": 1}

        def scan(root, source, **kwargs):
            return _scan(source["name"], [_finding(source["name"].encode().hex().ljust(64, "0")[:64], "high")], datetime.now(timezone.utc).isoformat())

        with tempfile.TemporaryDirectory() as folder, patch("tamandua.modules.runs.jobs.snapshot_source", side_effect=snapshot), \
                patch("tamandua.modules.runs.jobs.scan_repository", side_effect=scan):
            data = Path(folder)
            batch = batches.create(data, [item("acme/a"), item("acme/b"), item("acme/c")], by="ana", label="tres")
            jobs = ScanJobs(data)
            jobs.idle_poll = 0.05
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline and batches.load(data, batch["id"])["status"] == "running":
                time.sleep(0.1)
            state = batches.summary(data, batches.load(data, batch["id"]))
        self.assertEqual((state["status"], state["done"], state["failed"], state["high"]), ("done", 3, 0, 3))


class BatchRouteTests(HttpCase):
    def setUp(self):
        super().setUp()
        with patch.dict(os.environ, {"TAMANDUA_REQUIRE_TOTP": "none"}):
            Users(self.data_dir).create("admin", PASSWORD, role="admin")
            Users(self.data_dir).create("miembro", PASSWORD)
            self.admin = self.post("/api/auth/login", "login", {"username": "admin", "password": PASSWORD})[2][0].split("; ")[0]
            self.member = self.post("/api/auth/login", "login", {"username": "miembro", "password": PASSWORD})[2][0].split("; ")[0]
        save_github(self.data_dir, 7, {"account": "acme", "repository_selection": "all"}, "admin")
        # The worker takes nothing from the batch during the test: only the API is tested here.
        patcher = patch("tamandua.modules.runs.jobs.ScanJobs._feed_batch")
        patcher.start()
        self.addCleanup(patcher.stop)

    def create(self, body, cookie):
        with patch.dict(os.environ, {"TAMANDUA_REQUIRE_TOTP": "none"}), fake_github(REPOS, ACCOUNTS):
            return self.post("/api/repositories/batches", "scan-batch", body, cookie)

    def test_a_member_scans_a_selection_but_not_a_whole_organization(self):
        status, body, _ = self.create({"source_ids": ["github:acme/servicio-01", "github:acme/servicio-02"]}, self.member)
        self.assertEqual((status, body["total"], body["pending"]), (202, 2, 2))
        status, _, _ = self.create({"account": "acme"}, self.member)
        self.assertEqual(status, 403)
        # Another batch while one is still running: rejected.
        self.assertEqual(self.create({"source_ids": ["github:acme/servicio-03"]}, self.member)[0], 409)
        with patch.dict(os.environ, {"TAMANDUA_REQUIRE_TOTP": "none"}):
            _, listing, _ = self.call("GET", "/api/repositories/batches", headers={"Cookie": self.member})
            self.assertEqual(listing["active"]["total"], 2)
            self.assertEqual(self.post("/api/repositories/batches/cancel", "cancel-batch", {"id": listing["active"]["id"]}, self.member)[0], 200)

    def test_an_admin_scans_a_whole_organization(self):
        status, body, _ = self.create({"account": "ACME"}, self.admin)
        self.assertEqual((status, body["total"]), (202, 12))

    def test_a_member_scans_several_images_in_one_batch(self):
        def create(body):
            with patch.dict(os.environ, {"TAMANDUA_REQUIRE_TOTP": "none"}):
                return self.post("/api/images/batches", "scan-image-batch", body, self.member)
        for body in ({"references": []}, {"references": ["NGINX:Mayúsculas"]}, {"references": [7]},
                     {"references": [f"nginx:{index}" for index in range(101)]}, {"references": ["nginx"], "extra": 1}):
            self.assertEqual(create(body)[0], 400, body)
        status, body, _ = create({"references": ["nginx:1.21", " nginx:1.21 ", "ghcr.io/acme/api:2.0"], "context": "producción"})
        self.assertEqual((status, body["total"], body["label"]), (202, 2, "2 imágenes"))
        self.assertEqual(create({"references": ["nginx:1.27"]})[0], 409)  # one batch at a time

    def test_invalid_requests(self):
        for body, expected in (({"source_ids": ["github:otra/cosa"]}, 400), ({"source_ids": []}, 400),
                               ({"source_ids": ["x"] * 101}, 400), ({"source_ids": ["a"], "account": "acme"}, 400),
                               ({"account": "no-existe"}, 404)):
            status, _, _ = self.create(body, self.admin)
            self.assertEqual(status, expected, body)


if __name__ == "__main__":
    unittest.main()
