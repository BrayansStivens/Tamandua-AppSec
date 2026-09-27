"""Periodic tasks as rounds: due ones run once however many schedulers fire, and an API queues the heavy ones."""

import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from tamandua.modules.runs import periodic, queue
from tamandua.modules.runs.jobs import ScanJobs
from tamandua.shared import paths

from tests.test_auth import HttpCase

NOW = datetime(2026, 9, 27, 12, 0, tzinfo=timezone.utc)
TOKEN = "c" * 40


class RoundTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data_dir = Path(self.directory.name)
        config = patch.object(paths, "CONFIG_DIR", self.data_dir / "config")
        config.start()
        self.addCleanup(config.stop)
        self.calls = []
        fakes = {name: periodic.Task(task.every, task.on_worker, lambda data_dir, jobs, name=name: self.calls.append(name))
                 for name, task in periodic.TASKS.items()}
        tasks = patch.dict(periodic.TASKS, fakes)
        tasks.start()
        self.addCleanup(tasks.stop)
        self.jobs = ScanJobs(self.data_dir, worker=False)

    def test_an_api_runs_the_light_tasks_and_queues_the_heavy_ones(self):
        outcome = periodic.run_round(self.data_dir, self.jobs, here_only=True, now=NOW)
        self.assertEqual((sorted(outcome["ran"]), sorted(outcome["queued"])), (["outbox", "pull_requests"], ["advisories", "nvd"]))
        self.assertEqual(sorted(self.calls), ["outbox", "pull_requests"])
        self.assertEqual(queue.pending(self.data_dir), 2)
        job = queue.claim(self.data_dir, "w")
        self.jobs._execute({**job["payload"], "kind": job["kind"], "run_id": job["run_id"]})  # the worker runs it
        self.assertIn(job["payload"]["task"], self.calls)

    def test_a_task_runs_once_per_interval_whoever_fires(self):
        with patch.dict(os.environ, {"TAMANDUA_PR_POLL_SECONDS": "300", "TAMANDUA_CVE_SYNC": "off"}):
            periodic.run_round(self.data_dir, self.jobs, here_only=False, now=NOW)
            again = periodic.run_round(self.data_dir, self.jobs, here_only=False, now=NOW + timedelta(seconds=60))
            later = periodic.run_round(self.data_dir, self.jobs, here_only=False, now=NOW + timedelta(seconds=301))
        self.assertEqual(again["ran"], ["outbox"])  # the outbox goes every round; PRs wait their interval
        self.assertIn("pull_requests", later["ran"])
        with patch.dict(os.environ, {"TAMANDUA_CVE_SYNC": "on"}):
            first = periodic.run_round(self.data_dir, self.jobs, here_only=True, now=NOW)
            soon = periodic.run_round(self.data_dir, self.jobs, here_only=True, now=NOW + timedelta(minutes=1))
        self.assertEqual(("nvd" in first["queued"], "nvd" in soon["queued"]), (True, False))  # never piles up
        self.assertNotIn("nvd", self.calls)  # off


class CronRouteTests(HttpCase):
    def test_off_without_a_token_and_bearer_only(self):
        self.assertEqual(self.call("GET", "/api/cron")[0], 404)
        with patch.dict(os.environ, {"CRON_SECRET": TOKEN}):  # leader mode: the leader runs them, never twice
            self.assertEqual(self.call("GET", "/api/cron", headers={"Authorization": f"Bearer {TOKEN}"})[0], 404)
        with patch.dict(os.environ, {"CRON_SECRET": TOKEN, "TAMANDUA_PERIODIC": "external"}), \
                patch.object(periodic, "run_round", return_value={"ran": ["outbox"], "queued": [], "failed": []}) as round_:
            self.assertEqual(self.call("GET", "/api/cron")[0], 401)
            self.assertEqual(self.call("GET", "/api/cron", headers={"Authorization": "Bearer " + "x" * 40})[0], 401)
            status, body, _ = self.call("GET", "/api/cron", headers={"Authorization": f"Bearer {TOKEN}"})
        self.assertEqual((status, body["ran"]), (200, ["outbox"]))
        self.assertTrue(round_.call_args.kwargs["here_only"])


class NvdTaskTests(unittest.TestCase):
    def test_nvd_throttling_ends_the_round_quietly(self):
        from urllib.error import HTTPError
        with tempfile.TemporaryDirectory() as folder, \
                patch("tamandua.modules.intel.advisories.load_feeds", return_value={}), \
                patch("tamandua.modules.intel.cve_db.load_signals"), \
                patch("tamandua.modules.intel.cve_db.sync_step", side_effect=HTTPError("https://nvd", 403, "Forbidden", None, None)):
            self.assertEqual(periodic._nvd(Path(folder), None), 0)


if __name__ == "__main__":
    unittest.main()
