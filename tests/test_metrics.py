"""Operator signals: the Prometheus endpoint (bearer token, format, figures), degraded health and the proxy setting."""

import json
import os
import re
import tempfile
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import asgi
from tamandua.app.api import metrics as metrics_api
from tamandua.app.api.server import build_state, proxy_settings
from tamandua.modules.identity.auth import Users
from tamandua.modules.runs import queue
from tamandua.modules.runs.store import save_record

TOKEN = "a1" * 32
ORIGIN = "http://127.0.0.1:8766"
# One sample line of the text exposition format: name, optional labels, value.
SAMPLE = re.compile(r'^[a-zA-Z_:][a-zA-Z0-9_:]*(\{([a-zA-Z_][a-zA-Z0-9_]*="([^"\\]|\\.)*",?)*\})? (-?[0-9.eE+-]+|NaN)$')


class MetricsTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.directory.name)
        for patcher in (patch("tamandua.shared.paths.CONFIG_DIR", self.data_dir / "config"),
                        patch.dict("tamandua.modules.scanning.engines._docker_state", {"ok": False}, clear=True),
                        patch.dict(os.environ, {"TAMANDUA_REQUIRE_TOTP": "none"})):
            patcher.start()
            self.addCleanup(patcher.stop)
        # No worker in this process: the heartbeats are the test's.
        self.state = build_state(self.data_dir, worker=False)
        self.client = asgi.client_for(self.data_dir, self.state)

    def tearDown(self):
        self.directory.cleanup()

    def scrape(self, authorization=None, token=TOKEN):
        with patch.dict(os.environ, {"TAMANDUA_METRICS_TOKEN": token}):
            return asgi.request(self.client, "GET", "/api/metrics", headers={"Authorization": authorization} if authorization else {})

    def test_off_without_a_token_and_with_a_short_one(self):
        self.assertEqual(self.scrape(f"Bearer {TOKEN}", token="").status_code, 404)
        self.assertEqual(self.scrape("Bearer short", token="short").status_code, 404)

    def test_requires_the_exact_bearer_token(self):
        for header in (None, f"Bearer {TOKEN}x", f"Basic {TOKEN}", TOKEN, "Bearer "):
            response = self.scrape(header)
            self.assertEqual(response.status_code, 401, header)
            self.assertTrue(response.headers["www-authenticate"].startswith("Bearer"))
            self.assertIn("error", response.json())
            self.assertNotIn(TOKEN, response.text)
        self.assertEqual(self.scrape(f"bearer {TOKEN}").status_code, 200)

    def test_exposition_format_and_figures(self):
        queue.enqueue(self.data_dir, "noop", {})
        failed = queue.enqueue(self.data_dir, "noop", {})
        queue.claim(self.data_dir, "host:1")  # the older one: running
        queue.finish(self.data_dir, failed, error="boom")
        queue.heartbeat(self.data_dir, "host:1", docker=True, version="test")
        now = datetime.now(timezone.utc)
        save_record(self.data_dir, {"id": uuid.uuid4().hex, "type": "repository_scan", "status": "completed",
                                    "created_at": now.isoformat(), "started_at": (now - timedelta(seconds=90)).isoformat(),
                                    "finished_at": now.isoformat()})
        save_record(self.data_dir, {"id": uuid.uuid4().hex, "type": "repository_scan", "status": "queued",
                                    "created_at": now.isoformat()})

        response = self.scrape(f"Bearer {TOKEN}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "text/plain; version=0.0.4; charset=utf-8")
        lines = response.text.rstrip("\n").split("\n")
        samples = {}
        for line in lines:
            if line.startswith("# "):
                self.assertRegex(line, r"^# (HELP|TYPE) tamandua_[a-z0-9_]+ ")
                continue
            self.assertRegex(line, SAMPLE)
            name, value = line.rsplit(" ", 1)
            samples[name] = value
        self.assertEqual(samples['tamandua_jobs{status="running"}'], "1")
        self.assertEqual(samples['tamandua_jobs{status="failed"}'], "1")
        self.assertEqual(samples['tamandua_jobs{status="queued"}'], "0")
        self.assertEqual(samples["tamandua_jobs_failed_24h"], "1")
        self.assertEqual(samples["tamandua_workers_alive"], "1")
        self.assertEqual(samples["tamandua_workers_docker"], "1")
        self.assertEqual(samples['tamandua_runs_24h{type="repository_scan",status="completed"}'], "1")
        self.assertEqual(samples['tamandua_runs_24h{type="repository_scan",status="queued"}'], "1")
        self.assertAlmostEqual(float(samples['tamandua_run_duration_seconds_24h{type="repository_scan",status="completed",quantile="1"}']), 90, delta=1)
        self.assertNotIn('tamandua_run_duration_seconds_24h{type="repository_scan",status="queued",quantile="1"}', samples)
        # Aggregates only: no job, run or worker identifiers.
        self.assertNotIn("host:1", response.text)

    def test_empty_database(self):
        response = self.scrape(f"Bearer {TOKEN}")
        self.assertIn("tamandua_jobs_oldest_queued_age_seconds 0.0", response.text)
        self.assertIn("tamandua_worker_last_heartbeat_age_seconds NaN", response.text)
        self.assertIn("tamandua_workers_alive 0", response.text)

    def test_label_values_are_escaped(self):
        text = metrics_api.render({"jobs": {}, "jobs_failed_window": 0, "oldest_queued_seconds": 0.0,
                                   "workers": {"alive": 0, "docker": 0, "last_heartbeat_seconds": None},
                                   "runs": [{"type": 'a"b\\c\nd', "status": "x", "total": 1, "timed": 0, "max": None,
                                             "quantiles": {}}]})
        self.assertIn('tamandua_runs_24h{type="a\\"b\\\\c\\nd",status="x"} 1', text)


class DegradedHealthTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.directory.name)
        for patcher in (patch("tamandua.shared.paths.CONFIG_DIR", self.data_dir / "config"),
                        patch.dict(os.environ, {"TAMANDUA_REQUIRE_TOTP": "none"})):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.client = asgi.client_for(self.data_dir, build_state(self.data_dir, worker=False))
        Users(self.data_dir).create("operadora", "correcto-caballo-bateria", role="admin")
        login = asgi.request(self.client, "POST", "/api/auth/login",
                             json.dumps({"username": "operadora", "password": "correcto-caballo-bateria"}),
                             {"Origin": ORIGIN, "X-Tamandua-Action": "login", "Content-Type": "application/json"})
        self.cookie = login.headers["set-cookie"].split(";", 1)[0]

    def tearDown(self):
        self.directory.cleanup()

    def health(self, cookie=None):
        response = asgi.request(self.client, "GET", "/api/health", headers={"Cookie": cookie} if cookie else {})
        self.assertEqual(response.status_code, 200)  # always 200: the API answers even without a worker
        return response.json()

    def test_degraded_without_a_worker_heartbeat_only_for_signed_in_users(self):
        self.assertEqual(self.health(self.cookie)["status"], "degraded")
        self.assertEqual(self.health(), {"status": "ok", "version": self.health()["version"]})  # no internal state
        queue.heartbeat(self.data_dir, "host:1", docker=True, version="test")
        body = self.health(self.cookie)
        self.assertEqual((body["status"], body["workers"], body["docker"]), ("ok", 1, True))


class ProxySettingsTests(unittest.TestCase):
    def test_forwarded_headers_only_from_configured_proxies(self):
        with patch.dict(os.environ, {"TAMANDUA_FORWARDED_ALLOW_IPS": ""}):
            self.assertEqual(proxy_settings(), {"proxy_headers": False})
        with patch.dict(os.environ, {"TAMANDUA_FORWARDED_ALLOW_IPS": "*"}):
            self.assertEqual(proxy_settings(), {"proxy_headers": True, "forwarded_allow_ips": "*"})


if __name__ == "__main__":
    unittest.main()
