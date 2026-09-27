"""F3: cola durable en PostgreSQL, worker aparte, tokens sellados y buzón de avisos con reintentos."""

import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from sqlalchemy import select, text, update

from tamandua.modules.integrations import notifications
from tamandua.modules.integrations.tables import outbox
from tamandua.modules.runs import queue
from tamandua.modules.runs.jobs import ScanJobs
from tamandua.modules.runs.store import load_run
from tamandua.modules.runs.tables import jobs
from tamandua.shared import db, paths


class QueueTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.directory.name)
        config = patch.object(paths, "CONFIG_DIR", self.data_dir / "config")
        config.start()
        self.addCleanup(config.stop)

    def tearDown(self):
        self.directory.cleanup()

    def test_each_job_goes_to_exactly_one_worker(self):
        for index in range(40):
            queue.enqueue(self.data_dir, "noop", {"n": index})
        claimed, lock = [], threading.Lock()

        def worker(name):
            while (job := queue.claim(self.data_dir, name)) is not None:
                with lock:
                    claimed.append(job["payload"]["n"])
                queue.finish(self.data_dir, job["id"])
        threads = [threading.Thread(target=worker, args=(f"w{index}",)) for index in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sorted(claimed), list(range(40)))  # ni perdidos ni duplicados
        self.assertEqual(queue.pending(self.data_dir), 0)

    def test_a_dead_worker_jobs_are_recovered_and_its_run_fails(self):
        scans = ScanJobs(self.data_dir, worker=False)
        queued = scans.enqueue_image_scan(image={"reference": "nginx:1", "asset": "image:nginx", "name": "nginx"}, context="", requested_by="ana")
        job = queue.claim(self.data_dir, "muerto")
        with db.transaction(self.data_dir) as connection:  # dejó de renovar hace rato
            connection.execute(update(jobs).where(jobs.c.id == job["id"]).values(locked_at=text("now() - interval '10 minutes'")))
        scans._recover(everything=False)
        self.assertEqual(load_run(self.data_dir, queued["id"])["status"], "failed")
        self.assertEqual(queue.pending(self.data_dir), 0)

    def test_a_long_scan_keeps_its_lease_while_another_worker_recovers(self):
        import time
        from datetime import timedelta
        from tamandua.modules.runs import jobs as jobs_module
        slow, busy = ScanJobs(self.data_dir, worker=False), ScanJobs(self.data_dir, worker=False)
        queued = slow.enqueue_image_scan(image={"reference": "nginx:1", "asset": "image:nginx", "name": "nginx"}, context="", requested_by="ana")
        seen = {}

        def scan(job):
            time.sleep(3)  # longer than STALE below: without the heartbeat, the other worker takes it for dead
            seen["status"] = load_run(self.data_dir, queued["id"])["status"]
        slow._execute = scan
        with patch.object(queue, "STALE", timedelta(seconds=1)), patch.object(jobs_module, "HEARTBEAT_SECONDS", 0.2):
            worker = threading.Thread(target=slow.run_worker, daemon=True)
            worker.start()
            time.sleep(1.5)
            busy._recover(everything=False)
            time.sleep(2)
            slow.stop()
            worker.join(10)
        self.assertEqual(seen["status"], "queued")  # never failed by the other worker's recovery
        with db.transaction(self.data_dir) as connection:
            self.assertEqual(connection.execute(select(jobs.c.status)).scalar_one(), "done")

    def test_a_recovered_job_is_not_closed_again_by_its_old_worker(self):
        queue.enqueue(self.data_dir, "noop", {})
        job = queue.claim(self.data_dir, "lento")
        with db.transaction(self.data_dir) as connection:
            connection.execute(update(jobs).where(jobs.c.id == job["id"]).values(locked_at=text("now() - interval '10 minutes'")))
        queue.recover(self.data_dir)
        self.assertFalse(queue.finish(self.data_dir, job["id"], worker="lento"))
        with db.transaction(self.data_dir) as connection:
            self.assertEqual(connection.execute(select(jobs.c.status)).scalar_one(), "failed")

    def test_queued_scans_survive_a_restart_but_orphans_fail(self):
        scans = ScanJobs(self.data_dir, worker=False)
        queued = scans.enqueue_image_scan(image={"reference": "nginx:1", "asset": "image:nginx", "name": "nginx"}, context="", requested_by="ana")
        ScanJobs(self.data_dir, worker=False).prepare(embedded=False)  # otro worker arranca
        self.assertEqual(load_run(self.data_dir, queued["id"])["status"], "queued")  # antes se perdía al reiniciar
        with db.transaction(self.data_dir) as connection:
            connection.execute(update(jobs).values(status="done"))  # la ejecución queda sin trabajo: huérfana
        ScanJobs(self.data_dir, worker=False).prepare(embedded=False)
        self.assertEqual(load_run(self.data_dir, queued["id"])["status"], "failed")

    def test_code_tokens_never_reach_the_database_in_clear(self):
        scans = ScanJobs(self.data_dir, worker=False)
        scans.enqueue_repository_scan(source_id="gitlab:acme/api", source_name="acme/api", allow_osv_upload=False, context="",
                                      tokens={"gitlab": "glpat-SECRETO-123"}, installation_id=None)
        with db.transaction(self.data_dir) as connection:
            stored = json.dumps(connection.execute(select(jobs.c.payload)).scalar_one())
        self.assertNotIn("glpat-SECRETO-123", stored)
        from tamandua.shared import vault
        self.assertEqual(vault.unseal(json.loads(stored)["tokens"], "job-tokens"), {"gitlab": "glpat-SECRETO-123"})
        with self.assertRaises(vault.VaultError):  # sellado para otra cosa: no se abre
            vault.unseal(json.loads(stored)["tokens"], "otra-cosa")

    def test_only_the_leader_feeds_batches(self):
        follower = ScanJobs(self.data_dir, worker=False)
        self.assertFalse(follower.leader)
        with patch.object(follower, "_feed_batch") as feed, patch.object(queue, "claim", return_value=None), \
                patch.object(queue, "heartbeat"), patch.object(queue, "touch"):
            follower.idle_poll = 0.01
            threading.Timer(0.1, follower.stop).start()
            follower.run_worker()
        feed.assert_not_called()
        self.assertTrue(ScanJobs(self.data_dir, worker=True).leader)  # un solo proceso: siempre líder

    def test_a_leader_that_loses_its_connection_stops_its_tasks_and_competes_again(self):
        import time
        from tamandua.app import worker as worker_module
        stopped, started = [], []

        class Task:
            def stop(self):
                stopped.append(True)
        jobs = ScanJobs(self.data_dir, worker=False)
        stop = threading.Event()
        with patch.object(worker_module, "LEADER_CHECK_SECONDS", 0.2), \
                patch.object(worker_module, "start_periodic", side_effect=lambda *_: started.append(True) or [Task()]):
            leader = threading.Thread(target=worker_module._lead, args=(self.data_dir, jobs, stop), daemon=True)
            leader.start()
            try:
                deadline = time.monotonic() + 5
                while not jobs.leader and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertTrue(jobs.leader)
                with db.engine().connect() as admin:  # the database drops the leader's session (restart, network, idle kill)
                    admin.execute(text("SELECT pg_terminate_backend(pid) FROM pg_locks WHERE locktype = 'advisory' "
                                       "AND database = (SELECT oid FROM pg_database WHERE datname = current_database()) "
                                       "AND pid <> pg_backend_pid()"))
                    admin.commit()
                deadline = time.monotonic() + 5
                while not stopped and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertEqual(stopped, [True])  # its periodic tasks stop at once
                deadline = time.monotonic() + 5
                while len(started) < 2 and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertEqual(len(started), 2)  # and it leads again once it gets the lock back
            finally:
                stop.set()
                leader.join(5)

    def test_only_one_worker_leads_the_periodic_tasks(self):
        from tamandua.app.worker import LEADER_KEY
        first, second = db.engine().connect(), db.engine().connect()
        try:
            acquire = text("SELECT pg_try_advisory_lock(:key)")
            self.assertTrue(first.execute(acquire, {"key": LEADER_KEY}).scalar())
            self.assertFalse(second.execute(acquire, {"key": LEADER_KEY}).scalar())
            first.invalidate()  # el líder muere: su conexión se cierra de verdad (no vuelve al pool) y el cerrojo se libera
            self.assertTrue(second.execute(acquire, {"key": LEADER_KEY}).scalar())
        finally:
            second.close()


class OutboxTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.directory.name)
        channel = {"kind": "webhook", "name": "hook", "url": "https://hooks.example.com/x", "events": ["findings", "batches"],
                   "threshold": "high", "secret": "s"}
        vault_patch = patch.object(notifications, "_vault", return_value={"c1": channel})
        record_patch = patch.object(notifications, "_record_delivery")
        vault_patch.start()
        record_patch.start()
        self.addCleanup(vault_patch.stop)
        self.addCleanup(record_patch.stop)

    def tearDown(self):
        self.directory.cleanup()

    def test_a_message_is_sent_outside_any_transaction(self):
        from tamandua.shared.db import _current
        seen = []
        notifications.deliver("findings", lambda channel: {"event": "findings", "title": "t", "text": "x", "asset": None,
                                                           "run_id": None, "link": None, "counts": {}, "items": [], "more": 0},
                              data_dir=self.data_dir)
        notifications.drain(self.data_dir, sender=lambda url, body, headers: seen.append(_current.get()) or (True, "HTTP 200"))
        self.assertEqual(seen, [None])  # no connection held while the webhook answers

    def test_messages_wait_in_the_outbox_and_are_retried(self):
        notifications.on_batch({"label": "3 repositorios", "done": 3, "failed": 0, "critical": 1, "high": 2}, data_dir=self.data_dir)
        answers = iter([(False, "HTTP 503"), (True, "HTTP 200")])
        with patch.object(notifications, "_post", side_effect=lambda *args, **kwargs: next(answers)):
            self.assertEqual(notifications.drain(self.data_dir), 1)  # falla: se reintenta más tarde
            self.assertEqual(notifications.drain(self.data_dir), 0)  # todavía no le toca
            with db.transaction(self.data_dir) as connection:
                connection.execute(update(outbox).values(next_attempt_at=text("now() - interval '1 second'")))
            self.assertEqual(notifications.drain(self.data_dir), 1)
        with db.transaction(self.data_dir) as connection:
            row = connection.execute(select(outbox.c.status, outbox.c.attempts)).one()
        self.assertEqual((row.status, row.attempts), ("sent", 2))
        self.assertEqual(notifications.RETRY_MINUTES[0], 1)


if __name__ == "__main__":
    unittest.main()
