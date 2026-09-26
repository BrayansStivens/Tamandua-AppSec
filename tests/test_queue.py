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
