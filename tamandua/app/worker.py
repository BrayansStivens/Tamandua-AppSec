"""Proceso worker: ejecuta los análisis de la cola y las tareas periódicas. Es el único que necesita Docker.

* Análisis: reclama trabajos de la cola de PostgreSQL (varios workers pueden correr a la vez).
* Tareas periódicas —vigilancia de PRs y de la rama principal, avisos nuevos diarios, sincronización de NVD y el
  buzón de avisos—: solo las corre un worker, el que tiene el cerrojo de líder en PostgreSQL. Si ese worker muere,
  su conexión se cierra, el cerrojo se libera y otro lo toma.
"""

from __future__ import annotations

import hashlib
import signal
import threading
from pathlib import Path

from sqlalchemy import text

from tamandua.app import data_migrations, wiring
from tamandua.modules.runs.jobs import ScanJobs
from tamandua.shared import db
from tamandua.shared import log as logging_setup
from tamandua.shared.i18n import t

LEADER_KEY = int.from_bytes(hashlib.sha256(b"tamandua:worker-leader").digest()[:8], "big", signed=True)


def start_periodic(data_dir: Path, jobs: ScanJobs) -> list:
    """Arranca las tareas periódicas (hilos). Las usan el worker líder y el modo de un solo proceso."""
    from tamandua.modules.integrations.installations import github_installations
    from tamandua.modules.runs.advisory_watch import Watcher as AdvisoryWatcher
    from tamandua.modules.intel.cve_db import Syncer
    from tamandua.modules.pullrequests.watch import Watcher
    tasks = [Watcher(data_dir, jobs, lambda: github_installations(data_dir)), Syncer(data_dir),
             # Una vez al día, las dependencias ya analizadas contra los avisos publicados después (sin conexión).
             AdvisoryWatcher(data_dir), OutboxDrainer(data_dir)]
    for task in tasks:
        task.start()
    return tasks


class OutboxDrainer:
    """Entrega el buzón de avisos cada pocos segundos (con reintentos; ver notifications.drain)."""

    def __init__(self, data_dir: Path, interval: float = 10.0):
        self.data_dir, self.interval = data_dir, interval
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, name="tamandua-outbox", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        from tamandua.modules.integrations import notifications
        log = logging_setup.get("outbox")
        while not self._stop.wait(self.interval):
            try:
                notifications.drain(self.data_dir)
            except Exception:  # noqa: BLE001 — un canal o la base caídos no paran el worker
                log.exception("outbox_drain_failed")


def _lead(data_dir: Path, jobs: ScanJobs, stop: threading.Event) -> None:
    """Intenta ser líder; si lo consigue, arranca las tareas periódicas y mantiene la conexión (y el cerrojo)."""
    log = logging_setup.get("worker")
    while not stop.is_set():
        connection = db.engine().connect()
        try:
            if connection.execute(text("SELECT pg_try_advisory_lock(:key)"), {"key": LEADER_KEY}).scalar():
                connection.commit()
                log.info("worker_leader", extra={"reason": "este worker corre las tareas periódicas y avanza los lotes"})
                jobs.leader = True
                start_periodic(data_dir, jobs)
                stop.wait()  # mientras viva el proceso, la conexión abierta conserva el cerrojo
                return
            connection.rollback()
        except Exception:  # noqa: BLE001
            log.exception("worker_leader_failed")
        connection.close()
        stop.wait(60)


def run(data_dir: Path) -> None:
    wiring.configure()
    data_migrations.upgrade(data_dir)
    logging_setup.configure(data_dir)
    jobs = ScanJobs(data_dir, worker=False)
    jobs.prepare(embedded=False)
    stop = threading.Event()

    def shutdown(*_args) -> None:
        stop.set()
        jobs.stop()
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    threading.Thread(target=_lead, args=(data_dir, jobs, stop), name="tamandua-leader", daemon=True).start()
    print(t("cli.worker.started"), flush=True)
    jobs.run_worker()
    print(t("cli.worker.stopped"), flush=True)


def healthy(data_dir: Path) -> bool:
    """Para el healthcheck del contenedor: algún worker de esta máquina (hostname) latió hace poco."""
    import socket
    from tamandua.modules.runs import queue
    host = socket.gethostname()
    return any(worker["id"].startswith(f"{host}:") for worker in queue.workers_alive(data_dir))
