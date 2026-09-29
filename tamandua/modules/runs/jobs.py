"""Background scans with visible progress, on the durable PostgreSQL queue (runs/queue.py).

Queueing doesn't block the HTTP request: the run record (`queued`) and a job in the queue are stored, and the
id comes back right away. A worker (the `worker` process or, in single-process installs, a thread inside the
server) claims the jobs and runs them. While it runs, the run stores progress events meant for the user:
never internal paths, raw tool output or errors with infrastructure details. The code tokens that come with
a job are sealed with the master key, never stored in the clear.
"""

from __future__ import annotations

import os
import socket
import threading
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Callable
import uuid

from tamandua.modules.findings import registry as findings_registry
from tamandua.shared import log as logging_setup, settings
from tamandua.modules.scanning.repository import scan_repository
from tamandua.modules.sources.repositories import SourceError, snapshot_source
from tamandua.modules.sources.assets import asset_key, scan_branch
from tamandua.modules.integrations.github import GitHubAppError
from tamandua.modules.runs import queue
from tamandua.modules.runs import registry as run_registry
from tamandua.modules.runs.store import find_runs, load_run, save_record, save_repository_scan
from tamandua.shared import db, vault
from tamandua.shared.i18n import msg, text

log = logging_setup.get("jobs")
HEARTBEAT_SECONDS = 30  # well under queue.STALE
Progress = Callable[[str, object], None]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _event(level: str, message) -> dict:
    # Plain strings (older callers) are capped; catalog messages are stored whole.
    return {"at": _now(), "level": level, "message": message[:300] if isinstance(message, str) else message}


def _reason(exc: Exception):
    """The error's own message (a catalog message or plain text), to embed in ours."""
    value = getattr(exc, "message", None) or (exc.args[0] if exc.args else "")
    return value if isinstance(value, dict) else str(exc)[:300]


def _counts(summary: dict) -> dict:
    severities = summary.get("severities") or {}
    return msg("runs.progress.counts", count=summary["candidates"], critical=severities.get("critical", 0), high=severities.get("high", 0))


class ScanJobs:
    """Queues scans and, if `worker` (the default), runs them in a thread of this process. The `worker` process
    (python -m tamandua worker) uses the same class with `run_worker()`, without threads."""

    def __init__(self, data_dir: Path, *, worker: bool = True):
        self.data_dir = data_dir
        self.worker_id = f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:6]}"
        # How often the worker, with nothing queued, checks for a batch to advance.
        self.idle_poll = 3.0
        self._stop = threading.Event()
        self._thread = None
        # Only the leader advances batches (with several workers, two could take the same repository). In a single
        # process it is always the leader; the worker process turns it on when it wins the leader lock.
        self.leader = worker
        if worker:
            self.prepare(embedded=True)
            self._thread = threading.Thread(target=self.run_worker, name="tamandua-scans", daemon=True)
            self._thread.start()

    def prepare(self, *, embedded: bool) -> None:
        """On worker start. `embedded`: a single process, so whatever shows as running died with the previous one."""
        from tamandua.modules.runs import batches
        self._recover(everything=embedded)
        batches.release_taken(self.data_dir)
        # The findings registry is derived from the runs: if it is empty and there are runs, it is rebuilt.
        if findings_registry.is_empty(self.data_dir) and find_runs(self.data_dir, limit=1):
            run_registry.rebuild(self.data_dir)

    def stop(self) -> None:
        self._stop.set()

    def _recover(self, *, everything: bool) -> None:
        """Runs that will never finish: from a worker that stopped responding, or with no job in the queue (from an
        older version or an outage). They are marked failed with a clear message; relaunching them is up to the user."""
        from sqlalchemy import select, update
        from tamandua.modules.runs.tables import jobs
        from tamandua.shared import db
        interrupted = {job["run_id"] for job in queue.recover(self.data_dir) if job.get("run_id")}
        with db.transaction(self.data_dir) as connection:
            if everything:
                rows = connection.execute(update(jobs).where(jobs.c.tenant_id == db.TENANT, jobs.c.status == "running")
                                          .values(status="failed", error="Interrupted by a restart").returning(jobs.c.run_id)).all()
                interrupted |= {row.run_id for row in rows if row.run_id}
            active = set(connection.execute(select(jobs.c.run_id).where(jobs.c.tenant_id == db.TENANT,
                                                                       jobs.c.status.in_(("queued", "running")))).scalars())
        for row in find_runs(self.data_dir, statuses=("queued", "running")):
            if row["id"] in interrupted or row["id"] not in active:
                try:
                    record = load_run(self.data_dir, row["id"])
                except (ValueError, OSError):
                    continue
                self._fail(record, msg("runs.failure.restart"))
                log.warning("ejecución interrumpida por reinicio", extra={"run_id": row["id"]})

    # --- public API ----------------------------------------------------------------

    def enqueue_repository_scan(self, *, source_id: str, source_name: str, allow_osv_upload: bool,
                                context: str, tokens: dict[str, str], installation_id: int | None, uid: str | None = None,
                                requested_by: str | None = None, trigger: dict | None = None,
                                branch: str | None = None, commit: str | None = None) -> dict:
        """`branch` and `commit` pin what to scan (branch watch); otherwise the worker resolves the repository's scan
        branch (or the default one) and its latest commit when the job runs."""
        run_id = uuid.uuid4().hex
        source = {"id": source_id, "uid": uid, "name": source_name, "provider": source_id.partition(":")[0]}
        planned = branch or (scan_branch(self.data_dir, uid) if uid else None)
        if planned:
            source["branch"] = planned
        record = {"schema_version": "0.3.0", "id": run_id, "type": "repository_scan", "status": "queued",
                  "created_at": _now(), "target": source_name, "variant": "code", "source": source,
                  "context": " ".join(context.split())[:400], "summary": {"candidates": 0, "files": 0, "dependencies": 0},
                  "steps": [], "findings": [], "owasp_coverage": [], "limitations": [],
                  "progress": [_event("info", msg("runs.progress.queued"))]}
        if requested_by:
            record["requested_by"] = requested_by
        if trigger:
            # What triggered it (e.g. the main-branch watch, with the commit it saw change).
            record["trigger"] = trigger
        # The run and its job in one transaction: another worker's recovery never sees a queued run without its job.
        with db.transaction(self.data_dir):
            self._save(record)
            # Code tokens are never stored in the clear in the queue: they are sealed with the master key.
            queue.enqueue(self.data_dir, "repository_scan", {"source_id": source_id, "allow_osv_upload": allow_osv_upload, "context": context,
                                                             "tokens": vault.seal(tokens, "job-tokens") if tokens else None,
                                                             "installation_id": installation_id, "uid": uid,
                                                             "branch": branch, "commit": commit}, run_id=run_id)
        log.info("escaneo encolado", extra={"run_id": run_id, "path": source_id})
        return {"id": run_id, "status": "queued"}

    def enqueue_pr_review(self, *, source_id: str, pull: dict, installation_id: int, requested_by: str, uid: str | None = None,
                          default_branch: str | None = None) -> dict:
        """Review of a PR's head commit. Marked as reviewed when queued so it isn't queued twice."""
        from tamandua.modules.pullrequests import watch as pr_watch
        run_id = uuid.uuid4().hex
        name = source_id.removeprefix("github:")
        record = {"schema_version": "0.3.0", "id": run_id, "type": "pr_review", "status": "queued", "created_at": _now(),
                  "target": f"{name}#{pull['number']}", "variant": "pull_request",
                  "source": {"id": source_id, "uid": uid, "name": name, "provider": "github"},
                  "pull_request": {key: pull.get(key) for key in ("number", "title", "url", "author", "head_sha", "head_ref", "base_ref")},
                  "requested_by": requested_by, "context": "", "summary": {"candidates": 0, "files": 0, "dependencies": 0},
                  "steps": [], "findings": [], "owasp_coverage": [], "limitations": [],
                  "progress": [_event("info", msg("runs.progress.queued_pr", number=pull["number"], sha=pull["head_sha"][:7]))]}
        # All or nothing: a commit is never marked as reviewed without its review queued.
        with db.transaction(self.data_dir):
            self._save(record)
            pr_watch.mark(self.data_dir, uid or source_id, pull["number"], pull["head_sha"], run_id)
            queue.enqueue(self.data_dir, "pr_review", {"source_id": source_id, "pull": pull, "installation_id": installation_id,
                                                       "default_branch": default_branch}, run_id=run_id)
        log.info("revisión de PR encolada", extra={"run_id": run_id, "path": f"{source_id}#{pull['number']}"})
        return {"id": run_id, "status": "queued"}

    def enqueue_image_scan(self, *, image: dict, context: str, requested_by: str) -> dict:
        """Scan of a container image read from the registry: it is neither run nor built."""
        run_id = uuid.uuid4().hex
        record = {"schema_version": "0.3.0", "id": run_id, "type": "image_scan", "status": "queued", "created_at": _now(),
                  "target": image["reference"], "variant": "image",
                  "source": {"id": image["asset"], "uid": None, "name": image["name"], "provider": "registry", "image": image},
                  "requested_by": requested_by, "context": " ".join(context.split())[:400],
                  "summary": {"candidates": 0, "files": 0, "dependencies": 0},
                  "steps": [], "findings": [], "owasp_coverage": [], "limitations": [],
                  "progress": [_event("info", msg("runs.progress.queued_image", image=image["reference"]))]}
        with db.transaction(self.data_dir):
            self._save(record)
            queue.enqueue(self.data_dir, "image_scan", {"image": image, "context": context}, run_id=run_id)
        log.info("análisis de imagen encolado", extra={"run_id": run_id, "path": image["reference"]})
        return {"id": run_id, "status": "queued"}

    def enqueue_periodic(self, task: str) -> None:
        """A periodic task (NVD sync, advisory watch) for a worker to run: see runs/periodic.py."""
        queue.enqueue(self.data_dir, "periodic", {"task": task})

    def pending(self) -> int:
        return queue.pending(self.data_dir)

    def _feed_batch(self) -> None:
        from tamandua.modules.runs import batches
        try:
            taken = batches.take_next(self.data_dir)
        except (OSError, ValueError):
            log.exception("no se pudo leer el lote activo")
            return
        if taken is None:
            return
        batch, index = taken
        item = batch["items"][index]
        try:
            if item.get("kind") == "image":
                queued = self.enqueue_image_scan(image=item["image"], context=batch["context"], requested_by=batch.get("by") or "lote")
            else:
                queued = self.enqueue_repository_scan(source_id=item["source_id"], source_name=item["name"],
                                                      allow_osv_upload=batch["allow_osv_upload"], context=batch["context"],
                                                      tokens={}, installation_id=item.get("installation_id"), uid=item.get("uid"))
            batches.attach(self.data_dir, batch["id"], index, run_id=queued["id"])
        except Exception as exc:  # noqa: BLE001 — a failing repository doesn't stop the batch
            batches.attach(self.data_dir, batch["id"], index, error=_reason(exc))

    # --- worker --------------------------------------------------------------------

    def run_worker(self) -> None:
        """Claims and runs jobs until asked to stop. The heartbeat keeps beating while a scan runs (scans take far
        longer than queue.STALE), so no other worker takes a live job for a dead one."""
        beat = 0.0
        while not self._stop.is_set():
            if time.monotonic() - beat > HEARTBEAT_SECONDS:
                beat = time.monotonic()
                self._beat(recover=True)
            try:
                job = queue.claim(self.data_dir, self.worker_id)
            except Exception:  # noqa: BLE001
                log.exception("no se pudo reclamar trabajo")
                self._stop.wait(self.idle_poll)
                continue
            if job is None:
                # With nothing pending, the next repository of the active batch (if any); leader only.
                if self.leader:
                    self._feed_batch()
                self._stop.wait(self.idle_poll)
                continue
            error = None
            done = threading.Event()
            beating = threading.Thread(target=self._beat_until, args=(done,), name="tamandua-heartbeat", daemon=True)
            beating.start()
            try:
                self._execute({**job["payload"], "kind": job["kind"], "run_id": job["run_id"]})
            except Exception as exc:  # noqa: BLE001 — the worker must never die because of a scan
                error = type(exc).__name__
                log.exception("fallo inesperado del trabajador", extra={"run_id": job.get("run_id")})
            finally:
                done.set()
                beating.join()
                beat = time.monotonic()
                if not queue.finish(self.data_dir, job["id"], error=error, worker=self.worker_id):
                    log.warning("job_lease_lost", extra={"run_id": job.get("run_id")})

    def _beat(self, *, recover: bool) -> None:
        from tamandua.modules.scanning.engines import engines_available
        from tamandua.version import VERSION
        try:
            queue.heartbeat(self.data_dir, self.worker_id, docker=engines_available(), version=VERSION)
            queue.touch(self.data_dir, self.worker_id)
            if recover:
                self._recover(everything=False)
        except Exception:  # noqa: BLE001 — the database may not be ready for a moment; it retries
            log.exception("latido del worker fallido")

    def _beat_until(self, done: threading.Event) -> None:
        while not done.wait(HEARTBEAT_SECONDS):
            self._beat(recover=False)

    def _execute(self, job: dict) -> None:
        if job.get("kind") == "periodic":
            # Already claimed as due by whoever queued it: the worker just runs it.
            from tamandua.modules.runs import periodic
            task = periodic.TASKS.get(job.get("task"))
            if task is not None:
                log.info("periodic_task_done", extra={"reason": f"{job['task']}: {task.run(self.data_dir, self)}"})
            return None
        if job.get("kind") == "pr_review":
            return self._execute_pr(job)
        if job.get("kind") == "image_scan":
            return self._execute_image(job)
        run_id = job["run_id"]
        tokens = vault.unseal(job["tokens"], "job-tokens") if job.get("tokens") else {}
        record = load_run(self.data_dir, run_id)
        record["status"] = "running"
        record["started_at"] = _now()

        def progress(level: str, message) -> None:
            record["progress"].append(_event(level, message))
            self._save(record)
            log.info(text(message, "en"), extra={"run_id": run_id, "step": level})

        work = self.data_dir / "work"
        work.mkdir(parents=True, exist_ok=True)
        try:
            branch, commit = self._revision(job, record)
            if branch and commit:
                record["source"] = {**(record.get("source") or {}), "branch": branch, "commit": commit}
                progress("info", msg("runs.progress.branch_commit", branch=branch, sha=commit[:7]))
            progress("info", msg("runs.progress.downloading_snapshot"))
            with TemporaryDirectory(prefix="snapshot-", dir=work) as temporary:
                root, source = snapshot_source(job["source_id"], Path(temporary), tokens, job["installation_id"], ref=commit, progress=progress)
                if branch and commit:
                    source = {**source, "branch": branch, "commit": commit}
                snapshot = source.get("snapshot") or {}
                skipped = snapshot.get("skipped_not_analyzable")
                progress("ok", msg("runs.progress.snapshot_ready_skipped", count=source.get("files", 0), skipped=skipped) if skipped
                         else msg("runs.progress.snapshot_ready", count=source.get("files", 0)))
                scan = scan_repository(root, source, allow_osv_upload=job["allow_osv_upload"],
                                       context=job["context"], data_dir=self.data_dir, progress=progress)
            counts = _counts(scan["summary"])
            if scan["status"] == "incomplete":
                progress("warn", msg("runs.progress.finished_incomplete", counts=counts))
            else:
                progress("ok", msg("runs.progress.finished", counts=counts))
            final = save_repository_scan(self.data_dir, {**scan, "progress": record["progress"],
                                                         "started_at": record["started_at"], "finished_at": _now()},
                                         run_id=run_id, created_at=record["created_at"])
            log.info("escaneo terminado", extra={"run_id": run_id, "status": final["status"]})
        except (SourceError, GitHubAppError) as exc:
            self._fail(record, msg("runs.failure.source", reason=_reason(exc)))
        except Exception as exc:  # noqa: BLE001
            log.error("escaneo fallido: %s", traceback.format_exc().splitlines()[-1], extra={"run_id": run_id})
            # The user is told it failed and in which phase, never the traceback or server paths.
            self._fail(record, msg("runs.failure.internal"))
            del exc

    def _execute_image(self, job: dict) -> None:
        from tamandua.modules.scanning.image import ImageError, scan_image
        run_id = job["run_id"]
        record = load_run(self.data_dir, run_id)
        record["status"] = "running"
        record["started_at"] = _now()

        def progress(level: str, message) -> None:
            record["progress"].append(_event(level, message))
            self._save(record)
            log.info(text(message, "en"), extra={"run_id": run_id, "step": level})

        try:
            scan = scan_image(job["image"], data_dir=self.data_dir, context=job["context"], progress=progress)
            counts = _counts(scan["summary"])
            if scan["status"] == "incomplete":
                progress("warn", msg("runs.progress.finished_incomplete", counts=counts))
            else:
                progress("ok", msg("runs.progress.finished", counts=counts))
            final = save_repository_scan(self.data_dir, {**scan, "requested_by": record.get("requested_by"), "progress": record["progress"],
                                                         "started_at": record["started_at"], "finished_at": _now()},
                                         run_id=run_id, created_at=record["created_at"])
            log.info("análisis de imagen terminado", extra={"run_id": run_id, "status": final["status"]})
        except ImageError as exc:  # e.g. the registry now resolves to a private address
            log.warning("image_scan_refused", extra={"run_id": run_id, "reason": str(exc)})
            self._fail(record, exc.message)
        except Exception as exc:  # noqa: BLE001
            log.error("análisis de imagen fallido: %s", traceback.format_exc().splitlines()[-1], extra={"run_id": run_id})
            self._fail(record, msg("runs.failure.image_internal"))
            del exc

    def _revision(self, job: dict, record: dict) -> tuple[str | None, str | None]:
        """Branch and commit a GitHub App scan reads: the pinned ones, else the repository's scan branch, else its
        default branch, at its latest commit. (None, None) outside the GitHub App: the provider serves its default."""
        from tamandua.modules.integrations.github import branch_head, installation_repository
        source_id, installation = job["source_id"], job.get("installation_id")
        if not source_id.startswith("github:") or installation is None:
            return None, None
        uid = job.get("uid") or (record.get("source") or {}).get("uid")
        branch = job.get("branch") or (scan_branch(self.data_dir, uid) if uid else None)
        if branch and job.get("commit"):
            return branch, job["commit"]
        if branch:
            return branch, branch_head(installation, source_id.removeprefix("github:"), branch)
        # Default branch: if GitHub can't tell which one or its head right now, the tarball still serves it unpinned.
        try:
            branch = (installation_repository(installation, source_id) or {}).get("branch")
            return (branch, branch_head(installation, source_id.removeprefix("github:"), branch)) if branch else (None, None)
        except GitHubAppError:
            return None, None

    def _baseline(self, source_id: str, uid: str | None = None, *, branch: str | None = None,
                  default_branch: str | None = None) -> dict | None:
        """Latest full scan of the PR's base branch: what was already there before the PR.

        Scans that don't record their branch read the default branch."""
        for row in find_runs(self.data_dir, types=("repository_scan",), statuses=("completed", "incomplete"), assets=(source_id, uid)):
            scanned = (row.get("source") or {}).get("branch") or default_branch
            if branch and scanned and scanned != branch:
                continue
            try:
                return load_run(self.data_dir, row["id"])
            except (ValueError, OSError):
                return None
        return None

    def _execute_pr(self, job: dict) -> None:
        from tamandua.modules.pullrequests import review as pr_review
        from tamandua.modules.pullrequests import watch as pr_watch
        from tamandua.modules.integrations.github import GitHubAppError, pull_files
        run_id, pull, source_id = job["run_id"], job["pull"], job["source_id"]
        repository = source_id.removeprefix("github:")
        record = load_run(self.data_dir, run_id)
        record["status"], record["started_at"] = "running", _now()

        def progress(level: str, message) -> None:
            record["progress"].append(_event(level, message))
            self._save(record)
            log.info(text(message, "en"), extra={"run_id": run_id, "step": level})

        config = pr_watch.settings(self.data_dir, (record.get("source") or {}).get("uid") or source_id)
        installation = job["installation_id"]
        try:
            files = pull_files(installation, repository, pull["number"])
            changed = pr_review.changed_lines(files)
            progress("ok", msg("runs.progress.pr_files", count=len(changed)))
            progress("info", msg("runs.progress.downloading_commit", sha=pull["head_sha"][:7]))
            work = self.data_dir / "work"
            work.mkdir(parents=True, exist_ok=True)
            with TemporaryDirectory(prefix="pr-", dir=work) as temporary:
                root, source = snapshot_source(source_id, Path(temporary), None, installation, ref=pull["head_sha"], progress=progress)
                scan = scan_repository(root, source, allow_osv_upload=False, data_dir=self.data_dir, progress=progress)
            # Excluded paths are decided by the server, not the PR: they are removed before deciding whether it blocks.
            from tamandua.modules.findings.exclusions import apply_to_record
            scan = apply_to_record(self.data_dir, scan, asset_key(record))
            if (scan.get("excluded") or {}).get("findings"):
                progress("info", msg("runs.progress.pr_excluded", count=scan["excluded"]["findings"]))
            default_branch = job.get("default_branch")
            if default_branch is None:
                from tamandua.modules.integrations.github import installation_repository
                try:
                    default_branch = (installation_repository(installation, source_id) or {}).get("branch")
                except GitHubAppError:
                    default_branch = None
            baseline = self._baseline(source_id, (record.get("source") or {}).get("uid"), branch=pull.get("base_ref"),
                                      default_branch=default_branch)
            prints = {item["fingerprint"] for item in baseline["findings"]} if baseline else None
            outcome = pr_review.classify(scan["findings"], changed, prints)
            outcome["verdict"] = pr_review.verdict(outcome["introduced"], config["gate"])
            outcome["tools"] = scan["summary"].get("tools") or []
            # Informational and separate: declared but unused dependencies, singling out the ones the PR adds.
            from tamandua.modules.scanning.unused_deps import split_by_pr
            unused = scan.get("unused_dependencies") or {"unused": [], "ecosystems": []}
            new_unused, old_unused = split_by_pr(unused["unused"], changed)
            outcome["unused"] = {"new": new_unused, "before": old_unused, "ecosystems": unused["ecosystems"]}
            introduced = outcome["introduced"]
            severities = {level: sum(1 for item in introduced if item["severity"] == level) for level in ("critical", "high", "medium", "low", "info")}
            priorities = {level: sum(1 for item in introduced if (item.get("priority") or {}).get("action") == level) for level in ("act", "attend", "track")}
            summary = {**scan["summary"], "candidates": len(introduced), "severities": severities, "priorities": priorities,
                       "kev": sum(1 for item in introduced if item.get("kev")),
                       "fixable": sum(1 for item in introduced if (item.get("package") or {}).get("fixed_version")),
                       "preexisting": len(outcome["preexisting"]), "changed_files": len(changed)}
            progress("ok" if outcome["verdict"]["state"] == "success" else "warn",
                     msg("runs.progress.pr_summary" if baseline else "runs.progress.pr_summary_no_baseline",
                         count=len(introduced), preexisting=len(outcome["preexisting"])))
            delivery = self._deliver(installation, repository, pull, outcome, run_id, baseline, config, progress)
            save_repository_scan(self.data_dir, {**scan, "type": "pr_review", "target": record["target"], "variant": "pull_request",
                                                 "pull_request": record["pull_request"], "requested_by": record.get("requested_by"),
                                                 "findings": introduced, "summary": summary,
                                                 "unused_dependencies": outcome["unused"],
                                                 "review": {"baseline_run": baseline["id"] if baseline else None,
                                                            "verdict": outcome["verdict"], "delivery": delivery,
                                                            "gate": config["gate"]},
                                                 "progress": record["progress"], "started_at": record["started_at"], "finished_at": _now()},
                                 run_id=run_id, created_at=record["created_at"])
        except (SourceError, GitHubAppError) as exc:
            self._fail(record, msg("runs.failure.pr", reason=_reason(exc)))
        except Exception:  # noqa: BLE001
            log.error("revisión de PR fallida: %s", traceback.format_exc().splitlines()[-1], extra={"run_id": run_id})
            self._fail(record, msg("runs.failure.pr_internal"))

    def _deliver(self, installation, repository, pull, outcome, run_id, baseline, config, progress) -> dict:
        """Publishes the result on GitHub if the repository has it enabled and the App has permission."""
        from tamandua.modules.pullrequests import review as pr_review
        from tamandua.modules.integrations.github import GitHubAppError, installation_details, set_commit_status, upsert_pr_comment
        if not config.get("post_comment"):
            return {"comment": msg("runs.delivery.disabled"), "status": msg("runs.delivery.disabled")}
        try:
            permissions = installation_details(installation).get("permissions", {})
        except GitHubAppError:
            permissions = {}
        delivery = {}
        if permissions.get("pull_requests") == "write":
            try:
                body = pr_review.render_comment(pull, outcome, run_id=run_id, baseline_run=baseline["id"] if baseline else None,
                                                gate=config["gate"], tools=outcome.get("tools"),
                                                # Only a declared public panel is linked: never the internal host.
                                                panel_url=(lambda url: url if url.startswith("https://") else None)(
                                                    settings.text("TAMANDUA_PUBLIC_URL")))
                delivery["comment"] = upsert_pr_comment(installation, repository, pull["number"], body)
                progress("ok", msg("runs.progress.comment_posted"))
                unused = outcome.get("unused") or {}
                if unused.get("ecosystems"):
                    from tamandua.modules.integrations.github import UNUSED_MARKER
                    upsert_pr_comment(installation, repository, pull["number"],
                                      pr_review.render_unused_comment(unused["new"], unused["before"], unused["ecosystems"]), UNUSED_MARKER)
            except GitHubAppError as exc:
                delivery["comment"] = msg("runs.delivery.error", reason=_reason(exc))
                progress("warn", msg("runs.progress.comment_failed", reason=_reason(exc)))
        else:
            delivery["comment"] = msg("runs.delivery.no_comment_permission")
            progress("warn", msg("runs.progress.no_comment_permission"))
        if permissions.get("statuses") == "write":
            try:
                set_commit_status(installation, repository, pull["head_sha"], outcome["verdict"]["state"], outcome["verdict"]["description"])
                delivery["status"] = outcome["verdict"]["state"]
            except GitHubAppError as exc:
                delivery["status"] = msg("runs.delivery.error", reason=_reason(exc))
        else:
            delivery["status"] = msg("runs.delivery.no_status_permission")
        return delivery

    def _fail(self, record: dict, message: dict) -> None:
        record["status"] = "failed"
        record["finished_at"] = _now()
        record["progress"].append(_event("error", message))
        record["limitations"] = [message]
        self._save(record)

    def _save(self, record: dict) -> None:
        save_record(self.data_dir, record)
