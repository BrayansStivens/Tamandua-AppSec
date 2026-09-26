"""Escaneos en segundo plano con progreso visible.

Un escaneo no bloquea la petición HTTP: se encola, devuelve su identificador al
instante y un único hilo trabajador los procesa en orden. Mientras corre, el
registro `runs/<id>/run.json` existe con estado `queued` o `running` y una lista
de eventos de progreso pensada para mostrarse al usuario: qué paso empezó, qué
terminó y con qué cuenta. Nunca se vuelcan ahí rutas internas del servidor,
salidas crudas de herramientas ni errores con detalles de infraestructura.
"""

from __future__ import annotations

import json
import queue
import threading
import traceback
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Callable
import uuid

from tamandua.modules.findings import registry as findings_registry
from tamandua.shared import log as logging_setup
from tamandua.modules.scanning.repository import scan_repository
from tamandua.modules.sources.repositories import SourceError, snapshot_source
from tamandua.modules.sources.assets import asset_key
from tamandua.modules.runs.store import _run_dir, _write_atomic, list_runs, load_run, save_repository_scan, update_index

log = logging_setup.get("jobs")
Progress = Callable[[str, str], None]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ScanJobs:
    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self._queue: queue.Queue[dict] = queue.Queue()
        self._lock = threading.Lock()
        self._records: dict[str, dict] = {}
        # Cada cuánto mira el trabajador, sin nada en cola, si hay un lote que avanzar.
        self.idle_poll = 3.0
        self._recover()
        # El registro de hallazgos se deriva de las ejecuciones: si no existe, se reconstruye.
        if not (data_dir / "findings").is_dir():
            findings_registry.rebuild(data_dir)
        self._worker = threading.Thread(target=self._loop, name="appsec-scans", daemon=True)
        self._worker.start()

    def _recover(self) -> None:
        """Al arrancar, nada puede estar en marcha: lo que quedó en cola o corriendo murió con el proceso anterior."""
        for row in list_runs(self.data_dir):
            if row["status"] not in ("queued", "running"):
                continue
            try:
                record = load_run(self.data_dir, row["id"])
            except (ValueError, OSError):
                continue
            self._fail(record, "El servidor se reinició mientras corría esta ejecución y quedó interrumpida. Vuelve a lanzarla.")
            log.warning("ejecución interrumpida por reinicio", extra={"run_id": row["id"]})
        from tamandua.modules.runs import batches
        batches.release_taken(self.data_dir)

    # --- API pública ---------------------------------------------------------------

    def enqueue_repository_scan(self, *, source_id: str, source_name: str, allow_osv_upload: bool,
                                context: str, tokens: dict[str, str], installation_id: int | None, uid: str | None = None,
                                requested_by: str | None = None, trigger: dict | None = None) -> dict:
        run_id = uuid.uuid4().hex
        record = {"schema_version": "0.3.0", "id": run_id, "type": "repository_scan", "status": "queued",
                  "created_at": _now(), "fixture": source_name, "variant": "code",
                  "source": {"id": source_id, "uid": uid, "name": source_name, "provider": source_id.partition(":")[0]},
                  "context": " ".join(context.split())[:400], "summary": {"candidates": 0, "files": 0, "dependencies": 0},
                  "steps": [], "findings": [], "owasp_coverage": [], "limitations": [],
                  "progress": [{"at": _now(), "level": "info", "message": "En cola: esperando al trabajador de escaneos."}]}
        if requested_by:
            record["requested_by"] = requested_by
        if trigger:
            # Qué lo lanzó (p. ej. la vigilancia de la rama principal, con el commit que vio cambiar).
            record["trigger"] = trigger
        self._save(record)
        with self._lock:
            self._records[run_id] = record
        self._queue.put({"run_id": run_id, "source_id": source_id, "allow_osv_upload": allow_osv_upload,
                         "context": context, "tokens": tokens, "installation_id": installation_id})
        log.info("escaneo encolado", extra={"run_id": run_id, "path": source_id})
        return {"id": run_id, "status": "queued"}

    def enqueue_pr_review(self, *, source_id: str, pull: dict, installation_id: int, requested_by: str, uid: str | None = None) -> dict:
        """Revisión del commit de cabeza de un PR. Se marca como revisado al encolar para no duplicar."""
        from tamandua.modules.pullrequests import watch as pr_watch
        run_id = uuid.uuid4().hex
        name = source_id.removeprefix("github:")
        record = {"schema_version": "0.3.0", "id": run_id, "type": "pr_review", "status": "queued", "created_at": _now(),
                  "fixture": f"{name}#{pull['number']}", "variant": "pull_request",
                  "source": {"id": source_id, "uid": uid, "name": name, "provider": "github"},
                  "pull_request": {key: pull.get(key) for key in ("number", "title", "url", "author", "head_sha", "head_ref", "base_ref")},
                  "requested_by": requested_by, "context": "", "summary": {"candidates": 0, "files": 0, "dependencies": 0},
                  "steps": [], "findings": [], "owasp_coverage": [], "limitations": [],
                  "progress": [{"at": _now(), "level": "info", "message": f"En cola: revisión del PR #{pull['number']} ({pull['head_sha'][:7]})."}]}
        self._save(record)
        with self._lock:
            self._records[run_id] = record
        pr_watch.mark(self.data_dir, uid or source_id, pull["number"], pull["head_sha"], run_id)
        self._queue.put({"kind": "pr_review", "run_id": run_id, "source_id": source_id, "pull": pull,
                         "installation_id": installation_id})
        log.info("revisión de PR encolada", extra={"run_id": run_id, "path": f"{source_id}#{pull['number']}"})
        return {"id": run_id, "status": "queued"}

    def enqueue_image_scan(self, *, image: dict, context: str, requested_by: str) -> dict:
        """Análisis de una imagen de contenedor leída del registro: no se ejecuta ni se construye."""
        run_id = uuid.uuid4().hex
        record = {"schema_version": "0.3.0", "id": run_id, "type": "image_scan", "status": "queued", "created_at": _now(),
                  "fixture": image["reference"], "variant": "image",
                  "source": {"id": image["asset"], "uid": None, "name": image["name"], "provider": "registry", "image": image},
                  "requested_by": requested_by, "context": " ".join(context.split())[:400],
                  "summary": {"candidates": 0, "files": 0, "dependencies": 0},
                  "steps": [], "findings": [], "owasp_coverage": [], "limitations": [],
                  "progress": [{"at": _now(), "level": "info", "message": f"En cola: análisis de la imagen {image['reference']}."}]}
        self._save(record)
        with self._lock:
            self._records[run_id] = record
        self._queue.put({"kind": "image_scan", "run_id": run_id, "image": image, "context": context})
        log.info("análisis de imagen encolado", extra={"run_id": run_id, "path": image["reference"]})
        return {"id": run_id, "status": "queued"}

    def pending(self) -> int:
        return self._queue.qsize()

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
        except Exception as exc:  # noqa: BLE001 — un repositorio que falla no detiene el lote
            batches.attach(self.data_dir, batch["id"], index, error=str(exc))

    # --- trabajador ----------------------------------------------------------------

    def _loop(self) -> None:
        while True:
            try:
                job = self._queue.get(timeout=self.idle_poll)
            except queue.Empty:
                # Sin nada pendiente, el siguiente repositorio del lote activo (si lo hay).
                self._feed_batch()
                continue
            try:
                self._execute(job)
            except Exception:  # noqa: BLE001 — el trabajador nunca debe morir por un escaneo
                log.exception("fallo inesperado del trabajador", extra={"run_id": job.get("run_id")})
            finally:
                self._queue.task_done()

    def _execute(self, job: dict) -> None:
        if job.get("kind") == "pr_review":
            return self._execute_pr(job)
        if job.get("kind") == "image_scan":
            return self._execute_image(job)
        run_id = job["run_id"]
        record = self._records.get(run_id) or json.loads((_run_dir(self.data_dir, run_id) / "run.json").read_text(encoding="utf-8"))
        record["status"] = "running"
        record["started_at"] = _now()

        def progress(level: str, message: str) -> None:
            record["progress"].append({"at": _now(), "level": level, "message": message[:300]})
            self._save(record)
            log.info(message, extra={"run_id": run_id, "step": level})

        progress("info", "Descargando el snapshot del repositorio en solo lectura…")
        work = self.data_dir / "work"
        work.mkdir(parents=True, exist_ok=True)
        try:
            with TemporaryDirectory(prefix="snapshot-", dir=work) as temporary:
                root, source = snapshot_source(job["source_id"], Path(temporary), job["tokens"], job["installation_id"], progress=progress)
                snapshot = source.get("snapshot") or {}
                progress("ok", f"Snapshot listo: {source.get('files', 0)} archivos analizables"
                               + (f", {snapshot.get('skipped_not_analyzable', 0)} descartados por no ser código" if snapshot.get("skipped_not_analyzable") else "") + ".")
                scan = scan_repository(root, source, allow_osv_upload=job["allow_osv_upload"],
                                       context=job["context"], data_dir=self.data_dir, progress=progress)
            summary = scan["summary"]
            counts = (f"{summary['candidates']} hallazgos ({summary['severities'].get('critical', 0)} críticos, "
                      f"{summary['severities'].get('high', 0)} altos)")
            if scan["status"] == "incomplete":
                progress("warn", f"Terminado con cobertura incompleta: {counts}. Revisa arriba qué no se ejecutó.")
            else:
                progress("ok", f"Terminado: {counts}.")
            final = save_repository_scan(self.data_dir, {**scan, "progress": record["progress"],
                                                         "started_at": record["started_at"], "finished_at": _now()},
                                         run_id=run_id, created_at=record["created_at"])
            with self._lock:
                self._records[run_id] = final
            log.info("escaneo terminado", extra={"run_id": run_id, "status": final["status"]})
        except SourceError as exc:
            self._fail(record, f"No se pudo obtener el repositorio: {exc}")
        except Exception as exc:  # noqa: BLE001
            log.error("escaneo fallido: %s", traceback.format_exc().splitlines()[-1], extra={"run_id": run_id})
            # Al usuario se le dice que falló y en qué fase, nunca la traza ni rutas del servidor.
            self._fail(record, "El análisis falló por un error interno; el equipo puede revisar los logs del servidor con el identificador de la ejecución.")
            del exc

    def _execute_image(self, job: dict) -> None:
        from tamandua.modules.scanning.image import scan_image
        run_id = job["run_id"]
        record = self._records.get(run_id) or json.loads((_run_dir(self.data_dir, run_id) / "run.json").read_text(encoding="utf-8"))
        record["status"] = "running"
        record["started_at"] = _now()

        def progress(level: str, message: str) -> None:
            record["progress"].append({"at": _now(), "level": level, "message": message[:300]})
            self._save(record)
            log.info(message, extra={"run_id": run_id, "step": level})

        try:
            scan = scan_image(job["image"], data_dir=self.data_dir, context=job["context"], progress=progress)
            summary = scan["summary"]
            counts = (f"{summary['candidates']} hallazgos ({summary['severities'].get('critical', 0)} críticos, "
                      f"{summary['severities'].get('high', 0)} altos)")
            if scan["status"] == "incomplete":
                progress("warn", f"Terminado con cobertura incompleta: {counts}. Revisa arriba qué no se ejecutó.")
            else:
                progress("ok", f"Terminado: {counts}.")
            final = save_repository_scan(self.data_dir, {**scan, "requested_by": record.get("requested_by"), "progress": record["progress"],
                                                         "started_at": record["started_at"], "finished_at": _now()},
                                         run_id=run_id, created_at=record["created_at"])
            with self._lock:
                self._records[run_id] = final
            log.info("análisis de imagen terminado", extra={"run_id": run_id, "status": final["status"]})
        except Exception as exc:  # noqa: BLE001
            log.error("análisis de imagen fallido: %s", traceback.format_exc().splitlines()[-1], extra={"run_id": run_id})
            self._fail(record, "El análisis de la imagen falló por un error interno; revisa los logs con el identificador de la ejecución.")
            del exc

    def _baseline(self, source_id: str, uid: str | None = None) -> dict | None:
        """Último escaneo completo del repositorio: lo que ya estaba antes del PR."""
        for row in list_runs(self.data_dir):
            if (row["type"] == "repository_scan" and row["status"] in ("completed", "incomplete")
                    and asset_key(row) in {source_id, uid}):
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
        record = self._records.get(run_id) or json.loads((_run_dir(self.data_dir, run_id) / "run.json").read_text(encoding="utf-8"))
        record["status"], record["started_at"] = "running", _now()

        def progress(level: str, message: str) -> None:
            record["progress"].append({"at": _now(), "level": level, "message": message[:300]})
            self._save(record)
            log.info(message, extra={"run_id": run_id, "step": level})

        config = pr_watch.settings(self.data_dir, (record.get("source") or {}).get("uid") or source_id)
        installation = job["installation_id"]
        try:
            files = pull_files(installation, repository, pull["number"])
            changed = pr_review.changed_lines(files)
            progress("ok", f"El PR cambia {len(changed)} ficheros.")
            progress("info", f"Descargando el commit {pull['head_sha'][:7]} en solo lectura…")
            work = self.data_dir / "work"
            work.mkdir(parents=True, exist_ok=True)
            with TemporaryDirectory(prefix="pr-", dir=work) as temporary:
                root, source = snapshot_source(source_id, Path(temporary), None, installation, ref=pull["head_sha"], progress=progress)
                scan = scan_repository(root, source, allow_osv_upload=False, data_dir=self.data_dir, progress=progress)
            # Las rutas excluidas las decide el servidor, no el PR: se quitan antes de decidir si bloquea.
            from tamandua.modules.findings.exclusions import apply_to_record
            scan = apply_to_record(self.data_dir, scan, asset_key(record))
            if (scan.get("excluded") or {}).get("findings"):
                progress("info", f"{scan['excluded']['findings']} hallazgos en rutas excluidas por un administrador quedan fuera de la revisión.")
            baseline = self._baseline(source_id, (record.get("source") or {}).get("uid"))
            prints = {item["fingerprint"] for item in baseline["findings"]} if baseline else None
            outcome = pr_review.classify(scan["findings"], changed, prints)
            outcome["verdict"] = pr_review.verdict(outcome["introduced"], config["gate"])
            outcome["tools"] = scan["summary"].get("tools") or []
            # Informativo y aparte: dependencias declaradas sin uso, separando las que añade el PR.
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
                     f"{len(introduced)} hallazgos nuevos introducidos por el PR; {len(outcome['preexisting'])} ya existían"
                     + ("" if baseline else " (sin escaneo previo de la rama principal: se cuenta lo que cae en líneas cambiadas)") + ".")
            delivery = self._deliver(installation, repository, pull, outcome, run_id, baseline, config, progress)
            final = save_repository_scan(self.data_dir, {**scan, "type": "pr_review", "fixture": record["fixture"], "variant": "pull_request",
                                                         "pull_request": record["pull_request"], "requested_by": record.get("requested_by"),
                                                         "findings": introduced, "summary": summary,
                                                         "unused_dependencies": outcome["unused"],
                                                         "review": {"baseline_run": baseline["id"] if baseline else None,
                                                                    "verdict": outcome["verdict"], "delivery": delivery,
                                                                    "gate": config["gate"]},
                                                         "progress": record["progress"], "started_at": record["started_at"], "finished_at": _now()},
                                         run_id=run_id, created_at=record["created_at"])
            with self._lock:
                self._records[run_id] = final
        except (SourceError, GitHubAppError) as exc:
            self._fail(record, f"No se pudo revisar el PR: {exc}")
        except Exception:  # noqa: BLE001
            log.error("revisión de PR fallida: %s", traceback.format_exc().splitlines()[-1], extra={"run_id": run_id})
            self._fail(record, "La revisión falló por un error interno; el equipo puede revisar los logs del servidor con el identificador de la ejecución.")

    def _deliver(self, installation, repository, pull, outcome, run_id, baseline, config, progress) -> dict:
        """Publica el resultado en GitHub si el repositorio lo tiene activado y la App tiene permiso."""
        from tamandua.modules.pullrequests import review as pr_review
        import os
        from tamandua.modules.integrations.github import GitHubAppError, installation_details, set_commit_status, upsert_pr_comment
        if not config.get("post_comment"):
            return {"comment": "desactivado", "status": "desactivado"}
        try:
            permissions = installation_details(installation).get("permissions", {})
        except GitHubAppError:
            permissions = {}
        delivery = {}
        if permissions.get("pull_requests") == "write":
            try:
                body = pr_review.render_comment(pull, outcome, run_id=run_id, baseline_run=baseline["id"] if baseline else None,
                                                gate=config["gate"], tools=outcome.get("tools"),
                                                # Solo se enlaza un panel público declarado: nunca el host interno.
                                                panel_url=(lambda url: url if url.startswith("https://") else None)(
                                                    os.environ.get("APPSEC_AGENT_PUBLIC_URL", "").strip()))
                delivery["comment"] = upsert_pr_comment(installation, repository, pull["number"], body)
                progress("ok", "Comentario publicado en el PR.")
                unused = outcome.get("unused") or {}
                if unused.get("ecosystems"):
                    from tamandua.modules.integrations.github import UNUSED_MARKER
                    upsert_pr_comment(installation, repository, pull["number"],
                                      pr_review.render_unused_comment(unused["new"], unused["before"], unused["ecosystems"]), UNUSED_MARKER)
            except GitHubAppError as exc:
                delivery["comment"] = f"error: {exc}"
                progress("warn", f"No se pudo comentar en el PR: {exc}")
        else:
            delivery["comment"] = "sin permiso: la App necesita Pull requests en escritura"
            progress("warn", "El resultado no se publicó en GitHub: la App no tiene permiso de escritura en pull requests.")
        if permissions.get("statuses") == "write":
            try:
                set_commit_status(installation, repository, pull["head_sha"], outcome["verdict"]["state"], outcome["verdict"]["description"])
                delivery["status"] = outcome["verdict"]["state"]
            except GitHubAppError as exc:
                delivery["status"] = f"error: {exc}"
        else:
            delivery["status"] = "sin permiso: la App necesita Commit statuses en escritura"
        return delivery

    def _fail(self, record: dict, message: str) -> None:
        record["status"] = "failed"
        record["finished_at"] = _now()
        record["progress"].append({"at": _now(), "level": "error", "message": message[:300]})
        record["limitations"] = [message]
        self._save(record)

    def _save(self, record: dict) -> None:
        run_dir = _run_dir(self.data_dir, record["id"])
        run_dir.mkdir(parents=True, exist_ok=True)
        _write_atomic(run_dir / "run.json", json.dumps(record, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
        update_index(self.data_dir, record)
