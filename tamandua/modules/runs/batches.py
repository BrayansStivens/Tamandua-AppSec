"""Lotes de análisis: varios repositorios, o una organización entera, sin ir uno por uno.

Un lote es una lista persistida (`data/batches/<id>.json`). No crea cientos de ejecuciones en
cola de golpe: el trabajador toma el siguiente repositorio **solo cuando no tiene otra cosa**,
así un análisis manual o la revisión de un PR nunca esperan detrás de 900 repositorios. Si el
servidor se reinicia, el lote sigue donde iba. El progreso sale de las ejecuciones reales (el
índice), no de un contador aparte que pueda desincronizarse.

Repositorios de la GitHub App (su acceso se renueva solo; los tokens personales viven en memoria de la
sesión y no sirven para un trabajo de horas) o imágenes de contenedor (con las credenciales de registro
guardadas, si las hay).
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from tamandua.shared import documents
from tamandua.shared.i18n import msg, text

MAX_SELECTED = 100      # selección a mano, cualquier miembro
MAX_ITEMS = 5000        # organización entera (administración)
ID = re.compile(r"[0-9a-f]{32}")


class BatchError(ValueError):
    """`message` is a catalog message; the API renders it for the reader."""

    def __init__(self, message: dict):
        super().__init__(message)
        self.message = message

    def __str__(self) -> str:
        return text(self.message)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _name(batch_id: str) -> str:
    if not ID.fullmatch(batch_id or ""):
        raise BatchError(msg("runs.batch.invalid"))
    return f"batches/{batch_id}"


def _write(data_dir: Path, batch: dict) -> None:
    documents.save(data_dir, _name(batch["id"]), batch)


def load(data_dir: Path, batch_id: str) -> dict:
    batch = documents.load(data_dir, _name(batch_id))
    if batch is None:
        raise BatchError(msg("runs.batch.not_found"))
    return batch


def all_batches(data_dir: Path) -> list[dict]:
    rows = [documents.load(data_dir, name) for name in documents.names(data_dir, "batches/")]
    return sorted((row for row in rows if isinstance(row, dict)), key=lambda row: row.get("created_at", ""), reverse=True)


def active(data_dir: Path) -> dict | None:
    return next((row for row in all_batches(data_dir) if row.get("status") == "running"), None)


def create(data_dir: Path, items: list[dict], *, by: str, label: str, allow_osv_upload: bool = False, context: str = "") -> dict:
    """`items`: repositorios ya validados ({source_id, name, uid, installation_id}) o imágenes ya validadas
    ({kind: "image", image, name}). Uno activo a la vez."""
    if not items:
        raise BatchError(msg("runs.batch.empty"))
    if len(items) > MAX_ITEMS:
        raise BatchError(msg("runs.batch.too_many", max=MAX_ITEMS))
    with documents.lock(data_dir, "batches"):
        if active(data_dir):
            raise BatchError(msg("runs.batch.already_running"))
        # Una imagen se identifica por su referencia completa (dos etiquetas del mismo repositorio son dos análisis).
        unique = list({(item["image"]["reference"] if item.get("kind") == "image" else item["source_id"]): item for item in items}.values())
        batch = {"id": uuid.uuid4().hex, "created_at": _now(), "by": by, "label": label[:120], "status": "running",
                 "allow_osv_upload": bool(allow_osv_upload), "context": " ".join(context.split())[:400],
                 "items": [{"kind": "image", "image": item["image"], "name": item["image"]["reference"], "run_id": None}
                           if item.get("kind") == "image" else
                           {"source_id": item["source_id"], "name": item["name"], "uid": item.get("uid"),
                            "installation_id": item.get("installation_id"), "run_id": None} for item in unique]}
        _write(data_dir, batch)
    return batch


def cancel(data_dir: Path, batch_id: str, *, by: str) -> dict:
    with documents.lock(data_dir, "batches"):
        batch = load(data_dir, batch_id)
        if batch["status"] == "running":
            batch.update(status="cancelled", finished_at=_now(), cancelled_by=by)
            _write(data_dir, batch)
    return batch


def take_next(data_dir: Path) -> tuple[dict, int] | None:
    """El siguiente repositorio pendiente del lote activo (y lo marca como tomado). None si no queda nada."""
    finished = None
    with documents.lock(data_dir, "batches"):
        batch = active(data_dir)
        if batch is None:
            return None
        index = next((position for position, item in enumerate(batch["items"]) if not item.get("run_id") and not item.get("error")), None)
        if index is not None:
            batch["items"][index]["run_id"] = "pending"
            _write(data_dir, batch)
            return batch, index
        batch.update(status="done", finished_at=_now())
        _write(data_dir, batch)
        finished = batch
    # Fuera del cerrojo: el aviso consulta el progreso real (las ejecuciones) y no bloquea a nadie.
    from tamandua.modules.integrations import notifications
    notifications.on_batch(summary(data_dir, finished), data_dir=data_dir)
    return None


def release_taken(data_dir: Path) -> None:
    """Al arrancar: un repositorio tomado pero sin ejecución (el proceso murió entre medias) vuelve a la cola."""
    with documents.lock(data_dir, "batches"):
        batch = active(data_dir)
        if batch and any(item.get("run_id") == "pending" for item in batch["items"]):
            for item in batch["items"]:
                if item.get("run_id") == "pending":
                    item["run_id"] = None
            _write(data_dir, batch)


def attach(data_dir: Path, batch_id: str, index: int, *, run_id: str | None = None, error: str | dict | None = None) -> None:
    with documents.lock(data_dir, "batches"):
        batch = load(data_dir, batch_id)
        item = batch["items"][index]
        item["run_id"] = run_id
        if error:
            item["error"] = error[:200] if isinstance(error, str) else error
        _write(data_dir, batch)


def summary(data_dir: Path, batch: dict) -> dict:
    """Progreso derivado de las ejecuciones reales, con estimación del tiempo restante."""
    from tamandua.modules.runs.store import list_runs
    runs = {row["id"]: row for row in list_runs(data_dir)}
    counts = {"pending": 0, "running": 0, "done": 0, "failed": 0}
    critical = high = 0
    durations = []
    for item in batch["items"]:
        run = runs.get(item.get("run_id") or "")
        if item.get("error") or (run and run.get("status") == "failed"):
            counts["failed"] += 1
        elif run is None:
            counts["pending"] += 1
        elif run.get("status") in ("queued", "running"):
            counts["running"] += 1
        else:
            counts["done"] += 1
            severities = (run.get("summary") or {}).get("severities") or {}
            critical += int(severities.get("critical") or 0)
            high += int(severities.get("high") or 0)
            try:
                durations.append((datetime.fromisoformat(run["finished_at"]) - datetime.fromisoformat(run["started_at"])).total_seconds())
            except (KeyError, TypeError, ValueError):
                pass
    average = sum(durations) / len(durations) if durations else 60.0
    remaining = counts["pending"] + counts["running"]
    return {"id": batch["id"], "label": batch.get("label"), "status": batch["status"], "created_at": batch["created_at"], "by": batch.get("by"),
            "total": len(batch["items"]), **counts, "critical": critical, "high": high,
            "eta_seconds": round(remaining * average) if batch["status"] == "running" else 0,
            "failed_items": [{"name": item["name"], "error": item.get("error") or msg("runs.batch.item_failed")} for item in batch["items"]
                             if item.get("error") or (runs.get(item.get("run_id") or "") or {}).get("status") == "failed"][:20]}
