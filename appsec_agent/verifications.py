"""Reverificar un hallazgo: volver a analizar su activo y decir si sigue ahí.

Cierra el ciclo encontrar → corregir → verificar sin buscar a mano en un análisis nuevo. Se guarda qué
hallazgo pidió verificación y con qué ejecución (`data/verifications.json`); el resultado se deduce del
registro de hallazgos cuando esa ejecución termina:

- `running`: el análisis está en cola o en curso.
- `fixed`: el análisis completo ya no lo encuentra (el registro lo marcó remediado).
- `present`: sigue apareciendo.
- `inconclusive`: el análisis quedó incompleto (un motor no corrió): no demuestra nada, como en el registro.
- `failed`: el análisis falló.

Si ya hay un análisis de ese activo en cola o en curso (otra verificación, la vigilancia de la rama), el
hallazgo se engancha a él en vez de lanzar otro.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

_lock = threading.Lock()
MAX_PER_ASSET = 500


def _path(data_dir: Path) -> Path:
    return data_dir / "verifications.json"


def load(data_dir: Path) -> dict:
    try:
        payload = json.loads(_path(data_dir).read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else {}
    except (FileNotFoundError, ValueError, OSError):
        return {}


def record(data_dir: Path, key: str, fingerprint: str, run_id: str, *, by: str) -> dict:
    entry = {"run_id": run_id, "by": by, "at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    with _lock:
        payload = load(data_dir)
        asset = payload.setdefault(key, {})
        asset[fingerprint] = entry
        if len(asset) > MAX_PER_ASSET:  # las más antiguas se olvidan
            for old in sorted(asset, key=lambda item: asset[item]["at"])[:len(asset) - MAX_PER_ASSET]:
                del asset[old]
        target = _path(data_dir)
        temporary = target.with_suffix(".tmp")
        temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        os.replace(temporary, target)
    return entry


def in_flight(data_dir: Path, key: str) -> dict | None:
    """Un análisis completo de ese activo que aún no terminó, si lo hay."""
    from .assets import asset_key
    from .kinds import FULL_SCANS
    from .store import list_runs
    return next((row for row in list_runs(data_dir) if row["type"] in FULL_SCANS and row["status"] in ("queued", "running")
                 and asset_key(row) == key), None)


def latest_scan(data_dir: Path, key: str) -> dict | None:
    """El último análisis completo del activo: de él sale cómo volver a analizarlo (repositorio o imagen)."""
    from .assets import asset_key
    from .kinds import FULL_SCANS
    from .store import list_runs
    return next((row for row in list_runs(data_dir) if row["type"] in FULL_SCANS and asset_key(row) == key), None)


def annotate(data_dir: Path, key: str, findings: list[dict]) -> list[dict]:
    """Añade `verification` a los hallazgos con una verificación pedida."""
    requested = load(data_dir).get(key) or {}
    if not requested or not any(item.get("fingerprint") in requested for item in findings):
        return findings
    from .findings_registry import load as registry
    from .store import list_runs
    runs = {row["id"]: row for row in list_runs(data_dir)}
    entries = registry(data_dir, key).get("findings", {})
    for finding in findings:
        asked = requested.get(finding.get("fingerprint"))
        if not asked:
            continue
        run = runs.get(asked["run_id"]) or {}
        status = run.get("status")
        entry = entries.get(finding["fingerprint"]) or {}
        if status in ("queued", "running"):
            state = "running"
        elif status == "failed" or not run:
            state = "failed"
        elif status != "completed":
            state = "inconclusive"
        elif entry.get("status") == "fixed":
            state = "fixed"
        else:
            state = "present"
        finding["verification"] = {**asked, "state": state, "finished_at": run.get("finished_at")}
    return findings
