"""Plazos de corrección por severidad: cuántos días hay para corregir un hallazgo desde que se detectó.

La política es del espacio de trabajo (`data/sla.json`) y la cambia un administrador; sin archivo, o con
valores rotos, rigen los plazos por defecto. Un nivel sin plazo (`None`) no vence nunca.

Cuenta desde la **primera detección** en el registro (`first_seen`): reabrir un hallazgo no reinicia el
reloj. Solo corre para lo pendiente de verdad: abierto o «en curso». Lo remediado, lo excluido, el falso
positivo y el riesgo aceptado vigente no vencen; una aceptación caducada vuelve a abierto y su plazo con ella.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from . import logging_setup, triage

_log = logging_setup.get("sla")
_lock = threading.Lock()
LEVELS = ("critical", "high", "medium", "low")
DEFAULTS = {"critical": 7, "high": 30, "medium": 90, "low": 180}
MAX_DAYS = 3650
SOON_DAYS = 7  # «vence pronto»: dentro de una semana


class SlaError(ValueError):
    pass


def _path(data_dir: Path) -> Path:
    return data_dir / "sla.json"


def _clean_days(value) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_DAYS:
        raise SlaError(f"Cada plazo es un número de días entre 1 y {MAX_DAYS}, o vacío para no fijarlo.")
    return value


def policy(data_dir: Path) -> dict:
    """La política vigente. Tolerante: un nivel que falta o no es válido toma su valor por defecto."""
    try:
        stored = json.loads(_path(data_dir).read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError, OSError):
        stored = {}
    stored = stored if isinstance(stored, dict) else {}
    raw = stored.get("days") if isinstance(stored.get("days"), dict) else {}
    days = {}
    for level in LEVELS:
        try:
            days[level] = _clean_days(raw[level]) if level in raw else DEFAULTS[level]
        except SlaError:
            days[level] = DEFAULTS[level]
    return {"days": days, "defaults": dict(DEFAULTS), "updated_by": stored.get("updated_by"), "updated_at": stored.get("updated_at")}


def save(data_dir: Path, days, *, user: dict) -> dict:
    if not isinstance(days, dict) or set(days) != set(LEVELS):
        raise SlaError("Indica el plazo de cada severidad: crítica, alta, media y baja.")
    clean = {level: _clean_days(days[level]) for level in LEVELS}
    payload = {"days": clean, "updated_by": user["username"], "updated_at": datetime.now(timezone.utc).isoformat()}
    with _lock:
        target = _path(data_dir)
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_suffix(".tmp")
        temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        os.replace(temporary, target)
    _log.info("sla_updated", extra={"user": user["username"], "reason": ", ".join(f"{level}={clean[level]}" for level in LEVELS)})
    return policy(data_dir)


def _start(first_seen) -> date | None:
    try:
        moment = datetime.fromisoformat(str(first_seen))
    except (TypeError, ValueError):
        return None
    return (moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)).astimezone(timezone.utc).date()


def deadline(severity: str, first_seen, days: dict, *, today: date | None = None) -> dict | None:
    """El plazo de un hallazgo pendiente, o None si su severidad no tiene plazo o no se sabe cuándo se detectó."""
    limit = days.get(severity)
    start = _start(first_seen)
    if not limit or start is None:
        return None
    due = start + timedelta(days=limit)
    left = (due - (today or datetime.now(timezone.utc).date())).days
    return {"days": limit, "due": due.isoformat(), "days_left": left,
            "state": "overdue" if left < 0 else "soon" if left <= SOON_DAYS else "ok"}


def pending(finding: dict) -> bool:
    """Si el reloj corre: abierto en el registro y sin una decisión de triage que lo saque del trabajo pendiente."""
    lifecycle = finding.get("lifecycle") or {}
    if lifecycle.get("status", "open") != "open":
        return False
    return (finding.get("triage") or {}).get("status", "open") not in triage.SUPPRESSED


def annotate(findings: list[dict], days: dict, *, today: date | None = None) -> list[dict]:
    """Añade `sla` a cada hallazgo con `lifecycle` (los del registro); None si no corre plazo."""
    for finding in findings:
        if "lifecycle" in finding:
            finding["sla"] = deadline(finding.get("severity", ""), finding["lifecycle"].get("first_seen"), days, today=today) \
                if pending(finding) else None
    return findings


def counts(findings: list[dict]) -> dict:
    overdue = [item for item in findings if (item.get("sla") or {}).get("state") == "overdue"]
    return {"overdue": len(overdue), "soon": sum(1 for item in findings if (item.get("sla") or {}).get("state") == "soon"),
            "overdue_by_severity": {level: sum(1 for item in overdue if item.get("severity") == level) for level in LEVELS}}
