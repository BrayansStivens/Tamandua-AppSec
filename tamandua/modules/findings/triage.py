"""Decisiones de triage que sobreviven entre escaneos.

La decisión se ata a la huella estable del hallazgo dentro de un activo (el
repositorio), no a una ejecución: si mañana se vuelve a escanear y el hallazgo
sigue ahí, sigue marcado como falso positivo o riesgo aceptado. «Corregido» no se
guarda: se deduce cuando la huella deja de aparecer.

Estados:
* ``open``: por defecto, sin decisión.
* ``in_progress``: alguien lo está corrigiendo.
* ``false_positive``: no aplica; exige motivo.
* ``fixed``: remediado a mano, con justificación; se reabre si reaparece.
* ``accepted``: riesgo asumido; exige motivo, lo decide un administrador y
  caduca (máximo un año). Al caducar vuelve a contar como abierto.

Cada cambio queda en el historial del hallazgo con quién, cuándo y por qué.
"""

from __future__ import annotations

import re
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import delete, func, select
from sqlalchemy.dialects.postgresql import insert

from tamandua.modules.findings.tables import triage_decisions
from tamandua.shared import db
from tamandua.shared.db import TENANT

from tamandua.modules.runs.kinds import FINDING_RUNS
from tamandua.modules.sources.assets import asset_key


class TriageError(ValueError):
    pass


STATUSES = ("open", "in_progress", "false_positive", "accepted", "fixed")
LABELS = {"open": "Abierto", "in_progress": "En curso", "false_positive": "Falso positivo", "accepted": "Riesgo aceptado",
          "fixed": "Remediado"}
# Lo que deja de contar como trabajo pendiente en paneles, tickets y SARIF. «Remediado» a mano exige
# justificación y se reabre solo si el hallazgo vuelve a aparecer.
SUPPRESSED = ("false_positive", "accepted", "fixed")
REASON_MIN, REASON_MAX, NOTE_MAX = 10, 500, 1000
MAX_BATCH, HISTORY_MAX = 500, 50
ACCEPT_DEFAULT_DAYS, ACCEPT_MAX_DAYS = 90, 365


# `asset_key` vive en sources/assets.py: identidad estable del repositorio (id numérico de GitHub).
# Las decisiones viven en PostgreSQL (tabla triage_decisions), una fila por activo y huella.


def load(data_dir: Path) -> dict:
    """Todas las decisiones: {activo: {huella: decisión}}. Para un solo activo, `load_asset` (más barato)."""
    result: dict = {}
    with db.transaction(data_dir) as connection:
        for key, digest, decision in connection.execute(select(triage_decisions.c.asset_key, triage_decisions.c.fingerprint,
                                                               triage_decisions.c.decision).where(triage_decisions.c.tenant_id == TENANT)):
            result.setdefault(key, {})[digest] = decision
    return result


def load_asset(data_dir: Path, key: str) -> dict:
    with db.transaction(data_dir) as connection:
        return {digest: decision for digest, decision in connection.execute(
            select(triage_decisions.c.fingerprint, triage_decisions.c.decision)
            .where(triage_decisions.c.tenant_id == TENANT, triage_decisions.c.asset_key == key))}


def _save_asset(data_dir: Path, key: str, decisions: dict) -> None:
    if not decisions:
        return
    rows = [{"tenant_id": TENANT, "asset_key": key, "fingerprint": digest, "status": decision.get("status", "open"), "decision": decision}
            for digest, decision in decisions.items()]
    statement = insert(triage_decisions)
    with db.transaction(data_dir) as connection:
        connection.execute(statement.on_conflict_do_update(
            index_elements=[triage_decisions.c.tenant_id, triage_decisions.c.asset_key, triage_decisions.c.fingerprint],
            set_={"status": statement.excluded.status, "decision": statement.excluded.decision, "updated_at": func.now()}), rows)


def forget_asset(data_dir: Path, key: str) -> int:
    with db.transaction(data_dir) as connection:
        return connection.execute(delete(triage_decisions).where(triage_decisions.c.tenant_id == TENANT, triage_decisions.c.asset_key == key)).rowcount


def rename_asset(data_dir: Path, old: str, new: str) -> None:
    """Un activo gana identidad estable (p. ej. github#id): sus decisiones pasan a la clave nueva; mandan las ya existentes allí."""
    with db.transaction(data_dir) as connection:
        db.lock(connection, "triage", new)
        merged = {**load_asset(data_dir, old), **load_asset(data_dir, new)}
        forget_asset(data_dir, old)
        _save_asset(data_dir, new, merged)


def _clean_text(value, *, limit: int, field: str) -> str:
    if value is None:
        return ""
    if not isinstance(value, str) or len(value) > limit:
        raise TriageError(f"{field} admite hasta {limit} caracteres")
    cleaned = " ".join(value.split())
    if any(ord(character) < 32 or ord(character) == 127 for character in cleaned):
        raise TriageError(f"{field} contiene caracteres de control")
    return cleaned


def effective(entry: dict | None, today: date | None = None) -> dict:
    """Estado que cuenta hoy: una aceptación caducada vuelve a ser un hallazgo abierto."""
    if not entry:
        return {"status": "open"}
    status = entry.get("status", "open")
    expired = False
    if status == "accepted" and entry.get("expires_at"):
        try:
            expired = date.fromisoformat(entry["expires_at"]) < (today or datetime.now(timezone.utc).date())
        except ValueError:
            expired = True
    view = {key: entry.get(key) for key in ("status", "reason", "note", "by", "at", "expires_at")}
    view["history"] = entry.get("history", [])[-HISTORY_MAX:]
    if expired:
        view.update(status="open", expired=True)
    return view


def annotate(data_dir: Path, record: dict, decisions: dict | None = None) -> dict:
    """Copia de la ejecución con el estado de triage en cada hallazgo y el recuento en el resumen."""
    if record.get("type") not in FINDING_RUNS:
        return record
    key = asset_key(record)
    asset = decisions.get(key, {}) if decisions is not None else load_asset(data_dir, key)
    counts = {status: 0 for status in STATUSES}
    findings = []
    for finding in record.get("findings", []):
        state = effective(asset.get(finding["fingerprint"]))
        counts[state["status"]] += 1
        findings.append({**finding, "triage": state})
    summary = {**record.get("summary", {}), "triage": counts,
               "actionable": counts["open"] + counts["in_progress"]}
    # Cómo corregir cada hallazgo (comando, ejemplo, pasos): se calcula al servirlo, así mejora sin reanalizar.
    from tamandua.modules.findings.fix_guide import attach
    from tamandua.modules.findings.verifications import annotate as verified
    return {**record, "findings": verified(data_dir, asset_key(record), attach(findings)), "summary": summary}


def is_active(finding: dict) -> bool:
    return (finding.get("triage") or {}).get("status", "open") not in SUPPRESSED


def decide(data_dir: Path, record: dict, fingerprints, status, *, reason=None, note=None, expires_at=None,
           user: dict) -> dict:
    """Aplica una decisión a varios hallazgos de una ejecución. Solo huellas que la ejecución contiene."""
    if status not in STATUSES:
        raise TriageError("Estado de triage inválido")
    if (not isinstance(fingerprints, list) or not 1 <= len(fingerprints) <= MAX_BATCH
            or not all(isinstance(item, str) and re.fullmatch(r"[0-9a-f]{64}", item) for item in fingerprints)):
        raise TriageError(f"Indica entre 1 y {MAX_BATCH} huellas de hallazgo válidas")
    known = {finding["fingerprint"] for finding in record.get("findings", [])}
    unknown = set(fingerprints) - known
    if unknown:
        raise TriageError("Hay huellas que no pertenecen a esta ejecución")
    reason = _clean_text(reason, limit=REASON_MAX, field="El motivo")
    note = _clean_text(note, limit=NOTE_MAX, field="La nota")
    if status in SUPPRESSED and len(reason) < REASON_MIN:
        raise TriageError(f"Explica el motivo (mínimo {REASON_MIN} caracteres): queda en el historial")
    if status == "accepted":
        if user.get("role") != "admin":
            raise PermissionError("Aceptar un riesgo lo decide un administrador")
        today = datetime.now(timezone.utc).date()
        try:
            expiry = date.fromisoformat(expires_at) if expires_at else today + timedelta(days=ACCEPT_DEFAULT_DAYS)
        except (TypeError, ValueError) as exc:
            raise TriageError("Fecha de caducidad inválida (AAAA-MM-DD)") from exc
        if not today < expiry <= today + timedelta(days=ACCEPT_MAX_DAYS):
            raise TriageError(f"La aceptación caduca entre mañana y {ACCEPT_MAX_DAYS} días")
        expires_at = expiry.isoformat()
    else:
        expires_at = None
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    event = {"status": status, "reason": reason, "note": note, "by": user["username"], "at": stamp,
             "expires_at": expires_at, "run_id": record["id"]}
    key = asset_key(record)
    with db.transaction(data_dir) as connection:
        db.lock(connection, "triage", key)  # dos decisiones a la vez sobre el mismo activo no se pisan el historial
        asset = load_asset(data_dir, key)
        for digest in dict.fromkeys(fingerprints):
            entry = asset.get(digest, {"history": []})
            history = [*entry.get("history", []), event][-HISTORY_MAX:]
            asset[digest] = {**event, "history": history}
        _save_asset(data_dir, key, {digest: asset[digest] for digest in dict.fromkeys(fingerprints)})
    return annotate(data_dir, record, {key: asset})
