"""Triage decisions that survive across scans.

A decision is tied to the finding's stable fingerprint within an asset (the
repository), not to a run: if it is scanned again tomorrow and the finding is
still there, it stays marked as a false positive or accepted risk. "Fixed" is not
stored: it is inferred when the fingerprint stops appearing.

States:
* ``open``: the default, no decision.
* ``in_progress``: someone is fixing it.
* ``false_positive``: doesn't apply; requires a reason.
* ``fixed``: remediated by hand, with a justification; reopens if it shows up again.
* ``accepted``: risk accepted; requires a reason, is decided by an administrator and
  expires (one year at most). Once expired it counts as open again.

Every change is kept in the finding's history with who, when and why.
"""

from __future__ import annotations

import re
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import delete, func, select
from sqlalchemy.dialects.postgresql import insert

from tamandua.modules.findings.errors import LocalizedError
from tamandua.modules.findings.tables import triage_decisions
from tamandua.shared import db
from tamandua.shared.db import TENANT
from tamandua.shared.i18n import is_msg, msg

from tamandua.modules.findings.kinds import FINDING_RUNS
from tamandua.modules.sources.assets import asset_key
from tamandua.shared.model import Finding, RunRecord


class TriageError(LocalizedError, ValueError):
    pass


class TriageForbidden(LocalizedError, PermissionError):
    pass


STATUSES = ("open", "in_progress", "false_positive", "accepted", "fixed")
LABELS = {"open": msg("findings.triage.status.open"), "in_progress": msg("findings.triage.status.in_progress"),
          "false_positive": msg("findings.triage.status.false_positive"), "accepted": msg("findings.triage.status.accepted"),
          "fixed": msg("findings.triage.status.fixed")}
TOO_LONG = {"reason": "findings.triage.errors.reason_too_long", "note": "findings.triage.errors.note_too_long"}
CONTROL = {"reason": "findings.triage.errors.reason_control_characters", "note": "findings.triage.errors.note_control_characters"}
# What no longer counts as pending work in dashboards, tickets and SARIF. Marking it remediated by hand requires a
# justification, and it reopens only if the finding appears again.
SUPPRESSED = ("false_positive", "accepted", "fixed")
REASON_MIN, REASON_MAX, NOTE_MAX = 10, 500, 1000
MAX_BATCH, HISTORY_MAX = 500, 50
ACCEPT_DEFAULT_DAYS, ACCEPT_MAX_DAYS = 90, 365


# `asset_key` lives in sources/assets.py: the repository's stable identity (GitHub's numeric id).
# Decisions live in PostgreSQL (table triage_decisions), one row per asset and fingerprint.


def load(data_dir: Path) -> dict:
    """Every decision: {asset: {fingerprint: decision}}. For a single asset, `load_asset` (cheaper)."""
    result: dict = {}
    with db.transaction(data_dir) as connection:
        for key, digest, decision in connection.execute(select(triage_decisions.c.asset_key, triage_decisions.c.fingerprint,
                                                               triage_decisions.c.decision).where(triage_decisions.c.tenant_id == TENANT)):
            result.setdefault(key, {})[digest] = decision
    return result


def load_asset(data_dir: Path, key: str) -> dict:
    with db.transaction(data_dir) as connection:
        return dict(connection.execute(
            select(triage_decisions.c.fingerprint, triage_decisions.c.decision)
            .where(triage_decisions.c.tenant_id == TENANT, triage_decisions.c.asset_key == key)).all())


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
    """An asset gains a stable identity (e.g. github#id): its decisions move to the new key; those already there win."""
    with db.transaction(data_dir) as connection:
        db.lock(connection, "triage", new)
        merged = {**load_asset(data_dir, old), **load_asset(data_dir, new)}
        forget_asset(data_dir, old)
        _save_asset(data_dir, new, merged)


def carry_over(data_dir: Path, key: str, moved: dict[str, str]) -> None:
    """Findings with a new fingerprint (former → new) keep their decisions; one already under the new one wins."""
    with db.transaction(data_dir) as connection:
        db.lock(connection, "triage", key)
        asset = load_asset(data_dir, key)
        _save_asset(data_dir, key, {new: asset[former] for former, new in moved.items() if former in asset and new not in asset})


def _clean_text(value, *, limit: int, field: str) -> str:
    if value is None:
        return ""
    if not isinstance(value, str) or len(value) > limit:
        raise TriageError(msg(TOO_LONG[field], limit=limit))
    cleaned = " ".join(value.split())
    if any(ord(character) < 32 or ord(character) == 127 for character in cleaned):
        raise TriageError(msg(CONTROL[field]))
    return cleaned


def effective(entry: dict | None, today: date | None = None) -> dict:
    """The status that counts today: an expired acceptance is an open finding again."""
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


def annotate(data_dir: Path, record: RunRecord, decisions: dict | None = None) -> RunRecord:
    """A copy of the run with each finding's triage status and the counts in the summary."""
    if record.get("type") not in FINDING_RUNS:
        return record
    key = asset_key(record)
    asset = decisions.get(key, {}) if decisions is not None else load_asset(data_dir, key)
    counts = dict.fromkeys(STATUSES, 0)
    findings: list[Finding] = []
    for finding in record.get("findings", []):
        state = effective(asset.get(finding["fingerprint"]))
        counts[state["status"]] += 1
        findings.append({**finding, "triage": state})
    summary = {**record.get("summary", {}), "triage": counts,
               "actionable": counts["open"] + counts["in_progress"]}
    # How to fix each finding (command, example, steps) is computed when served, so it improves without rescanning.
    from tamandua.modules.findings.fix_guide import attach
    from tamandua.modules.findings.verifications import annotate as verified
    return {**record, "findings": verified(data_dir, asset_key(record), attach(findings)), "summary": summary}


def is_active(finding: dict) -> bool:
    return (finding.get("triage") or {}).get("status", "open") not in SUPPRESSED


def decide(data_dir: Path, record: RunRecord, fingerprints, status, *, reason=None, note=None, expires_at=None,
           user: dict, system_note: dict | None = None) -> RunRecord:
    """Applies one decision to several findings of a run. Only fingerprints the run contains.

    `system_note`: a message written by Tamandua itself (never from a request), stored instead of `note`."""
    if status not in STATUSES:
        raise TriageError(msg("findings.triage.errors.invalid_status"))
    if (not isinstance(fingerprints, list) or not 1 <= len(fingerprints) <= MAX_BATCH
            or not all(isinstance(item, str) and re.fullmatch(r"[0-9a-f]{64}", item) for item in fingerprints)):
        raise TriageError(msg("findings.triage.errors.invalid_fingerprints", max=MAX_BATCH))
    known = {finding["fingerprint"] for finding in record.get("findings", [])}
    unknown = set(fingerprints) - known
    if unknown:
        raise TriageError(msg("findings.triage.errors.unknown_fingerprints"))
    reason = _clean_text(reason, limit=REASON_MAX, field="reason")
    note = system_note if is_msg(system_note) else _clean_text(note, limit=NOTE_MAX, field="note")
    if status in SUPPRESSED and len(reason) < REASON_MIN:
        raise TriageError(msg("findings.triage.errors.reason_required", min=REASON_MIN))
    if status == "accepted":
        if user.get("role") != "admin":
            raise TriageForbidden(msg("findings.triage.errors.accept_admin_only"))
        today = datetime.now(timezone.utc).date()
        try:
            expiry = date.fromisoformat(expires_at) if expires_at else today + timedelta(days=ACCEPT_DEFAULT_DAYS)
        except (TypeError, ValueError) as exc:
            raise TriageError(msg("findings.triage.errors.invalid_expiry")) from exc
        if not today < expiry <= today + timedelta(days=ACCEPT_MAX_DAYS):
            raise TriageError(msg("findings.triage.errors.expiry_range", max=ACCEPT_MAX_DAYS))
        expires_at = expiry.isoformat()
    else:
        expires_at = None
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    event = {"status": status, "reason": reason, "note": note, "by": user["username"], "at": stamp,
             "expires_at": expires_at, "run_id": record["id"]}
    key = asset_key(record)
    with db.transaction(data_dir) as connection:
        db.lock(connection, "triage", key)  # concurrent decisions on one asset don't overwrite each other's history
        asset = load_asset(data_dir, key)
        for digest in dict.fromkeys(fingerprints):
            entry = asset.get(digest, {"history": []})
            history = [*entry.get("history", []), event][-HISTORY_MAX:]
            asset[digest] = {**event, "history": history}
        _save_asset(data_dir, key, {digest: asset[digest] for digest in dict.fromkeys(fingerprints)})
    return annotate(data_dir, record, {key: asset})
