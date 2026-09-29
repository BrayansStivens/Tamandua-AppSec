"""Remediation deadlines by severity: how many days there are to fix a finding from when it was detected.

The policy belongs to the workspace (`data/sla.json`) and an administrator changes it; with no file, or with
broken values, the default deadlines apply. A level with no deadline (`None`) is never overdue.

It counts from the **first detection** in the registry (`first_seen`): reopening a finding doesn't restart the
clock. It only runs for what is really pending: open or "in progress". Remediated, excluded, false positives
and an active accepted risk are never overdue; an expired acceptance goes back to open, and its deadline with it.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from tamandua.shared import documents
from tamandua.shared import log as logging_setup
from tamandua.shared.i18n import msg
from tamandua.modules.findings import triage
from tamandua.modules.findings.errors import LocalizedError

_log = logging_setup.get("sla")
LEVELS = ("critical", "high", "medium", "low")
DEFAULTS = {"critical": 7, "high": 30, "medium": 90, "low": 180}
MAX_DAYS = 3650
SOON_DAYS = 7  # "due soon": within a week


class SlaError(LocalizedError, ValueError):
    pass


def _clean_days(value) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_DAYS:
        raise SlaError(msg("findings.sla.errors.invalid_days", max=MAX_DAYS))
    return value


def policy(data_dir: Path) -> dict:
    """The policy in force. Tolerant: a missing or invalid level takes its default value."""
    stored = documents.load(data_dir, "sla", {})
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
        raise SlaError(msg("findings.sla.errors.missing_levels"))
    clean = {level: _clean_days(days[level]) for level in LEVELS}
    payload = {"days": clean, "updated_by": user["username"], "updated_at": datetime.now(timezone.utc).isoformat()}
    documents.save(data_dir, "sla", payload)
    _log.info("sla_updated", extra={"user": user["username"], "reason": ", ".join(f"{level}={clean[level]}" for level in LEVELS)})
    return policy(data_dir)


def _start(first_seen) -> date | None:
    try:
        moment = datetime.fromisoformat(str(first_seen))
    except (TypeError, ValueError):
        return None
    return (moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)).astimezone(timezone.utc).date()


def deadline(severity: str, first_seen, days: dict, *, today: date | None = None) -> dict | None:
    """A pending finding's deadline, or None if its severity has none or when it was detected is unknown."""
    limit = days.get(severity)
    start = _start(first_seen)
    if not limit or start is None:
        return None
    due = start + timedelta(days=limit)
    left = (due - (today or datetime.now(timezone.utc).date())).days
    return {"days": limit, "due": due.isoformat(), "days_left": left,
            "state": "overdue" if left < 0 else "soon" if left <= SOON_DAYS else "ok"}


def pending(finding: dict) -> bool:
    """Whether the clock runs: open in the registry and no triage decision takes it out of pending work."""
    lifecycle = finding.get("lifecycle") or {}
    if lifecycle.get("status", "open") != "open":
        return False
    return (finding.get("triage") or {}).get("status", "open") not in triage.SUPPRESSED


def annotate(findings: list[dict], days: dict, *, today: date | None = None) -> list[dict]:
    """Adds `sla` to each finding with `lifecycle` (the registry's); None when no deadline runs."""
    for finding in findings:
        if "lifecycle" in finding:
            finding["sla"] = deadline(finding.get("severity", ""), finding["lifecycle"].get("first_seen"), days, today=today) \
                if pending(finding) else None
    return findings


def counts(findings: list[dict]) -> dict:
    overdue = [item for item in findings if (item.get("sla") or {}).get("state") == "overdue"]
    return {"overdue": len(overdue), "soon": sum(1 for item in findings if (item.get("sla") or {}).get("state") == "soon"),
            "overdue_by_severity": {level: sum(1 for item in overdue if item.get("severity") == level) for level in LEVELS}}
