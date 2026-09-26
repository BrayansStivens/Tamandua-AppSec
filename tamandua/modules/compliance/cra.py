"""CRA kit: reporting deadlines for actively exploited vulnerabilities (EU Regulation 2024/2847, art. 14).

Only for manufacturers that sell products with digital elements in the EU, so it is opt-in: a workspace policy
(`policy`, off by default) turns it on. Off, nothing is computed and the API answers 404; the data stays.

A manufacturer must report a vulnerability that is actively exploited **in its product** to ENISA's single
reporting platform: early warning within 24 h of becoming aware, notification within 72 h, final report within
14 days of a corrective measure. A CISA KEV listing only says the CVE is exploited somewhere, so a KEV match on a
product opens an event **to assess** with no clock running. An admin then records either "doesn't affect our
product" (with a reason; the event closes) or "actively exploited in our product": that moment is the awareness
time and the three clocks start from it. Tamandua never reports: it prepares the draft and records who marked
each stage as sent.

Events are derived on read from the findings registry; what people decide lives in the `cra` document:
`products`, `reports[event_id]` (`assessment`, `history` and one entry per stage sent) and `policy`.
Events without a stored assessment read as `to_assess`, unless a stage was already marked as sent before
assessments existed: someone already reported it, so it reads as exploited from the original signal time.
"""

from __future__ import annotations

import re
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from tamandua.shared import documents
from tamandua.modules.findings import registry as findings_registry
from tamandua.shared import log as logging_setup
from tamandua.modules.findings import triage
from tamandua.shared.i18n import msg, text

_log = logging_setup.get("cra")
STAGES = (("early_warning", msg("compliance.cra.stages.early_warning"), timedelta(hours=24)),
          ("notification", msg("compliance.cra.stages.notification"), timedelta(hours=72)),
          ("final_report", msg("compliance.cra.stages.final_report"), timedelta(days=14)))
STAGE_IDS = tuple(stage for stage, _, _ in STAGES)
VERDICTS = ("not_affected", "exploited")
REPORTING_PAGE = "https://digital-strategy.ec.europa.eu/en/policies/cra-reporting"
NAME_MAX = 120
REASON_MIN, REASON_MAX = 5, 500
PACKAGES_SHOWN = 10  # per event
HISTORY = 20  # policy changes and assessments kept per event
EVENT_ID = re.compile(r"[A-Za-z0-9#:_./@+|-]{3,300}")


class CraError(ValueError):
    """`message` is what people read (rendered per reader); str() stays English, for logs."""

    def __init__(self, message):
        super().__init__(text(message, "en"))
        self.message = message


def load(data_dir: Path) -> dict:
    payload = documents.load(data_dir, "cra", {})
    payload = payload if isinstance(payload, dict) else {}
    return {name: payload.get(name) if isinstance(payload.get(name), dict) else {} for name in ("products", "reports", "policy")}


def _save(data_dir: Path, payload: dict) -> None:
    documents.save(data_dir, "cra", payload)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _reason(value, *, required: bool) -> str | None:
    note = " ".join(str(value or "").split())
    if required and len(note) < REASON_MIN:
        raise CraError(msg("compliance.cra.errors.reason_required", min=REASON_MIN))
    if len(note) > REASON_MAX or any(not char.isprintable() for char in note):
        raise CraError(msg("compliance.cra.errors.reason_too_long", max=REASON_MAX))
    return note or None


# --- Policy -------------------------------------------------------------------------------------------------------

def policy(data_dir: Path) -> dict:
    """Whether the workspace sells products in the EU (CRA on), who said so and why; newest change first."""
    stored = load(data_dir)["policy"]
    history = [entry for entry in (stored.get("history") or []) if isinstance(entry, dict)][-HISTORY:]
    return {"enabled": stored.get("enabled") is True, "by": stored.get("by"), "at": stored.get("at"), "reason": stored.get("reason"),
            "history": [{"enabled": entry.get("enabled") is True, "by": entry.get("by"), "at": entry.get("at"), "reason": entry.get("reason")}
                        for entry in reversed(history)]}


def enabled(data_dir: Path) -> bool:
    return load(data_dir)["policy"].get("enabled") is True


def set_policy(data_dir: Path, on: bool, *, reason: str | None, user: dict) -> dict:
    """Turns the CRA kit on or off. Off hides it and stops events; products and decisions are kept."""
    note = _reason(reason, required=True)
    with documents.lock(data_dir, "cra"):
        state = load(data_dir)
        entry = {"enabled": bool(on), "by": user["username"], "at": _now(), "reason": note}
        history = [item for item in (state["policy"].get("history") or []) if isinstance(item, dict)]
        state["policy"] = {**entry, "history": (history + [entry])[-HISTORY:]}
        _save(data_dir, state)
    _log.info("cra_policy", extra={"user": user["username"], "reason": f"CRA {'on' if on else 'off'}: {note}"})
    return policy(data_dir)


# --- Products -----------------------------------------------------------------------------------------------------

def set_product(data_dir: Path, key: str, *, name: str, support_until: str | None, user: dict) -> dict:
    name = " ".join(str(name or "").split())
    if not name or len(name) > NAME_MAX:
        raise CraError(msg("compliance.cra.errors.product_name", max=NAME_MAX))
    if support_until:
        try:
            date.fromisoformat(support_until)
        except (TypeError, ValueError) as exc:
            raise CraError(msg("compliance.cra.errors.support_date")) from exc
    with documents.lock(data_dir, "cra"):
        state = load(data_dir)
        state["products"][key] = {"name": name, "support_until": support_until or None, "by": user["username"], "at": _now()}
        _save(data_dir, state)
    _log.info("cra_product", extra={"user": user["username"], "reason": f"{key} marked as a CRA product"})
    return state["products"][key]


def remove_product(data_dir: Path, key: str, *, user: dict) -> None:
    with documents.lock(data_dir, "cra"):
        state = load(data_dir)
        if state["products"].pop(key, None) is not None:
            _save(data_dir, state)
            _log.info("cra_product", extra={"user": user["username"], "reason": f"{key} is no longer a CRA product"})


# --- Events -------------------------------------------------------------------------------------------------------

def _moment(value) -> datetime | None:
    try:
        moment = datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def _signals(data_dir: Path, key: str, manual: dict) -> dict[str, dict]:
    """KEV matches of one product, one per CVE: when the signal arrived (the later of first detection and the KEV
    listing), whether it is still open and when it was fixed. A false positive in triage opens nothing."""
    grouped: dict[str, dict] = {}
    for digest, entry in (findings_registry.load(data_dir, key).get("findings") or {}).items():
        finding = entry.get("finding") or {}
        kev = finding.get("kev")
        cves = finding.get("cve") or []
        if not kev or not cves or entry.get("status") == "excluded":
            continue
        if (triage.effective(manual.get(digest)) or {}).get("status") == "false_positive":
            continue
        seen, listed = _moment(entry.get("first_seen")), _moment(kev.get("date_added"))
        signal = max(moment for moment in (seen, listed) if moment) if (seen or listed) else None
        fixed = entry.get("fixed") or {}
        event = grouped.setdefault(cves[0], {"signal": signal, "fixed_at": None, "open": False, "packages": set(),
                                             "title": finding.get("title"), "kev": kev, "severity": finding.get("severity")})
        if signal and (event["signal"] is None or signal < event["signal"]):
            event["signal"] = signal
        event["open"] |= entry.get("status") == "open"
        if entry.get("status") == "fixed" and fixed.get("at"):
            event["fixed_at"] = max(filter(None, [event["fixed_at"], fixed["at"]]))
        name = (finding.get("package") or {}).get("name")
        if name:
            event["packages"].add(f"{name} {(finding.get('package') or {}).get('version') or ''}".strip())
    return grouped


def _assessment(report: dict, signal: datetime | None) -> dict:
    """The decision on an event. Tolerant: nothing stored is `to_assess`; stages marked as sent before assessments
    existed mean it was already reported, so it reads as exploited from the original signal time."""
    stored = report.get("assessment")
    if isinstance(stored, dict) and stored.get("state") in VERDICTS and _moment(stored.get("at")):
        return {"state": stored["state"], "by": stored.get("by"), "at": _moment(stored["at"]).isoformat(),
                "reason": stored.get("reason"), "legacy": stored.get("legacy") is True}
    sent = [report[stage] for stage in STAGE_IDS if isinstance(report.get(stage), dict)]
    if sent:
        first = min(sent, key=lambda item: str(item.get("at")))
        at = signal or _moment(first.get("at"))
        return {"state": "exploited", "by": first.get("by"), "at": at.isoformat() if at else None, "reason": None, "legacy": True}
    return {"state": "to_assess", "by": None, "at": None, "reason": None, "legacy": False}


def _stage(stage: str, label: dict, due: datetime | None, sent: dict | None, now: datetime) -> dict:
    state = "sent" if sent else "waiting" if due is None else "overdue" if now > due else "pending"
    return {"id": stage, "label": label, "due": due.isoformat() if due else None, "state": state, "sent": sent}


def _event(key: str, product: dict, cve: str, signal: dict, report: dict, now: datetime) -> dict:
    assessment = _assessment(report, signal["signal"])
    fixed_at = None if signal["open"] else _moment(signal["fixed_at"])
    stages: list[dict] = []
    aware = _moment(assessment["at"]) if assessment["state"] == "exploited" else None
    if aware:  # the clocks only exist once the manufacturer knows its product is exploited
        dues = {"early_warning": aware + STAGES[0][2], "notification": aware + STAGES[1][2],
                "final_report": fixed_at + STAGES[2][2] if fixed_at else None}
        stages = [_stage(stage, label, dues[stage], report.get(stage) if isinstance(report.get(stage), dict) else None, now)
                  for stage, label, _ in STAGES]
    done = assessment["state"] == "not_affected" or bool(stages) and all(stage["state"] == "sent" for stage in stages)
    kev = signal["kev"]
    return {"id": f"{key}|{cve}", "asset": key, "product": product["name"], "support_until": product.get("support_until"),
            "cve": cve, "title": signal["title"], "severity": signal["severity"], "packages": sorted(signal["packages"])[:PACKAGES_SHOWN],
            "kev": {"date_added": kev.get("date_added"), "ransomware": bool(kev.get("ransomware")), "name": kev.get("name")},
            "signal_at": signal["signal"].isoformat() if signal["signal"] else None,
            "state": assessment["state"], "assessment": None if assessment["state"] == "to_assess" else
            {key_: assessment[key_] for key_ in ("by", "at", "reason", "legacy")},
            "aware_at": aware.isoformat() if aware else None,
            "status": "open" if signal["open"] else "fixed", "fixed_at": fixed_at.isoformat() if fixed_at else None,
            "stages": stages, "done": done}


def events(data_dir: Path, *, now: datetime | None = None) -> list[dict]:
    """One event per product and KEV CVE; empty while the policy is off. Most urgent first: overdue stages, then
    what is still to assess (oldest signal first), then pending stages; closed or fully reported last."""
    state = load(data_dir)
    if state["policy"].get("enabled") is not True:
        return []
    now = now or datetime.now(timezone.utc)
    decisions = triage.load(data_dir)
    result = [_event(key, product, cve, signal, state["reports"].get(f"{key}|{cve}") or {}, now)
              for key, product in state["products"].items()
              for cve, signal in _signals(data_dir, key, decisions.get(key, {})).items()]
    order = {"overdue": 0, "pending": 2, "waiting": 3, "sent": 4}

    def urgency(event: dict) -> tuple:
        if event["state"] == "to_assess":
            return (event["done"], 1, event["signal_at"] or "9999")
        open_stages = [stage for stage in event["stages"] if stage["state"] != "sent"]
        return (event["done"], min((order[stage["state"]] for stage in event["stages"]), default=4),
                min((stage["due"] for stage in open_stages if stage["due"]), default="9999"))
    result.sort(key=urgency)
    return result


def _find(data_dir: Path, state: dict, event_id) -> tuple[str, dict]:
    """The event's product key and current signal, or CraError if it is not an event of a product right now."""
    if not isinstance(event_id, str) or not EVENT_ID.fullmatch(event_id) or "|" not in event_id:
        raise CraError(msg("compliance.cra.errors.unknown_event"))
    key, _, cve = event_id.rpartition("|")
    if key not in state["products"]:
        raise CraError(msg("compliance.cra.errors.unknown_event"))
    signal = _signals(data_dir, key, triage.load(data_dir).get(key, {})).get(cve)
    if signal is None:
        raise CraError(msg("compliance.cra.errors.unknown_event"))
    return key, signal


def assess(data_dir: Path, event_id: str, verdict: str, *, reason: str | None, user: dict) -> dict:
    """Records the assessment of an event still to assess. `exploited` starts the clocks now (the awareness time);
    `not_affected` needs a reason and closes the event."""
    if verdict not in VERDICTS:
        raise CraError(msg("compliance.cra.errors.unknown_event"))
    note = _reason(reason, required=verdict == "not_affected")
    with documents.lock(data_dir, "cra"):
        state = load(data_dir)
        _, signal = _find(data_dir, state, event_id)
        report = state["reports"].setdefault(event_id, {})
        if _assessment(report, signal["signal"])["state"] != "to_assess":
            raise CraError(msg("compliance.cra.errors.already_assessed"))
        entry = {"state": verdict, "by": user["username"], "at": _now(), "reason": note}
        report["assessment"] = entry
        report["history"] = ([item for item in report.get("history") or [] if isinstance(item, dict)] + [entry])[-HISTORY:]
        _save(data_dir, state)
    _log.info("cra_assessment", extra={"user": user["username"], "reason": f"{event_id}: {verdict}" + (f" ({note})" if note else "")})
    return entry


def reopen(data_dir: Path, event_id: str, *, user: dict) -> None:
    """Back to `to_assess` after "doesn't affect our product" (new information). An exploited event can't be undone:
    its clocks and what was reported stay on record."""
    with documents.lock(data_dir, "cra"):
        state = load(data_dir)
        _, signal = _find(data_dir, state, event_id)
        report = state["reports"].setdefault(event_id, {})
        if _assessment(report, signal["signal"])["state"] != "not_affected":
            raise CraError(msg("compliance.cra.errors.not_reopenable"))
        report.pop("assessment", None)
        report["history"] = ([item for item in report.get("history") or [] if isinstance(item, dict)]
                             + [{"state": "reopened", "by": user["username"], "at": _now(), "reason": None}])[-HISTORY:]
        _save(data_dir, state)
    _log.info("cra_assessment", extra={"user": user["username"], "reason": f"{event_id}: reopened"})


def mark(data_dir: Path, event_id: str, stage: str, *, sent: bool, user: dict) -> None:
    """Records a stage as sent (or not). Only for events assessed as actively exploited in the product."""
    if stage not in STAGE_IDS:
        raise CraError(msg("compliance.cra.errors.invalid_stage"))
    with documents.lock(data_dir, "cra"):
        state = load(data_dir)
        _, signal = _find(data_dir, state, event_id)
        report = state["reports"].setdefault(event_id, {})
        current = _assessment(report, signal["signal"])
        if current["state"] != "exploited":
            raise CraError(msg("compliance.cra.errors.not_exploited"))
        if current["legacy"] and "assessment" not in report:
            # Stored once touched: unmarking every stage of an event reported before assessments must not reopen it.
            report["assessment"] = {"state": "exploited", "by": current["by"], "at": current["at"], "reason": None, "legacy": True}
        if sent:
            report[stage] = {"at": _now(), "by": user["username"]}
        else:
            report.pop(stage, None)
        _save(data_dir, state)
    _log.info("cra_report", extra={"user": user["username"], "reason": f"{event_id} {stage} {'sent' if sent else 'unmarked'}"})


# --- Draft --------------------------------------------------------------------------------------------------------

def draft_message(event: dict) -> dict | None:
    """Draft for ENISA's reporting platform, only once the event is assessed as exploited in the product; what we
    don't know is left as placeholders."""
    if event.get("state") != "exploited":
        return None
    kev = event["kev"]
    return msg("compliance.cra.draft.body", product=event["product"], cve=event["cve"],
               support=msg("compliance.cra.draft.support", date=event["support_until"]) if event.get("support_until") else "",
               kev_name=f" · {kev['name']}" if kev.get("name") else "",
               packages=", ".join(event["packages"]) or msg("compliance.cra.draft.no_component"),
               kev_date=kev.get("date_added") or "—",
               ransomware=msg("compliance.cra.draft.ransomware") if kev.get("ransomware") else "",
               aware=(event.get("aware_at") or "")[:16].replace("T", " "),
               fixed=msg("compliance.cra.draft.fixed_since", date=event["fixed_at"][:10]) if event.get("fixed_at")
               else msg("compliance.cra.draft.not_fixed"))


def draft(event: dict, locale: str | None = None) -> str:
    message = draft_message(event)
    return text(message, locale) if message else ""


def with_draft(event: dict) -> dict:
    return {**event, "draft": draft_message(event)}


# --- Overview -----------------------------------------------------------------------------------------------------

def products(data_dir: Path) -> list[dict]:
    """The assets marked as CRA products, with their latest complete scan (without one, "nothing to report" means nothing)."""
    from tamandua.modules.compliance.evidence import catalog
    rows = {row["key"]: row for row in catalog(data_dir)}
    return [{"key": key, **product, "asset": (rows.get(key) or {}).get("name", key), "last_complete": (rows.get(key) or {}).get("last_complete")}
            for key, product in load(data_dir)["products"].items()]


def candidates(data_dir: Path, *, query: str = "") -> list[dict]:
    """Analyzed assets that are not products yet, optionally filtered by name."""
    from tamandua.modules.compliance.evidence import catalog
    marked = load(data_dir)["products"]
    needle = query.strip().lower()
    return [{"key": row["key"], "name": row["name"]} for row in catalog(data_dir)
            if row["key"] not in marked and (not needle or needle in row["name"].lower())]


def overview(data_dir: Path) -> dict:
    """What the CRA section summarizes; the lists themselves are paged (products, events, candidates)."""
    from tamandua.modules.compliance.evidence import catalog
    rows = catalog(data_dir)
    complete = {row["key"] for row in rows if row["last_complete"]}
    marked = load(data_dir)["products"]
    found = events(data_dir)
    return {"reporting_page": REPORTING_PAGE,
            "counts": {"products": len(marked), "unscanned": sum(1 for key in marked if key not in complete),
                       "events": len(found), "pending": sum(1 for event in found if not event["done"]),
                       "to_assess": sum(1 for event in found if event["state"] == "to_assess"),
                       "assets": len(rows), "candidates": sum(1 for row in rows if row["key"] not in marked)}}
