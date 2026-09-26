"""Kit CRA: plazos de notificación de vulnerabilidades explotadas activamente (Reglamento UE 2024/2847, art. 14).

Desde el 11-09-2026 el fabricante de un producto con elementos digitales vendido en la UE debe notificar a ENISA
(plataforma única de notificación) cada vulnerabilidad de su producto que se explote activamente:

* **Alerta temprana**: sin demora indebida y, como mucho, 24 h después de tener conocimiento.
* **Notificación**: como mucho 72 h después, con la información general y las medidas disponibles.
* **Informe final**: como mucho 14 días después de que haya una medida correctora disponible.

Aquí un administrador marca qué activos son **productos** bajo el CRA. Un hallazgo abierto de un producto con un CVE
del catálogo CISA KEV abre un **evento** con esos tres relojes, que cuentan desde que se supo (lo más tardío entre
la primera detección y el alta en KEV). Tamandua no notifica: prepara el borrador y guarda quién marcó cada etapa
como enviada y cuándo. Un falso positivo en el triage («no afecta») no abre evento. Los datos: `data/cra.json`.
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
REPORTING_PAGE = "https://digital-strategy.ec.europa.eu/en/policies/cra-reporting"
NAME_MAX = 120


class CraError(ValueError):
    """`message` is what people read (rendered per reader); str() stays English, for logs."""

    def __init__(self, message):
        super().__init__(text(message, "en"))
        self.message = message


def load(data_dir: Path) -> dict:
    payload = documents.load(data_dir, "cra", {})
    payload = payload if isinstance(payload, dict) else {}
    return {"products": payload.get("products") if isinstance(payload.get("products"), dict) else {},
            "reports": payload.get("reports") if isinstance(payload.get("reports"), dict) else {}}


def _save(data_dir: Path, payload: dict) -> None:
    documents.save(data_dir, "cra", payload)


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
        state["products"][key] = {"name": name, "support_until": support_until or None, "by": user["username"],
                                  "at": datetime.now(timezone.utc).isoformat()}
        _save(data_dir, state)
    _log.info("cra_product", extra={"user": user["username"], "reason": f"{key} marcado como producto CRA"})
    return state["products"][key]


def remove_product(data_dir: Path, key: str, *, user: dict) -> None:
    with documents.lock(data_dir, "cra"):
        state = load(data_dir)
        if state["products"].pop(key, None) is not None:
            _save(data_dir, state)
            _log.info("cra_product", extra={"user": user["username"], "reason": f"{key} ya no es producto CRA"})


def mark(data_dir: Path, event_id: str, stage: str, *, sent: bool, user: dict) -> None:
    if stage not in STAGE_IDS or not isinstance(event_id, str) or not re.fullmatch(r"[A-Za-z0-9#:_./@+|-]{3,300}", event_id):
        raise CraError(msg("compliance.cra.errors.invalid_stage"))
    with documents.lock(data_dir, "cra"):
        state = load(data_dir)
        stages = state["reports"].setdefault(event_id, {})
        if sent:
            stages[stage] = {"at": datetime.now(timezone.utc).isoformat(), "by": user["username"]}
        else:
            stages.pop(stage, None)
        _save(data_dir, state)
    _log.info("cra_report", extra={"user": user["username"], "reason": f"{event_id} {stage} {'enviada' if sent else 'desmarcada'}"})


def _moment(value) -> datetime | None:
    try:
        moment = datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def _stage(stage: str, label: dict, due: datetime | None, sent: dict | None, now: datetime) -> dict:
    state = "sent" if sent else "waiting" if due is None else "overdue" if now > due else "pending"
    return {"id": stage, "label": label, "due": due.isoformat() if due else None, "state": state, "sent": sent}


def events(data_dir: Path, *, now: datetime | None = None) -> list[dict]:
    """Un evento por producto y CVE en KEV, con sus tres relojes. Lo más urgente primero."""
    now = now or datetime.now(timezone.utc)
    state = load(data_dir)
    decisions = triage.load(data_dir)
    result = []
    for key, product in state["products"].items():
        manual = decisions.get(key, {})
        grouped: dict[str, dict] = {}
        for digest, entry in (findings_registry.load(data_dir, key).get("findings") or {}).items():
            finding = entry.get("finding") or {}
            kev = finding.get("kev")
            cves = finding.get("cve") or []
            if not kev or not cves or entry.get("status") == "excluded":
                continue
            if (triage.effective(manual.get(digest)) or {}).get("status") == "false_positive":
                continue  # decidido que no afecta al producto: no hay nada que notificar
            seen, listed = _moment(entry.get("first_seen")), _moment(kev.get("date_added"))
            aware = max(moment for moment in (seen, listed) if moment) if (seen or listed) else None
            fixed = entry.get("fixed") or {}
            event = grouped.setdefault(cves[0], {"cve": cves[0], "aware": aware, "fixed_at": None, "open": False, "packages": set(),
                                                 "title": finding.get("title"), "kev": kev, "severity": finding.get("severity")})
            if aware and (event["aware"] is None or aware < event["aware"]):
                event["aware"] = aware
            event["open"] |= entry.get("status") == "open"
            if entry.get("status") == "fixed" and fixed.get("at"):
                event["fixed_at"] = max(filter(None, [event["fixed_at"], fixed["at"]]))
            name = (finding.get("package") or {}).get("name")
            if name:
                event["packages"].add(f"{name} {(finding.get('package') or {}).get('version') or ''}".strip())
        for cve, event in grouped.items():
            identifier = f"{key}|{cve}"
            sent = state["reports"].get(identifier, {})
            fixed_at = None if event["open"] else _moment(event["fixed_at"])
            dues = {"early_warning": event["aware"] + STAGES[0][2] if event["aware"] else None,
                    "notification": event["aware"] + STAGES[1][2] if event["aware"] else None,
                    "final_report": fixed_at + STAGES[2][2] if fixed_at else None}
            stages = [_stage(stage, label, dues[stage], sent.get(stage), now) for stage, label, _ in STAGES]
            result.append({"id": identifier, "asset": key, "product": product["name"], "support_until": product.get("support_until"),
                           "cve": cve, "title": event["title"], "severity": event["severity"], "packages": sorted(event["packages"])[:10],
                           "kev": {"date_added": event["kev"].get("date_added"), "ransomware": bool(event["kev"].get("ransomware")),
                                   "name": event["kev"].get("name")},
                           "aware_at": event["aware"].isoformat() if event["aware"] else None,
                           "status": "open" if event["open"] else "fixed", "fixed_at": fixed_at.isoformat() if fixed_at else None,
                           "stages": stages, "done": all(stage["state"] == "sent" for stage in stages)})
    order = {"overdue": 0, "pending": 1, "waiting": 2, "sent": 3}
    result.sort(key=lambda item: (item["done"], min(order[stage["state"]] for stage in item["stages"]),
                                  min((stage["due"] for stage in item["stages"] if stage["due"] and stage["state"] != "sent"), default="9999")))
    return result


def draft_message(event: dict) -> dict:
    """Draft for ENISA's reporting platform: what to tell, with what we don't know left as placeholders."""
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
    return text(draft_message(event), locale)


def overview(data_dir: Path) -> dict:
    """Lo que muestra la vista Cumplimiento: productos (con su último análisis completo), eventos con su borrador y
    los activos que se pueden marcar. Sin un análisis completo terminado, «nada por notificar» no significaría nada."""
    from tamandua.modules.runs.kinds import FULL_SCANS
    from tamandua.modules.runs.store import list_runs
    from tamandua.modules.sources.assets import asset_key, overview as assets_overview
    assets = {row["key"]: row.get("name") or row["key"] for row in assets_overview(data_dir)}
    complete: dict[str, str] = {}
    for row in list_runs(data_dir):  # de más reciente a más antiguo
        if row["type"] in FULL_SCANS and row["status"] == "completed":
            complete.setdefault(asset_key(row), row["created_at"])
    products = [{"key": key, **product, "asset": assets.get(key, key), "last_complete": complete.get(key)}
                for key, product in load(data_dir)["products"].items()]
    return {"products": products, "events": [{**event, "draft": draft_message(event)} for event in events(data_dir)],
            "reporting_page": REPORTING_PAGE, "assets": [{"key": key, "name": name} for key, name in assets.items()]}
