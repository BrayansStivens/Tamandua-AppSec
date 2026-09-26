"""VEX (OpenVEX 0.2.0): el triage convertido en declaraciones estándar sobre cada vulnerabilidad.

Un VEX responde «¿esta vulnerabilidad de una dependencia afecta a mi producto?». Tamandua ya guarda esa decisión
con su motivo, autor y fecha; aquí se traduce, sin inventar más de lo que se decidió:

* **Abierto, sin decidir** → `under_investigation`: el escáner lo encontró, nadie lo ha confirmado.
* **En curso** → `affected`, con la corrección como acción.
* **Riesgo aceptado** → `affected`, con el motivo y la caducidad como acción.
* **Falso positivo** → `not_affected`, con el motivo como declaración de impacto.
* **Remediado** (a mano o porque dejó de aparecer) → `fixed`.

Solo entran avisos de dependencias con identificador (CVE, GHSA…): el código propio no se describe con VEX.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from tamandua.modules.intel.advisory_watch import purl as build_purl
from tamandua.modules.compliance.sbom import root_ref
from tamandua.shared.i18n import default_locale, t, text

CONTEXT = "https://openvex.dev/ns/v0.2.0"


def _status(finding: dict, locale: str) -> tuple[str, dict]:
    decision = finding.get("triage") or {}
    manual = decision.get("status", "open")
    reason = text(decision.get("reason"), locale).strip()
    if (finding.get("lifecycle") or {}).get("status") == "fixed" or manual == "fixed":
        return "fixed", {}
    if manual == "false_positive":
        return "not_affected", {"impact_statement": reason or t("compliance.vex.false_positive", locale)}
    if manual == "accepted":
        statement = (t("compliance.vex.accepted_until", locale, date=decision["expires_at"], reason=reason) if decision.get("expires_at")
                     else t("compliance.vex.accepted", locale, reason=reason))
        return "affected", {"action_statement": statement.strip()}
    if manual == "in_progress":
        return "affected", {"action_statement": text(finding.get("remediation"), locale) or t("compliance.vex.in_progress", locale)}
    return "under_investigation", {}


def _vulnerability(finding: dict) -> dict | None:
    ids = [*(finding.get("cve") or []), *(finding.get("ghsa") or [])]
    main = ids[0] if ids else str(finding.get("rule_id") or "")
    if not main:
        return None
    aliases = sorted({item for item in [*ids, finding.get("rule_id")] if item and item != main})
    return {"name": main, **({"aliases": aliases} if aliases else {})}


def openvex(record: dict, *, version: str, now: datetime | None = None, locale: str | None = None) -> dict:
    locale = locale or default_locale()
    stamp = (now or datetime.now(timezone.utc)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    product = root_ref(record)
    statements = []
    for finding in record.get("findings") or []:
        package = finding.get("package") or {}
        if finding.get("scanner") != "sca" or not package.get("name") or (finding.get("lifecycle") or {}).get("status") == "excluded":
            continue
        vulnerability = _vulnerability(finding)
        if vulnerability is None:
            continue
        status, extra = _status(finding, locale)
        subcomponent = build_purl(package)
        decided = (finding.get("triage") or {}).get("at")
        statements.append({"vulnerability": vulnerability,
                           "products": [{"@id": product, **({"subcomponents": [{"@id": subcomponent}]} if subcomponent else {})}],
                           "status": status, **extra, **({"timestamp": decided} if decided else {})})
    return {"@context": CONTEXT, "@id": f"urn:uuid:{uuid.uuid4()}", "author": "Tamandua", "role": t("compliance.vex.role", locale),
            "timestamp": stamp, "version": 1, "tooling": f"Tamandua {version}", "statements": statements}
