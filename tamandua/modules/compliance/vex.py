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

CONTEXT = "https://openvex.dev/ns/v0.2.0"


def _status(finding: dict) -> tuple[str, dict]:
    decision = finding.get("triage") or {}
    manual = decision.get("status", "open")
    reason = str(decision.get("reason") or "").strip()
    if (finding.get("lifecycle") or {}).get("status") == "fixed" or manual == "fixed":
        return "fixed", {}
    if manual == "false_positive":
        return "not_affected", {"impact_statement": reason or "Descartado en el triage como falso positivo."}
    if manual == "accepted":
        until = f" (hasta {decision['expires_at']})" if decision.get("expires_at") else ""
        return "affected", {"action_statement": f"Riesgo aceptado{until}: {reason}".strip()}
    if manual == "in_progress":
        return "affected", {"action_statement": finding.get("remediation") or "Corrección en curso."}
    return "under_investigation", {}


def _vulnerability(finding: dict) -> dict | None:
    ids = [*(finding.get("cve") or []), *(finding.get("ghsa") or [])]
    main = ids[0] if ids else str(finding.get("rule_id") or "")
    if not main:
        return None
    aliases = sorted({item for item in [*ids, finding.get("rule_id")] if item and item != main})
    return {"name": main, **({"aliases": aliases} if aliases else {})}


def openvex(record: dict, *, version: str, now: datetime | None = None) -> dict:
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
        status, extra = _status(finding)
        subcomponent = build_purl(package)
        decided = (finding.get("triage") or {}).get("at")
        statements.append({"vulnerability": vulnerability,
                           "products": [{"@id": product, **({"subcomponents": [{"@id": subcomponent}]} if subcomponent else {})}],
                           "status": status, **extra, **({"timestamp": decided} if decided else {})})
    return {"@context": CONTEXT, "@id": f"urn:uuid:{uuid.uuid4()}", "author": "Tamandua", "role": "Documento generado a partir del triage",
            "timestamp": stamp, "version": 1, "tooling": f"Tamandua {version}", "statements": statements}
