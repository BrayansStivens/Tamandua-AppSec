"""VEX (OpenVEX 0.2.0): triage turned into standard statements about each vulnerability.

A VEX answers "does this dependency vulnerability affect my product?". Tamandua already stores that decision with
its reason, author and date; this maps it over, claiming nothing beyond what was decided:

* **Open, undecided** → `under_investigation`: the scanner found it, nobody has confirmed it.
* **In progress** → `affected`, with the fix as the action.
* **Risk accepted** → `affected`, with the reason and the expiry as the action.
* **False positive** → `not_affected`, with the reason as the impact statement.
* **Remediated** (by hand or because it stopped showing up) → `fixed`.

Only dependency advisories with an identifier (CVE, GHSA…) are included: first-party code is not described with VEX.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from tamandua.modules.scanning.dependency_merge import purl as build_purl
from tamandua.modules.compliance.sbom import PORTFOLIO_ASSETS, root_ref
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


def statements(record: dict, product: dict, locale: str) -> list[dict]:
    """One statement per dependency advisory of `record`, about `product` (an OpenVEX component)."""
    result = []
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
        result.append({"vulnerability": vulnerability,
                       "products": [{**product, **({"subcomponents": [{"@id": subcomponent}]} if subcomponent else {})}],
                       "status": status, **extra, **({"timestamp": decided} if decided else {})})
    return result


def _document(items: list[dict], *, tooling: str, now: datetime | None, locale: str) -> dict:
    stamp = (now or datetime.now(timezone.utc)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return {"@context": CONTEXT, "@id": f"urn:uuid:{uuid.uuid4()}", "author": "Tamandua", "role": t("compliance.vex.role", locale),
            "timestamp": stamp, "version": 1, "tooling": tooling, "statements": items}


def openvex(record: dict, *, version: str, now: datetime | None = None, locale: str | None = None) -> dict:
    locale = locale or default_locale()
    return _document(statements(record, {"@id": root_ref(record)}, locale), tooling=f"Tamandua {version}", now=now, locale=locale)


PORTFOLIO_STATEMENTS = 50_000


def portfolio(records: list[tuple[str, dict]], *, total: int, version: str, now: datetime | None = None, locale: str | None = None) -> dict:
    """The statements of several assets in one document. `records` pairs each asset's ref (the same as in the
    portfolio SBOM) with its registry view; `total` counts every asset with a complete scan. Past the limits the
    tooling line says the document is partial."""
    locale = locale or default_locale()
    items: list[dict] = []
    for ref, record in records:
        product = {"@id": ref, **({"identifiers": {"purl": ref}} if ref.startswith("pkg:") and "#" not in ref else {})}
        items.extend(statements(record, product, locale))
    tooling = f"Tamandua {version}"
    if len(records) < total:
        tooling += " · " + t("compliance.vex.portfolio_truncated", locale, shown=len(records), total=total, max_assets=PORTFOLIO_ASSETS,
                             max_statements=PORTFOLIO_STATEMENTS)
    elif len(items) > PORTFOLIO_STATEMENTS:
        first_cut = items[PORTFOLIO_STATEMENTS]["products"][0]["@id"]
        tooling += " · " + t("compliance.vex.statements_truncated", locale, max_statements=PORTFOLIO_STATEMENTS, asset=first_cut)
    return _document(items[:PORTFOLIO_STATEMENTS], tooling=tooling, now=now, locale=locale)
