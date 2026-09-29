"""OWASP Web Top 10:2025 coverage computed from what actually ran.

Each category is marked from the engines and rules that ran and the findings
they produced, not with a generic sentence. Our own rules declare their
category in `metadata.owasp`; here they are counted per category by reading the
rule files (our own format, so a regular expression is enough).
"""

from __future__ import annotations

import re
from functools import lru_cache

from tamandua.shared import paths
from tamandua.shared.i18n import msg
from tamandua.modules.scanning.engines import and_list, joined
from tamandua.modules.scanning.owasp import WEB_TOP_10_2025

RULES_DIR = paths.RULES_DIR
RULE_LINE = re.compile(r"^  - id: (?P<id>\S+)|^\s+metadata: \{.*?owasp: \"(?P<owasp>A\d\d):2025\"", re.M)
UNTESTABLE = {
    "A06": msg("coverage.untestable.a06"),
    "A09": msg("coverage.untestable.a09"),
    "A10": msg("coverage.untestable.a10"),
}


@lru_cache(maxsize=1)
def rules_by_category() -> dict[str, int]:
    """How many of our own rules target each OWASP category."""
    counts: dict[str, int] = {}
    for path in sorted(RULES_DIR.glob("*.yml")):
        current = None
        for match in RULE_LINE.finditer(path.read_text(encoding="utf-8")):
            if match.group("id"):
                current = match.group("id")
            elif current and match.group("owasp"):
                counts[match.group("owasp")] = counts.get(match.group("owasp"), 0) + 1
                current = None
    return counts


def owasp_coverage(findings: list[dict], *, sast_ran: bool, sca_status: str, iac_ran: bool,
                   iac_files: int, secrets_ran: bool, engines: bool, iac_tools: tuple[str, ...] = ("Trivy",),
                   cicd_tools: tuple[str, ...] = (), pipeline_files: int = 0) -> list[dict]:
    rules = rules_by_category() if sast_ran else {}
    per_category: dict[str, int] = {}
    for finding in findings:
        for category in finding.get("owasp", []):
            per_category[category[:3]] = per_category.get(category[:3], 0) + 1
    result = []
    for identifier, title in WEB_TOP_10_2025:
        found = per_category.get(identifier, 0)
        parts, status = [], "not_tested"
        if identifier == "A03":
            if sca_status in ("partial", "completed"):
                status = "partial"
                parts.append(msg("coverage.sca.engines") if engines else msg("coverage.sca.osv"))
            elif sca_status == "inconclusive":
                status = "inconclusive"
                parts.append(msg("coverage.sca.inconclusive"))
            else:
                parts.append(msg("coverage.sca.none"))
            if cicd_tools and pipeline_files:
                status = "partial" if status == "not_tested" else status
                parts.append(msg("coverage.cicd", tools=and_list(cicd_tools), count=pipeline_files))
        if identifier == "A02":
            if iac_ran and iac_files:
                status = "partial"
                parts.append(msg("coverage.iac.reviewed", tools=and_list(iac_tools), count=iac_files))
            elif iac_ran:
                parts.append(msg("coverage.iac.none_many", tools=and_list(iac_tools)) if len(iac_tools) > 1
                             else msg("coverage.iac.none_one", tools=and_list(iac_tools)))
            if rules.get("A02"):
                status = "partial"
                parts.append(msg("coverage.rules.configuration", count=rules["A02"]))
        if identifier == "A04":
            if secrets_ran:
                status = "partial"
                parts.append(msg("coverage.secrets.engines") if engines else msg("coverage.secrets.internal"))
            if rules.get("A04"):
                status = "partial"
                parts.append(msg("coverage.rules.crypto", count=rules["A04"]))
        if identifier in ("A01", "A05", "A07", "A08") and rules.get(identifier):
            status = "partial"
            parts.append(msg("coverage.rules.opengrep", count=rules[identifier]))
        if identifier == "A05" and not sast_ran and not engines:
            status = "partial"
            parts.append(msg("coverage.internal_ast"))
        if identifier in UNTESTABLE and status == "not_tested":
            parts.append(UNTESTABLE[identifier])
        if status == "not_tested" and not parts:
            parts.append(msg("coverage.no_engine"))
        reason = joined(parts, "coverage.join")
        if status == "partial":
            reason = msg("coverage.with_findings", reason=reason, count=found) if found else msg("coverage.without_findings", reason=reason)
        result.append({"id": identifier, "title": title, "status": status,
                       "rules": rules.get(identifier, 0), "findings": found, "reason": reason})
    return result
