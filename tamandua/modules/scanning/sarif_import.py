"""Findings from any tool's SARIF 2.1.0 (Semgrep, CodeQL, Snyk, Trivy, Gitleaks…) as Tamandua findings.

Pure: no database and no network. `parse` returns one entry per tool; results of several `runs[]` of the same tool
are merged, because an import of a tool is what later proves that tool's findings fixed.

* **Severity.** `properties["security-severity"]` (0-10, the GitHub/CodeQL convention) on the result or its rule:
  critical ≥ 9, high ≥ 7, medium ≥ 4, low > 0, info at 0. Without it, the SARIF `level` (result, else the rule's
  default): error → high, warning → medium, note → low, none → info; absent means warning.
* **Scanner.** secrets when the tool or a tag says so; sca when the rule names a CVE or GHSA or the tool is a
  dependency scanner; iac and cicd for configuration scanners; sast otherwise.
* **Fingerprint.** sha256 over ("sarif", tool, key): never equal to one of Tamandua's own engines. The key is the
  result's `fingerprints`, else rule + path + its `partialFingerprints`, else rule + path + snippet (or message).
  Never the line: adding lines above a finding must not make it look fixed. Equal keys are told apart by order.
* Text written by the tool (titles, messages, help) is kept as published and only shown inside our own sentences.
"""

from __future__ import annotations

import re
from typing import Any, TypedDict
from urllib.parse import unquote

from tamandua.modules.scanning.engines import SEVERITY_NAME, _base, _stable
from tamandua.shared.i18n import msg
from tamandua.shared.model import Finding

MAX_BYTES = 10_000_000
MAX_RUNS = 20
MAX_RESULTS = 5000
TITLE_MAX, MESSAGE_MAX, PATH_MAX, RULE_MAX, TOOL_MAX, VERSION_MAX = 300, 2000, 1000, 200, 100, 50

SECRET_TOOLS = ("gitleaks", "trufflehog", "detect-secrets", "ggshield", "gitguardian", "secretlint", "talisman")
SCA_TOOLS = ("trivy", "grype", "osv-scanner", "dependabot", "dependency-check", "npm audit", "pip-audit", "retire")
IAC_TOOLS = ("checkov", "kics", "tfsec", "terrascan", "tflint", "kube-linter", "hadolint")
CICD_TOOLS = ("zizmor", "poutine", "actionlint")
IAC_TAGS = frozenset(("misconfiguration", "iac", "infrastructure-as-code", "terraform", "kubernetes", "dockerfile", "cloudformation"))
LEVELS = {"error": "high", "warning": "medium", "note": "low", "none": "info"}
PRECISION = {"very-high": 9, "high": 8, "medium": 6, "low": 4, "very-low": 3}
CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
GHSA = re.compile(r"GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}", re.IGNORECASE)
CWE = re.compile(r"(?:^|[^a-z])cwe[-/:_ ]?0*(\d{1,5})\b", re.IGNORECASE)
OWASP = re.compile(r"\bA(\d{2}):(20\d{2})\b")


class SarifError(ValueError):
    """A document that can't be imported; `message` is a catalog message."""

    def __init__(self, message: dict):
        super().__init__(message)
        self.message = message


class ParsedRun(TypedDict):
    tool: str
    version: str | None
    findings: list[Finding]
    results: int   # results read
    skipped: int   # suppressed, passing or absent results: not findings


def clean_name(value: Any, limit: int = TOOL_MAX) -> str:
    """One printable line, bounded: a tool name or version as given by the tool."""
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        return ""  # an object where a name belongs is not a name
    return " ".join("".join(ch for ch in str(value) if ch.isprintable()).split())[:limit]


def _text(value: Any, limit: int) -> str:
    if isinstance(value, dict):
        value = value.get("text") or value.get("markdown") or ""
    return str(value or "").strip()[:limit] if isinstance(value, str) else ""


def _dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list:
    return value if isinstance(value, list) else []


def _path(uri: Any) -> str:
    path = unquote(str(uri or "")) if isinstance(uri, str) else ""
    path = re.sub(r"^file:(?://[^/]*)?", "", path)
    while path.startswith(("./", "/")):
        path = path[2:] if path.startswith("./") else path[1:]
    return "".join(ch for ch in path if ch.isprintable())[:PATH_MAX]


def _location(result: dict, artifacts: list) -> tuple[str, int, str]:
    """(path, line, normalized snippet) of the result's first physical location."""
    physical = _dict(_dict((_list(result.get("locations")) or [{}])[0]).get("physicalLocation"))
    artifact = _dict(physical.get("artifactLocation"))
    uri = artifact.get("uri")
    index = artifact.get("index")
    if not uri and isinstance(index, int) and 0 <= index < len(artifacts):
        uri = _dict(_dict(artifacts[index]).get("location")).get("uri")
    region = _dict(physical.get("region"))
    line = region.get("startLine")
    snippet = _text(_dict(region.get("snippet")).get("text"), MESSAGE_MAX) or _text(_dict(physical.get("contextRegion")).get("snippet"), MESSAGE_MAX)
    return _path(uri), line if isinstance(line, int) and not isinstance(line, bool) and 0 < line < 10_000_000 else 1, " ".join(snippet.split())


def _severity(result: dict, rule: dict) -> str:
    for properties in (_dict(result.get("properties")), _dict(rule.get("properties"))):
        raw = properties.get("security-severity")
        try:
            score = float(raw) if raw is not None and not isinstance(raw, bool) else None
        except (TypeError, ValueError):
            score = None
        if score is not None and 0 <= score <= 10:
            return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low" if score > 0 else "info"
    level = result.get("level") or _dict(rule.get("defaultConfiguration")).get("level") or "warning"
    return LEVELS.get(str(level), "medium")


def _tags(result: dict, rule: dict) -> list[str]:
    return [tag for properties in (_dict(result.get("properties")), _dict(rule.get("properties")))
            for tag in _list(properties.get("tags")) if isinstance(tag, str)][:200]


def _cwes(result: dict, rule: dict, tags: list[str]) -> list[int]:
    found = [int(match.group(1)) for tag in tags for match in CWE.finditer(tag)]
    references = [*_list(result.get("taxa")), *(_dict(item).get("target") for item in _list(rule.get("relationships")))]
    for reference in references:
        reference = _dict(reference)
        if str(_dict(reference.get("toolComponent")).get("name", "")).upper() == "CWE":
            number = re.sub(r"(?i)^cwe-?", "", str(reference.get("id") or ""))
            if number.isdigit():
                found.append(int(number))
    return sorted({item for item in found if 0 < item < 100_000})[:20]


def _scanner(tool: str, tags: list[str], cves: list[str], ghsas: list[str]) -> str:
    name, lowered = tool.lower(), {tag.lower() for tag in tags}
    if any(item in name for item in SECRET_TOOLS) or any("secret" in tag for tag in lowered):
        return "secrets"
    if cves or ghsas:
        return "sca"
    if any(item in name for item in CICD_TOOLS):
        return "cicd"
    if any(item in name for item in IAC_TOOLS) or lowered & IAC_TAGS:
        return "iac"
    if any(item in name for item in SCA_TOOLS) or ("snyk" in name and "code" not in name):
        return "sca"
    return "sast"


def _rule(result: dict, rules: dict[str, dict], components: list[dict]) -> tuple[str, dict]:
    """The result's rule, from the driver or an extension (CodeQL keeps its queries in `tool.extensions`)."""
    reference = _dict(result.get("rule"))
    rule_id = result.get("ruleId") or reference.get("id")
    index = result.get("ruleIndex", reference.get("index"))
    component = _dict(reference.get("toolComponent")).get("index")
    ordered = _list(components[component + 1].get("rules")) if isinstance(component, int) and 0 <= component < len(components) - 1 \
        else _list(components[0].get("rules"))
    rule = _dict(ordered[index]) if isinstance(index, int) and 0 <= index < len(ordered) else rules.get(str(rule_id), {})
    rule_id = rule_id or rule.get("id") or "sarif"
    return clean_name(rule_id, RULE_MAX) or "sarif", rule


def _suppressed(result: dict) -> bool:
    kind = result.get("kind", "fail")
    if kind in ("pass", "notApplicable", "informational") or result.get("baselineState") == "absent":
        return True
    return any(_dict(item).get("status", "accepted") == "accepted" for item in _list(result.get("suppressions")))


def _key(result: dict, rule_id: str, path: str, snippet: str, message: str) -> str:
    full = {name: value for name, value in _dict(result.get("fingerprints")).items() if isinstance(value, str) and value}
    if full:
        return "\x1f".join(f"{name}={full[name]}" for name in sorted(full))
    partial = {name: value for name, value in _dict(result.get("partialFingerprints")).items() if isinstance(value, str) and value}
    evidence = ("\x1f".join(f"{name}={partial[name]}" for name in sorted(partial)) if partial
                else snippet or " ".join(message.split()))
    return "\x1f".join((rule_id, path, evidence))


def _finding(result: dict, rule: dict, rule_id: str, tool: str, location: tuple[str, int, str], digest: str) -> Finding:
    path, line, _ = location
    message = _text(result.get("message"), MESSAGE_MAX)
    title = _text(rule.get("shortDescription"), TITLE_MAX) or (message.splitlines() or [""])[0][:TITLE_MAX] or rule_id
    tags = _tags(result, rule)
    identifiers = [rule_id, *tags]
    cves = sorted({match.upper() for item in identifiers for match in CVE.findall(item)})[:20]
    ghsas = sorted({match[:4].upper() + match[4:].lower() for item in identifiers for match in GHSA.findall(item)})[:20]
    scanner = _scanner(tool, tags, cves, ghsas)
    severity = _severity(result, rule)
    help_text = _text(rule.get("help"), MESSAGE_MAX) or _text(rule.get("fullDescription"), MESSAGE_MAX)
    precision = str(_dict(rule.get("properties")).get("precision") or "").lower()
    finding = _base(scanner, rule_id, title, path, line, severity, tool=tool,
                    reason=msg("scanning.sarif.reason", tool=tool, message=message or title),
                    remediation=msg("scanning.sarif.remediation_help", tool=tool, help=help_text) if help_text
                    else msg("scanning.sarif.remediation", tool=tool),
                    cwe=_cwes(result, rule, tags), owasp="", confidence=PRECISION.get(precision, 6), digest=digest)
    finding["title"], finding["cve"], finding["ghsa"] = title, cves, ghsas
    finding["owasp"] = sorted({f"A{number}:{year}" for tag in tags for number, year in OWASP.findall(tag)})[:10]
    finding["priority"]["factors"] = [msg("scanning.sarif.priority", tool=tool, severity=SEVERITY_NAME.get(finding["severity"], severity)),
                                      msg("scanning.priority.confirm_reachability")]
    return finding


def parse(document: Any, *, tool: str | None = None) -> list[ParsedRun]:
    """The document's findings, one entry per tool, in order of appearance. `tool` names every run."""
    if not isinstance(document, dict) or document.get("version") != "2.1.0":
        raise SarifError(msg("scanning.sarif.errors.version"))
    runs = document.get("runs")
    if not isinstance(runs, list) or not runs:
        raise SarifError(msg("scanning.sarif.errors.no_runs"))
    if len(runs) > MAX_RUNS:
        raise SarifError(msg("scanning.sarif.errors.too_many_runs", max=MAX_RUNS))
    if sum(len(_list(_dict(run).get("results"))) for run in runs) > MAX_RESULTS:
        raise SarifError(msg("scanning.sarif.errors.too_many_results", max=MAX_RESULTS))
    override = clean_name(tool) if tool is not None else None
    if tool is not None and not override:
        raise SarifError(msg("scanning.sarif.errors.no_tool"))
    grouped: dict[str, ParsedRun] = {}
    occurrences: dict[tuple[str, str], int] = {}
    for run in runs:
        driver = _dict(_dict(_dict(run).get("tool")).get("driver"))
        name = override or clean_name(driver.get("name"))
        if not name:
            raise SarifError(msg("scanning.sarif.errors.no_tool"))
        group = grouped.setdefault(name.lower(), {"tool": name, "version": clean_name(driver.get("semanticVersion") or driver.get("version"),
                                                                                       VERSION_MAX) or None,
                                                  "findings": [], "results": 0, "skipped": 0})
        components = [driver, *(_dict(item) for item in _list(_dict(_dict(run).get("tool")).get("extensions")))]
        rules = {str(_dict(item).get("id")): _dict(item) for component in reversed(components) for item in _list(component.get("rules"))
                 if _dict(item).get("id")}
        artifacts = _list(_dict(run).get("artifacts"))
        for result in _list(_dict(run).get("results")):
            if not isinstance(result, dict):
                continue
            group["results"] += 1
            if _suppressed(result):
                group["skipped"] += 1
                continue
            rule_id, rule = _rule(result, rules, components)
            location = _location(result, artifacts)
            key = _key(result, rule_id, location[0], location[2], _text(result.get("message"), MESSAGE_MAX))
            seen = occurrences.get((name.lower(), key), 0)
            occurrences[(name.lower(), key)] = seen + 1
            digest = _stable("sarif", name.lower(), key if not seen else f"{key}\x1f#{seen + 1}")
            group["findings"].append(_finding(result, rule, rule_id, group["tool"], location, digest))
    return list(grouped.values())
