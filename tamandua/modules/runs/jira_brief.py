"""The description of a Jira issue, written for the developer who has to fix it.

In the order they need it: what's wrong in one sentence, where (repository, file and line, linked to the code when the
commit is known), how to fix it (steps, the exact command, a before/after example), how to verify it, the deadline and
the context that justifies it, and references. No internal jargon (engine names, rule ids, priority factors, CVSS
vectors) and never a secret's value. Built as structured blocks (`jira.adf_document`), not from Markdown, with a plain
text version for text fields and templates.
"""

from __future__ import annotations

import re
from typing import Any, cast

from tamandua.modules.findings import fix_guide, sla
from tamandua.modules.intel.advisories import compare_versions
from tamandua.shared.i18n import localize, t, text
from tamandua.shared.model import Finding

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
REFERENCES_MAX = 8
ADVISORIES_MAX = 20
SHA = re.compile(r"[0-9a-f]{7,40}")
OS_MANAGERS = frozenset(fix_guide.OS_DATABASES.values())  # apt, apk, dnf: a package of an image's system


def _t(key: str, locale: str, **params) -> str:
    return t(f"integrations.jira.brief.{key}", locale, **params)


def severity_label(level: str, locale: str) -> str:
    label = t(f"scanning.severity.{level}", locale) if level in SEVERITY_ORDER else level
    return label[:1].upper() + label[1:]


def _code_url(source: dict, path: str, line: int | None) -> str | None:
    """The file at the scanned commit on GitHub; nothing when the commit or the repository isn't known."""
    repository = str(source.get("id") or "").removeprefix("github:")
    commit = str(source.get("commit") or "")
    if not str(source.get("id") or "").startswith("github:") or "/" not in repository or not SHA.fullmatch(commit) or not path:
        return None
    anchor = f"#L{line}" if isinstance(line, int) and line > 0 else ""
    return f"https://github.com/{repository}/blob/{commit}/{path}{anchor}"


def _reference_url(identifier: str) -> str | None:
    if identifier.startswith("CVE-"):
        return f"https://nvd.nist.gov/vuln/detail/{identifier}"
    if identifier.startswith("GHSA-"):
        return f"https://github.com/advisories/{identifier}"
    return None


# Steps that speak to the panel (a "Verify again" button, "this advisory") or that "How to verify it" already says.
NOT_FOR_JIRA = ("findings.fix.verify", "findings.fix.verify_dependency", "findings.fix.verify_image", "findings.fix.secret.verify",
                "findings.fix.closes_all")


def _fix(members: list[dict], locale: str) -> dict:
    """The fix guide of the group: for a package, the version that closes every advisory (same as the panel)."""
    attached = fix_guide.attach([cast(Finding, dict(item)) for item in members])
    found = next((item.get("fix") for item in attached if item.get("fix")), None)
    guide: dict = dict(found) if found else {}
    if not guide:
        return {}
    guide["steps"] = [step for step in guide.get("steps") or [] if not (isinstance(step, dict) and step.get("$t") in NOT_FOR_JIRA)]
    return localize(guide, locale)


def _sentence(value: str) -> str:
    value = value.strip()
    return value if not value or value[-1] in ".!?:…" else value + "."


def _kind(members: list[dict], guide: dict) -> str:
    """What "fixed" means for this issue: secret, image (an OS package), dependency, dependency without a fix, code."""
    lead = members[0]
    package = lead.get("package") or {}
    if lead.get("scanner") == "secrets":
        return "secret"
    if package.get("name"):
        if fix_guide.manager(str(lead.get("path") or ""), str(package.get("ecosystem") or "")) in OS_MANAGERS:
            return "image"
        return "dependency" if guide.get("commands") or any((item.get("package") or {}).get("fixed_version") for item in members) else "no_fix"
    return "code"


def _how_to_fix(guide: dict, fallback: str, update: str | None, locale: str) -> list[dict]:
    steps = [_sentence(step) for step in (guide.get("steps") or []) if step]
    blocks: list[dict] = [{"heading": _t("how_to_fix", locale)}]
    if steps:
        blocks.append({"ordered": [[step] for step in steps]})
    elif update:
        blocks.append({"paragraph": [_sentence(update)]})
    elif fallback:
        blocks.append({"paragraph": [_sentence(fallback)]})
    # The panel's order: the edit first (example), then the command that applies it.
    example = guide.get("example") or {}
    language = example.get("language")
    if example.get("before"):
        blocks += [{"paragraph": [{"strong": _t("before", locale)}]}, {"code": example["before"], "language": language},
                   {"paragraph": [{"strong": _t("after", locale)}]}, {"code": example.get("after") or "", "language": language}]
    elif example.get("after"):
        blocks.append({"code": example["after"], "language": language})  # a snippet to add (overrides, a pinned version…)
    if example.get("note") and (example.get("before") or example.get("after")):
        blocks.append({"paragraph": [example["note"]]})
    for command in guide.get("commands") or []:
        blocks += [{"paragraph": [f"{command.get('label') or ''}:"]}, {"code": command.get("code") or "", "language": "bash"}]
    return blocks


def brief(group: list[dict], findings: dict, *, asset: str, source: dict | None, first_seen: dict, days: dict,
          panel_url: str | None, locale: str) -> dict[str, Any]:
    """{"blocks": [...], "text": "..."} for one issue: a group of tickets (one finding, or one package's advisories)."""
    source = source or {}
    members = [findings.get(ticket["fingerprint"]) or {} for ticket in group]
    first, lead = group[0], members[0]
    severity = min((ticket["severity"] for ticket in group), key=lambda item: SEVERITY_ORDER.index(item) if item in SEVERITY_ORDER else 9)
    package = lead.get("package") or {}
    blocks: list[dict] = [{"heading": _t("whats_wrong", locale)}]

    # What's wrong
    if package.get("name"):
        fixes = [(item.get("package") or {}).get("fixed_version") for item in members]
        target = None
        for version in filter(None, fixes):
            target = version if target is None or compare_versions(version, target) > 0 else target
        closes = "all" if target and all(fixes) else "some" if target else "none"
        fixed = sum(1 for version in fixes if version)
        blocks.append({"paragraph": [_t(f"package_{closes}", locale, package=package["name"], version=package.get("version") or "?",
                                        ecosystem=package.get("ecosystem") or "", count=len(group), target=target or "",
                                        fixed=fixed, rest=len(group) - fixed)]})
        rows = []
        for item, ticket in list(zip(members, group))[:ADVISORIES_MAX]:
            identifier = next(iter(item.get("cve") or item.get("ghsa") or [item.get("rule_id") or ""]), "")
            url = _reference_url(identifier)
            summary = text((item.get("advisory") or {}).get("summary"), locale) or text(item.get("title"), locale)
            rows.append([{"link": identifier, "url": url} if url else {"code": identifier}, f" · {severity_label(ticket['severity'], locale)} · {summary}"])
        blocks += [{"paragraph": [{"strong": _t("advisories", locale, count=len(group))}]}, {"bullets": rows}]
    else:
        sentence: list = [{"strong": text(lead.get("title"), locale) or text(first.get("summary"), locale)}]
        reason = text(lead.get("reason"), locale)
        if reason:
            sentence.append(". " + _sentence(reason))
        blocks.append({"paragraph": sentence})
        if lead.get("scanner") == "secrets":
            blocks.append({"paragraph": [_t("secret_value", locale)]})
    cwes = list(dict.fromkeys(item for member in members for item in member.get("cwe") or []))
    if cwes:
        blocks.append({"paragraph": [_t("weakness", locale)] + [
            part for index, cwe in enumerate(cwes[:3]) for part in ([", "] if index else [])
            + [{"link": f"CWE-{cwe}", "url": f"https://cwe.mitre.org/data/definitions/{cwe}.html"}]]})

    # Where
    guide = _fix(members, locale)
    kind = _kind(members, guide)
    image = source.get("provider") == "registry" or kind == "image"
    where: list[list] = [[_t("image" if image else "repository", locale), {"strong": asset}]
                         + ([f" ({_t('branch', locale, branch=source['branch'])})"] if source.get("branch") and not image else [])]
    path, line = str(lead.get("path") or ""), lead.get("line") if isinstance(lead.get("line"), int) else None
    if path:
        label = path if package.get("name") or not line else f"{path}:{line}"
        url = _code_url(source, path, None if package.get("name") else line)
        where.append([_t("in_image" if image else "manifest" if package.get("name") else "file", locale)]
                     + [{"link": label, "url": url} if url else {"code": label}])
    if package.get("name") and len(group) == 1:
        where.append([_t("package", locale), {"code": f"{package['name']} {package.get('version') or ''}".strip()}])
    blocks += [{"heading": _t("where", locale)}, {"bullets": where}]

    # How to fix, and how to verify (what "fixed" means depends on what it is)
    target = next((version for version in sorted(filter(None, ((item.get("package") or {}).get("fixed_version") for item in members)),
                                                 key=_version_key)[-1:]), None)
    update = t("findings.remediation.update", locale, package=package["name"], version=target) if package.get("name") and target else None
    blocks += _how_to_fix(guide, text(lead.get("remediation"), locale), update, locale)
    blocks += [{"heading": _t("verify", locale)}, {"paragraph": [_t(f"verify_{kind}", locale)]}]

    # Deadline and context
    context: list[list] = [[_t("severity", locale), {"strong": severity_label(severity, locale)}]]
    deadlines = sorted(filter(None, ((sla.deadline(ticket["severity"], first_seen.get(ticket["fingerprint"]), days) or {}).get("due")
                                     for ticket in group)))
    if deadlines:
        context.append([_t("due", locale), {"strong": deadlines[0]}])
    seen = sorted(filter(None, (first_seen.get(ticket["fingerprint"]) for ticket in group)))
    if seen:
        context.append([_t("detected", locale, date=str(seen[0])[:10])])
    kev = next((item["kev"] for item in members if item.get("kev")), None)
    if kev:
        context.append([{"strong": _t("kev_ransomware" if kev.get("ransomware") else "kev", locale, date=kev.get("date_added") or "?")}])
    scores: list[float] = [score for item in members if isinstance(score := (item.get("advisory") or {}).get("cvss_score"), (int, float))]
    if scores:
        context.append([_t("cvss", locale, score=f"{max(scores):.1f}")])
    blocks += [{"heading": _t("context", locale)}, {"bullets": context}]

    # References
    identifiers = list(dict.fromkeys(item for member in members for item in [*(member.get("cve") or []), *(member.get("ghsa") or [])]))
    references = [[{"link": item, "url": url}] for item in identifiers if (url := _reference_url(item))]
    extra = [url for member in members for url in (member.get("advisory") or {}).get("references") or [] if isinstance(url, str)]
    references += [[{"link": url, "url": url}] for url in dict.fromkeys(extra) if url.startswith("https://")]
    if references:
        blocks += [{"heading": _t("references", locale)}, {"bullets": references[:REFERENCES_MAX]}]

    footer: list = []
    if panel_url:
        footer.append({"link": _t("open_in_tamandua", locale), "url": panel_url})
    footer.append(("  ·  " if footer else "") + _t("finding_id", locale, id=str(first.get("finding_id") or first["fingerprint"][:16])))
    blocks.append({"paragraph": footer})
    return {"blocks": blocks, "text": plain(blocks)}


def _version_key(version: str):
    from functools import cmp_to_key
    return cmp_to_key(compare_versions)(version)


def plain(blocks: list[dict]) -> str:
    """The same content as plain text (text fields and templates)."""
    def inline(items) -> str:
        parts = []
        for item in items if isinstance(items, list) else [items]:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                parts.append(str(item.get("strong") or item.get("code") or item.get("link") or ""))
        return "".join(parts)
    lines: list[str] = []
    for block in blocks:
        if "heading" in block:
            lines += ["", str(block["heading"])]
        elif "paragraph" in block:
            if block is blocks[-1]:
                lines.append("")  # the footer, apart
            lines.append(inline(block["paragraph"]))
        elif "bullets" in block:
            lines += [f"- {inline(item)}" for item in block["bullets"]]
        elif "ordered" in block:
            lines += [f"{index}. {inline(item)}" for index, item in enumerate(block["ordered"], 1)]
        elif "code" in block:
            lines += [f"    {row}" for row in str(block["code"]).splitlines()]
    return "\n".join(lines).strip()
