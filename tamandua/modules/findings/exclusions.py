"""Paths excluded per repository: test folders, intentionally vulnerable examples, generated code.

An admin sets them in the panel and they live on the server (in its database), not in a file in the
repository: if they lived in the repository, a PR could exclude itself. Each change records who, when
and why, and the latest changes are kept as history.

What happens to what is excluded:

* **Runs**: findings under excluded paths are taken out of the run (report, SARIF, panel, PR review
  and its verdict) and counted in `excluded` and in the limits, so it shows that they exist. Nothing
  is hidden without saying so.
* **Registry**: whatever was open under those paths becomes **excluded**, not remediated: it wasn't
  fixed, someone decided not to look at it. If the path stops being excluded, it goes back to open.

Glob-style patterns, relative to the repository root: `fixtures`, `fixtures/*`, `docs/*.md`,
`**/testdata/**`. `*` doesn't cross `/`; `**` does. As in `.gitignore`, a pattern that matches a folder
excludes everything inside it: `fixtures` or `fixtures/*` also exclude `fixtures/a/b.py`.
Patterns that exclude everything are rejected.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

from tamandua.modules.findings.errors import LocalizedError
from tamandua.shared import documents
from tamandua.shared import log as logging_setup
from tamandua.shared.i18n import is_msg, msg

_log = logging_setup.get("exclusions")
MAX_PATTERNS = 50
MAX_LENGTH = 200
PATTERN = re.compile(r"[A-Za-z0-9_.\-/*?]+")
# Asset keys: github#123, local:my-repo, image:ghcr.io/acme/api… Nothing that could break a log line.
ASSET_KEY = re.compile(r"[A-Za-z0-9#:_./@+-]{1,200}")
HISTORY = 20


class ExclusionError(LocalizedError, ValueError):
    pass


def _load_all(data_dir: Path) -> dict:
    payload = documents.load(data_dir, "exclusions", {})
    return payload if isinstance(payload, dict) else {}


def _write(data_dir: Path, payload: dict) -> None:
    documents.save(data_dir, "exclusions", payload)


def get(data_dir: Path, key: str) -> dict:
    entry = _load_all(data_dir).get(key) or {}
    return {"patterns": list(entry.get("patterns") or []), "reason": entry.get("reason"), "by": entry.get("by"),
            "at": entry.get("at"), "history": list(entry.get("history") or [])}


def patterns(data_dir: Path, key: str) -> list[str]:
    return get(data_dir, key)["patterns"]


def normalize(raw) -> list[str]:
    """Validates and normalizes. `fixtures/` is the same as `fixtures/**`."""
    if not isinstance(raw, list) or len(raw) > MAX_PATTERNS:
        raise ExclusionError(msg("findings.exclusions.errors.too_many", max=MAX_PATTERNS))
    result = []
    for item in raw:
        if not isinstance(item, str):
            raise ExclusionError(msg("findings.exclusions.errors.not_text"))
        pattern = item.strip()
        if not pattern:
            continue
        if len(pattern) > MAX_LENGTH or not PATTERN.fullmatch(pattern):
            raise ExclusionError(msg("findings.exclusions.errors.invalid", pattern=pattern[:60]))
        if pattern.startswith("/") or any(part in ("..", ".") for part in pattern.split("/")):
            raise ExclusionError(msg("findings.exclusions.errors.not_relative", pattern=pattern))
        if pattern.endswith("/"):
            pattern += "**"
        while "**/**" in pattern or "***" in pattern:  # equivalent and, when repeated, costly to evaluate
            pattern = pattern.replace("**/**", "**").replace("***", "**")
        if matches_everything(pattern):
            raise ExclusionError(msg("findings.exclusions.errors.everything", pattern=pattern))
        if pattern not in result:
            result.append(pattern)
    return result


def matches_everything(pattern: str) -> bool:
    """Free-name wildcards only (`*`, `?*`, `**/*`…): matches any top-level folder and, since whole folders are
    excluded, the entire repository."""
    return all(part == "**" or ("*" in part and set(part) <= {"*", "?"}) for part in pattern.split("/"))


@lru_cache(maxsize=512)
def _regex(pattern: str) -> re.Pattern:
    out, index = [], 0
    while index < len(pattern):
        if pattern.startswith("**/", index):
            out.append("(?:.*/)?")
            index += 3
        elif pattern.startswith("**", index):
            out.append(".*")
            index += 2
        elif pattern[index] == "*":
            out.append("[^/]*")
            index += 1
        elif pattern[index] == "?":
            out.append("[^/]")
            index += 1
        else:
            out.append(re.escape(pattern[index]))
            index += 1
    return re.compile("".join(out) + r"\Z")


def excluded(path: str, active: list[str]) -> str | None:
    """The first pattern that excludes this path (or one of its folders), or None."""
    parts = str(path or "").removeprefix("./").lstrip("/").split("/")
    candidates = ["/".join(parts[:end]) for end in range(len(parts), 0, -1)]  # the file and every folder containing it
    for pattern in active:
        regex = _regex(pattern)
        if any(regex.match(candidate) for candidate in candidates):
            return pattern
    return None


def save(data_dir: Path, key: str, raw, *, reason: str | None, user: dict) -> dict:
    active = normalize(raw)
    note = " ".join(str(reason or "").split())[:300]
    if active and len(note) < 5:
        raise ExclusionError(msg("findings.exclusions.errors.reason_required"))
    stamp = datetime.now(timezone.utc).isoformat()
    with documents.lock(data_dir, "exclusions"):
        payload = _load_all(data_dir)
        previous = payload.get(key) or {}
        history = (list(previous.get("history") or []) + [{"at": stamp, "by": user["username"], "patterns": active,
                                                           "reason": note or None}])[-HISTORY:]
        if active:
            payload[key] = {"patterns": active, "reason": note, "by": user["username"], "at": stamp, "history": history}
        elif key in payload:
            payload[key] = {"patterns": [], "reason": None, "by": user["username"], "at": stamp, "history": history}
        _write(data_dir, payload)
    _log.info("exclusions_saved", extra={"user": user["username"], "reason": f"{key}: {len(active)} rutas"})
    return get(data_dir, key)


def forget(data_dir: Path, key: str) -> None:
    with documents.lock(data_dir, "exclusions"):
        payload = _load_all(data_dir)
        if payload.pop(key, None) is not None:
            _write(data_dir, payload)


SUMMARY_SCANNERS = ("sast", "secrets", "sca", "iac", "cicd")


def _recount(reason, count: int):
    """The coverage reason with its finding count updated: legacy Spanish text, or any `findings` param of a message."""
    if isinstance(reason, str):
        return re.sub(r"\. (?:\d+ hallazgo\(s\)|Sin hallazgos)\.$", f". {count} hallazgo(s)." if count else ". Sin hallazgos.", reason)
    if is_msg(reason):
        params = {name: count if name == "findings" else _recount(value, count) for name, value in (reason.get("params") or {}).items()}
        return {**reason, "params": params} if params else reason
    return reason


def apply_to_record(data_dir: Path, record: dict, key: str) -> dict:
    """Takes findings under excluded paths out of the run and recomputes the summary counts."""
    if "excluded" in record:  # already applied (the PR review does it before classifying)
        return record
    active = patterns(data_dir, key)
    if not active:
        return record
    kept, dropped, removed = [], {}, []
    for finding in record.get("findings") or []:
        pattern = excluded(finding.get("path", ""), active)
        if pattern is None:
            kept.append(finding)
        else:
            dropped[pattern] = dropped.get(pattern, 0) + 1
            removed.append({**finding, "excluded_by": pattern})
    if not dropped:
        return {**record, "excluded": {"patterns": active, "findings": 0, "by_pattern": {}}}
    total = sum(dropped.values())
    summary = dict(record.get("summary") or {})
    summary.update(candidates=len(kept),
                   severities={level: sum(1 for item in kept if item.get("severity") == level)
                               for level in ("critical", "high", "medium", "low", "info")},
                   priorities={action: sum(1 for item in kept if (item.get("priority") or {}).get("action") == action)
                               for action in ("act", "attend", "track")},
                   kev=sum(1 for item in kept if item.get("kev")),
                   fixable=sum(1 for item in kept if (item.get("package") or {}).get("fixed_version")),
                   excluded=total)
    for scanner in SUMMARY_SCANNERS:
        if scanner in summary:
            summary[scanner] = sum(1 for item in kept if item.get("scanner") == scanner)
    coverage = []
    for row in record.get("owasp_coverage") or []:
        count = sum(1 for item in kept for category in item.get("owasp", []) if category[:3] == row.get("id"))
        reason = _recount(row.get("reason") or "", count)
        coverage.append({**row, "findings": count, "reason": reason})
    limitation = msg("findings.exclusions.limitation", patterns=", ".join(active), count=total)
    # Secrets withheld by the secret detection settings (scanning) may already be there.
    return {**record, "findings": kept, "summary": summary, "owasp_coverage": coverage or record.get("owasp_coverage"),
            "excluded": {"patterns": active, "findings": total, "by_pattern": dropped},
            "excluded_findings": [*(record.get("excluded_findings") or []), *removed],
            "limitations": [*(record.get("limitations") or []), limitation]}
