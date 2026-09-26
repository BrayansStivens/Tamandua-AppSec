"""Organization-wide secret detection settings for Gitleaks and Trivy: allowlist, custom rules and disabled built-ins.

They live on the server, never in the repository: a pull request must not be able to weaken detection (that is also
why a repository's own `.gitleaks.toml` is stripped from the snapshot). Every change records who, when and why.

User regexes are compiled here only to validate them; they never run in Python against repository data. The engines
(Go, RE2: linear time) run them inside their sandboxed containers, so only syntax that means the same in both is
accepted. Allowlisted paths use the glob syntax of excluded paths (`fixtures/**`, `**/testdata/**`).
"""

from __future__ import annotations

import json
import re
import unicodedata
import warnings
from datetime import datetime, timezone
from pathlib import Path

from tamandua.modules.scanning.secret_builtin_rules import GITLEAKS_DEFAULT_RULES, TRIVY_EQUIVALENTS
from tamandua.shared import db, documents
from tamandua.shared import log as logging_setup
from tamandua.shared.i18n import msg, text

_log = logging_setup.get("secret-rules")
DOCUMENT = "secret-detection"
MAX_RULES = 50
MAX_ENTRIES = 100
MAX_REGEX = 500
MAX_DESCRIPTION = 120
MAX_KEYWORDS = 10
MAX_REPEAT = 1000
HISTORY = 20
SEVERITIES = ("critical", "high", "medium", "low")
RULE_ID = re.compile(r"[a-z0-9-]{1,60}")
KEYWORD = re.compile(r"[a-z0-9_.:=@/+-]{1,60}")
STOPWORD = re.compile(r"[a-z0-9_.-]{3,60}")
PATH = re.compile(r"[A-Za-z0-9_.\-/*?]{1,200}")
ENGINE_PREFIX = "tamandua-"  # custom rules run as `tamandua-<id>`: never the id of a built-in rule in either engine
LISTS = ("regexes", "paths", "stopwords")
LIMITS = {"rules": MAX_RULES, "entries": MAX_ENTRIES, "regex": MAX_REGEX, "description": MAX_DESCRIPTION,
          "keywords": MAX_KEYWORDS}


class SecretRulesError(ValueError):
    """`message` is rendered for the reader; `field` points at the offending input (`rules.2.regex`)."""

    def __init__(self, message, field: str | None = None):
        super().__init__(text(message, "en"))
        self.message, self.field = message, field


def empty() -> dict:
    return {"allowlist": {name: [] for name in LISTS}, "rules": [], "disabled_rules": []}


def _stored(data_dir: Path) -> dict:
    payload = documents.load(data_dir, DOCUMENT, {})
    return payload if isinstance(payload, dict) else {}


def get(data_dir: Path) -> dict:
    payload = _stored(data_dir)
    allowlist = payload.get("allowlist") or {}
    return {"allowlist": {name: list(allowlist.get(name) or []) for name in LISTS},
            "rules": [dict(rule) for rule in payload.get("rules") or []],
            "disabled_rules": list(payload.get("disabled_rules") or []),
            "reason": payload.get("reason"), "by": payload.get("by"), "at": payload.get("at"),
            "history": list(payload.get("history") or [])}


def configured(settings: dict | None) -> bool:
    return bool(settings) and bool(settings["rules"] or settings["disabled_rules"]
                                   or any(settings["allowlist"][name] for name in LISTS))


def counts(settings: dict) -> dict:
    return {"rules": len(settings["rules"]), "disabled": len(settings["disabled_rules"]),
            "allowlist": sum(len(settings["allowlist"][name]) for name in LISTS)}


def for_scan(data_dir: Path | None) -> dict | None:
    """The settings a scan applies, or None. A standalone CLI scan without a database runs with the defaults."""
    if data_dir is None:
        return None
    try:
        settings = get(data_dir)
    except db.DatabaseNotConfigured:
        return None
    return settings if configured(settings) else None


# --- Validation ------------------------------------------------------------------------

_GROUP_FLAGS = re.compile(r"\?[ims]*(?:-[ims]+)?[:)]")
_REPEAT = re.compile(r"\{(\d+)(?:,(\d*))?\}")


def unsupported_construct(pattern: str) -> str | None:
    """The first construct RE2 (Go) rejects or reads differently from Python, or None. Conservative on purpose."""
    index, size, in_class = 0, len(pattern), False
    while index < size:
        char = pattern[index]
        if char == "\\":
            following = pattern[index + 1:index + 2]
            if following.isdigit() and following != "0":
                return "backreference"
            if following in ("Z", "u", "U", "N", "g"):
                return "escape"
            index += 2
            continue
        if in_class:
            if char == "[":
                return "nested_class"
            in_class = char != "]"
            index += 1
            continue
        if char == "[":
            index += 1
            if pattern[index:index + 1] == "^":
                index += 1
            if pattern[index:index + 1] == "]":
                index += 1
            in_class = True
            continue
        if char == "(" and pattern[index + 1:index + 2] == "?":
            rest = pattern[index + 1:]
            if rest.startswith(("?:", "?P<")) or _GROUP_FLAGS.match(rest):
                index += 2
                continue
            if rest.startswith(("?=", "?!", "?<=", "?<!")):
                return "lookaround"
            if rest.startswith("?>"):
                return "atomic"
            if rest.startswith("?P="):
                return "backreference"
            if rest.startswith("?("):
                return "conditional"
            return "group"
        if char in "*+?" and pattern[index + 1:index + 2] == "+":
            return "possessive"
        if char == "{":
            repeat = _REPEAT.match(pattern, index)
            if repeat:
                if any(int(value) > MAX_REPEAT for value in repeat.groups() if value):
                    return "repeat"
                if pattern[repeat.end():repeat.end() + 1] == "+":
                    return "possessive"
                index = repeat.end()
                continue
            if pattern.startswith("{,", index):
                return "repeat"
        index += 1
    return None


def _plain(value, field: str, *, maximum: int) -> str:
    if not isinstance(value, str):
        raise SecretRulesError(msg("scanning.secret_rules.errors.not_text"), field)
    value = value.strip()
    if len(value) > maximum:
        raise SecretRulesError(msg("scanning.secret_rules.errors.too_long", max=maximum), field)
    # Control characters, line separators and lone surrogates would break the engines' configuration files.
    if any(unicodedata.category(char) in ("Cc", "Cs", "Zl", "Zp") for char in value):
        raise SecretRulesError(msg("scanning.secret_rules.errors.control_characters"), field)
    return value


def validate_regex(value, field: str, *, allowlist: bool = False) -> str:
    pattern = _plain(value, field, maximum=MAX_REGEX)
    if not pattern:
        raise SecretRulesError(msg("scanning.secret_rules.errors.regex_required"), field)
    shown = pattern[:60]
    if "'''" in pattern:
        raise SecretRulesError(msg("scanning.secret_rules.errors.triple_quote", pattern=shown), field)
    construct = unsupported_construct(pattern)
    if construct:
        raise SecretRulesError(msg("scanning.secret_rules.errors.regex_unsupported", pattern=shown,
                                   construct=msg(f"scanning.secret_rules.constructs.{construct}")), field)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            compiled = re.compile(pattern)
    except (re.error, FutureWarning, DeprecationWarning, RecursionError, OverflowError):
        raise SecretRulesError(msg("scanning.secret_rules.errors.regex_invalid", pattern=shown), field) from None
    # Matching the empty string is checked on a constant, never on repository data. Such a rule would flag every
    # position; such an allowlist entry would silence every secret.
    if compiled.fullmatch(""):
        key = "allow_everything" if allowlist else "regex_empty"
        raise SecretRulesError(msg(f"scanning.secret_rules.errors.{key}", pattern=shown), field)
    return pattern


def _path(value, field: str) -> str:
    pattern = _plain(value, field, maximum=200)
    if not PATH.fullmatch(pattern):
        raise SecretRulesError(msg("scanning.secret_rules.errors.path_invalid", pattern=pattern[:60]), field)
    if pattern.startswith("/") or any(part in ("..", ".") for part in pattern.split("/")):
        raise SecretRulesError(msg("scanning.secret_rules.errors.path_not_relative", pattern=pattern), field)
    if pattern.endswith("/"):
        pattern += "**"
    while "**/**" in pattern or "***" in pattern:
        pattern = pattern.replace("**/**", "**").replace("***", "**")
    if all(part == "**" or ("*" in part and set(part) <= {"*", "?"}) for part in pattern.split("/")):
        raise SecretRulesError(msg("scanning.secret_rules.errors.path_everything", pattern=pattern), field)
    return pattern


def _entries(raw, field: str) -> list:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise SecretRulesError(msg("scanning.secret_rules.errors.not_list"), field)
    if len(raw) > MAX_ENTRIES:
        raise SecretRulesError(msg("scanning.secret_rules.errors.too_many_entries", max=MAX_ENTRIES), field)
    return raw


def _unique(items: list) -> list:
    return list(dict.fromkeys(item for item in items if item))


def _rule(raw, index: int, seen: set[str]) -> dict:
    field = f"rules.{index}"
    if not isinstance(raw, dict):
        raise SecretRulesError(msg("scanning.secret_rules.errors.not_rule"), field)
    identifier = _plain(raw.get("id"), f"{field}.id", maximum=60)
    if not RULE_ID.fullmatch(identifier):
        raise SecretRulesError(msg("scanning.secret_rules.errors.rule_id", id=identifier[:60]), f"{field}.id")
    if identifier in seen:
        raise SecretRulesError(msg("scanning.secret_rules.errors.duplicate_rule", id=identifier), f"{field}.id")
    seen.add(identifier)
    description = " ".join(_plain(raw.get("description"), f"{field}.description", maximum=MAX_DESCRIPTION).split())
    if len(description) < 3:
        raise SecretRulesError(msg("scanning.secret_rules.errors.description_required", id=identifier), f"{field}.description")
    regex = validate_regex(raw.get("regex"), f"{field}.regex")
    keywords_raw = raw.get("keywords") or []
    if not isinstance(keywords_raw, list) or len(keywords_raw) > MAX_KEYWORDS:
        raise SecretRulesError(msg("scanning.secret_rules.errors.too_many_keywords", max=MAX_KEYWORDS), f"{field}.keywords")
    keywords = []
    for keyword in keywords_raw:
        word = _plain(keyword, f"{field}.keywords", maximum=60).lower()
        if word and not KEYWORD.fullmatch(word):
            raise SecretRulesError(msg("scanning.secret_rules.errors.keyword_invalid", keyword=word[:60]), f"{field}.keywords")
        keywords.append(word)
    severity = raw.get("severity")
    if severity not in SEVERITIES:
        raise SecretRulesError(msg("scanning.secret_rules.errors.severity_invalid", id=identifier), f"{field}.severity")
    return {"id": identifier, "description": description, "regex": regex, "keywords": _unique(keywords), "severity": severity}


def normalize(raw) -> dict:
    """Validates and normalizes the settings (without reason or history). Raises SecretRulesError."""
    if not isinstance(raw, dict):
        raise SecretRulesError(msg("scanning.secret_rules.errors.not_settings"))
    allowlist_raw = raw.get("allowlist") or {}
    if not isinstance(allowlist_raw, dict):
        raise SecretRulesError(msg("scanning.secret_rules.errors.not_settings"), "allowlist")
    regexes = [validate_regex(item, f"allowlist.regexes.{index}", allowlist=True)
               for index, item in enumerate(_entries(allowlist_raw.get("regexes"), "allowlist.regexes"))]
    paths = [_path(item, f"allowlist.paths.{index}")
             for index, item in enumerate(_entries(allowlist_raw.get("paths"), "allowlist.paths"))]
    stopwords = []
    for index, item in enumerate(_entries(allowlist_raw.get("stopwords"), "allowlist.stopwords")):
        word = _plain(item, f"allowlist.stopwords.{index}", maximum=60).lower()
        if not STOPWORD.fullmatch(word):
            raise SecretRulesError(msg("scanning.secret_rules.errors.stopword_invalid", word=word[:60]), f"allowlist.stopwords.{index}")
        stopwords.append(word)
    rules_raw = raw.get("rules") or []
    if not isinstance(rules_raw, list):
        raise SecretRulesError(msg("scanning.secret_rules.errors.not_list"), "rules")
    if len(rules_raw) > MAX_RULES:
        raise SecretRulesError(msg("scanning.secret_rules.errors.too_many_rules", max=MAX_RULES), "rules")
    seen: set[str] = set()
    rules = [_rule(item, index, seen) for index, item in enumerate(rules_raw)]
    disabled_raw = raw.get("disabled_rules") or []
    if not isinstance(disabled_raw, list) or len(disabled_raw) > len(GITLEAKS_DEFAULT_RULES):
        raise SecretRulesError(msg("scanning.secret_rules.errors.not_list"), "disabled_rules")
    builtin = set(GITLEAKS_DEFAULT_RULES)
    for rule in disabled_raw:
        if not isinstance(rule, str) or rule not in builtin:
            raise SecretRulesError(msg("scanning.secret_rules.errors.unknown_rule", rule=str(rule)[:60]), "disabled_rules")
    return {"allowlist": {"regexes": _unique(regexes), "paths": _unique(paths), "stopwords": _unique(stopwords)},
            "rules": rules, "disabled_rules": sorted(set(disabled_raw))}


def _changes(before: dict, after: dict) -> dict:
    """What a save changed, compactly, for the history."""
    def diff(old: list, new: list) -> dict:
        return {"added": [item for item in new if item not in old][:20], "removed": [item for item in old if item not in new][:20]}
    old_rules = {rule["id"]: rule for rule in before["rules"]}
    new_rules = {rule["id"]: rule for rule in after["rules"]}
    changes = {name: diff(before["allowlist"][name], after["allowlist"][name]) for name in LISTS}
    changes["rules"] = {**diff(list(old_rules), list(new_rules)),
                        "changed": [key for key in new_rules if key in old_rules and new_rules[key] != old_rules[key]][:20]}
    changes["disabled_rules"] = diff(before["disabled_rules"], after["disabled_rules"])
    return {key: {kind: items for kind, items in value.items() if items} for key, value in changes.items()
            if any(value.values())}


def save(data_dir: Path, raw, *, reason: str | None, user: dict) -> dict:
    settings = normalize(raw)
    note = " ".join(str(reason or "").split())[:300]
    if len(note) < 5:
        raise SecretRulesError(msg("scanning.secret_rules.errors.reason_required"), "reason")
    stamp = datetime.now(timezone.utc).isoformat()
    with documents.lock(data_dir, DOCUMENT):
        previous = get(data_dir)
        entry = {"at": stamp, "by": user["username"], "reason": note, "changes": _changes(previous, settings)}
        history = (previous["history"] + [entry])[-HISTORY:]
        documents.save(data_dir, DOCUMENT, {**settings, "reason": note, "by": user["username"], "at": stamp, "history": history})
    _log.info("secret_rules_saved", extra={"user": user["username"], "reason":
                                           f"{len(settings['rules'])} rules, {len(settings['disabled_rules'])} disabled, "
                                           f"{sum(len(items) for items in settings['allowlist'].values())} allowlist entries"})
    return get(data_dir)


# --- Engine configuration --------------------------------------------------------------

def engine_id(rule_id: str) -> str:
    return ENGINE_PREFIX + rule_id


def custom_rules(settings: dict | None) -> dict[str, dict]:
    """Custom rules by the id the engines report."""
    return {engine_id(rule["id"]): rule for rule in (settings or {}).get("rules") or []}


def _glob_body(pattern: str) -> str:
    out, index = [], 0
    while index < len(pattern):
        if pattern.startswith("**/", index):
            out.append("(?:.*/)?")
            index += 3
        elif pattern.startswith("**", index):
            out.append(".*")
            index += 2
        else:
            out.append({"*": "[^/]*", "?": "[^/]", ".": r"\."}.get(pattern[index], pattern[index]))
            index += 1
    # Like .gitignore: a pattern that names a folder covers everything inside it.
    return "".join(out) + "(?:/.*)?$"


def _toml(value: str) -> str:
    """A TOML string. Literal ('…') when that is exact, which keeps regexes readable; otherwise an escaped basic string."""
    if any(unicodedata.category(char) == "Cs" for char in value):
        raise SecretRulesError(msg("scanning.secret_rules.errors.control_characters"))
    if "'" not in value and not any(unicodedata.category(char) == "Cc" for char in value):
        return f"'{value}'"
    escaped = []
    for char in value:
        if char in ('"', "\\"):
            escaped.append("\\" + char)
        elif unicodedata.category(char) == "Cc":
            escaped.append(f"\\u{ord(char):04X}")
        else:
            escaped.append(char)
    return '"' + "".join(escaped) + '"'


def _toml_list(values: list[str]) -> str:
    return "[" + ", ".join(_toml(value) for value in values) + "]"


def gitleaks_toml(settings: dict) -> str:
    """Gitleaks 8.30 configuration: the default rules (minus the disabled ones), the custom rules and one global
    allowlist. Keys are fixed here; only values come from the settings, always quoted by `_toml`."""
    lines = ["# Generated by Tamandua from the organization's secret detection settings.", "title = 'Tamandua'", "",
             "[extend]", "useDefault = true"]
    if settings["disabled_rules"]:
        lines.append(f"disabledRules = {_toml_list(settings['disabled_rules'])}")
    for rule in settings["rules"]:
        lines += ["", "[[rules]]", f"id = {_toml(engine_id(rule['id']))}", f"description = {_toml(rule['description'])}",
                  f"regex = {_toml(rule['regex'])}"]
        if rule["keywords"]:
            lines.append(f"keywords = {_toml_list(rule['keywords'])}")
    allowlist = settings["allowlist"]
    if any(allowlist[name] for name in LISTS):
        lines += ["", "[[allowlists]]", "description = 'Tamandua'"]
        if allowlist["paths"]:
            lines.append(f"paths = {_toml_list(['^/src/' + _glob_body(pattern) for pattern in allowlist['paths']])}")
        if allowlist["regexes"]:
            lines.append(f"regexes = {_toml_list(allowlist['regexes'])}")
        if allowlist["stopwords"]:
            lines.append(f"stopwords = {_toml_list(allowlist['stopwords'])}")
    return "\n".join(lines) + "\n"


def trivy_secret_config(settings: dict) -> str:
    """Trivy's `--secret-config`. JSON is valid YAML, and json.dumps escapes every value.

    Trivy has no stopwords: each one becomes a case-insensitive allow regex on the secret, as Gitleaks applies them.
    Disabled rules carry over only where Trivy has the same detector (TRIVY_EQUIVALENTS)."""
    allowlist = settings["allowlist"]
    allow = ([{"id": f"tamandua-path-{index}", "description": "Tamandua", "path": "^" + _glob_body(pattern)}
              for index, pattern in enumerate(allowlist["paths"], 1)]
             + [{"id": f"tamandua-regex-{index}", "description": "Tamandua", "regex": pattern}
                for index, pattern in enumerate(allowlist["regexes"], 1)]
             + [{"id": f"tamandua-stopword-{index}", "description": "Tamandua", "regex": "(?i)" + re.escape(word)}
                for index, word in enumerate(allowlist["stopwords"], 1)])
    config: dict = {}
    if settings["rules"]:
        config["rules"] = [{"id": engine_id(rule["id"]), "category": "Tamandua", "title": rule["description"],
                            "severity": rule["severity"].upper(), "regex": rule["regex"],
                            **({"keywords": rule["keywords"]} if rule["keywords"] else {})} for rule in settings["rules"]]
    if allow:
        config["allow-rules"] = allow
    disabled = sorted({TRIVY_EQUIVALENTS[rule] for rule in settings["disabled_rules"] if rule in TRIVY_EQUIVALENTS})
    if disabled:
        config["disable-rules"] = disabled
    return json.dumps(config, ensure_ascii=False, indent=2) + "\n"
