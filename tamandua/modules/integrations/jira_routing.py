"""Where each finding's Jira issue goes: destinations and routing rules (document `jira-routing`).

* A **destination** is a project + issue type + field mapping (`jira_mapping.py`), checked against Jira's live create
  metadata when saved.
* **Rules** are an ordered list: name, assets (explicit asset keys and/or glob patterns on the asset name, such as
  ``org/payments-*``), destination, mode (``manual`` or ``auto``), minimum severity and backfill (auto). The last
  rule, ``default``, matches every asset; it can point to any destination or be disabled.
* **The first enabled rule whose assets match wins**, for manual exports and automatic creation alike. Severity does not
  take part in matching: a finding below the winning rule's minimum is not created automatically, and it does not fall
  through to a later rule. A disabled rule is skipped as if it weren't there.

Every change is logged with who made it and kept in the document's short history.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from fnmatch import fnmatchcase
from pathlib import Path

from tamandua.modules.integrations import jira
from tamandua.modules.integrations.jira_mapping import MappingError, default_mapping, validate
from tamandua.shared import documents
from tamandua.shared import log as logging_setup
from tamandua.shared.i18n import msg, text

DOCUMENT = "jira-routing"
DEFAULT_RULE = "default"
MODES = ("manual", "auto")
SEVERITIES = ("critical", "high", "medium", "low", "info")
MAX_DESTINATIONS = 20
MAX_RULES = 50
MAX_ASSETS = 200
MAX_PATTERNS = 20
NAME_MAX = 60
ASSET_MAX = 200
HISTORY_MAX = 100
IDENTIFIER = re.compile(r"[0-9a-f]{12}|default|legacy")
_log = logging_setup.get("jira")


class RoutingError(ValueError):
    """A change that can't be saved: `message` for the reader and, when it is about fields, `errors` [{field, error}]."""

    def __init__(self, message, errors: list[dict] | None = None):
        super().__init__(text(message, "en"))
        self.message, self.errors = message, errors or []


def _stamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _default_rule() -> dict:
    return {"id": DEFAULT_RULE, "name": msg("integrations.jira.routing.default_rule_name"), "default": True, "assets": [], "patterns": [], "destination": None,
            "mode": "manual", "min_severity": "high", "backfill": False, "enabled": False}


def load(data_dir: Path) -> dict:
    stored = documents.load(data_dir, DOCUMENT, {})
    return _normalized(stored if isinstance(stored, dict) else {})


def _normalized(stored: dict) -> dict:
    destinations = [item for item in stored.get("destinations") or [] if isinstance(item, dict) and item.get("id")]
    rules = [item for item in stored.get("rules") or [] if isinstance(item, dict) and item.get("id") and item["id"] != DEFAULT_RULE]
    default = next((item for item in stored.get("rules") or [] if isinstance(item, dict) and item.get("id") == DEFAULT_RULE), None)
    return {"destinations": destinations, "rules": [*rules, {**_default_rule(), **(default or {}), "default": True}],
            "history": list(stored.get("history") or [])[-HISTORY_MAX:]}


def view(data_dir: Path) -> dict:
    """What an administrator sees: destinations (with the mapped fields), rules in order, limits and recent changes."""
    state = load(data_dir)
    return {"destinations": state["destinations"], "rules": state["rules"], "history": state["history"][-20:][::-1],
            "limits": {"destinations": MAX_DESTINATIONS, "rules": MAX_RULES, "assets": MAX_ASSETS, "patterns": MAX_PATTERNS}}


def destination(state: dict, identifier) -> dict | None:
    return next((item for item in state["destinations"] if item["id"] == identifier), None)


def rule(state: dict, identifier) -> dict | None:
    return next((item for item in state["rules"] if item["id"] == identifier), None)


def matches(item: dict, key: str, name: str | None) -> bool:
    if item.get("default"):
        return True
    if key in (item.get("assets") or []):
        return True
    lowered = (name or "").lower()
    return bool(lowered) and any(fnmatchcase(lowered, pattern.lower()) for pattern in item.get("patterns") or [])


def resolve(state: dict, key: str, name: str | None) -> dict | None:
    """The rule that decides for this asset: the first enabled one that matches (with a destination), or None."""
    for item in state["rules"]:
        if item.get("enabled") and item.get("destination") and matches(item, key, name):
            return item
    return None


def _record(state: dict, by: str, action: str, target: str) -> None:
    state["history"] = [*state["history"], {"at": _stamp(), "by": by, "action": action, "target": target}][-HISTORY_MAX:]
    _log.info("jira_routing_changed", extra={"user": by, "reason": f"{action} {target}"})


def _name(value, field: str = "name") -> str:
    if not isinstance(value, str) or not 1 <= len(value.strip()) <= NAME_MAX or any(not character.isprintable() for character in value):
        raise RoutingError(msg("integrations.jira.routing.invalid"), [{"field": field, "error": msg("integrations.jira.routing.invalid_name", max=NAME_MAX)}])
    return " ".join(value.split())


# ------------------------------------------------------------------ destinations

def save_destination(data_dir: Path, payload: dict, *, by: str, http=None) -> tuple[dict, list[dict]]:
    """Creates or updates a destination after checking it against Jira's live create metadata. Returns it and warnings."""
    if not jira.configured():
        raise RoutingError(msg("integrations.jira.not_configured"))
    identifier = payload.get("id")
    name = _name(payload.get("name"))
    try:
        project = jira.project(payload.get("project"), http=http)
    except jira.JiraError as exc:
        raise RoutingError(msg("integrations.jira.routing.invalid"), [{"field": "project", "error": exc.message}]) from exc
    types = jira.issue_types(project["id"], http=http)["items"]
    wanted = str(payload.get("issue_type") or "")
    issue_type = next((item for item in types if item["id"] == wanted), None) \
        or next((item for item in types if item["name"].lower() == wanted.lower()), None)
    if issue_type is None:
        raise RoutingError(msg("integrations.jira.routing.invalid"), [{"field": "issue_type", "error": msg(
            "integrations.jira.missing_issue_type", project=project["key"], type=wanted[:60],
            available=", ".join(item["name"] for item in types[:8]))}])
    # Every allowed value, not the panel's first page: a value chosen through the search must validate.
    fields = jira.create_fields(project["id"], issue_type["id"], http=http, allowed_limit=jira.MAX_ALLOWED_CHECKED)["fields"]
    requested = payload.get("mapping")
    try:
        mapping, snapshot, warnings = validate(requested if requested else default_mapping(fields), fields)
    except MappingError as exc:
        raise RoutingError(msg("integrations.jira.mapping.invalid"), exc.errors) from exc
    with documents.edit(data_dir, DOCUMENT, {}) as stored:
        state = _normalized(stored)
        current = destination(state, identifier) if identifier else None
        if identifier and current is None:
            raise RoutingError(msg("integrations.jira.routing.destination_not_found"))
        if current is None and len(state["destinations"]) >= MAX_DESTINATIONS:
            raise RoutingError(msg("integrations.jira.routing.too_many_destinations", max=MAX_DESTINATIONS))
        if any(item["name"].lower() == name.lower() and item["id"] != identifier for item in state["destinations"]):
            raise RoutingError(msg("integrations.jira.routing.invalid"), [{"field": "name", "error": msg("integrations.jira.routing.duplicate_name")}])
        saved = {"id": current["id"] if current else uuid.uuid4().hex[:12], "name": name, "project": project,
                 "issue_type": {"id": issue_type["id"], "name": issue_type["name"]}, "mapping": mapping, "fields": snapshot,
                 "created_by": (current or {}).get("created_by", by), "created_at": (current or {}).get("created_at", _stamp()),
                 "updated_by": by, "updated_at": _stamp()}
        state["destinations"] = [saved if item["id"] == saved["id"] else item for item in state["destinations"]] if current \
            else [*state["destinations"], saved]
        _record(state, by, "destination_saved", f"{saved['id']} {project['key']}/{issue_type['name']}")
        stored.clear()
        stored.update(state)
    return saved, warnings


def remove_destination(data_dir: Path, identifier, *, by: str) -> None:
    with documents.edit(data_dir, DOCUMENT, {}) as stored:
        state = _normalized(stored)
        if destination(state, identifier) is None:
            raise RoutingError(msg("integrations.jira.routing.destination_not_found"))
        users = [text(item.get("name"), "en") or item["id"] for item in state["rules"] if item.get("destination") == identifier]
        if users:
            raise RoutingError(msg("integrations.jira.routing.destination_in_use", rules=", ".join(users[:5])))
        state["destinations"] = [item for item in state["destinations"] if item["id"] != identifier]
        _record(state, by, "destination_removed", str(identifier))
        stored.clear()
        stored.update(state)


# ------------------------------------------------------------------ rules

def _strings(value, *, field: str, limit: int, item_max: int) -> list[str]:
    if value is None:
        return []
    if (not isinstance(value, list) or len(value) > limit
            or any(not isinstance(item, str) or not 1 <= len(item.strip()) <= item_max or any(not ch.isprintable() for ch in item) for item in value)):
        raise RoutingError(msg("integrations.jira.routing.invalid"), [{"field": field, "error": msg("integrations.jira.routing.invalid_list", max=limit)}])
    return list(dict.fromkeys(item.strip() for item in value))


def _clean_rule(state: dict, payload: dict, current: dict | None) -> dict:
    is_default = (current or {}).get("default", False)
    errors = []
    try:
        name = (current or {}).get("name") if is_default else _name(payload.get("name"))
    except RoutingError as exc:
        errors += exc.errors
        name = ""
    assets = patterns = []
    if not is_default:
        try:
            assets = _strings(payload.get("assets"), field="assets", limit=MAX_ASSETS, item_max=ASSET_MAX)
            patterns = _strings(payload.get("patterns"), field="patterns", limit=MAX_PATTERNS, item_max=ASSET_MAX)
        except RoutingError as exc:
            errors += exc.errors
        if any(pattern.count("*") > 10 for pattern in patterns):
            errors.append({"field": "patterns", "error": msg("integrations.jira.routing.invalid_list", max=MAX_PATTERNS)})
        if not assets and not patterns and not errors:
            errors.append({"field": "assets", "error": msg("integrations.jira.routing.no_assets")})
    enabled = payload.get("enabled", True)
    target = payload.get("destination")
    if not isinstance(enabled, bool):
        errors.append({"field": "enabled", "error": msg("integrations.jira.routing.invalid_value")})
    if target is None and not (is_default and enabled is False):
        errors.append({"field": "destination", "error": msg("integrations.jira.routing.destination_required")})
    elif target is not None and destination(state, target) is None:
        errors.append({"field": "destination", "error": msg("integrations.jira.routing.destination_not_found")})
    mode, minimum, backfill = payload.get("mode", "manual"), payload.get("min_severity", "high"), payload.get("backfill", False)
    if mode not in MODES:
        errors.append({"field": "mode", "error": msg("integrations.jira.routing.invalid_value")})
    if minimum not in SEVERITIES:
        errors.append({"field": "min_severity", "error": msg("integrations.jira.routing.invalid_value")})
    if not isinstance(backfill, bool):
        errors.append({"field": "backfill", "error": msg("integrations.jira.routing.invalid_value")})
    if errors:
        raise RoutingError(msg("integrations.jira.routing.invalid"), errors)
    return {"name": name, "assets": assets, "patterns": patterns, "destination": target, "mode": mode, "min_severity": minimum,
            "backfill": bool(backfill and mode == "auto"), "enabled": enabled}


BACKFILL_KEYS = ("assets", "patterns", "destination", "mode", "min_severity", "backfill", "enabled")


def wants_backfill(saved: dict, previous: dict | None) -> bool:
    """A backfill runs when an automatic rule with backfill is saved new, enabled, or changed in what it covers."""
    if not (saved.get("enabled") and saved.get("mode") == "auto" and saved.get("backfill") and saved.get("destination")):
        return False
    return previous is None or any(saved.get(key) != previous.get(key) for key in BACKFILL_KEYS)


def save_rule(data_dir: Path, payload: dict, *, by: str) -> tuple[dict, dict | None]:
    """Creates or updates a rule (the `default` one included). Returns it and how it was before (None if new)."""
    identifier = payload.get("id")
    with documents.edit(data_dir, DOCUMENT, {}) as stored:
        state = _normalized(stored)
        current = rule(state, identifier) if identifier else None
        if identifier and current is None:
            raise RoutingError(msg("integrations.jira.routing.rule_not_found"))
        if current is None and len(state["rules"]) - 1 >= MAX_RULES:
            raise RoutingError(msg("integrations.jira.routing.too_many_rules", max=MAX_RULES))
        clean = _clean_rule(state, payload, current)
        if not (current or {}).get("default") and any(
                text(item["name"], "en").lower() == clean["name"].lower() and item["id"] != identifier for item in state["rules"] if not item.get("default")):
            raise RoutingError(msg("integrations.jira.routing.invalid"), [{"field": "name", "error": msg("integrations.jira.routing.duplicate_name")}])
        saved = {**(current or {"id": uuid.uuid4().hex[:12]}), **clean, "updated_by": by, "updated_at": _stamp()}
        if current:
            state["rules"] = [saved if item["id"] == saved["id"] else item for item in state["rules"]]
        else:
            state["rules"] = [*state["rules"][:-1], saved, state["rules"][-1]]
        _record(state, by, "rule_saved", f"{saved['id']} → {saved.get('destination')} ({saved['mode']}, {'on' if saved['enabled'] else 'off'})")
        stored.clear()
        stored.update(state)
    return saved, current


def remove_rule(data_dir: Path, identifier, *, by: str) -> None:
    with documents.edit(data_dir, DOCUMENT, {}) as stored:
        state = _normalized(stored)
        found = rule(state, identifier)
        if found is None or found.get("default"):
            raise RoutingError(msg("integrations.jira.routing.rule_not_found"))
        state["rules"] = [item for item in state["rules"] if item["id"] != identifier]
        _record(state, by, "rule_removed", str(identifier))
        stored.clear()
        stored.update(state)


def reorder(data_dir: Path, identifiers, *, by: str) -> None:
    """The new order of the rules (every one except `default`, which stays last)."""
    with documents.edit(data_dir, DOCUMENT, {}) as stored:
        state = _normalized(stored)
        movable = [item for item in state["rules"] if not item.get("default")]
        if not isinstance(identifiers, list) or sorted(map(str, identifiers)) != sorted(item["id"] for item in movable):
            raise RoutingError(msg("integrations.jira.routing.invalid"), [{"field": "ids", "error": msg("integrations.jira.routing.invalid_order")}])
        by_id = {item["id"]: item for item in movable}
        state["rules"] = [*(by_id[item] for item in identifiers), state["rules"][-1]]
        _record(state, by, "rules_reordered", ",".join(identifiers))
        stored.clear()
        stored.update(state)


def preview_state(data_dir: Path, payload: dict) -> tuple[dict, dict]:
    """The routing as it would be with this rule saved (for a preview), and the rule. Nothing is written."""
    state = load(data_dir)
    identifier = payload.get("id")
    current = rule(state, identifier) if identifier else None
    if identifier and current is None:
        raise RoutingError(msg("integrations.jira.routing.rule_not_found"))
    candidate = {**(current or {"id": "preview"}), **_clean_rule(state, payload, current)}
    rules = [candidate if item["id"] == candidate["id"] else item for item in state["rules"]] if current \
        else [*state["rules"][:-1], candidate, state["rules"][-1]]
    return {**state, "rules": rules}, candidate


# ------------------------------------------------------------------ earlier versions

def adopt_legacy(data_dir: Path, project: dict, issue_type: dict, *, by: str) -> bool:
    """The single project + issue type of earlier versions becomes a destination and the default rule (manual), unless
    routing is already set up. The destination has no field snapshot: it sends the fields Tamandua always sent
    (summary, description, priority by name and labels) until an administrator saves it again."""
    with documents.edit(data_dir, DOCUMENT, {}) as stored:
        state = _normalized(stored)
        if state["destinations"]:
            return False
        name = (project.get("name") or project["key"])[:NAME_MAX]
        state["destinations"] = [{"id": "legacy", "name": name, "project": {"id": None, "key": project["key"], "name": project.get("name")},
                                  "issue_type": {"id": None, "name": issue_type["name"]}, "legacy": True,
                                  "mapping": {"summary": {"source": "tamandua", "key": "summary"},
                                              "description": {"source": "tamandua", "key": "description"},
                                              "priority": {"source": "tamandua", "key": "jira_priority"},
                                              "labels": {"source": "tamandua", "key": "labels"}},
                                  "fields": None, "created_by": by, "created_at": _stamp(), "updated_by": by, "updated_at": _stamp()}]
        state["rules"] = [{**state["rules"][-1], "destination": "legacy", "enabled": True, "mode": "manual", "backfill": False}]
        _record(state, by, "legacy_adopted", f"{project['key']}/{issue_type['name']}")
        stored.clear()
        stored.update(state)
    return True


def adopt_project(data_dir: Path, project, issue_type, *, by: str, http=None) -> dict:
    """How earlier panels connect: one project key and one issue type name. It becomes a destination with the default
    mapping and, if the default rule has none, the default rule's destination (manual)."""
    project_key = jira.check_project_key(project)
    wanted = " ".join(issue_type.split())[:60] if isinstance(issue_type, str) and issue_type.strip() else "Task"
    state = load(data_dir)
    current = next((item for item in state["destinations"] if item["project"].get("key") == project_key
                    and item["issue_type"].get("name", "").lower() == wanted.lower()), None)
    try:
        saved, _ = save_destination(data_dir, {"id": current["id"] if current else None,
                                               "name": current["name"] if current else project_key, "project": project_key,
                                               "issue_type": wanted}, by=by, http=http)
    except RoutingError as exc:
        raise RoutingError(exc.errors[0]["error"] if exc.errors else exc.message) from exc
    default = state["rules"][-1]
    if not default.get("destination") or default["destination"] == (current or {}).get("id"):
        save_rule(data_dir, {"id": DEFAULT_RULE, "destination": saved["id"], "enabled": True, "mode": default.get("mode", "manual"),
                             "min_severity": default.get("min_severity", "high"), "backfill": default.get("backfill", False)}, by=by)
    return saved


def rename_assets(data_dir: Path, moved: dict[str, str]) -> None:
    """Assets that gained a stable identity (old key → new): rules naming the old key follow them."""
    if not moved or not any(set(item.get("assets") or []) & set(moved) for item in load(data_dir)["rules"]):
        return
    with documents.edit(data_dir, DOCUMENT, {}) as stored:
        for item in stored.get("rules") or []:
            if isinstance(item, dict) and item.get("assets"):
                item["assets"] = list(dict.fromkeys(moved.get(key, key) for key in item["assets"]))
