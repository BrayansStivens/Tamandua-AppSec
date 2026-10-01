"""What Tamandua puts in each field of a Jira issue: the variables it offers and the mapping of a destination.

A destination maps each field of its create screen (by field id) to one of:

* ``{"source": "tamandua", "key": <variable>}``: the value of a variable (below);
* ``{"source": "fixed", "value": ...}``: an allowed value's id (option, priority), a list of them (options), or a literal
  (text, number, YYYY-MM-DD date, labels);
* ``{"source": "template", "text": "… {{title}} …"}``: plain substitution of ``{{variable}}``, nothing else. There is no
  expression language, no attribute access and no format string: an unknown name is rejected when saved.

A field left out is left empty. The mapping is validated against the live create metadata when it is saved: every
required field without a default is mapped, each source fits the field's type and fixed values are among the allowed
ones. A snapshot of the mapped fields is kept with the destination, so creating an issue needs no metadata call.

Variables (one issue may cover several findings of one package: the notes say what a group takes):

======================  ==========  ==========================================================================
``summary``             text        Tamandua's issue title: ``Severity: title in path:line``, or the package update
``title``               text        The finding's title (for a group, the package upgrade without the severity)
``severity``            text        critical, high, medium, low or info (a group: the highest)
``jira_priority``       text        Highest, High or Medium, from Tamandua's priority (act, attend, track)
``description``         rich_text   The developer's brief (runs/jira_brief.py): problem, where, fix, verify, deadline
``cwe``                 text        CWE-79, CWE-89 (a group: all of them)
``cve``                 text        The CVE identifiers (a group: all of them)
``package``             text        Package and installed version, e.g. ``lodash 4.17.20``
``fixed_version``       text        The version that fixes it (a group: the one that fixes them all)
``path``                text        File of the finding
``line``                number      Line of the finding
``asset``               text        Repository or image name
``panel_url``           text        Link to the finding in the panel (needs TAMANDUA_PUBLIC_URL)
``first_seen``          datetime    First detection (a group: the earliest)
``due_date``            date        First detection + the SLA days for its severity (a group: the earliest)
``labels``              labels      Tamandua's labels: appsec, scanner, severity, cisa-kev, fix-available
======================  ==========  ==========================================================================

One identity label per issue (``jira.identity_label``: the finding's, or the package's) is always added when the labels field is on the screen, whatever
the mapping: it is how an issue is found again (idempotency).
"""

from __future__ import annotations

import re
from datetime import date, datetime, timezone

from tamandua.modules.integrations.jira import adf, label_for, plain
from tamandua.shared.i18n import is_msg, msg, text

VARIABLES: dict[str, str] = {
    "summary": "text", "title": "text", "severity": "text", "jira_priority": "text", "description": "rich_text",
    "cwe": "text", "cve": "text", "package": "text", "fixed_version": "text", "path": "text", "line": "number",
    "asset": "text", "panel_url": "text", "first_seen": "datetime", "due_date": "date", "labels": "labels",
}
VARIABLE_LABELS = {
    "summary": msg("integrations.jira.variables.summary"), "title": msg("integrations.jira.variables.title"),
    "severity": msg("integrations.jira.variables.severity"), "jira_priority": msg("integrations.jira.variables.jira_priority"),
    "description": msg("integrations.jira.variables.description"), "cwe": msg("integrations.jira.variables.cwe"),
    "cve": msg("integrations.jira.variables.cve"), "package": msg("integrations.jira.variables.package"),
    "fixed_version": msg("integrations.jira.variables.fixed_version"), "path": msg("integrations.jira.variables.path"),
    "line": msg("integrations.jira.variables.line"), "asset": msg("integrations.jira.variables.asset"),
    "panel_url": msg("integrations.jira.variables.panel_url"), "first_seen": msg("integrations.jira.variables.first_seen"),
    "due_date": msg("integrations.jira.variables.due_date"), "labels": msg("integrations.jira.variables.labels"),
}
# Variables whose value names an option: they go into select and priority fields by matching the option's name.
BY_NAME = ("severity", "jira_priority")
NAMED_KINDS = ("option", "priority")  # field types a BY_NAME variable fills by matching the value's name
SEVERITIES = ("critical", "high", "medium", "low")
JIRA_PRIORITIES = ("Highest", "High", "Medium")
# Which variable types fit each field type.
FITS = {
    "text": {"text", "number", "date", "datetime", "labels"},
    "rich_text": {"text", "rich_text", "number", "date", "datetime", "labels"},
    "number": {"number"},
    "date": {"date", "datetime"},
    "datetime": {"datetime"},
    "labels": {"text", "labels"},
    "strings": {"text", "labels"},
    "option": set(),
    "options": set(),
    "priority": set(),
}
TEMPLATED = ("text", "rich_text", "labels", "strings")
MAX_FIELDS = 50
TEMPLATE_MAX = 2000
LITERAL_MAX = 255
FIXED_LIST_MAX = 20
SUMMARY_MAX = 255
RICH_MAX = 30_000
TEXT_MAX = 255
LABEL_MAX = 60
PLACEHOLDER = re.compile(r"\{\{\s*([a-z_]{1,40})\s*\}\}")
DEFAULTS = {"summary": {"source": "tamandua", "key": "summary"}, "description": {"source": "tamandua", "key": "description"},
            "priority": {"source": "tamandua", "key": "jira_priority"}, "labels": {"source": "tamandua", "key": "labels"},
            "duedate": {"source": "tamandua", "key": "due_date"}}
# Destinations migrated from the single project of earlier versions: no snapshot, the fields Tamandua always sent.
LEGACY_FIELDS: dict[str, dict] = {"summary": {"type": "text"}, "description": {"type": "rich_text"}, "priority": {"type": "priority", "by_name": True},
                 "labels": {"type": "labels"}}


class MappingError(ValueError):
    """`errors`: [{"field", "error"}] (messages), one per field that doesn't fit."""

    def __init__(self, errors: list[dict]):
        super().__init__("; ".join(f"{item['field']}: {text(item['error'], 'en')}" for item in errors))
        self.errors = errors


def variables() -> list[dict]:
    return [{"key": key, "type": kind, "label": VARIABLE_LABELS[key]} for key, kind in VARIABLES.items()]


def default_mapping(fields: list[dict]) -> dict:
    on_screen = {field["id"] for field in fields}
    return {field: spec for field, spec in DEFAULTS.items() if field in on_screen}


SNAPSHOT_ALLOWED_MAX = 1000


def _kept(field: dict, spec: dict) -> list[dict]:
    """The allowed values a destination keeps: a fixed choice needs only itself; a Tamandua datum is matched by name
    when the issue is created, so it keeps the list (bounded: those fields are short, like priorities)."""
    allowed = field.get("allowed") or []
    if spec.get("source") == "fixed":
        chosen = spec["value"] if isinstance(spec["value"], list) else [spec["value"]]
        return [item for item in allowed if item["id"] in chosen]
    return allowed[:SNAPSHOT_ALLOWED_MAX] if spec.get("source") == "tamandua" else []


def _allowed(field: dict) -> dict[str, str]:
    return {item["id"]: item["name"] for item in field.get("allowed") or []}


def _check_template(template) -> str | dict:
    if not isinstance(template, str) or not template.strip() or len(template) > TEMPLATE_MAX:
        return msg("integrations.jira.mapping.template_length", max=TEMPLATE_MAX)
    unknown = sorted({name for name in PLACEHOLDER.findall(template) if name not in VARIABLES})
    if unknown:
        return msg("integrations.jira.mapping.unknown_variables", names=", ".join(unknown[:5]))
    return template


def _check_fixed(field: dict, value):
    """The fixed value, cleaned, or an error message."""
    kind, allowed = field["type"], _allowed(field)
    if kind in ("option", "priority"):
        if not isinstance(value, str) or value not in allowed:
            return msg("integrations.jira.mapping.not_allowed", field=field["name"])
        return value
    if kind == "options":
        if (not isinstance(value, list) or not 1 <= len(value) <= FIXED_LIST_MAX
                or any(not isinstance(item, str) or item not in allowed for item in value)):
            return msg("integrations.jira.mapping.not_allowed", field=field["name"])
        return list(dict.fromkeys(value))
    if kind in ("labels", "strings"):
        items = value if isinstance(value, list) else [value]
        if (not 1 <= len(items) <= FIXED_LIST_MAX
                or any(not isinstance(item, str) or not item.strip() or len(item) > LITERAL_MAX for item in items)):
            return msg("integrations.jira.mapping.invalid_literal", field=field["name"])
        return [plain(item, LITERAL_MAX) for item in items]
    if kind == "number":
        if isinstance(value, bool) or not isinstance(value, (int, float)) or abs(value) > 1e15:
            return msg("integrations.jira.mapping.invalid_number", field=field["name"])
        return value
    if kind in ("date", "datetime"):
        try:
            parsed = date.fromisoformat(value) if kind == "date" else datetime.fromisoformat(value)
        except (TypeError, ValueError):
            return msg("integrations.jira.mapping.invalid_date", field=field["name"])
        return parsed.isoformat()
    if kind in ("text", "rich_text"):
        limit = TEMPLATE_MAX if kind == "rich_text" else LITERAL_MAX
        if not isinstance(value, str) or not value.strip() or len(value) > limit:
            return msg("integrations.jira.mapping.invalid_literal", field=field["name"])
        return value
    return msg("integrations.jira.mapping.unsupported_type", field=field["name"])


def validate(mapping, fields: list[dict]) -> tuple[dict, dict, list[dict]]:
    """Checks a mapping against the create fields (normalized). Returns the clean mapping, the snapshot of the mapped
    fields and the warnings; raises MappingError with one message per field that doesn't fit."""
    if not isinstance(mapping, dict):
        raise MappingError([{"field": "mapping", "error": msg("integrations.jira.mapping.invalid")}])
    if len(mapping) > MAX_FIELDS:
        raise MappingError([{"field": "mapping", "error": msg("integrations.jira.mapping.too_many", max=MAX_FIELDS)}])
    by_id = {field["id"]: field for field in fields}
    errors, clean, warnings = [], {}, []
    for identifier, spec in mapping.items():
        field = by_id.get(identifier) if isinstance(identifier, str) else None
        if field is None:
            errors.append({"field": str(identifier)[:64], "error": msg("integrations.jira.mapping.not_on_screen")})
            continue
        if spec is None:
            continue
        if not field["fillable"]:
            errors.append({"field": identifier, "error": msg("integrations.jira.mapping.unsupported_type", field=field["name"])})
            continue
        source = spec.get("source") if isinstance(spec, dict) else None
        kind = field["type"]
        if source == "tamandua":
            key = spec.get("key")
            if key not in VARIABLES:
                errors.append({"field": identifier, "error": msg("integrations.jira.mapping.unknown_variables", names=str(key)[:40])})
            elif VARIABLES[key] in FITS[kind] or (kind in NAMED_KINDS and key in BY_NAME):
                clean[identifier] = {"source": "tamandua", "key": key}
                if kind in NAMED_KINDS and key in BY_NAME:
                    names = {name.lower() for name in _allowed(field).values()}
                    expected = SEVERITIES if key == "severity" else JIRA_PRIORITIES
                    missing = [value for value in expected if value.lower() not in names]
                    if missing:
                        warnings.append({"field": identifier, "error": msg("integrations.jira.mapping.unmatched_names",
                                                                          field=field["name"], names=", ".join(missing))})
            else:
                errors.append({"field": identifier, "error": msg("integrations.jira.mapping.type_mismatch", field=field["name"], variable=key)})
        elif source == "fixed":
            value = _check_fixed(field, spec.get("value"))
            if is_msg(value):
                errors.append({"field": identifier, "error": value})
            else:
                clean[identifier] = {"source": "fixed", "value": value}
        elif source == "template":
            if kind not in TEMPLATED:
                errors.append({"field": identifier, "error": msg("integrations.jira.mapping.no_template", field=field["name"])})
                continue
            template = _check_template(spec.get("text"))
            if is_msg(template):
                errors.append({"field": identifier, "error": template})
            else:
                clean[identifier] = {"source": "template", "text": template}
        else:
            errors.append({"field": identifier, "error": msg("integrations.jira.mapping.invalid_source")})
    for field in fields:
        if field["required"] and not field["has_default"] and field["type"] != "managed" and field["id"] not in clean \
                and not any(item["field"] == field["id"] for item in errors):
            errors.append({"field": field["id"], "error": msg("integrations.jira.mapping.required" if field["fillable"]
                                                              else "integrations.jira.mapping.required_unsupported", field=field["name"])})
    for required in ("summary", "description"):
        if required in by_id and required not in clean and not any(item["field"] == required for item in errors):
            errors.append({"field": required, "error": msg("integrations.jira.mapping.required", field=by_id[required]["name"])})
    if errors:
        raise MappingError(errors[:100])
    if "labels" not in by_id:
        warnings.append({"field": "labels", "error": msg("integrations.jira.mapping.no_labels_field")})
    snapshot = {identifier: {"type": by_id[identifier]["type"], "name": by_id[identifier]["name"],
                             "allowed": _kept(by_id[identifier], clean[identifier])} for identifier in clean}
    if "labels" in by_id and "labels" not in snapshot:
        snapshot["labels"] = {"type": by_id["labels"]["type"], "name": by_id["labels"]["name"], "allowed": []}
    return clean, snapshot, warnings


# ------------------------------------------------------------------ building an issue

def substitute(template: str, values: dict) -> str:
    """Replaces each {{name}} with its value as text; nothing is evaluated."""
    return PLACEHOLDER.sub(lambda match: _as_text(values.get(match.group(1))) if match.group(1) in VARIABLES else "", template)


def _as_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return ", ".join(str(item) for item in value)
    return str(value)


def _label(value) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "-", plain(value, LABEL_MAX))[:LABEL_MAX]


def _jira_datetime(value) -> str | None:
    try:
        moment = datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None
    moment = (moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.000+0000")


def _jira_date(value) -> str | None:
    try:
        return datetime.fromisoformat(str(value)).date().isoformat() if "T" in str(value) else date.fromisoformat(str(value)).isoformat()
    except (TypeError, ValueError):
        return None


def _by_name(field: dict, value) -> dict | None:
    wanted = str(value or "").lower()
    if field.get("by_name"):
        return {"name": str(value)} if value else None
    match = next((item["id"] for item in field.get("allowed") or [] if item["name"].lower() == wanted), None)
    return {"id": match} if match else None


def _value(kind: str, field: dict, spec: dict, values: dict):
    """The Jira value of one field, or None to leave it out."""
    source = spec["source"]
    if source == "fixed":
        value = spec["value"]
        if kind in ("option", "priority"):
            return {"id": value}
        if kind == "options":
            return [{"id": item} for item in value]
        if kind in ("labels", "strings"):
            return [_label(item) if kind == "labels" else plain(item, LITERAL_MAX) for item in value]
        if kind == "rich_text":
            return adf(value)
        if kind == "text":
            return plain(value, TEXT_MAX)
        if kind == "datetime":
            return _jira_datetime(value)
        return value
    if kind == "rich_text" and source == "tamandua" and spec["key"] == "description" and values.get("_description_adf"):
        return values["_description_adf"]  # the developer's brief, structured (runs/jira_brief.py)
    raw = substitute(spec["text"], values) if source == "template" else values.get(spec["key"])
    if raw is None or raw == "" or raw == []:
        return None
    if kind in ("option", "priority"):
        return _by_name(field, raw)
    if kind in ("labels", "strings"):
        items = raw if isinstance(raw, list) else [raw]
        cleaned = [_label(item) if kind == "labels" else plain(item, LITERAL_MAX) for item in items]
        return [item for item in cleaned if item.strip("-")] or None
    if kind == "rich_text":
        return adf(_as_text(raw)[:RICH_MAX])
    if kind == "text":
        return plain(_as_text(raw), TEXT_MAX) or None
    if kind == "number":
        return raw if isinstance(raw, (int, float)) and not isinstance(raw, bool) else None
    if kind == "date":
        return _jira_date(raw)
    if kind == "datetime":
        return _jira_datetime(raw)
    return None


def build(destination: dict, values: dict, fingerprints: list[str], *, identity: str | None = None) -> dict:
    """The `fields` of the create request for a destination (see `jira_routing`) and the values of one issue."""
    project, issue_type = destination["project"], destination["issue_type"]
    fields: dict = {"project": {"id": project["id"]} if project.get("id") else {"key": project["key"]},
                    "issuetype": {"id": issue_type["id"]} if issue_type.get("id") else {"name": issue_type["name"]}}
    snapshot: dict = destination.get("fields") or LEGACY_FIELDS
    for identifier, spec in (destination.get("mapping") or {}).items():
        field = snapshot.get(identifier)
        if field is None:
            continue
        value = _value(field["type"], field, spec, values)
        if value is not None:
            fields[identifier] = value
    if "summary" in fields and isinstance(fields["summary"], str):
        fields["summary"] = fields["summary"][:SUMMARY_MAX]
    if "labels" in snapshot:
        labels: list = fields["labels"] if isinstance(fields.get("labels"), list) else []
        fields["labels"] = sorted({*labels, identity or label_for(fingerprints[0])})
    return fields
