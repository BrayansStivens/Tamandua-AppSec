"""Jira: the credential, discovery of projects and fields, destinations, routing rules, backfills and issue creation.

Administrators configure and discover; any signed-in user may create issues for the findings they select, as before.
The token never leaves the server; Jira is only reached at `https://<site>.atlassian.net` (integrations/jira.py).
"""

from __future__ import annotations

import re

from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError

from tamandua.app.api.deps import ApiError, Context, Policy, body, documented, guard, json_body, problem
from tamandua.app.api.schemas import AS_RETURNED, Open
from tamandua.modules.findings import triage
from tamandua.modules.findings.kinds import FINDING_RUNS
from tamandua.modules.findings.registry import VIEW_PREFIX
from tamandua.modules.integrations import jira, jira_mapping, jira_routing as routing
from tamandua.modules.runs import jira_sync
from tamandua.modules.runs.registry import resolve
from tamandua.shared.i18n import default_locale, msg

router = APIRouter(tags=["jira"])

FIELD_TYPES = Literal["text", "rich_text", "number", "date", "datetime", "option", "options", "priority", "labels", "strings",
                      "unsupported", "managed"]
VARIABLE_TYPES = Literal["text", "rich_text", "number", "date", "datetime", "labels"]
SEVERITY = Literal["critical", "high", "medium", "low", "info"]
MODE = Literal["manual", "auto"]


# --- responses ---------------------------------------------------------------------------------------------------

class JiraStatus(Open):
    """The credential (never the token: its last four characters) and, for earlier panels, the default destination."""
    configured: bool
    site: str | None = None
    email: str | None = None
    last4: str | None = None
    saved_at: str | None = None
    saved_by: str | None = None
    project: str | None = None
    project_name: str | None = None
    issue_type: str | None = None
    destinations: int | None = None
    rules: int | None = None
    automatic: bool | None = None


class JiraProject(BaseModel):
    id: str
    key: str
    name: str


class JiraProjectPage(BaseModel):
    items: list[JiraProject] = Field(max_length=jira.PAGE)
    total: int
    start: int
    limit: int
    last: bool


class JiraIssueType(BaseModel):
    id: str
    name: str
    subtask: bool


class JiraIssueTypes(BaseModel):
    items: list[JiraIssueType] = Field(max_length=jira.MAX_ISSUE_TYPES)
    truncated: bool


class JiraAllowedValue(BaseModel):
    id: str
    name: str


class JiraFieldSchema(BaseModel):
    type: str
    items: str | None = None
    system: str | None = None
    custom: str | None = None


class JiraField(BaseModel):
    """A create field. `type` says what Tamandua can put in it; `fillable` false: it can only be left empty."""
    id: str
    name: str
    required: bool
    has_default: bool
    type: FIELD_TYPES
    schema_: JiraFieldSchema = Field(alias="schema")
    allowed: list[JiraAllowedValue] = Field(max_length=jira.MAX_ALLOWED_VALUES)
    allowed_truncated: bool
    fillable: bool


class JiraFields(BaseModel):
    """The fields of an issue type's create screen and the mapping Tamandua proposes for them."""
    fields: list[JiraField] = Field(max_length=jira.MAX_FIELDS)
    truncated: bool
    suggested: dict[str, dict[str, Any]]


class JiraVariable(BaseModel):
    key: str
    type: VARIABLE_TYPES
    label: str


class JiraVariables(BaseModel):
    """What a mapping can use: Tamandua's variables (`source: tamandua`, or `{{key}}` in a template)."""
    variables: list[JiraVariable] = Field(max_length=len(jira_mapping.VARIABLES))
    sources: list[str] = Field(max_length=3)
    fits: dict[str, Annotated[list[str], Field(max_length=len(jira_mapping.VARIABLES))]]
    # Variables matched by the value's name (e.g. severity → an option called "High"), per field type.
    by_name: dict[str, Annotated[list[str], Field(max_length=len(jira_mapping.BY_NAME))]]
    limits: dict[str, int]


class JiraFieldError(BaseModel):
    field: str
    error: str


class JiraDestination(Open):
    """Project + issue type + mapping. `fields`: the snapshot of the mapped fields (null for one migrated from the
    single project of earlier versions, `legacy`, until it is saved again)."""
    id: str
    name: str
    project: dict[str, Any]
    issue_type: dict[str, Any]
    mapping: dict[str, dict[str, Any]]
    fields: dict[str, dict[str, Any]] | None = None
    legacy: bool | None = None


class JiraRule(Open):
    """A routing rule; the last one (`default`) matches every asset. First enabled match wins."""
    id: str
    name: str
    default: bool | None = None
    assets: list[str] = Field(max_length=routing.MAX_ASSETS)
    patterns: list[str] = Field(max_length=routing.MAX_PATTERNS)
    destination: str | None = None
    mode: MODE
    min_severity: SEVERITY
    backfill: bool
    enabled: bool


class JiraRouting(BaseModel):
    destinations: list[JiraDestination] = Field(max_length=routing.MAX_DESTINATIONS)
    rules: list[JiraRule] = Field(max_length=routing.MAX_RULES + 1)
    history: list[dict[str, Any]] = Field(max_length=20)
    limits: dict[str, int]


class JiraDestinationSaved(BaseModel):
    destination: JiraDestination
    warnings: list[JiraFieldError] = Field(max_length=100)
    routing: JiraRouting


class JiraBackfill(Open):
    """One rule's last backfill: issues queued and what became of them (`pending` still in the queue)."""
    rule: str
    batch: str | None = None
    by: str | None = None
    started_at: str | None = None
    finished_at: str | None = None
    queued: int = 0
    findings: int = 0
    created: int = 0
    existing: int = 0
    skipped: int = 0
    failed: int = 0
    pending: int = 0
    truncated: bool = False
    last_error: str | None = None


class JiraBackfills(BaseModel):
    items: list[JiraBackfill] = Field(max_length=routing.MAX_RULES + 1)


class JiraRuleSaved(BaseModel):
    rule: JiraRule
    backfill: JiraBackfill | None
    routing: JiraRouting


class JiraRulePreview(BaseModel):
    """What a backfill of this rule would queue now (up to the backfill limit)."""
    assets: int
    findings: int
    issues: int
    linked: int
    truncated: bool


class JiraExportItem(Open):
    fingerprint: str
    asset: str | None = None
    key: str | None = None
    url: str | None = None
    project: str | None = None
    error: str | None = None


class JiraExport(BaseModel):
    """Each finding exported: an issue created, one that already existed, or why it failed."""
    created: list[JiraExportItem] = Field(max_length=jira.MAX_BATCH)
    existing: list[JiraExportItem] = Field(max_length=jira.MAX_BATCH)
    failed: list[JiraExportItem] = Field(max_length=jira.MAX_BATCH)


class JiraQueued(BaseModel):
    """A selection sent through the queue: progress of its issues, and the findings no rule routes (failed at once)."""
    batch: str
    by: str
    started_at: str
    finished_at: str | None
    queued: int
    findings: int
    linked: int = 0
    created: int
    existing: int
    skipped: int
    failed: int
    pending: int
    last_error: str | None
    rejected: list[JiraExportItem] = Field(default_factory=list, max_length=jira_sync.MANUAL_MAX)


# --- requests ------------------------------------------------------------------------------------------------------

class JiraRemoveIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["remove"]


class JiraSaveIn(BaseModel):
    """The credential. `project` and `issue_type` (earlier panels): also a destination and the default rule."""
    model_config = ConfigDict(extra="forbid")
    action: Literal["save"]
    site: Any
    email: Any
    token: Any
    project: Any = None
    issue_type: Any = None


class JiraMappingIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: Literal["tamandua", "fixed", "template"]
    key: str | None = Field(None, max_length=40)
    value: (Annotated[str, Field(max_length=jira_mapping.TEMPLATE_MAX)] | int | float
            | Annotated[list[Annotated[str, Field(max_length=jira_mapping.LITERAL_MAX)]], Field(max_length=jira_mapping.FIXED_LIST_MAX)]
            | None) = None
    text: str | None = Field(None, max_length=jira_mapping.TEMPLATE_MAX)


class JiraDestinationIn(BaseModel):
    """`project`: key or id; `issue_type`: id (or name). No `mapping`: Tamandua's suggested one."""
    model_config = ConfigDict(extra="forbid")
    id: str | None = Field(None, max_length=12)
    name: str = Field(max_length=routing.NAME_MAX)
    project: str = Field(max_length=20)
    issue_type: str = Field(max_length=60)
    mapping: dict[str, JiraMappingIn | None] | None = Field(None, max_length=jira_mapping.MAX_FIELDS)


class JiraRuleIn(BaseModel):
    """A rule; `id` "default" edits the last rule (its assets are all of them)."""
    model_config = ConfigDict(extra="forbid")
    id: str | None = Field(None, max_length=12)
    name: str | None = Field(None, max_length=routing.NAME_MAX)
    assets: list[str] = Field(default_factory=list, max_length=routing.MAX_ASSETS)
    patterns: list[str] = Field(default_factory=list, max_length=routing.MAX_PATTERNS)
    destination: str | None = Field(None, max_length=12)
    mode: MODE = "manual"
    min_severity: SEVERITY = "high"
    backfill: bool = False
    enabled: bool = True


class JiraIdIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(max_length=12)


class JiraOrderIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ids: list[str] = Field(max_length=routing.MAX_RULES)


class JiraSelectionIn(BaseModel):
    """Findings of one run (`run_id`, or `asset:<key>` for an asset's state) or of one asset (`asset`)."""
    model_config = ConfigDict(extra="forbid")
    run_id: str | None = Field(None, max_length=400)
    asset: str | None = Field(None, max_length=300)
    fingerprints: list[str] = Field(min_length=1, max_length=jira.MAX_BATCH)


class JiraQueueSelectionIn(JiraSelectionIn):
    fingerprints: list[str] = Field(min_length=1, max_length=jira_sync.MANUAL_MAX)


class JiraQueueIn(BaseModel):
    """A large selection (up to 5000 findings): its issues are created in the background."""
    model_config = ConfigDict(extra="forbid")
    selections: list[JiraQueueSelectionIn] = Field(min_length=1, max_length=100)


class JiraExportIn(BaseModel):
    """One selection (`run_id` or `asset` + `fingerprints`) or several (`selections`), up to 50 findings in all."""
    model_config = ConfigDict(extra="forbid")
    run_id: str | None = Field(None, max_length=400)
    asset: str | None = Field(None, max_length=300)
    fingerprints: Any = None
    selections: list[JiraSelectionIn] | None = Field(None, max_length=jira.MAX_BATCH)


# --- helpers -------------------------------------------------------------------------------------------------------

def _parse(model, payload):
    """Like `body`, but a field that doesn't fit is named in `errors`, so the panel can point at it."""
    try:
        return TypeAdapter(model).validate_python(payload)
    except ValidationError as exc:
        errors = [{"field": ".".join(str(part) for part in error["loc"][:2])[:100] or "body", "error": msg("integrations.jira.routing.invalid_value")}
                  for error in exc.errors()[:20]]
        raise ApiError(400, msg("integrations.jira.routing.invalid"), errors=errors) from exc


def _by(context: Context) -> str:
    return str((context.user or {}).get("username") or "")


def _routing_error(exc: routing.RoutingError) -> ApiError:
    return ApiError(400, exc.message, errors=exc.errors) if exc.errors else ApiError(400, exc.message)


def _status(context: Context) -> dict:
    found = jira.status()
    if not found["configured"]:
        return found
    state = routing.load(context.data_dir)
    default = routing.destination(state, state["rules"][-1].get("destination")) if state["rules"][-1].get("enabled") else None
    compat = {"project": default["project"].get("key"), "project_name": default["project"].get("name"),
              "issue_type": default["issue_type"].get("name")} if default else {}
    return {**found, **compat, "destinations": len(state["destinations"]), "rules": len(state["rules"]),
            "automatic": any(item.get("enabled") and item.get("mode") == "auto" for item in state["rules"])}


def _routing(context: Context) -> dict:
    return context.render(routing.view(context.data_dir))


# --- credential ----------------------------------------------------------------------------------------------------

@router.get("/api/integrations/jira", response_model=JiraStatus, **AS_RETURNED)
def jira_status(context: Context = Depends(guard())) -> Any:
    return context.render(_status(context))


@router.post("/api/integrations/jira", openapi_extra=documented(JiraSaveIn, JiraRemoveIn), response_model=JiraStatus, **AS_RETURNED)
def jira_configure(context: Context = Depends(guard(Policy(admin=True, action="connect-jira", body=1024))),
                   data: JiraSaveIn | JiraRemoveIn = Depends(body(JiraSaveIn | JiraRemoveIn,  # type: ignore[arg-type]
                                                                  msg("integrations.jira.invalid_request")))) -> Any:
    by = _by(context)
    if isinstance(data, JiraRemoveIn):
        jira.forget()
        context.state.log.info("jira_removed", extra={"user": by})
        return context.render(_status(context))
    try:
        jira.configure(data.site, data.email, data.token, by=by)
        if data.project:
            routing.adopt_project(context.data_dir, data.project, data.issue_type, by=by)
        return context.render(_status(context))
    except jira.JiraError as exc:
        raise ApiError(400, problem(exc)) from exc
    except routing.RoutingError as exc:
        raise _routing_error(exc) from exc
    except OSError as exc:
        raise ApiError(500, msg("api.save_settings_failed")) from exc


# --- discovery (administrators) ------------------------------------------------------------------------------------

@router.get("/api/integrations/jira/projects", response_model=JiraProjectPage)
def jira_projects(q: str = Query("", max_length=80), start: int = Query(0, ge=0, le=10_000), limit: int = Query(jira.PAGE, ge=1, le=jira.PAGE),
                  context: Context = Depends(guard(Policy(admin=True)))) -> Any:
    """Projects the credential can see, by name or key (`q`), a page at a time."""
    try:
        return context.render(jira.projects(q, start, limit))
    except jira.JiraError as exc:
        raise ApiError(400, problem(exc)) from exc


@router.get("/api/integrations/jira/projects/{project}/issue-types", response_model=JiraIssueTypes)
def jira_issue_types(project: str, context: Context = Depends(guard(Policy(admin=True)))) -> Any:
    try:
        return context.render(jira.issue_types(project))
    except jira.JiraError as exc:
        raise ApiError(400, problem(exc)) from exc


@router.get("/api/integrations/jira/projects/{project}/issue-types/{issue_type}/fields", response_model=JiraFields)
def jira_fields(project: str, issue_type: str, context: Context = Depends(guard(Policy(admin=True)))) -> Any:
    """The create screen's fields, normalized, and the mapping Tamandua suggests for them."""
    try:
        found = jira.create_fields(project, issue_type)
    except jira.JiraError as exc:
        raise ApiError(400, problem(exc)) from exc
    return context.render({**found, "suggested": jira_mapping.default_mapping(found["fields"])})


class JiraFieldValues(BaseModel):
    """Allowed values of one field matching a search (lists too long for `allowed`)."""
    items: list[JiraAllowedValue] = Field(max_length=jira.MAX_VALUE_RESULTS)
    total: int
    truncated: bool


@router.get("/api/integrations/jira/projects/{project}/issue-types/{issue_type}/fields/{field}/values",
            response_model=JiraFieldValues)
def jira_field_values(project: str, issue_type: str, field: str, q: str = Query("", max_length=100),
                      limit: int = Query(jira.MAX_VALUE_RESULTS, ge=1, le=jira.MAX_VALUE_RESULTS),
                      context: Context = Depends(guard(Policy(admin=True)))) -> Any:
    """Searches a field's allowed values by name: for fields whose `allowed_truncated` is true."""
    try:
        return context.render(jira.field_values(project, issue_type, field, q, limit=limit))
    except jira.JiraError as exc:
        raise ApiError(400, problem(exc)) from exc


@router.get("/api/integrations/jira/variables", response_model=JiraVariables)
def jira_variables(context: Context = Depends(guard(Policy(admin=True)))) -> Any:
    return context.render({"variables": jira_mapping.variables(), "sources": ["tamandua", "fixed", "template"],
                           "fits": {kind: sorted(types) for kind, types in jira_mapping.FITS.items()},
                           "by_name": {kind: list(jira_mapping.BY_NAME) for kind in jira_mapping.NAMED_KINDS},
                           "limits": {"fields": jira_mapping.MAX_FIELDS, "template": jira_mapping.TEMPLATE_MAX,
                                      "fixed_values": jira_mapping.FIXED_LIST_MAX, "backfill": jira_sync.BACKFILL_MAX}})


# --- destinations and rules (administrators) -----------------------------------------------------------------------

@router.get("/api/integrations/jira/routing", response_model=JiraRouting)
def jira_routing(context: Context = Depends(guard(Policy(admin=True)))) -> Any:
    return _routing(context)


@router.post("/api/integrations/jira/destinations", openapi_extra=documented(JiraDestinationIn), response_model=JiraDestinationSaved)
def jira_destination_save(context: Context = Depends(guard(Policy(admin=True, action="jira-routing", body=160_000))),
                          payload: Any = Depends(json_body)) -> Any:
    """Creates (no `id`) or updates a destination, validated against Jira's live create metadata."""
    data = _parse(JiraDestinationIn, payload)
    mapping = {key: (value.model_dump(exclude_none=True) if value else None) for key, value in (data.mapping or {}).items()}
    try:
        saved, warnings = routing.save_destination(context.data_dir, {**data.model_dump(exclude={"mapping"}), "mapping": mapping},
                                                   by=_by(context))
    except routing.RoutingError as exc:
        raise _routing_error(exc) from exc
    except jira.JiraError as exc:
        raise ApiError(400, problem(exc)) from exc
    return context.render({"destination": saved, "warnings": warnings, "routing": routing.view(context.data_dir)})


@router.post("/api/integrations/jira/destinations/remove", openapi_extra=documented(JiraIdIn), response_model=JiraRouting)
def jira_destination_remove(context: Context = Depends(guard(Policy(admin=True, action="jira-routing"))),
                            payload: Any = Depends(json_body)) -> Any:
    data = _parse(JiraIdIn, payload)
    try:
        routing.remove_destination(context.data_dir, data.id, by=_by(context))
    except routing.RoutingError as exc:
        raise _routing_error(exc) from exc
    return _routing(context)


@router.post("/api/integrations/jira/rules", openapi_extra=documented(JiraRuleIn), response_model=JiraRuleSaved)
def jira_rule_save(context: Context = Depends(guard(Policy(admin=True, action="jira-routing", body=64_000))),
                   payload: Any = Depends(json_body)) -> Any:
    """Creates (no `id`) or updates a rule. An automatic rule with backfill starts its backfill when saved new,
    enabled or changed in what it covers (`backfill` in the answer)."""
    data = _parse(JiraRuleIn, payload)
    try:
        saved, started = jira_sync.save_rule(context.data_dir, data.model_dump(), by=_by(context))
    except routing.RoutingError as exc:
        raise _routing_error(exc) from exc
    except jira.JiraError as exc:
        raise ApiError(400, problem(exc)) from exc
    return context.render({"rule": saved, "backfill": started, "routing": routing.view(context.data_dir)})


@router.post("/api/integrations/jira/rules/remove", openapi_extra=documented(JiraIdIn), response_model=JiraRouting)
def jira_rule_remove(context: Context = Depends(guard(Policy(admin=True, action="jira-routing"))),
                     payload: Any = Depends(json_body)) -> Any:
    data = _parse(JiraIdIn, payload)
    try:
        routing.remove_rule(context.data_dir, data.id, by=_by(context))
    except routing.RoutingError as exc:
        raise _routing_error(exc) from exc
    return _routing(context)


@router.post("/api/integrations/jira/rules/order", openapi_extra=documented(JiraOrderIn), response_model=JiraRouting)
def jira_rule_order(context: Context = Depends(guard(Policy(admin=True, action="jira-routing", body=2048))),
                    payload: Any = Depends(json_body)) -> Any:
    """The rules in their new order (all but `default`, which stays last)."""
    data = _parse(JiraOrderIn, payload)
    try:
        routing.reorder(context.data_dir, data.ids, by=_by(context))
    except routing.RoutingError as exc:
        raise _routing_error(exc) from exc
    return _routing(context)


@router.post("/api/integrations/jira/rules/preview", openapi_extra=documented(JiraRuleIn), response_model=JiraRulePreview)
def jira_rule_preview(context: Context = Depends(guard(Policy(admin=True, action="jira-preview", body=64_000))),
                      payload: Any = Depends(json_body)) -> Any:
    """How many open findings this rule (as sent, saved or not) would backfill. Nothing is queued."""
    data = _parse(JiraRuleIn, payload)
    try:
        return jira_sync.preview(context.data_dir, data.model_dump())
    except routing.RoutingError as exc:
        raise _routing_error(exc) from exc


@router.post("/api/integrations/jira/rules/backfill", openapi_extra=documented(JiraIdIn), response_model=JiraBackfill, **AS_RETURNED)
def jira_rule_backfill(context: Context = Depends(guard(Policy(admin=True, action="jira-routing"))),
                       payload: Any = Depends(json_body)) -> Any:
    """Runs an automatic rule's backfill again (what already has an issue is skipped)."""
    data = _parse(JiraIdIn, payload)
    try:
        return context.render(jira_sync.backfill(context.data_dir, data.id, by=_by(context)))
    except routing.RoutingError as exc:
        raise _routing_error(exc) from exc
    except jira.JiraError as exc:
        raise ApiError(400, problem(exc)) from exc


@router.get("/api/integrations/jira/backfill", response_model=JiraBackfills)
def jira_backfill_status(context: Context = Depends(guard(Policy(admin=True)))) -> Any:
    return context.render({"items": jira_sync.backfill_status(context.data_dir)})


# --- issues (any signed-in user) -----------------------------------------------------------------------------------

def _record(context: Context, run_id: str | None, asset: str | None) -> dict:
    record: dict
    if bool(run_id) == bool(asset):
        raise ApiError(400, msg("integrations.jira.invalid_export"))
    try:
        record = dict(resolve(context.data_dir, run_id if run_id else f"{VIEW_PREFIX}{asset}"))
        record = record if record.get("type") == "asset_state" else dict(triage.annotate(context.data_dir, record))  # type: ignore[arg-type]
    except (ValueError, OSError) as exc:
        raise ApiError(404, msg("api.run_not_found")) from exc
    if record.get("type") not in (*FINDING_RUNS, "asset_state"):
        raise ApiError(400, msg("integrations.jira.code_only"))
    return record


@router.post("/api/integrations/jira/issues", openapi_extra=documented(JiraExportIn), response_model=JiraExport)
def jira_export(context: Context = Depends(guard(Policy(action="export-jira", body=20_000))),
                data: JiraExportIn = Depends(body(JiraExportIn, msg("integrations.jira.invalid_export")))) -> Any:
    """Creates the issues of the selected findings, each in the destination its asset's rules pick."""
    if data.selections is not None:
        if data.run_id or data.asset or data.fingerprints is not None:
            raise ApiError(400, msg("integrations.jira.invalid_export"))
        selections = [(_record(context, item.run_id, item.asset), item.fingerprints) for item in data.selections]
    else:
        selections = [(_record(context, data.run_id, data.asset), data.fingerprints)]
    try:
        # Issues are read by the whole team: TAMANDUA_DEFAULT_LOCALE, not the requester's language.
        return context.render(jira_sync.export(context.data_dir, selections, by=_by(context), locale=default_locale()))
    except jira.JiraError as exc:
        raise ApiError(400, problem(exc)) from exc


@router.post("/api/integrations/jira/issues/queue", response_model=JiraQueued, status_code=202,
             openapi_extra=documented(JiraQueueIn))
def jira_export_queue(context: Context = Depends(guard(Policy(action="export-jira", body=400_000))),
                      data: JiraQueueIn = Depends(body(JiraQueueIn, msg("integrations.jira.invalid_export")))) -> Any:
    """Queues the issues of a large selection; `GET …/issues/batches/{batch}` follows them."""
    selections = [(_record(context, item.run_id, item.asset), item.fingerprints) for item in data.selections]
    try:
        return context.render(jira_sync.queue_export(context.data_dir, selections, by=_by(context)))
    except jira.JiraError as exc:
        raise ApiError(400, problem(exc)) from exc


@router.get("/api/integrations/jira/issues/batches/{batch}", response_model=JiraQueued, responses={404: {"description": "Unknown batch"}})
def jira_export_batch(batch: str, context: Context = Depends(guard(Policy()))) -> Any:
    """Progress of a queued selection: counts only."""
    found = jira_sync.manual_status(context.data_dir, batch) if re.fullmatch(r"[0-9a-f]{16}", batch) else None
    if found is None:
        raise ApiError(404, msg("api.not_found"))
    return context.render(found)
