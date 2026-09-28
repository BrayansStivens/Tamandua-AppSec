"""Threat models: create (blank or proposed from the scans), edit, decide and export."""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field

from tamandua.app.api.deps import ApiError, Context, Policy, body, documented, guard, json_body
from tamandua.app.api.schemas import AS_RETURNED, MANY, Open
from tamandua.modules.integrations import code_tokens
from tamandua.modules.integrations.github import GitHubAppError
from tamandua.modules.integrations.installations import github_installations
from tamandua.modules.runs.store import find_runs, load_run
from tamandua.modules.scanning.inventory import live as live_inventory
from tamandua.modules.sources.assets import asset_key
from tamandua.modules.sources.domains import list_domains
from tamandua.modules.sources.repositories import SourceError, find_source
from tamandua.modules.threats import model as tm
from tamandua.modules.threats import report as threat_report
from tamandua.shared.i18n import msg
from tamandua.version import VERSION

router = APIRouter(tags=["threats"])


# --- responses ---------------------------------------------------------------------------------------------------

class ThreatModelRow(Open):
    id: str
    name: str
    description: str | None = None
    methodology: str | None = None
    components: int | None = None
    flows: int | None = None
    repositories: int | None = None
    created_at: str | None = None
    updated_at: str | None = None
    updated_by: str | None = None


class ThreatCatalog(Open):
    """The models, the assets a component can link to, and the catalogs the editor offers."""
    models: list[ThreatModelRow] = Field(max_length=MANY)
    assets: list[dict[str, Any]] = Field(max_length=MANY)
    kinds: dict[str, str]
    protocols: list[str] = Field(max_length=len(tm.PROTOCOLS))
    classifications: dict[str, str]
    methods: dict[str, Any]


class ThreatSummary(Open):
    total: int
    by_status: dict[str, int]
    by_stride: dict[str, int]
    by_severity: dict[str, int]


class ThreatModelView(Open):
    """A model with its threats (evidence from the linked assets' scans), their summary and the linked assets."""
    model: dict[str, Any]
    threats: list[dict[str, Any]] = Field(max_length=MANY)
    summary: ThreatSummary
    assets: list[dict[str, Any]] = Field(max_length=MANY)


class ImportCheck(BaseModel):
    """What an import would create, counted, without creating it."""
    name: str
    methodology: str
    components: int
    flows: int
    boundaries: int
    repository_refs: int
    manual_threats: int
    attack_trees: int
    attack_mappings: int
    pasta_stages: int
    relayout: bool


class Proposal(Open):
    """The model with the proposed components merged in, and which ones are new."""
    model: dict[str, Any]
    added: list[str] = Field(max_length=tm.LIMITS["components"])


class Deleted(BaseModel):
    deleted: bool


def _model_keys(model) -> list[str]:
    """Assets a model (or an unvalidated draft) references: its repositories and its components'."""
    if not isinstance(model, dict):
        return []
    repositories = model.get("repositories") if isinstance(model.get("repositories"), list) else []
    components = model.get("components") if isinstance(model.get("components"), list) else []
    keys = [*repositories, *(item.get("asset") for item in components if isinstance(item, dict))]
    return list(dict.fromkeys(key for key in keys if isinstance(key, str) and key and not key.startswith("domain:")))[:120]


def _assets(context: Context, keys: list[str] = ()) -> dict[str, dict]:
    """Linkable assets: analyzed repositories, domains and the repositories asked for in `keys`.

    Those asked for are checked one by one against their credential: validating a model that uses three
    repositories does not list the whole organization."""
    assets: dict[str, dict] = {}
    for row in find_runs(context.data_dir, types=("repository_scan",)):
        source = row.get("source") or {}
        key = asset_key(row)
        if source.get("id"):
            entry = assets.setdefault(key, {"id": key, "source_id": source["id"], "name": source.get("name"), "kind": "repository", "last_run": None})
            if entry["last_run"] is None and row["status"] in ("completed", "incomplete"):
                entry["last_run"], entry["scanned_at"] = row["id"], row["created_at"]
    for domain in list_domains(context.data_dir):
        assets[f"domain:{domain['id']}"] = {"id": f"domain:{domain['id']}", "name": domain["host"], "kind": "domain"}
    if keys:
        tokens = code_tokens.current()
        installations = github_installations(context.data_dir)
        for key in keys:
            try:
                source = find_source(tokens, installations, key)
            except (SourceError, GitHubAppError):
                source = None
            # Linked by stable identity: the model survives a repository rename.
            if source is None or key not in (source.get("uid"), source["id"]):
                continue
            entry = assets.setdefault(key, {"id": key, "kind": "repository", "last_run": None})
            entry.update(source_id=source["id"], name=source["name"], installation_id=source.get("installation_id"))
    return assets


def _view(context: Context, model: dict) -> dict:
    linked = {item["asset"] for item in model.get("components", []) if item.get("asset")}
    rows = tm.threats(model, tm.evidence_index(context.data_dir, linked), locale=context.locale)
    keys = _model_keys(model)
    assets = _assets(context, keys)
    return {"model": model, "threats": rows, "summary": tm.summary(rows),
            "assets": [assets[key] for key in keys if key in assets]}


def _read_repositories(context: Context, assets: dict, chosen) -> list[dict] | dict:
    """Manifests of the chosen repositories, read live. Returns the error as a message."""
    if (not isinstance(chosen, list) or not 1 <= len(chosen) <= 10
            or any(not isinstance(item, str) or assets.get(item, {}).get("kind") != "repository" for item in chosen)):
        return msg("threats.errors.choose_repositories")
    repositories = []
    for item in chosen:
        # The inventory is read now: it does not depend on whether there is a scan, nor on how old it is.
        try:
            inventory = live_inventory(assets[item].get("source_id") or item, installation_id=assets[item].get("installation_id"))
        except (GitHubAppError, SourceError, OSError) as exc:
            return msg("threats.errors.manifests_failed", name=assets[item]["name"], detail=getattr(exc, "message", None) or str(exc))
        record = load_run(context.data_dir, assets[item]["last_run"]) if assets[item]["last_run"] else {}
        repositories.append({"id": item, "name": assets[item]["name"],
                             "inventory": inventory or record.get("inventory"), "findings": record.get("findings", [])})
    return repositories


@router.get("/api/threat-models", response_model=ThreatCatalog, **AS_RETURNED)
def models(context: Context = Depends(guard())) -> Any:
    return context.render({"models": tm.list_models(context.data_dir), "assets": list(_assets(context).values()),
                           "kinds": tm.KINDS, "protocols": tm.PROTOCOLS, "classifications": tm.CLASSIFICATION_LABELS,
                           "methods": tm.threat_methods.catalog()})


def _stored_view(context: Context, model_id: str) -> dict:
    try:
        return _view(context, tm.load(context.data_dir, model_id))
    except tm.ModelError as exc:
        raise ApiError(404, exc.message) from exc


@router.get("/api/threat-models/{model_id}", response_model=ThreatModelView, **AS_RETURNED)
def model_detail(model_id: str, context: Context = Depends(guard())) -> Any:
    return context.render(_stored_view(context, model_id))


def _document(document) -> bytes:
    return json.dumps(document, ensure_ascii=False, indent=2).encode("utf-8")


EXPORTS = {
    "threat-dragon.json": "application/json; charset=utf-8",
    "tm.py": "text/x-python; charset=utf-8",
    "report.md": "text/markdown; charset=utf-8",
    "report.pdf": "application/pdf",
    "diagram.svg": "image/svg+xml; charset=utf-8",
    "model.json": "application/json; charset=utf-8",
}


@router.get("/api/threat-models/{model_id}/{artifact}", response_class=Response,
            responses={200: {"content": {content_type.split(";")[0]: {} for content_type in EXPORTS.values()}}})
def model_export(model_id: str, artifact: str, context: Context = Depends(guard())) -> Response:
    """The model in another format: Threat Dragon, pytm, Markdown or PDF report, SVG diagram or the portable JSON."""
    view, locale = _stored_view(context, model_id), context.locale
    model, threats = view["model"], view["threats"]
    if artifact == "threat-dragon.json":
        content = _document(tm.to_threat_dragon(model, threats, locale=locale))
    elif artifact == "tm.py":
        content = tm.to_pytm(model, locale=locale).encode("utf-8")
    elif artifact == "report.md":
        content = tm.to_markdown(model, threats, locale=locale).encode("utf-8")
    elif artifact == "report.pdf":
        content = threat_report.render_pdf({**model, "id": model_id}, threats, version=VERSION, locale=locale)
    elif artifact == "diagram.svg":
        content = tm.to_svg(model, locale=locale).encode("utf-8")
    elif artifact == "model.json":
        content = _document(tm.to_portable(model, _assets(context, _model_keys(model))))
    else:
        raise ApiError(404, msg("api.not_found"))
    return Response(content, status_code=200, headers={"content-type": EXPORTS[artifact]})


class ThreatModelIn(BaseModel):
    """A model to save (`model`, with `id` to update it) or a new one proposed from repositories (`suggest`)."""
    model_config = ConfigDict(extra="forbid")
    id: Any = None
    model: Any = None
    suggest: Any = None
    name: Any = None
    methodology: Any = None
    custom_modules: Any = Field(default_factory=lambda: ["manual", "elements"])


class ProposeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    model: Any
    repositories: Any


class DecisionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: Any
    threat: Any
    status: Any
    reason: Any = None


class ModelIdIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: Any


ANY_JSON = {"requestBody": {"required": True, "content": {"application/json": {"schema": {}}}}}


@router.post("/api/threat-models", openapi_extra=documented(ThreatModelIn), response_model=ThreatModelView, **AS_RETURNED)
def save_model(context: Context = Depends(guard(Policy(action="save-threat-model", body=600_000))),
               data: ThreatModelIn = Depends(body(ThreatModelIn, msg("api.invalid_request")))) -> Any:
    suggested = data.suggest if isinstance(data.suggest, list) else []
    assets = _assets(context, list(dict.fromkeys([*_model_keys(data.model), *(item for item in suggested[:10] if isinstance(item, str))])))
    by = context.user["username"]
    try:
        if "suggest" in data.model_fields_set:
            # A new model proposed from the inventory of each chosen repository.
            repositories = _read_repositories(context, assets, data.suggest)
            if not isinstance(repositories, list):
                raise ApiError(400, repositories)
            draft = tm.suggest(tm._text(data.name, 80, msg("threats.fields.name"), required=True), repositories, locale=context.locale)
            draft["methodology"] = data.methodology or "stride"
            draft["custom_modules"] = data.custom_modules
            draft["repositories"] = data.suggest
            model = tm.validate(draft, known_assets=set(assets))
            return context.render(_view(context, tm.save(context.data_dir, model, by=by)))
        model = tm.validate(data.model, known_assets=set(assets))
        stored = tm.save(context.data_dir, model, by=by, model_id=data.id if isinstance(data.id, str) else None)
        return context.render(_view(context, stored))
    except tm.ModelError as exc:
        raise ApiError(400, exc.message) from exc
    except (OSError, ValueError) as exc:
        raise ApiError(400, msg("threats.errors.save_failed")) from exc


@router.post("/api/threat-models/import", openapi_extra=ANY_JSON, response_model=ThreatModelView, **AS_RETURNED)
def import_model(context: Context = Depends(guard(Policy(action="import-threat-model", body=600_000))),
                 data: Any = Depends(json_body)) -> Any:
    """Creates a model from the portable format (model.json)."""
    try:
        model = tm.from_portable(data)
        model.pop("relayout", None)
        return context.render(_view(context, tm.save(context.data_dir, model, by=context.user["username"])))
    except tm.ModelError as exc:
        raise ApiError(400, exc.message) from exc
    except (OSError, ValueError) as exc:
        raise ApiError(400, msg("threats.errors.import_failed")) from exc


@router.post("/api/threat-models/validate", openapi_extra=ANY_JSON, response_model=ImportCheck, **AS_RETURNED)
def validate_import(context: Context = Depends(guard(Policy(action="validate-threat-model", body=600_000))),
                    data: Any = Depends(json_body)) -> Any:
    """Checks the portable format without creating or changing a model."""
    try:
        model = tm.from_portable(data)
    except tm.ModelError as exc:
        raise ApiError(400, exc.message) from exc
    return {
        "name": model["name"], "methodology": model["methodology"],
        "components": len(model["components"]), "flows": len(model["flows"]),
        "boundaries": len(model["boundaries"]),
        "repository_refs": len(model["repository_refs"]),
        "manual_threats": len(model["manual_threats"]),
        "attack_trees": len(model["attack_trees"]),
        "attack_mappings": len(model["attack_mappings"]),
        "pasta_stages": len(model["pasta"]),
        "relayout": bool(model.get("relayout")),
    }


@router.post("/api/threat-models/propose", openapi_extra=documented(ProposeIn), response_model=Proposal, **AS_RETURNED)
def propose(context: Context = Depends(guard(Policy(action="propose-components", body=600_000))),
            data: ProposeIn = Depends(body(ProposeIn, msg("api.invalid_request")))) -> Any:
    """Components proposed from repositories, merged into the draft being edited. Saves nothing."""
    chosen = data.repositories if isinstance(data.repositories, list) else []
    assets = _assets(context, list(dict.fromkeys([*_model_keys(data.model), *(item for item in chosen[:10] if isinstance(item, str))])))
    try:
        current = tm.validate(data.model, known_assets=set(assets))
        repositories = _read_repositories(context, assets, data.repositories)
        if not isinstance(repositories, list):
            raise ApiError(400, repositories)
        proposal = tm.validate(tm.suggest(current["name"], repositories, locale=context.locale), known_assets=set(assets))
        merged, added = tm.merge_proposal(current, proposal)
        merged = tm.validate({**merged, "repositories": [*current.get("repositories", []), *data.repositories]}, known_assets=set(assets))
    except tm.ModelError as exc:
        raise ApiError(400, exc.message) from exc
    return context.render({"model": merged, "added": added})


@router.post("/api/threat-models/decide", openapi_extra=documented(DecisionIn), response_model=ThreatModelView, **AS_RETURNED)
def decide(context: Context = Depends(guard(Policy(action="threat-decision", body=1024))),
           data: DecisionIn = Depends(body(DecisionIn, msg("api.invalid_request")))) -> Any:
    try:
        model = tm.decide(context.data_dir, data.id, data.threat, data.status, data.reason, by=context.user["username"])
    except tm.ModelError as exc:
        raise ApiError(400, exc.message) from exc
    return context.render(_view(context, model))


@router.post("/api/threat-models/delete", openapi_extra=documented(ModelIdIn), response_model=Deleted, **AS_RETURNED)
def remove(context: Context = Depends(guard(Policy(admin=True, action="delete-threat-model", body=128))),
           data: ModelIdIn = Depends(body(ModelIdIn, msg("api.invalid_request")))) -> Any:
    try:
        tm.delete(context.data_dir, data.id)
    except tm.ModelError as exc:
        raise ApiError(404, exc.message) from exc
    context.state.log.info("threat_model_deleted", extra={"user": context.user["username"], "reason": data.id})
    return {"deleted": True}
