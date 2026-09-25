"""Modelos de amenazas: crear (en blanco o propuesto desde los escaneos), editar, decidir y exportar."""

from __future__ import annotations

import json

from .. import threat_model as tm, threat_report
from ..domains import list_domains
from ..github_app import GitHubAppError
from ..integrations import github_installations
from ..inventory import live as live_inventory
from ..repository_sources import SourceError, find_source
from ..assets import asset_key
from ..store import list_runs, load_run
from .core import VERSION, Request, route


def _model_keys(model) -> list[str]:
    """Activos que un modelo (o un borrador sin validar) referencia: sus repositorios y los de sus componentes."""
    if not isinstance(model, dict):
        return []
    repositories = model.get("repositories") if isinstance(model.get("repositories"), list) else []
    components = model.get("components") if isinstance(model.get("components"), list) else []
    keys = [*repositories, *(item.get("asset") for item in components if isinstance(item, dict))]
    return list(dict.fromkeys(key for key in keys if isinstance(key, str) and key and not key.startswith("domain:")))[:120]


def _assets(request: Request, keys: list[str] = ()) -> dict[str, dict]:
    """Activos enlazables: repositorios analizados, dominios y los repositorios pedidos en `keys`.

    Los pedidos se comprueban uno a uno contra su credencial: no se lista la organización entera
    para validar un modelo que usa tres repositorios."""
    assets: dict[str, dict] = {}
    for row in list_runs(request.data_dir):
        source = row.get("source") or {}
        key = asset_key(row)
        if row["type"] == "repository_scan" and source.get("id"):
            entry = assets.setdefault(key, {"id": key, "source_id": source["id"], "name": source.get("name"), "kind": "repository", "last_run": None})
            if entry["last_run"] is None and row["status"] in ("completed", "incomplete"):
                entry["last_run"], entry["scanned_at"] = row["id"], row["created_at"]
    for domain in list_domains(request.data_dir):
        assets[f"domain:{domain['id']}"] = {"id": f"domain:{domain['id']}", "name": domain["host"], "kind": "domain"}
    if keys:
        with request.state.code_lock:
            tokens = request.state.code_tokens.copy()
        installations = github_installations(request.data_dir)
        for key in keys:
            try:
                source = find_source(tokens, installations, key)
            except (SourceError, GitHubAppError):
                source = None
            # Se enlaza por identidad estable: el modelo sobrevive a un renombrado del repositorio.
            if source is None or key not in (source.get("uid"), source["id"]):
                continue
            entry = assets.setdefault(key, {"id": key, "kind": "repository", "last_run": None})
            entry.update(source_id=source["id"], name=source["name"], installation_id=source.get("installation_id"))
    return assets


def _view(request: Request, model: dict) -> dict:
    linked = {item["asset"] for item in model.get("components", []) if item.get("asset")}
    rows = tm.threats(model, tm.evidence_index(request.data_dir, linked))
    keys = _model_keys(model)
    assets = _assets(request, keys)
    return {"model": model, "threats": rows, "summary": tm.summary(rows),
            "assets": [assets[key] for key in keys if key in assets]}


@route("GET", "/api/threat-models")
def models(request: Request):
    return request.json(200, {"models": tm.list_models(request.data_dir), "assets": list(_assets(request).values()),
                              "kinds": tm.KINDS, "protocols": tm.PROTOCOLS, "classifications": tm.CLASSIFICATION_LABELS,
                              "methods": tm.threat_methods.catalog()})


@route("GET", "/api/threat-models/", prefix=True)
def model_detail(request: Request):
    model_id, _, artifact = request.path.removeprefix("/api/threat-models/").partition("/")
    try:
        view = _view(request, tm.load(request.data_dir, model_id))
    except tm.ModelError as exc:
        return request.json(404, {"error": str(exc)})
    if not artifact:
        return request.json(200, view)
    if artifact == "threat-dragon.json":
        return request.send(200, json.dumps(tm.to_threat_dragon(view["model"], view["threats"]), ensure_ascii=False, indent=2).encode("utf-8"),
                            "application/json; charset=utf-8")
    if artifact == "tm.py":
        return request.send(200, tm.to_pytm(view["model"]).encode("utf-8"), "text/x-python; charset=utf-8")
    if artifact == "report.md":
        return request.send(200, tm.to_markdown(view["model"], view["threats"]).encode("utf-8"), "text/markdown; charset=utf-8")
    if artifact == "report.pdf":
        return request.send(200, threat_report.render_pdf({**view["model"], "id": model_id}, view["threats"], version=VERSION),
                            "application/pdf")
    if artifact == "diagram.svg":
        return request.send(200, tm.to_svg(view["model"]).encode("utf-8"), "image/svg+xml; charset=utf-8")
    if artifact == "model.json":
        document = tm.to_portable(view["model"], _assets(request, _model_keys(view["model"])))
        return request.send(200, json.dumps(document, ensure_ascii=False, indent=2).encode("utf-8"),
                            "application/json; charset=utf-8")
    return request.json(404, {"error": "Ruta no encontrada"})


@route("POST", "/api/threat-models", action="save-threat-model", body=600_000)
def save_model(request: Request):
    payload = request.payload
    if not isinstance(payload, dict) or not set(payload) <= {"id", "model", "suggest", "name", "methodology", "custom_modules"}:
        return request.json(400, {"error": "Solicitud inválida"})
    suggested = payload.get("suggest") if isinstance(payload.get("suggest"), list) else []
    assets = _assets(request, list(dict.fromkeys([*_model_keys(payload.get("model")),
                                                  *(item for item in suggested[:10] if isinstance(item, str))])))
    try:
        if "suggest" in payload:
            # Modelo nuevo propuesto desde el inventario del último escaneo de cada repositorio elegido.
            chosen = payload["suggest"]
            repositories = _read_repositories(request, assets, chosen)
            if isinstance(repositories, str):
                return request.json(400, {"error": repositories})
            draft = tm.suggest(tm._text(payload.get("name"), 80, "El nombre", required=True), repositories)
            draft["methodology"] = payload.get("methodology") or "stride"
            draft["custom_modules"] = payload.get("custom_modules", ["manual", "elements"])
            draft["repositories"] = chosen
            model = tm.validate(draft, known_assets=set(assets))
            return request.json(200, _view(request, tm.save(request.data_dir, model, by=request.user["username"])))
        model = tm.validate(payload.get("model"), known_assets=set(assets))
        model_id = payload.get("id")
        stored = tm.save(request.data_dir, model, by=request.user["username"], model_id=model_id if isinstance(model_id, str) else None)
        return request.json(200, _view(request, stored))
    except tm.ModelError as exc:
        return request.json(400, {"error": str(exc)})
    except (OSError, ValueError):
        return request.json(400, {"error": "No se pudo guardar el modelo"})


@route("POST", "/api/threat-models/import", action="import-threat-model", body=600_000)
def import_model(request: Request):
    try:
        model = tm.from_portable(request.payload)
        model.pop("relayout", None)
        return request.json(200, _view(request, tm.save(request.data_dir, model, by=request.user["username"])))
    except tm.ModelError as exc:
        return request.json(400, {"error": str(exc)})
    except (OSError, ValueError):
        return request.json(400, {"error": "No se pudo importar el modelo"})


@route("POST", "/api/threat-models/validate", action="validate-threat-model", body=600_000)
def validate_import(request: Request):
    """Comprueba el formato portátil sin crear ni modificar un modelo."""
    try:
        model = tm.from_portable(request.payload)
    except tm.ModelError as exc:
        return request.json(400, {"error": str(exc)})
    return request.json(200, {
        "name": model["name"], "methodology": model["methodology"],
        "components": len(model["components"]), "flows": len(model["flows"]),
        "boundaries": len(model["boundaries"]),
        "repository_refs": len(model["repository_refs"]),
        "manual_threats": len(model["manual_threats"]),
        "attack_trees": len(model["attack_trees"]),
        "attack_mappings": len(model["attack_mappings"]),
        "pasta_stages": len(model["pasta"]),
        "relayout": bool(model.get("relayout")),
    })


def _read_repositories(request: Request, assets: dict, chosen) -> list[dict] | str:
    """Manifiestos de los repositorios elegidos, leídos en el momento. Devuelve el error como texto."""
    if (not isinstance(chosen, list) or not 1 <= len(chosen) <= 10
            or any(not isinstance(item, str) or assets.get(item, {}).get("kind") != "repository" for item in chosen)):
        return "Elige entre 1 y 10 repositorios"
    repositories = []
    for item in chosen:
        # El inventario se lee en el momento: no depende de si hay escaneo ni de lo antiguo que sea.
        try:
            inventory = live_inventory(assets[item].get("source_id") or item,
                                       installation_id=assets[item].get("installation_id"))
        except (GitHubAppError, SourceError, OSError) as exc:
            return f"No se pudieron leer los manifiestos de {assets[item]['name']}: {exc}"
        record = load_run(request.data_dir, assets[item]["last_run"]) if assets[item]["last_run"] else {}
        repositories.append({"id": item, "name": assets[item]["name"],
                             "inventory": inventory or record.get("inventory"), "findings": record.get("findings", [])})
    return repositories


@route("POST", "/api/threat-models/propose", action="propose-components", body=600_000)
def propose(request: Request):
    """Componentes propuestos desde repositorios, fusionados en el borrador que se está editando. No guarda nada."""
    payload = request.payload
    if not isinstance(payload, dict) or set(payload) != {"model", "repositories"}:
        return request.json(400, {"error": "Solicitud inválida"})
    chosen = payload["repositories"] if isinstance(payload["repositories"], list) else []
    assets = _assets(request, list(dict.fromkeys([*_model_keys(payload["model"]),
                                                  *(item for item in chosen[:10] if isinstance(item, str))])))
    try:
        current = tm.validate(payload["model"], known_assets=set(assets))
        repositories = _read_repositories(request, assets, payload["repositories"])
        if isinstance(repositories, str):
            return request.json(400, {"error": repositories})
        proposal = tm.validate(tm.suggest(current["name"], repositories), known_assets=set(assets))
        merged, added = tm.merge_proposal(current, proposal)
        merged = tm.validate({**merged, "repositories": [*current.get("repositories", []), *payload["repositories"]]}, known_assets=set(assets))
    except tm.ModelError as exc:
        return request.json(400, {"error": str(exc)})
    return request.json(200, {"model": merged, "added": added})


@route("POST", "/api/threat-models/decide", action="threat-decision", body=1024)
def decide(request: Request):
    payload = request.payload
    if not isinstance(payload, dict) or not {"id", "threat", "status"} <= set(payload) or not set(payload) <= {"id", "threat", "status", "reason"}:
        return request.json(400, {"error": "Solicitud inválida"})
    try:
        model = tm.decide(request.data_dir, payload["id"], payload["threat"], payload["status"], payload.get("reason"),
                          by=request.user["username"])
    except tm.ModelError as exc:
        return request.json(400, {"error": str(exc)})
    return request.json(200, _view(request, model))


@route("POST", "/api/threat-models/delete", admin=True, action="delete-threat-model", body=128)
def remove(request: Request):
    payload = request.payload
    if not isinstance(payload, dict) or set(payload) != {"id"}:
        return request.json(400, {"error": "Solicitud inválida"})
    try:
        tm.delete(request.data_dir, payload["id"])
    except tm.ModelError as exc:
        return request.json(404, {"error": str(exc)})
    request.log.info("threat_model_deleted", extra={"user": request.user["username"], "reason": payload["id"]})
    return request.json(200, {"deleted": True})
