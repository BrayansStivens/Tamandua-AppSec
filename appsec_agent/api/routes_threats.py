"""Modelos de amenazas: crear (en blanco o propuesto desde los escaneos), editar, decidir y exportar."""

from __future__ import annotations

import json

from .. import threat_model as tm
from ..domains import list_domains
from ..github_app import GitHubAppError
from ..integrations import github_installation
from ..inventory import live as live_inventory
from ..repository_sources import SourceError, available_sources
from ..assets import asset_key
from ..store import list_runs, load_run
from .core import Request, route


def _assets(request: Request) -> dict[str, dict]:
    """Activos enlazables: todos los repositorios a los que hay acceso (escaneados o no) y los dominios."""
    assets: dict[str, dict] = {}
    with request.state.code_lock:
        tokens = request.state.code_tokens.copy()
    try:
        for source in available_sources(tokens, github_installation(request.data_dir))["sources"]:
            # Se enlaza por identidad estable: el modelo sobrevive a un renombrado del repositorio.
            key = source.get("uid") or source["id"]
            assets[key] = {"id": key, "source_id": source["id"], "name": source["name"], "kind": "repository", "last_run": None}
    except (SourceError, GitHubAppError):
        pass
    for row in list_runs(request.data_dir):
        source = row.get("source") or {}
        key = asset_key(row)
        if row["type"] == "repository_scan" and source.get("id"):
            entry = assets.setdefault(key, {"id": key, "source_id": source["id"], "name": source.get("name"), "kind": "repository", "last_run": None})
            if entry["last_run"] is None and row["status"] in ("completed", "incomplete"):
                entry["last_run"], entry["scanned_at"] = row["id"], row["created_at"]
    for domain in list_domains(request.data_dir):
        assets[f"domain:{domain['id']}"] = {"id": f"domain:{domain['id']}", "name": domain["host"], "kind": "domain"}
    return assets


def _view(request: Request, model: dict) -> dict:
    linked = {item["asset"] for item in model.get("components", []) if item.get("asset")}
    rows = tm.threats(model, tm.evidence_index(request.data_dir, linked))
    return {"model": model, "threats": rows, "summary": tm.summary(rows)}


@route("GET", "/api/threat-models")
def models(request: Request):
    return request.json(200, {"models": tm.list_models(request.data_dir), "assets": list(_assets(request).values()),
                              "kinds": tm.KINDS, "protocols": tm.PROTOCOLS, "classifications": tm.CLASSIFICATION_LABELS})


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
    return request.json(404, {"error": "Ruta no encontrada"})


@route("POST", "/api/threat-models", action="save-threat-model", body=200_000)
def save_model(request: Request):
    payload = request.payload
    if not isinstance(payload, dict) or not set(payload) <= {"id", "model", "suggest", "name"}:
        return request.json(400, {"error": "Solicitud inválida"})
    assets = _assets(request)
    try:
        if "suggest" in payload:
            # Modelo nuevo propuesto desde el inventario del último escaneo de cada repositorio elegido.
            chosen = payload["suggest"]
            if (not isinstance(chosen, list) or not 1 <= len(chosen) <= 10
                    or any(not isinstance(item, str) or assets.get(item, {}).get("kind") != "repository" for item in chosen)):
                return request.json(400, {"error": "Elige entre 1 y 10 repositorios"})
            repositories = []
            installation = github_installation(request.data_dir)
            for item in chosen:
                # El inventario se lee en el momento: no depende de si hay escaneo ni de lo antiguo que sea.
                try:
                    inventory = live_inventory(assets[item].get("source_id") or item, installation_id=installation)
                except (GitHubAppError, SourceError, OSError) as exc:
                    return request.json(400, {"error": f"No se pudieron leer los manifiestos de {assets[item]['name']}: {exc}"})
                record = load_run(request.data_dir, assets[item]["last_run"]) if assets[item]["last_run"] else {}
                repositories.append({"id": item, "name": assets[item]["name"],
                                     "inventory": inventory or record.get("inventory"), "findings": record.get("findings", [])})
            draft = tm.suggest(tm._text(payload.get("name"), 80, "El nombre", required=True), repositories)
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
