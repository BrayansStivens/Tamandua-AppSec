"""Revisión de pull requests: qué repositorios se vigilan, sus PRs abiertos y revisar uno ahora."""

from __future__ import annotations

import re

from tamandua.modules.pullrequests import watch as pr_watch
from tamandua.modules.integrations.github import GitHubAppError, installation_repositories, installation_repository, open_pull_requests, pull_request
from tamandua.modules.sources.repositories import source_page
from tamandua.modules.integrations.installations import github_installations
from tamandua.modules.runs.store import list_runs
from tamandua.app.api.routing import Request, route
from tamandua.app.api.routes.sources import paging


def _repository(request: Request, source_id) -> tuple[int, str, str] | None:
    """Solo repositorios que la instalación cubre. Devuelve instalación, nombre e identidad estable."""
    if not isinstance(source_id, str) or not re.fullmatch(r"github:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", source_id):
        return None
    for installation in github_installations(request.data_dir):
        try:
            entry = installation_repository(installation, source_id)
        except GitHubAppError:
            continue
        if entry:
            return installation, entry["name"], entry["uid"]
    return None


@route("GET", "/api/pull-requests")
def pulls(request: Request):
    source_id = request.arg("source_id")
    target = _repository(request, source_id)
    if target is None:
        return request.json(400, {"error": "Elige un repositorio de la GitHub App conectada"})
    installation, repository, uid = target
    settings = {**pr_watch.settings(request.data_dir, uid), "branch_scan": pr_watch.branch_state(request.data_dir, uid),
                "branch_min_minutes": pr_watch.branch_min_seconds() // 60}
    try:
        rows = open_pull_requests(installation, repository)
    except GitHubAppError as exc:
        # La configuración se puede dejar lista aunque GitHub aún no deje leer los PRs.
        return request.json(200, {"settings": settings, "pulls": [], "pulls_error": str(exc)})
    done = pr_watch.reviewed(request.data_dir, uid)
    runs = {row["id"]: row for row in list_runs(request.data_dir) if row["type"] == "pr_review"}
    for row in rows:
        entry = done.get(str(row["number"]))
        run = runs.get(entry["run_id"]) if entry else None
        row["review"] = None if run is None else {
            "run_id": run["id"], "status": run["status"], "head_sha": entry["head_sha"], "created_at": run["created_at"],
            "current": entry["head_sha"] == row["head_sha"], "new": (run.get("summary") or {}).get("candidates", 0),
            "severities": (run.get("summary") or {}).get("severities", {})}
    return request.json(200, {"settings": settings, "pulls": rows})


def _row(item: dict, state: dict) -> dict:
    return {"id": item["id"], "uid": item["uid"], "name": item["name"], "private": item.get("private"),
            **pr_watch.DEFAULTS, **state["repositories"].get(item["uid"], {}), "reviewed": len(state["reviewed"].get(item["uid"], {})),
            "branch_scan": state["branches"].get(item["uid"])}


@route("GET", "/api/pull-requests/watch")
def watch_overview(request: Request):
    """Una página de repositorios de la instalación con su vigilancia (`q`, `page`, `per_page`, `only=enabled`)."""
    installations = github_installations(request.data_dir)
    if not installations:
        return request.json(400, {"error": "Conecta la GitHub App para vigilar pull requests"})
    paged = paging(request)
    query, only = request.arg("q", ""), request.arg("only")
    if paged is None or len(query) > 100 or only not in (None, "enabled"):
        return request.json(400, {"error": "Parámetros de búsqueda inválidos"})
    page, per_page = paged
    state = pr_watch.load(request.data_dir)
    enabled = sorted(key for key, value in state["repositories"].items() if value.get("enabled"))
    partial = False
    if only == "enabled":
        # Los vigilados salen de la configuración guardada. Sus nombres se toman de la lista completa
        # (en caché y la que mantiene fresca el vigilante): resolverlos uno a uno costaría una o dos
        # llamadas a GitHub por repositorio y un miembro podría agotar el límite de la instalación.
        wanted, items = set(enabled), []
        for installation in installations if wanted else []:
            try:
                items.extend({**row, "installation_id": installation} for row in installation_repositories(installation) if row["uid"] in wanted)
            except GitHubAppError:
                continue
        items = [item for item in items if query.strip().casefold() in item["name"].casefold()]
        total, items = len(items), items[(page - 1) * per_page:page * per_page]
    else:
        listing = source_page(None, installations, query=query, provider="github", page=page, per_page=per_page)
        items, total, partial = listing["sources"], listing["total"], listing["partial"]
        pr_watch.migrate(request.data_dir, items)
        state = pr_watch.load(request.data_dir)
    return request.json(200, {"repositories": [_row(item, state) for item in items], "total": total, "page": page,
                              "per_page": per_page, "partial": partial, "interval": pr_watch.interval(), "enabled": len(enabled),
                              "branch_min_minutes": pr_watch.branch_min_seconds() // 60})


@route("POST", "/api/pull-requests/settings", admin=True, action="pr-settings", body=16_000)
def pr_settings(request: Request):
    """Configura uno o varios repositorios (`source_id` o `source_ids`), o todos (`all`)."""
    payload = request.payload
    fields = {"source_id", "source_ids", "all", "enabled", "post_comment", "gate", "branch"}
    if (not isinstance(payload, dict) or not set(payload) <= fields
            or sum(key in payload for key in ("source_id", "source_ids", "all")) != 1
            or any(key in payload and not isinstance(payload[key], bool) for key in ("all", "enabled", "post_comment", "branch"))):
        return request.json(400, {"error": "Configuración inválida"})
    options = {"enabled": payload.get("enabled"), "post_comment": payload.get("post_comment"), "gate": payload.get("gate"),
               "branch": payload.get("branch"), "by": request.user["username"]}
    if "all" in payload:
        if payload["all"] is not True or set(payload) - {"all", "enabled"} or not isinstance(payload.get("enabled"), bool):
            return request.json(400, {"error": "Configuración inválida"})
        if payload["enabled"]:
            # Activar todos sí necesita la lista completa; es una acción puntual de administración.
            keys = []
            for installation in github_installations(request.data_dir):
                try:
                    keys.extend(item["uid"] for item in installation_repositories(installation))
                except GitHubAppError as exc:
                    return request.json(502, {"error": str(exc)})
        else:
            keys = [key for key, value in pr_watch.load(request.data_dir)["repositories"].items() if value.get("enabled")]
        results = pr_watch.configure_many(request.data_dir, keys, **options) if keys else []
        return request.json(200, {"updated": len(results)})
    chosen = [payload["source_id"]] if "source_id" in payload else payload["source_ids"]
    if not isinstance(chosen, list) or not 1 <= len(chosen) <= 200 or not all(isinstance(item, str) for item in chosen):
        return request.json(400, {"error": "Indica entre 1 y 200 repositorios"})
    uid_of = {}
    for item in dict.fromkeys(chosen):
        # Cada selección se comprueba sola; las que la vista acaba de listar no cuestan otra llamada.
        target = _repository(request, item)
        if target is None:
            return request.json(400, {"error": "Hay repositorios que no están en la GitHub App conectada"})
        uid_of[item] = target[2]
    try:
        results = pr_watch.configure_many(request.data_dir, list(uid_of.values()), **options)
    except ValueError as exc:
        return request.json(400, {"error": str(exc)})
    return request.json(200, results[0] if "source_id" in payload else {"updated": len(results)})


@route("POST", "/api/pull-requests/review", action="review-pr", body=256)
def review_now(request: Request):
    payload = request.payload
    if (not isinstance(payload, dict) or set(payload) != {"source_id", "number"}
            or not isinstance(payload["number"], int) or isinstance(payload["number"], bool)):
        return request.json(400, {"error": "Pull request inválido"})
    target = _repository(request, payload["source_id"])
    if target is None:
        return request.json(400, {"error": "Repositorio no disponible en la GitHub App conectada"})
    installation, repository, uid = target
    try:
        pull = pull_request(installation, repository, payload["number"])
    except GitHubAppError as exc:
        return request.json(400, {"error": str(exc)})
    if not pull["head_sha"]:
        return request.json(400, {"error": "GitHub no devolvió el commit de cabeza del PR"})
    if request.state.jobs.pending() >= 20:
        return request.json(429, {"error": "Demasiados escaneos en cola"})
    queued = request.state.jobs.enqueue_pr_review(source_id=payload["source_id"], uid=uid, pull=pull, installation_id=installation,
                                                  requested_by=request.user["username"])
    return request.json(202, {"run": queued})
