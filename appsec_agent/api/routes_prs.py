"""Revisión de pull requests: qué repositorios se vigilan, sus PRs abiertos y revisar uno ahora."""

from __future__ import annotations

import re

from .. import pr_watch
from ..github_app import GitHubAppError, installation_repositories, open_pull_requests, pull_request
from ..integrations import github_installations
from ..store import list_runs
from .core import Request, route


def _repository(request: Request, source_id) -> tuple[int, str, str] | None:
    """Solo repositorios que la instalación cubre. Devuelve instalación, nombre e identidad estable."""
    if not isinstance(source_id, str) or not re.fullmatch(r"github:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", source_id):
        return None
    for installation in github_installations(request.data_dir):
        try:
            entry = next((item for item in installation_repositories(installation) if item["id"] == source_id), None)
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
    settings = pr_watch.settings(request.data_dir, uid)
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


def _installed(request: Request) -> list[dict] | None:
    installations = github_installations(request.data_dir)
    if not installations:
        return None
    repositories = []
    for installation in installations:
        try:
            repositories.extend({**item, "installation_id": installation} for item in installation_repositories(installation))
        except GitHubAppError:
            continue
    return repositories


@route("GET", "/api/pull-requests/watch")
def watch_overview(request: Request):
    """Todos los repositorios de la instalación con su configuración de vigilancia."""
    target = _installed(request)
    if target is None:
        return request.json(400, {"error": "Conecta la GitHub App para vigilar pull requests"})
    pr_watch.migrate(request.data_dir, target)
    reviewed = pr_watch.load(request.data_dir)["reviewed"]
    rows = [{"id": item["id"], "uid": item["uid"], "name": item["name"], "private": item.get("private"),
             **pr_watch.settings(request.data_dir, item["uid"]), "reviewed": len(reviewed.get(item["uid"], {}))}
            for item in target]
    return request.json(200, {"repositories": rows, "interval": pr_watch.interval(),
                              "enabled": sum(1 for row in rows if row["enabled"])})


@route("POST", "/api/pull-requests/settings", admin=True, action="pr-settings", body=16_000)
def pr_settings(request: Request):
    """Configura uno o varios repositorios a la vez (`source_id` o `source_ids`)."""
    payload = request.payload
    fields = {"source_id", "source_ids", "enabled", "post_comment", "gate"}
    if (not isinstance(payload, dict) or not set(payload) <= fields or ("source_id" in payload) == ("source_ids" in payload)
            or any(key in payload and not isinstance(payload[key], bool) for key in ("enabled", "post_comment"))):
        return request.json(400, {"error": "Configuración inválida"})
    chosen = [payload["source_id"]] if "source_id" in payload else payload["source_ids"]
    if not isinstance(chosen, list) or not 1 <= len(chosen) <= 200 or not all(isinstance(item, str) for item in chosen):
        return request.json(400, {"error": "Indica entre 1 y 200 repositorios"})
    target = _installed(request)
    uid_of = {item["id"]: item["uid"] for item in target} if target else {}
    if not set(chosen) <= set(uid_of):
        return request.json(400, {"error": "Hay repositorios que no están en la GitHub App conectada"})
    try:
        results = [pr_watch.configure(request.data_dir, uid_of[item], enabled=payload.get("enabled"), post_comment=payload.get("post_comment"),
                                      gate=payload.get("gate"), by=request.user["username"]) for item in dict.fromkeys(chosen)]
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
