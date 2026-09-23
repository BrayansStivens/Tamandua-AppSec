"""Fuentes de código (GitHub App y tokens), dominios y claves de IA del usuario."""

from __future__ import annotations

import html
import json

from ..kinds import FINDING_RUNS
from .. import jira, logging_setup, triage
from ..domains import DomainError, check_reachability, list_domains, register_domain, verify_domain
from ..github_app import REQUIRED_PERMISSIONS, GitHubAppError, app_installations, app_permissions, config as github_config, forget as forget_installation
from ..github_app import forget_app, install_url, installation_details, permission_review, save_credentials, verify_app
from ..integrations import clear_github, github_installation, load as load_integrations, save_github
from ..providers import ProviderError, check_provider, forget_provider_key, provider_status, save_provider_key
from ..repository_sources import SourceError, available_sources, list_repositories
from ..store import load_run, render_tickets
from .core import Request, public_url, route



# ------------------------------------------------------------------ código

@route("GET", "/api/sources")
def sources(request: Request):
    with request.state.code_lock:
        tokens = request.state.code_tokens.copy()
    return request.json(200, available_sources(tokens, github_installation(request.data_dir)))


@route("POST", "/api/integrations/code", admin=True, action="connect-code", body=1024)
def connect_code(request: Request):
    payload, state = request.payload, request.state
    if (not isinstance(payload, dict) or set(payload) not in ({"provider", "token"}, {"provider", "disconnect"})
            or payload.get("provider") not in ("github", "gitlab")):
        return request.json(400, {"error": "Proveedor inválido"})
    provider = payload["provider"]
    if "disconnect" in payload:
        if payload["disconnect"] is not True:
            return request.json(400, {"error": "Solicitud inválida"})
        with state.code_lock:
            state.code_tokens.pop(provider, None)
        return request.json(200, {"provider": provider, "connected": False})
    token = payload["token"]
    if (not isinstance(token, str) or not 8 <= len(token) <= 512
            or any(character.isspace() or ord(character) < 33 or ord(character) > 126 for character in token)):
        return request.json(400, {"error": "Token inválido"})
    try:
        repositories = list_repositories(provider, token)
    except SourceError:
        return request.json(400, {"error": "No se pudo autenticar con el proveedor; revisa el token y sus permisos"})
    with state.code_lock:
        state.code_tokens[provider] = token
    return request.json(200, {"provider": provider, "connected": True, "repositories": len(repositories)})


# ---------------------------------------------------------------- dominios

@route("GET", "/api/domains")
def domains(request: Request):
    return request.json(200, list_domains(request.data_dir))


@route("POST", "/api/domains", action="register-domain", body=1024)
def add_domain(request: Request):
    payload = request.payload
    if (not isinstance(payload, dict) or not set(payload) <= {"url", "kind", "context"}
            or not isinstance(payload.get("url"), str) or not isinstance(payload.get("kind", "web"), str)
            or not isinstance(payload.get("context", ""), str)):
        return request.json(400, {"error": "Solicitud de dominio inválida"})
    with request.state.domain_lock:
        try:
            record = register_domain(request.data_dir, payload["url"], payload.get("kind", "web"), payload.get("context", ""))
        except DomainError as exc:
            return request.json(400, {"error": str(exc)})
    return request.json(200, record)


@route("POST", "/api/domains/verify", action="verify-domain")
def verify(request: Request):
    payload = request.payload
    if not isinstance(payload, dict) or set(payload) != {"domain_id"} or not isinstance(payload["domain_id"], str):
        return request.json(400, {"error": "Solicitud de dominio inválida"})
    with request.state.domain_lock:
        try:
            record = verify_domain(request.data_dir, payload["domain_id"])
        except DomainError as exc:
            return request.json(400, {"error": str(exc)})
    return request.json(200, record)


@route("POST", "/api/domains/check", action="check-domain", body=512)
def reachability(request: Request):
    payload = request.payload
    if not isinstance(payload, dict) or set(payload) != {"url"} or not isinstance(payload["url"], str):
        return request.json(400, {"error": "Solicitud de dominio inválida"})
    try:
        return request.json(200, check_reachability(payload["url"]))
    except DomainError as exc:
        return request.json(400, {"error": str(exc)})


# ---------------------------------------------------------------------- IA

@route("GET", "/api/providers")
def providers(request: Request):
    return request.json(200, provider_status())


@route("POST", "/api/providers/keys", admin=True, action="save-ai-key", body=768)
def provider_keys(request: Request):
    payload = request.payload
    if (not isinstance(payload, dict) or not {"provider", "action"} <= set(payload)
            or not set(payload) <= {"provider", "action", "api_key"} or payload["action"] not in ("save", "remove")):
        return request.json(400, {"error": "Solicitud de credencial inválida"})
    try:
        if payload["action"] == "remove":
            forget_provider_key(payload["provider"])
            return request.json(200, {"providers": provider_status()})
        result = save_provider_key(payload["provider"], payload.get("api_key", ""))
    except ProviderError as exc:
        return request.json(400, {"error": str(exc)})
    except (ValueError, TypeError):
        return request.json(400, {"error": "Solicitud de credencial inválida"})
    except OSError:
        return request.json(500, {"error": "No se pudo guardar la credencial"})
    return request.json(200, {"result": result, "providers": provider_status()})


@route("POST", "/api/providers/check", action="check-provider")
def provider_check(request: Request):
    payload = request.payload
    if not isinstance(payload, dict) or set(payload) != {"provider"}:
        return request.json(400, {"error": "Proveedor inválido"})
    try:
        return request.json(200, check_provider(payload["provider"]))
    except (ValueError, TypeError):
        return request.json(400, {"error": "Proveedor inválido"})


# -------------------------------------------------------------- GitHub App

def _landing(request: Request, title: str, detail: str):
    """Página mínima de vuelta: sin scripts, y vuelve al panel con un enlace."""
    body = ("<!doctype html><meta charset=utf-8><title>Tamandua</title>"
            "<style>body{font:15px system-ui,sans-serif;background:#0a0a0a;color:#eee;max-width:560px;margin:15vh auto;padding:0 20px}"
            "a{color:#fff}</style>"
            f"<h1>{html.escape(title)}</h1><p>{html.escape(detail)}</p>"
            f"<p><a href=\"{html.escape(public_url(request.port))}/#/integraciones\">Volver al panel</a></p>")
    return request.send(200, body.encode("utf-8"), "text/html; charset=utf-8",
                        csp="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")


def github_status(request: Request, *, live: bool = False) -> dict:
    state = github_config()
    record = load_integrations(request.data_dir).get("github")
    status = {**state, "connected": isinstance(record, dict), "installation": record,
              "public_url": public_url(request.port), "required_permissions": REQUIRED_PERMISSIONS}
    if live and state["configured"]:
        # Los permisos cambian en GitHub sin avisar: se leen de allí, no de lo guardado al conectar.
        try:
            declared = app_permissions()
            granted = installation_details(record["installation_id"]).get("permissions", {}) if isinstance(record, dict) else declared
            if isinstance(record, dict):
                status["installation"] = {**record, "permissions": granted}
            status["permissions"] = permission_review(declared, granted)
        except GitHubAppError:
            status["permissions"] = None
    return status


def _attach(request: Request, installation_id: int | None = None) -> dict | None:
    """Guarda la instalación de NUESTRA App: el id se contrasta con GitHub, no se cree tal cual."""
    rows = app_installations()
    chosen = next((row for row in rows if installation_id is None or row["installation_id"] == installation_id), None)
    if chosen is None:
        return None
    details = installation_details(chosen["installation_id"])
    save_github(request.data_dir, chosen["installation_id"], details, (request.user or {}).get("username"))
    return chosen


@route("GET", "/api/integrations/github")
def github(request: Request):
    return request.json(200, github_status(request, live=True))


@route("POST", "/api/integrations/github/app", admin=True, action="save-github-app", body=20_000)
def github_app_credentials(request: Request):
    """App ID + clave privada pegados por un administrador: se verifican con GitHub y se guardan cifrados."""
    payload = request.payload
    if not isinstance(payload, dict) or set(payload) != {"app_id", "private_key"}:
        return request.json(400, {"error": "Solicitud inválida"})
    if github_config()["source"] == "entorno":
        return request.json(409, {"error": "La App viene de variables de entorno del servidor; cámbiala allí"})
    try:
        verified = verify_app(payload["app_id"], payload["private_key"])
    except GitHubAppError as exc:
        return request.json(400, {"error": str(exc)})
    save_credentials(verified)
    logging_setup.get("github").info("github_app_saved", extra={"user": request.user["username"], "reason": f"{verified['owner']}/{verified['slug']}"})
    # Si ya estaba instalada (p. ej. se reconfigura), se conecta sola.
    try:
        _attach(request)
    except GitHubAppError:
        pass
    return request.json(200, {**github_status(request, live=True), "events": verified["events"]})


@route("POST", "/api/integrations/github", admin=True, action="connect-github", body=256)
def github_action(request: Request):
    payload = request.payload
    if not isinstance(payload, dict) or set(payload) != {"action"} or payload["action"] not in ("install", "detect", "disconnect", "forget_app"):
        return request.json(400, {"error": "Acción de integración inválida"})
    action = payload["action"]
    if action in ("disconnect", "forget_app"):
        installation = github_installation(request.data_dir)
        clear_github(request.data_dir)
        if installation is not None:
            forget_installation(installation)
        if action == "forget_app":
            if github_config()["source"] == "entorno":
                return request.json(409, {"error": "La App viene de variables de entorno del servidor; quítala allí"})
            forget_app()
        return request.json(200, github_status(request))
    try:
        if action == "install":
            return request.json(200, {"url": install_url()})
        if _attach(request) is None:
            return request.json(404, {"error": "La App todavía no está instalada en ninguna cuenta. Pulsa Instalar en GitHub y elige los repositorios."})
    except GitHubAppError as exc:
        return request.json(400, {"error": str(exc)})
    return request.json(200, github_status(request, live=True))


# Vuelta opcional tras instalar (Setup URL de la App). Pública porque la cookie SameSite=Strict
# no viaja desde github.com; no hace falta `state`: el id se acepta solo si es de nuestra App.
@route("GET", "/oauth/callback", public=True)
def github_callback(request: Request):
    raw = request.arg("installation_id", "") or ""
    if not raw.isdigit() or len(raw) > 19:
        return _landing(request, "GitHub no devolvió una instalación", "Si cancelaste la instalación no hay nada que guardar.")
    # Pública y con llamada a GitHub detrás: con límite, para que no sirva para agotar la cuota de la App.
    scope = f"oauth-callback:{request.client}"
    if request.auth.throttle.reserve(scope):
        return _landing(request, "Demasiados intentos", "Espera unos minutos y vuelve a pulsar «Ya la instalé» en Integraciones.")
    try:
        if _attach(request, int(raw)) is None:
            return _landing(request, "Instalación desconocida", "Esa instalación no pertenece a la GitHub App configurada en este panel.")
    except (GitHubAppError, ValueError) as exc:
        return _landing(request, "La conexión con GitHub falló", str(exc))
    request.auth.throttle.succeeded(scope)
    return request.redirect(public_url(request.port) + "/#/integraciones")


# -------------------------------------------------------------------- Jira

@route("GET", "/api/integrations/jira")
def jira_status(request: Request):
    return request.json(200, jira.status())


@route("POST", "/api/integrations/jira", admin=True, action="connect-jira", body=1024)
def jira_configure(request: Request):
    payload = request.payload
    if isinstance(payload, dict) and payload == {"action": "remove"}:
        jira.forget()
        request.log.info("jira_removed", extra={"user": request.user["username"]})
        return request.json(200, jira.status())
    fields = {"action", "site", "email", "token", "project", "issue_type"}
    if not isinstance(payload, dict) or payload.get("action") != "save" or not set(payload) <= fields \
            or not {"site", "email", "token", "project"} <= set(payload):
        return request.json(400, {"error": "Solicitud de Jira inválida"})
    try:
        return request.json(200, jira.configure(payload["site"], payload["email"], payload["token"], payload["project"],
                                                payload.get("issue_type", "Task"), by=request.user["username"]))
    except jira.JiraError as exc:
        return request.json(400, {"error": str(exc)})
    except OSError:
        return request.json(500, {"error": "No se pudo guardar la configuración"})


@route("POST", "/api/integrations/jira/issues", action="export-jira", body=6000)
def jira_export(request: Request):
    payload = request.payload
    if (not isinstance(payload, dict) or set(payload) != {"run_id", "fingerprints"} or not isinstance(payload["run_id"], str)):
        return request.json(400, {"error": "Solicitud de exportación inválida"})
    try:
        from ..findings_registry import resolve
        record = resolve(request.data_dir, payload["run_id"])
        record = record if record.get("type") == "asset_state" else triage.annotate(request.data_dir, record)
    except (ValueError, OSError, json.JSONDecodeError):
        return request.json(404, {"error": "Ejecución no encontrada"})
    if record.get("type") not in (*FINDING_RUNS, "asset_state"):
        return request.json(400, {"error": "Solo las revisiones de código generan tickets"})
    try:
        return request.json(200, jira.export(request.data_dir, record, render_tickets(record), payload["fingerprints"],
                                             by=request.user["username"]))
    except jira.JiraError as exc:
        return request.json(400, {"error": str(exc)})
