"""Fuentes de código (GitHub App y tokens), dominios y claves de IA del usuario."""

from __future__ import annotations

import html
import json

from tamandua.modules.runs.kinds import FINDING_RUNS
from tamandua.modules.integrations import jira
from tamandua.shared import log as logging_setup
from tamandua.modules.findings import triage
from tamandua.modules.sources.domains import DomainError, check_reachability, list_domains, register_domain, verify_domain
from tamandua.modules.integrations.github import REQUIRED_PERMISSIONS, GitHubAppError, app_installations, app_permissions, config as github_config, forget as forget_installation
from tamandua.modules.integrations.github import forget_app, forget_catalog, install_url, installation_details, permission_review, save_credentials, verify_app
from tamandua.modules.integrations.installations import clear_github, github_connections, github_installations, save_github
from tamandua.modules.integrations.ai_providers import ProviderError, check_provider, forget_provider_key, provider_status, save_provider_key
from tamandua.modules.sources.repositories import SourceError, find_source, list_repositories, source_page
from tamandua.modules.sources.assets import with_scan_branches
from tamandua.modules.runs.store import render_tickets
from tamandua.app.api.routing import Request, problem, route
from tamandua.app.api.security import public_url
from tamandua.shared.i18n import default_locale, msg, t, text



# ------------------------------------------------------------------ código

def paging(request: Request, default: int = 25) -> tuple[int, int] | None:
    """`page` (desde 1) y `per_page` (1-100) de la URL; None si no son válidos."""
    try:
        page, per_page = int(request.arg("page", "1")), int(request.arg("per_page", str(default)))
    except ValueError:
        return None
    return (page, per_page) if 1 <= per_page <= 100 and 1 <= page and page * per_page <= 10_000 else None


@route("GET", "/api/sources")
def sources(request: Request):
    """Una página de repositorios (`q`, `account`, `provider`, `page`, `per_page`) o uno concreto (`id`)."""
    with request.state.code_lock:
        tokens = request.state.code_tokens.copy()
    installations = github_installations(request.data_dir)
    if request.arg("id") is not None:
        found = find_source(tokens, installations, request.arg("id") or "")
        return request.json(200, {"sources": with_scan_branches(request.data_dir, [found] if found else []), "total": 1 if found else 0})
    paged = paging(request)
    query, account, provider = request.arg("q", ""), request.arg("account"), request.arg("provider")
    if paged is None or len(query) > 100 or (account is not None and len(account) > 100) or provider not in (None, "github", "gitlab", "local"):
        return request.json(400, {"error": msg("api.invalid_search")})
    if request.arg("refresh") == "1":
        for installation in installations:
            forget_catalog(installation)
    listing = source_page(tokens, installations, query=query, account=account or None, provider=provider, page=paged[0], per_page=paged[1])
    return request.json(200, {**listing, "sources": with_scan_branches(request.data_dir, listing["sources"])})


@route("POST", "/api/integrations/code", admin=True, action="connect-code", body=1024)
def connect_code(request: Request):
    payload, state = request.payload, request.state
    if (not isinstance(payload, dict) or set(payload) not in ({"provider", "token"}, {"provider", "disconnect"})
            or payload.get("provider") not in ("github", "gitlab")):
        return request.json(400, {"error": msg("integrations.code.invalid_provider")})
    provider = payload["provider"]
    if "disconnect" in payload:
        if payload["disconnect"] is not True:
            return request.json(400, {"error": msg("api.invalid_request")})
        with state.code_lock:
            state.code_tokens.pop(provider, None)
        return request.json(200, {"provider": provider, "connected": False})
    token = payload["token"]
    if (not isinstance(token, str) or not 8 <= len(token) <= 512
            or any(character.isspace() or ord(character) < 33 or ord(character) > 126 for character in token)):
        return request.json(400, {"error": msg("integrations.code.invalid_token")})
    try:
        repositories = list_repositories(provider, token)
    except SourceError:
        return request.json(400, {"error": msg("integrations.code.auth_failed")})
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
        return request.json(400, {"error": msg("sources.domains.invalid_request")})
    with domains.locked(request.data_dir):
        try:
            record = register_domain(request.data_dir, payload["url"], payload.get("kind", "web"), payload.get("context", ""))
        except DomainError as exc:
            return request.json(400, {"error": problem(exc)})
    return request.json(200, record)


@route("POST", "/api/domains/verify", action="verify-domain")
def verify(request: Request):
    payload = request.payload
    if not isinstance(payload, dict) or set(payload) != {"domain_id"} or not isinstance(payload["domain_id"], str):
        return request.json(400, {"error": msg("sources.domains.invalid_request")})
    with domains.locked(request.data_dir):
        try:
            record = verify_domain(request.data_dir, payload["domain_id"])
        except DomainError as exc:
            return request.json(400, {"error": problem(exc)})
    return request.json(200, record)


@route("POST", "/api/domains/check", action="check-domain", body=512)
def reachability(request: Request):
    payload = request.payload
    if not isinstance(payload, dict) or set(payload) != {"url"} or not isinstance(payload["url"], str):
        return request.json(400, {"error": msg("sources.domains.invalid_request")})
    try:
        return request.json(200, check_reachability(payload["url"]))
    except DomainError as exc:
        return request.json(400, {"error": problem(exc)})


# ---------------------------------------------------------------------- IA

@route("GET", "/api/providers")
def providers(request: Request):
    return request.json(200, provider_status())


@route("POST", "/api/providers/keys", admin=True, action="save-ai-key", body=768)
def provider_keys(request: Request):
    payload = request.payload
    if (not isinstance(payload, dict) or not {"provider", "action"} <= set(payload)
            or not set(payload) <= {"provider", "action", "api_key"} or payload["action"] not in ("save", "remove")):
        return request.json(400, {"error": msg("integrations.ai.invalid_request")})
    try:
        if payload["action"] == "remove":
            forget_provider_key(payload["provider"])
            return request.json(200, {"providers": provider_status()})
        result = save_provider_key(payload["provider"], payload.get("api_key", ""))
    except ProviderError as exc:
        return request.json(400, {"error": problem(exc)})
    except (ValueError, TypeError):
        return request.json(400, {"error": msg("integrations.ai.invalid_request")})
    except OSError:
        return request.json(500, {"error": msg("integrations.ai.save_failed")})
    return request.json(200, {"result": result, "providers": provider_status()})


@route("POST", "/api/providers/check", action="check-provider")
def provider_check(request: Request):
    payload = request.payload
    if not isinstance(payload, dict) or set(payload) != {"provider"}:
        return request.json(400, {"error": msg("integrations.code.invalid_provider")})
    try:
        return request.json(200, check_provider(payload["provider"]))
    except (ValueError, TypeError):
        return request.json(400, {"error": msg("integrations.code.invalid_provider")})


# -------------------------------------------------------------- GitHub App

def _landing(request: Request, title, detail):
    """Página mínima de vuelta: sin scripts, y vuelve al panel con un enlace."""
    locale = request.locale
    body = (f"<!doctype html><html lang={locale}><meta charset=utf-8><title>Tamandua</title>"
            "<style>body{font:15px system-ui,sans-serif;background:#0a0a0a;color:#eee;max-width:560px;margin:15vh auto;padding:0 20px}"
            "a{color:#fff}</style>"
            f"<h1>{html.escape(text(title, locale))}</h1><p>{html.escape(text(detail, locale))}</p>"
            f"<p><a href=\"{html.escape(public_url(request.port))}/#/integraciones\">{html.escape(t('integrations.github.landing.back', locale))}</a></p>")
    return request.send(200, body.encode("utf-8"), "text/html; charset=utf-8",
                        csp="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")


def github_status(request: Request, *, live: bool = False) -> dict:
    state = github_config()
    records = github_connections(request.data_dir)
    status = {**state, "connected": bool(records), "installation": records[0] if records else None,
              "installations": records,
              "public_url": public_url(request.port), "required_permissions": REQUIRED_PERMISSIONS}
    if live and state["configured"]:
        # Los permisos cambian en GitHub sin avisar: se leen de allí, no de lo guardado al conectar.
        try:
            declared = app_permissions()
            current = []
            for record in records:
                try:
                    granted = installation_details(record["installation_id"]).get("permissions", {})
                    current.append({**record, "permissions": granted, "permission_review": permission_review(declared, granted)})
                except GitHubAppError:
                    current.append(record)
            status["installations"] = current
            status["installation"] = current[0] if current else None
            reviews = [row["permission_review"] for row in current if row.get("permission_review")]
            if reviews:
                summary = dict(reviews[0])
                for field in ("excess", "missing", "pending_acceptance"):
                    summary[field] = sorted({name for review in reviews for name in review[field]})
                status["permissions"] = summary
            else:
                status["permissions"] = permission_review(declared, declared)
        except GitHubAppError:
            status["permissions"] = None
    return status


def _attach(request: Request, installation_id: int) -> dict | None:
    """Guarda la instalación de NUESTRA App: el id se contrasta con GitHub, no se cree tal cual."""
    rows = app_installations()
    chosen = next((row for row in rows if row["installation_id"] == installation_id), None)
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
        return request.json(400, {"error": msg("api.invalid_request")})
    if github_config()["source"] == "environment":
        return request.json(409, {"error": msg("integrations.github.env_managed_change")})
    previous_app = github_config().get("app_id")
    try:
        verified = verify_app(payload["app_id"], payload["private_key"])
    except GitHubAppError as exc:
        return request.json(400, {"error": problem(exc)})
    save_credentials(verified)
    if previous_app != verified["app_id"]:
        clear_github(request.data_dir)
    logging_setup.get("github").info("github_app_saved", extra={"user": request.user["username"], "reason": f"{verified['owner']}/{verified['slug']}"})
    return request.json(200, {**github_status(request, live=True), "events": verified["events"]})


@route("POST", "/api/integrations/github", admin=True, action="connect-github", body=256)
def github_action(request: Request):
    payload = request.payload
    if (not isinstance(payload, dict) or not set(payload) <= {"action", "installation_id"}
            or payload.get("action") not in ("install", "detect", "connect", "disconnect", "forget_app")
            or ("installation_id" in payload and (payload["action"] not in ("disconnect", "connect")
                                                 or not isinstance(payload["installation_id"], int)
                                                 or isinstance(payload["installation_id"], bool) or payload["installation_id"] <= 0))
            or (payload.get("action") == "connect" and "installation_id" not in payload)):
        return request.json(400, {"error": msg("integrations.github.invalid_action")})
    action = payload["action"]
    if action in ("disconnect", "forget_app"):
        if action == "forget_app":
            if github_config()["source"] == "environment":
                return request.json(409, {"error": msg("integrations.github.env_managed_remove")})
        installation_id = payload.get("installation_id")
        if installation_id is not None and installation_id not in github_installations(request.data_dir):
            return request.json(404, {"error": msg("integrations.github.not_connected")})
        to_forget = [installation_id] if installation_id is not None else github_installations(request.data_dir)
        clear_github(request.data_dir, installation_id)
        for current in to_forget:
            forget_installation(current)
        if action == "forget_app":
            forget_app()
        return request.json(200, github_status(request))
    try:
        if action == "install":
            return request.json(200, {"url": install_url()})
        if action == "connect":
            if _attach(request, payload["installation_id"]) is None:
                return request.json(404, {"error": msg("integrations.github.foreign_installation")})
            return request.json(200, github_status(request, live=True))
        rows = app_installations()
        if not rows:
            return request.json(404, {"error": msg("integrations.github.not_installed")})
        connected = set(github_installations(request.data_dir))
        status = github_status(request, live=True)
        status["available_installations"] = [{**row, "connected": row["installation_id"] in connected} for row in rows]
        return request.json(200, status)
    except GitHubAppError as exc:
        return request.json(400, {"error": problem(exc)})


# Vuelta opcional tras instalar (Setup URL de la App). La cookie SameSite=Strict no viaja
# desde github.com: no se conecta nada aquí; el administrador elige la cuenta en el panel.
@route("GET", "/oauth/callback", public=True)
def github_callback(request: Request):
    raw = request.arg("installation_id", "") or ""
    if not raw.isdigit() or len(raw) > 19:
        return _landing(request, msg("integrations.github.landing.no_installation"), msg("integrations.github.landing.no_installation_detail"))
    # Pública y con llamada a GitHub detrás: con límite, para que no sirva para agotar la cuota de la App.
    scope = f"oauth-callback:{request.client}"
    if request.auth.throttle.reserve(scope):
        return _landing(request, msg("integrations.github.landing.too_many"), msg("integrations.github.landing.too_many_detail"))
    try:
        if not any(row["installation_id"] == int(raw) for row in app_installations()):
            return _landing(request, msg("integrations.github.landing.unknown"), msg("integrations.github.landing.unknown_detail"))
    except (GitHubAppError, ValueError) as exc:
        return _landing(request, msg("integrations.github.landing.failed"), problem(exc))
    request.auth.throttle.succeeded(scope)
    return _landing(request, msg("integrations.github.landing.available"), msg("integrations.github.landing.available_detail"))


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
        return request.json(400, {"error": msg("integrations.jira.invalid_request")})
    try:
        return request.json(200, jira.configure(payload["site"], payload["email"], payload["token"], payload["project"],
                                                payload.get("issue_type", "Task"), by=request.user["username"]))
    except jira.JiraError as exc:
        return request.json(400, {"error": problem(exc)})
    except OSError:
        return request.json(500, {"error": msg("api.save_settings_failed")})


@route("POST", "/api/integrations/jira/issues", action="export-jira", body=6000)
def jira_export(request: Request):
    payload = request.payload
    if (not isinstance(payload, dict) or set(payload) != {"run_id", "fingerprints"} or not isinstance(payload["run_id"], str)):
        return request.json(400, {"error": msg("integrations.jira.invalid_export")})
    try:
        from tamandua.modules.findings.registry import resolve
        record = resolve(request.data_dir, payload["run_id"])
        record = record if record.get("type") == "asset_state" else triage.annotate(request.data_dir, record)
    except (ValueError, OSError, json.JSONDecodeError):
        return request.json(404, {"error": msg("api.run_not_found")})
    if record.get("type") not in (*FINDING_RUNS, "asset_state"):
        return request.json(400, {"error": msg("integrations.jira.code_only")})
    try:
        # Issues are read by the whole team: TAMANDUA_DEFAULT_LOCALE, not the requester's language.
        return request.json(200, jira.export(request.data_dir, record, render_tickets(record, locale=default_locale()), payload["fingerprints"],
                                             by=request.user["username"]))
    except jira.JiraError as exc:
        return request.json(400, {"error": problem(exc)})
