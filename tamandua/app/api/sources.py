"""Code sources (GitHub App and tokens), domains, AI provider keys and Jira."""

from __future__ import annotations

import html
import json
from typing import Any, Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field, StrictInt, model_validator

from tamandua.app.api.deps import ApiError, Context, Policy, body, documented, guard
from tamandua.app.api.deps import problem
from tamandua.app.api.security import public_url
from tamandua.modules.findings import triage
from tamandua.modules.runs.registry import resolve
from tamandua.modules.findings import tickets
from tamandua.modules.integrations import jira
from tamandua.modules.integrations.ai_providers import ProviderError, check_provider, forget_provider_key, provider_status, save_provider_key
from tamandua.modules.integrations.github import (REQUIRED_PERMISSIONS, GitHubAppError, app_installations, app_permissions,
                                                  config as github_config, forget as forget_installation, forget_app, forget_catalog,
                                                  install_url, installation_details, permission_review, save_credentials, verify_app)
from tamandua.modules.integrations.installations import clear_github, github_connections, github_installations, save_github
from tamandua.modules.findings.kinds import FINDING_RUNS
from tamandua.modules.runs.store import render_tickets
from tamandua.modules.sources.assets import with_scan_branches
from tamandua.modules.sources.domains import DomainError, check_reachability, list_domains, locked, register_domain, verify_domain
from tamandua.modules.sources.repositories import SourceError, find_source, list_repositories, source_page
from tamandua.shared import log as logging_setup
from tamandua.shared.i18n import default_locale, msg, t, text

router = APIRouter(tags=["sources"])


def server_port(request: Request) -> int:
    return request.app.state.port


# --- Code -----------------------------------------------------------------------------------------------------------

def _page(page: str | None, per_page: str | None) -> tuple[int, int] | None:
    try:
        page_number, size = int(page or "1"), int(per_page or "25")
    except ValueError:
        return None
    return (page_number, size) if 1 <= size <= 100 and 1 <= page_number and page_number * size <= 10_000 else None


@router.get("/api/sources")
def sources(source_id: str | None = Query(None, alias="id"), q: str | None = None, account: str | None = None,
            provider: str | None = None, page: str | None = None, per_page: str | None = None, refresh: str | None = None,
            context: Context = Depends(guard())) -> Any:
    """A page of repositories (`q`, `account`, `provider`, `page` from 1, `per_page` 1–100) or one of them (`id`)."""
    # An empty parameter counts as absent, and they are read as text: `id` answers whatever the others say.
    with context.state.code_lock:
        tokens = context.state.code_tokens.copy()
    installations = github_installations(context.data_dir)
    if source_id:
        found = find_source(tokens, installations, source_id)
        return context.render({"sources": with_scan_branches(context.data_dir, [found] if found else []), "total": 1 if found else 0})
    paged, query, account, provider = _page(page, per_page), q or "", account or None, provider or None
    if paged is None or len(query) > 100 or (account is not None and len(account) > 100) or provider not in (None, "github", "gitlab", "local"):
        raise ApiError(400, msg("api.invalid_search"))
    if refresh == "1":
        for installation in installations:
            forget_catalog(installation)
    listing = source_page(tokens, installations, query=query, account=account, provider=provider, page=paged[0], per_page=paged[1])
    return context.render({**listing, "sources": with_scan_branches(context.data_dir, listing["sources"])})


class CodeTokenIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: Literal["github", "gitlab"]
    token: Any


class CodeDisconnectIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: Literal["github", "gitlab"]
    disconnect: Any


@router.post("/api/integrations/code", openapi_extra=documented(CodeTokenIn, CodeDisconnectIn))
def connect_code(context: Context = Depends(guard(Policy(admin=True, action="connect-code", body=1024))),
                 data: CodeTokenIn | CodeDisconnectIn = Depends(body(CodeTokenIn | CodeDisconnectIn,
                                                                     msg("integrations.code.invalid_provider")))) -> Any:
    """Connects a GitHub or GitLab token (kept in memory only), or disconnects it with `disconnect: true`."""
    state = context.state
    if isinstance(data, CodeDisconnectIn):
        if data.disconnect is not True:
            raise ApiError(400, msg("api.invalid_request"))
        with state.code_lock:
            state.code_tokens.pop(data.provider, None)
        return {"provider": data.provider, "connected": False}
    token = data.token
    if (not isinstance(token, str) or not 8 <= len(token) <= 512
            or any(character.isspace() or ord(character) < 33 or ord(character) > 126 for character in token)):
        raise ApiError(400, msg("integrations.code.invalid_token"))
    try:
        repositories = list_repositories(data.provider, token)
    except SourceError as exc:
        raise ApiError(400, msg("integrations.code.auth_failed")) from exc
    with state.code_lock:
        state.code_tokens[data.provider] = token
    return {"provider": data.provider, "connected": True, "repositories": len(repositories)}


# --- Domains --------------------------------------------------------------------------------------------------------

class DomainIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str
    kind: str = "web"
    context: str = ""


class DomainIdIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    domain_id: str


class DomainUrlIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str


@router.get("/api/domains")
def domains(context: Context = Depends(guard())) -> Any:
    return context.render(list_domains(context.data_dir))


@router.post("/api/domains", openapi_extra=documented(DomainIn))
def add_domain(context: Context = Depends(guard(Policy(action="register-domain", body=1024))),
               data: DomainIn = Depends(body(DomainIn, msg("sources.domains.invalid_request")))) -> Any:
    with locked(context.data_dir):
        try:
            record = register_domain(context.data_dir, data.url, data.kind, data.context)
        except DomainError as exc:
            raise ApiError(400, problem(exc)) from exc
    return context.render(record)


@router.post("/api/domains/verify", openapi_extra=documented(DomainIdIn))
def verify(context: Context = Depends(guard(Policy(action="verify-domain"))),
           data: DomainIdIn = Depends(body(DomainIdIn, msg("sources.domains.invalid_request")))) -> Any:
    with locked(context.data_dir):
        try:
            record = verify_domain(context.data_dir, data.domain_id)
        except DomainError as exc:
            raise ApiError(400, problem(exc)) from exc
    return context.render(record)


@router.post("/api/domains/check", openapi_extra=documented(DomainUrlIn))
def reachability(context: Context = Depends(guard(Policy(action="check-domain", body=512))),
                 data: DomainUrlIn = Depends(body(DomainUrlIn, msg("sources.domains.invalid_request")))) -> Any:
    try:
        return context.render(check_reachability(data.url))
    except DomainError as exc:
        raise ApiError(400, problem(exc)) from exc


# --- AI providers ---------------------------------------------------------------------------------------------------

class ProviderKeyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: Any
    action: Literal["save", "remove"]
    api_key: Any = ""


class ProviderIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: Any


@router.get("/api/providers")
def providers(context: Context = Depends(guard())) -> Any:
    return context.render(provider_status())


@router.post("/api/providers/keys", openapi_extra=documented(ProviderKeyIn))
def provider_keys(context: Context = Depends(guard(Policy(admin=True, action="save-ai-key", body=768))),
                  data: ProviderKeyIn = Depends(body(ProviderKeyIn, msg("integrations.ai.invalid_request")))) -> Any:
    """Saves (after checking it with the provider) or removes the workspace's own key; the key never comes back."""
    try:
        if data.action == "remove":
            forget_provider_key(data.provider)
            return context.render({"providers": provider_status()})
        result = save_provider_key(data.provider, data.api_key)
    except ProviderError as exc:
        raise ApiError(400, problem(exc)) from exc
    except (ValueError, TypeError) as exc:
        raise ApiError(400, msg("integrations.ai.invalid_request")) from exc
    except OSError as exc:
        raise ApiError(500, msg("integrations.ai.save_failed")) from exc
    return context.render({"result": result, "providers": provider_status()})


@router.post("/api/providers/check", openapi_extra=documented(ProviderIn))
def provider_check(context: Context = Depends(guard(Policy(action="check-provider"))),
                   data: ProviderIn = Depends(body(ProviderIn, msg("integrations.code.invalid_provider")))) -> Any:
    try:
        return context.render(check_provider(data.provider))
    except (ValueError, TypeError) as exc:
        raise ApiError(400, msg("integrations.code.invalid_provider")) from exc


# --- GitHub App -----------------------------------------------------------------------------------------------------

LANDING_CSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'"


def _landing(locale: str, port: int, title, detail) -> Response:
    """Minimal return page: no scripts, and a link back to the panel."""
    page = (f"<!doctype html><html lang={locale}><meta charset=utf-8><title>Tamandua</title>"
            "<style>body{font:15px system-ui,sans-serif;background:#0a0a0a;color:#eee;max-width:560px;margin:15vh auto;padding:0 20px}"
            "a{color:#fff}</style>"
            f"<h1>{html.escape(text(title, locale))}</h1><p>{html.escape(text(detail, locale))}</p>"
            f"<p><a href=\"{html.escape(public_url(port))}/#/integraciones\">{html.escape(t('integrations.github.landing.back', locale))}</a></p>")
    return Response(page.encode("utf-8"), status_code=200,
                    headers={"content-type": "text/html; charset=utf-8", "content-security-policy": LANDING_CSP})


def github_status(data_dir, port: int, *, live: bool = False) -> dict:
    state = github_config()
    records = github_connections(data_dir)
    status = {**state, "connected": bool(records), "installation": records[0] if records else None,
              "installations": records, "public_url": public_url(port), "required_permissions": REQUIRED_PERMISSIONS}
    if live and state["configured"]:
        # Permissions change on GitHub without notice: read them there, not from what was stored when connecting.
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


def _attach(context: Context, installation_id: int) -> dict | None:
    """Stores an installation of OUR App: the id is checked with GitHub, never taken as given."""
    chosen = next((row for row in app_installations() if row["installation_id"] == installation_id), None)
    if chosen is None:
        return None
    details = installation_details(chosen["installation_id"])
    save_github(context.data_dir, chosen["installation_id"], details, (context.user or {}).get("username"))
    return chosen


@router.get("/api/integrations/github")
def github(context: Context = Depends(guard()), port: int = Depends(server_port)) -> Any:
    return context.render(github_status(context.data_dir, port, live=True))


class GitHubAppIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    app_id: Any
    private_key: Any


@router.post("/api/integrations/github/app", openapi_extra=documented(GitHubAppIn))
def github_app_credentials(context: Context = Depends(guard(Policy(admin=True, action="save-github-app", body=20_000))),
                           data: GitHubAppIn = Depends(body(GitHubAppIn, msg("api.invalid_request"))),
                           port: int = Depends(server_port)) -> Any:
    """App ID and private key pasted by an administrator: checked with GitHub and stored encrypted."""
    if github_config()["source"] == "environment":
        raise ApiError(409, msg("integrations.github.env_managed_change"))
    previous_app = github_config().get("app_id")
    try:
        verified = verify_app(data.app_id, data.private_key)
    except GitHubAppError as exc:
        raise ApiError(400, problem(exc)) from exc
    save_credentials(verified)
    if previous_app != verified["app_id"]:
        clear_github(context.data_dir)
    logging_setup.get("github").info("github_app_saved", extra={"user": context.user["username"], "reason": f"{verified['owner']}/{verified['slug']}"})
    return context.render({**github_status(context.data_dir, port, live=True), "events": verified["events"]})


class GitHubActionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["install", "detect", "connect", "disconnect", "forget_app"]
    installation_id: StrictInt = Field(None, gt=0)  # only to connect (required) or disconnect one installation

    @model_validator(mode="after")
    def _installation_scope(self):
        if "installation_id" in self.model_fields_set:
            if self.action not in ("disconnect", "connect"):
                raise ValueError("installation_id")
        elif self.action == "connect":
            raise ValueError("installation_id")
        return self


@router.post("/api/integrations/github", openapi_extra=documented(GitHubActionIn))
def github_action(context: Context = Depends(guard(Policy(admin=True, action="connect-github", body=256))),
                  data: GitHubActionIn = Depends(body(GitHubActionIn, msg("integrations.github.invalid_action"))),
                  port: int = Depends(server_port)) -> Any:
    action, data_dir = data.action, context.data_dir
    if action in ("disconnect", "forget_app"):
        if action == "forget_app" and github_config()["source"] == "environment":
            raise ApiError(409, msg("integrations.github.env_managed_remove"))
        installation_id = data.installation_id
        if installation_id is not None and installation_id not in github_installations(data_dir):
            raise ApiError(404, msg("integrations.github.not_connected"))
        to_forget = [installation_id] if installation_id is not None else github_installations(data_dir)
        clear_github(data_dir, installation_id)
        for current in to_forget:
            forget_installation(current)
        if action == "forget_app":
            forget_app()
        return context.render(github_status(data_dir, port))
    try:
        if action == "install":
            return {"url": install_url()}
        if action == "connect":
            if _attach(context, data.installation_id) is None:
                raise ApiError(404, msg("integrations.github.foreign_installation"))
            return context.render(github_status(data_dir, port, live=True))
        rows = app_installations()
        if not rows:
            raise ApiError(404, msg("integrations.github.not_installed"))
        connected = set(github_installations(data_dir))
        status = github_status(data_dir, port, live=True)
        status["available_installations"] = [{**row, "connected": row["installation_id"] in connected} for row in rows]
        return context.render(status)
    except GitHubAppError as exc:
        raise ApiError(400, problem(exc)) from exc


# Optional return after installing (the App's Setup URL). The SameSite=Strict cookie does not travel from github.com:
# nothing is connected here; the administrator picks the account in the panel.
@router.get("/oauth/callback", response_class=Response, responses={200: {"content": {"text/html": {}}}})
def github_callback(request: Request, installation_id: str = "", context: Context = Depends(guard(Policy(public=True))),
                    port: int = Depends(server_port)) -> Response:
    locale = context.locale
    if not installation_id.isdigit() or len(installation_id) > 19:
        return _landing(locale, port, msg("integrations.github.landing.no_installation"), msg("integrations.github.landing.no_installation_detail"))
    # Public and backed by a GitHub call: throttled, so it cannot be used to drain the App's quota.
    throttle = context.state.auth.throttle
    scope = f"oauth-callback:{request.client.host if request.client else ''}"
    if throttle.reserve(scope):
        return _landing(locale, port, msg("integrations.github.landing.too_many"), msg("integrations.github.landing.too_many_detail"))
    try:
        if not any(row["installation_id"] == int(installation_id) for row in app_installations()):
            return _landing(locale, port, msg("integrations.github.landing.unknown"), msg("integrations.github.landing.unknown_detail"))
    except (GitHubAppError, ValueError) as exc:
        return _landing(locale, port, msg("integrations.github.landing.failed"), problem(exc))
    throttle.succeeded(scope)
    return _landing(locale, port, msg("integrations.github.landing.available"), msg("integrations.github.landing.available_detail"))


# --- Jira -----------------------------------------------------------------------------------------------------------

class JiraRemoveIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["remove"]


class JiraSaveIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["save"]
    site: Any
    email: Any
    token: Any
    project: Any
    issue_type: Any = "Task"


class JiraExportIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    run_id: str
    fingerprints: Any


@router.get("/api/integrations/jira")
def jira_status(context: Context = Depends(guard())) -> Any:
    return context.render(jira.status())


@router.post("/api/integrations/jira", openapi_extra=documented(JiraSaveIn, JiraRemoveIn))
def jira_configure(context: Context = Depends(guard(Policy(admin=True, action="connect-jira", body=1024))),
                   data: JiraSaveIn | JiraRemoveIn = Depends(body(JiraSaveIn | JiraRemoveIn,
                                                                  msg("integrations.jira.invalid_request")))) -> Any:
    if isinstance(data, JiraRemoveIn):
        jira.forget()
        context.state.log.info("jira_removed", extra={"user": context.user["username"]})
        return context.render(jira.status())
    try:
        return context.render(jira.configure(data.site, data.email, data.token, data.project, data.issue_type, by=context.user["username"]))
    except jira.JiraError as exc:
        raise ApiError(400, problem(exc)) from exc
    except OSError as exc:
        raise ApiError(500, msg("api.save_settings_failed")) from exc


@router.post("/api/integrations/jira/issues", openapi_extra=documented(JiraExportIn))
def jira_export(context: Context = Depends(guard(Policy(action="export-jira", body=6000))),
                data: JiraExportIn = Depends(body(JiraExportIn, msg("integrations.jira.invalid_export")))) -> Any:
    try:
        record = resolve(context.data_dir, data.run_id)
        record = record if record.get("type") == "asset_state" else triage.annotate(context.data_dir, record)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        raise ApiError(404, msg("api.run_not_found")) from exc
    if record.get("type") not in (*FINDING_RUNS, "asset_state"):
        raise ApiError(400, msg("integrations.jira.code_only"))
    try:
        # Issues are read by the whole team: TAMANDUA_DEFAULT_LOCALE, not the requester's language.
        return context.render(tickets.export(context.data_dir, record, render_tickets(record, locale=default_locale()), data.fingerprints,
                                             by=context.user["username"]))
    except jira.JiraError as exc:
        raise ApiError(400, problem(exc)) from exc
