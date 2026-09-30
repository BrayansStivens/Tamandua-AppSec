"""HTTP API on FastAPI: one router per context (`<context>.py`).

Every request goes through the same control (see `security.py`): allowed host (middleware) → CSRF, session,
second factor and role (`security.authorize`, via `deps.guard`) → body limits. Responses carry the same security
headers (CSP, nosniff, frame, HSTS over HTTPS). Neither the interactive docs nor the OpenAPI document are served:
the schema is generated with `make openapi`.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from tamandua.app.api import assets, auth, compliance, cron, findings, images, imports, intel, metrics, notifications, onboarding, pullrequests, reporting, repositories, runs, scanning, sources, static, system, threats
from tamandua.app.api.deps import ApiError
from tamandua.app.api.security import DEFAULT_CSP, State, host_allowed, public_url
from tamandua.modules.identity.auth import COOKIE_NAME
from tamandua.shared.i18n import localize, msg, negotiate
from tamandua.shared.vault import VaultError
from tamandua.version import VERSION

ROUTERS = (auth, system, metrics, cron, reporting, intel, findings, compliance, pullrequests, repositories, scanning, sources, threats, runs, assets, images, imports, notifications, onboarding, static)


def _security_headers(response, port: int) -> None:
    headers = response.headers
    headers.setdefault("cache-control", "no-store")
    headers.setdefault("x-content-type-options", "nosniff")
    headers.setdefault("content-security-policy", DEFAULT_CSP)
    headers.setdefault("referrer-policy", "no-referrer")
    headers.setdefault("x-frame-options", "DENY")
    headers.setdefault("permissions-policy", "camera=(), microphone=(), geolocation=(), payment=()")
    if public_url(port).startswith("https://"):
        headers.setdefault("strict-transport-security", "max-age=31536000; includeSubDomains")


# FastAPI reads a typed route's body before its guard runs: cap it here, by the declared length, before anything
# is read (the server never reads more than Content-Length). Each route then applies its own, smaller limit.
MAX_BODY = 1_000_000
# The only routes allowed more: SARIF imports (a large repository's results).
LARGE_BODIES = dict.fromkeys(imports.PATHS, imports.MAX_BYTES)


def _body_problem(request: Request) -> int | None:
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return None
    declared = request.headers.get("content-length")
    if declared is None:
        return 411 if request.headers.get("transfer-encoding") else None
    try:
        return 413 if int(declared) > LARGE_BODIES.get(request.url.path, MAX_BODY) else None
    except ValueError:
        return 400


def _error(request: Request, message, **extra) -> dict:
    return localize({"error": message, **extra}, negotiate(request.headers.get("accept-language")))


def create_app(data_dir: Path, *, port: int, state: State | None = None, watch: bool = False) -> FastAPI:
    """`state`: an existing state (tests reuse one); otherwise one is built with its queue and threads."""
    if state is None:
        from tamandua.app.api.server import build_state
        state = build_state(data_dir, watch_pull_requests=watch)
    # No trailing-slash redirects: an unknown route is a 404, not a 307.
    app = FastAPI(title="Tamandua", version=VERSION, docs_url=None, redoc_url=None, openapi_url=None, redirect_slashes=False)
    app.state.core, app.state.port = state, port
    log = state.log

    @app.middleware("http")
    async def pipeline(request: Request, call_next):
        started = time.time()
        if not host_allowed(port, request.headers.get("host")):
            if request.method == "GET" and request.url.path == "/api/health":
                # Platforms probe health with a Host of their own: it gets the anonymous answer, never session data.
                response = JSONResponse({"status": "ok", "version": VERSION})
            else:
                response = JSONResponse(_error(request, msg("api.host_not_allowed")), status_code=403)
        elif (oversized := _body_problem(request)) is not None:
            response = JSONResponse(_error(request, msg("api.invalid_request")), status_code=oversized)
        else:
            response = await call_next(request)
        _security_headers(response, port)
        if not request.url.path.startswith("/assets/"):
            log.info("http", extra={"method": request.method, "path": request.url.path, "status": response.status_code,
                                    "client": request.client.host if request.client else "", "duration_ms": round((time.time() - started) * 1000)})
        return response

    @app.exception_handler(ApiError)
    async def api_error(request: Request, error: ApiError):
        return JSONResponse(_error(request, error.message, **error.extra), status_code=error.status)

    @app.exception_handler(VaultError)
    async def vault_error(request: Request, error: VaultError):
        log.error("vault error: %s", error, extra={"method": request.method, "path": request.url.path})
        return JSONResponse(_error(request, error.message), status_code=500)

    @app.exception_handler(RequestValidationError)
    async def invalid(request: Request, error: RequestValidationError):
        return JSONResponse(_error(request, msg("api.invalid_parameters")), status_code=400)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, error: StarletteHTTPException):
        if error.status_code in (404, 405):  # method not allowed: as before, the route doesn't exist for that method
            return JSONResponse(_error(request, msg("api.not_found")), status_code=404)
        return JSONResponse({"error": str(error.detail)}, status_code=error.status_code)

    @app.exception_handler(Exception)
    async def crashed(request: Request, error: Exception):
        # No traceback goes out; the details stay in the server log.
        log.exception("error no controlado", extra={"method": request.method, "path": request.url.path})
        response = JSONResponse(_error(request, msg("api.internal_error")), status_code=500)
        _security_headers(response, port)  # this handler runs outside the middleware, so it sets them itself
        return response

    for module in ROUTERS:
        app.include_router(module.router)
    return app


def _invalid_parameters_as_400(document: dict) -> None:
    """FastAPI documents a 422 with its own error body; this API answers invalid input with a 400 {"error": …}."""
    schemas = document.setdefault("components", {}).setdefault("schemas", {})
    for name in ("HTTPValidationError", "ValidationError"):
        schemas.pop(name, None)
    schemas["Error"] = {"title": "Error", "type": "object", "required": ["error"],
                        "properties": {"error": {"type": "string", "title": "Error", "description": "In the reader's language."}}}
    for operations in document.get("paths", {}).values():
        for operation in operations.values():
            responses = operation.get("responses", {})
            if responses.pop("422", None) is not None:
                responses["400"] = {"description": "Invalid parameters",
                                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}


def openapi_document(data_dir: Path | None = None) -> str:
    """The OpenAPI schema of the migrated routes, to generate the panel's TypeScript client (make openapi)."""
    from fastapi.openapi.utils import get_openapi
    app = FastAPI(title="Tamandua", version=VERSION)
    for module in ROUTERS:
        app.include_router(module.router)
    document = get_openapi(title=app.title, version=app.version, routes=app.routes)
    _invalid_parameters_as_400(document)
    # How the API authenticates: the session cookie (HttpOnly) everywhere, except what a route declares public.
    # POSTs also require Origin and the X-Tamandua-Action header (CSRF), which the cookie alone doesn't cover.
    document.setdefault("components", {})["securitySchemes"] = {
        "session": {"type": "apiKey", "in": "cookie", "name": COOKIE_NAME, "description": "Session signed in to the panel."},
        "metrics": {"type": "http", "scheme": "bearer", "description": "TAMANDUA_METRICS_TOKEN (Prometheus scraper)."},
        "cron": {"type": "http", "scheme": "bearer", "description": "TAMANDUA_CRON_TOKEN or CRON_SECRET (external scheduler)."},
        "import": {"type": "http", "scheme": "bearer", "description": "TAMANDUA_IMPORT_TOKEN (CI uploading SARIF)."}}
    document["security"] = [{"session": []}]
    return json.dumps(document, ensure_ascii=False, indent=2) + "\n"
