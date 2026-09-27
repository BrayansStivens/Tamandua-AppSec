"""HTTP API on FastAPI: one router per context (`<context>.py`).

Toda petición pasa por el mismo control (ver `security.py`): host permitido (middleware) → CSRF, sesión, segundo
factor y rol (`security.authorize`, vía `deps.guard`) → límites de cuerpo. Las respuestas llevan
las mismas cabeceras de seguridad (CSP, nosniff, frame, HSTS si hay HTTPS). No se publica la documentación
interactiva ni el OpenAPI: el esquema se genera con `make openapi`.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from tamandua.app.api import assets, auth, compliance, cron, findings, images, intel, metrics, notifications, onboarding, pullrequests, reporting, repositories, runs, scanning, sources, static, system, threats
from tamandua.app.api.deps import ApiError
from tamandua.app.api.security import DEFAULT_CSP, State, host_allowed, public_url
from tamandua.modules.identity.auth import COOKIE_NAME
from tamandua.shared.i18n import localize, msg, negotiate
from tamandua.shared.vault import VaultError
from tamandua.version import VERSION

ROUTERS = (auth, system, metrics, cron, reporting, intel, findings, compliance, pullrequests, repositories, scanning, sources, threats, runs, assets, images, notifications, onboarding, static)


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


def _body_problem(request: Request) -> int | None:
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return None
    declared = request.headers.get("content-length")
    if declared is None:
        return 411 if request.headers.get("transfer-encoding") else None
    try:
        return 413 if int(declared) > MAX_BODY else None
    except ValueError:
        return 400


def _error(request: Request, message, **extra) -> dict:
    return localize({"error": message, **extra}, negotiate(request.headers.get("accept-language")))


def create_app(data_dir: Path, *, port: int, state: State | None = None, watch: bool = False) -> FastAPI:
    """`state`: el estado ya creado (las pruebas lo reutilizan); si no, se crea con su cola y sus hilos."""
    if state is None:
        from tamandua.app.api.server import build_state
        state = build_state(data_dir, watch_pull_requests=watch)
    # Sin redirecciones de barra final: una ruta desconocida es un 404, no un 307.
    app = FastAPI(title="Tamandua", version=VERSION, docs_url=None, redoc_url=None, openapi_url=None, redirect_slashes=False)
    app.state.core, app.state.port = state, port
    log = state.log

    @app.middleware("http")
    async def pipeline(request: Request, call_next):
        started = time.time()
        if not host_allowed(port, request.headers.get("host")):
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
        if error.status_code in (404, 405):  # método no admitido: como antes, la ruta no existe para ese método
            return JSONResponse(_error(request, msg("api.not_found")), status_code=404)
        return JSONResponse({"error": str(error.detail)}, status_code=error.status_code)

    @app.exception_handler(Exception)
    async def crashed(request: Request, error: Exception):
        # Sin traza hacia fuera; el detalle queda en el log del servidor.
        log.exception("error no controlado", extra={"method": request.method, "path": request.url.path})
        response = JSONResponse(_error(request, msg("api.internal_error")), status_code=500)
        _security_headers(response, port)  # este manejador corre fuera del middleware: las pone él
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
    """El esquema OpenAPI de las rutas migradas, para generar el cliente TypeScript del panel (make openapi)."""
    from fastapi.openapi.utils import get_openapi
    app = FastAPI(title="Tamandua", version=VERSION)
    for module in ROUTERS:
        app.include_router(module.router)
    document = get_openapi(title=app.title, version=app.version, routes=app.routes)
    _invalid_parameters_as_400(document)
    # Cómo se autentica la API: la cookie de sesión (HttpOnly) en todo, salvo lo que cada ruta declare como público.
    # Los POST exigen además Origin y la cabecera X-Tamandua-Action (CSRF), que la cookie sola no cubre.
    document.setdefault("components", {})["securitySchemes"] = {
        "session": {"type": "apiKey", "in": "cookie", "name": COOKIE_NAME, "description": "Session signed in to the panel."},
        "metrics": {"type": "http", "scheme": "bearer", "description": "TAMANDUA_METRICS_TOKEN (Prometheus scraper)."},
        "cron": {"type": "http", "scheme": "bearer", "description": "TAMANDUA_CRON_TOKEN or CRON_SECRET (external scheduler)."}}
    document["security"] = [{"session": []}]
    return json.dumps(document, ensure_ascii=False, indent=2) + "\n"
