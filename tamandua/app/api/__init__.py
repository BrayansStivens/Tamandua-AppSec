"""API HTTP sobre FastAPI: rutas tipadas por contexto (`<contexto>.py`) y rutas declaradas en tabla (`routes/`).

Toda petición pasa por el mismo control (ver `security.py`): host permitido (middleware) → CSRF, sesión, segundo
factor y rol (`security.authorize`, vía `deps.guard` o `routing.mount`) → límites de cuerpo. Las respuestas llevan
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

from tamandua.app.api import compliance, findings, intel, reporting, routing, system
from tamandua.app.api.deps import ApiError
from tamandua.app.api.routes import auth, cra, prs, runs, sources, threats  # noqa: F401 — registran sus rutas
from tamandua.app.api.security import DEFAULT_CSP, State, host_allowed, public_url
from tamandua.modules.identity.auth import COOKIE_NAME
from tamandua.version import VERSION

ROUTERS = (system, reporting, intel, findings, compliance)


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
            response = JSONResponse({"error": "Host no permitido"}, status_code=403)
        else:
            response = await call_next(request)
        _security_headers(response, port)
        if not request.url.path.startswith("/assets/"):
            log.info("http", extra={"method": request.method, "path": request.url.path, "status": response.status_code,
                                    "client": request.client.host if request.client else "", "duration_ms": round((time.time() - started) * 1000)})
        return response

    @app.exception_handler(ApiError)
    async def api_error(request: Request, error: ApiError):
        return JSONResponse({"error": error.message, **error.extra}, status_code=error.status)

    @app.exception_handler(RequestValidationError)
    async def invalid(request: Request, error: RequestValidationError):
        return JSONResponse({"error": "Parámetros inválidos"}, status_code=400)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, error: StarletteHTTPException):
        if error.status_code in (404, 405):  # método no admitido: como antes, la ruta no existe para ese método
            return JSONResponse({"error": "Ruta no encontrada"}, status_code=404)
        return JSONResponse({"error": str(error.detail)}, status_code=error.status_code)

    @app.exception_handler(Exception)
    async def crashed(request: Request, error: Exception):
        # Sin traza hacia fuera; el detalle queda en el log del servidor.
        log.exception("error no controlado", extra={"method": request.method, "path": request.url.path})
        response = JSONResponse({"error": "Error interno del servidor"}, status_code=500)
        _security_headers(response, port)  # este manejador corre fuera del middleware: las pone él
        return response

    for module in ROUTERS:
        app.include_router(module.router)
    routing.mount(app)  # después de las tipadas: sus prefijos (/api/runs/…) no deben tapar a ninguna
    return app


def openapi_document(data_dir: Path | None = None) -> str:
    """El esquema OpenAPI de las rutas migradas, para generar el cliente TypeScript del panel (make openapi)."""
    from fastapi.openapi.utils import get_openapi
    app = FastAPI(title="Tamandua", version=VERSION)
    for module in ROUTERS:
        app.include_router(module.router)
    document = get_openapi(title=app.title, version=app.version, routes=app.routes)
    # Cómo se autentica la API: la cookie de sesión (HttpOnly) en todo, salvo lo que cada ruta declare como público.
    # Los POST exigen además Origin y la cabecera X-Tamandua-Action (CSRF), que la cookie sola no cubre.
    document.setdefault("components", {})["securitySchemes"] = {
        "session": {"type": "apiKey", "in": "cookie", "name": COOKIE_NAME, "description": "Sesión iniciada en el panel."}}
    document["security"] = [{"session": []}]
    return json.dumps(document, ensure_ascii=False, indent=2) + "\n"
