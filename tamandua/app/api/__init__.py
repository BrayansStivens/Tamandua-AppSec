"""API HTTP sobre FastAPI (F1 del rediseño): rutas tipadas por contexto y, detrás, el router clásico para lo no migrado.

Toda petición pasa por el mismo control que antes:
host permitido (middleware) → CSRF, sesión, segundo factor y rol (`deps.guard`, que usa `core.authorize`) →
límites de cuerpo. Las respuestas llevan las mismas cabeceras de seguridad (CSP, nosniff, frame, HSTS si hay HTTPS).
No se publica la documentación interactiva ni el OpenAPI: el esquema se genera con `make openapi`.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from tamandua.app.api import compliance, findings, intel, reporting, system
from tamandua.app.api.deps import ApiError
from tamandua.app.api.legacy import forward
from tamandua.app.http.core import DEFAULT_CSP, host_allowed, public_url
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


def create_app(data_dir: Path, *, port: int, handler=None, watch: bool = False) -> FastAPI:
    """`handler`: el manejador clásico ya creado (las pruebas lo reutilizan); si no, se crea con su estado y sus hilos."""
    if handler is None:
        from tamandua.app.http import make_handler
        handler = make_handler(data_dir, watch_pull_requests=watch)
    app = FastAPI(title="Tamandua", version=VERSION, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.handler, app.state.legacy, app.state.port = handler, handler.state, port
    log = handler.state.log

    @app.middleware("http")
    async def pipeline(request: Request, call_next):
        started = time.time()
        if not host_allowed(port, request.headers.get("host")):
            response = JSONResponse({"error": "Host no permitido"}, status_code=403)
        else:
            response = await call_next(request)
        legacy = response.headers.get("x-tamandua-legacy")
        if legacy:
            del response.headers["x-tamandua-legacy"]
        _security_headers(response, port)
        if not legacy and not request.url.path.startswith("/assets/"):
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
        return JSONResponse({"error": "Ruta no encontrada" if error.status_code == 404 else str(error.detail)}, status_code=error.status_code)

    for module in ROUTERS:
        app.include_router(module.router)
    # Lo que no se ha migrado todavía: al router clásico (ver legacy.py). Siempre la última ruta.
    app.add_api_route("/{path:path}", forward, methods=["GET", "POST"], include_in_schema=False)
    return app


def openapi_document(data_dir: Path | None = None) -> str:
    """El esquema OpenAPI de las rutas migradas, para generar el cliente TypeScript del panel (make openapi)."""
    from fastapi.openapi.utils import get_openapi
    app = FastAPI(title="Tamandua", version=VERSION)
    for module in ROUTERS:
        app.include_router(module.router)
    return json.dumps(get_openapi(title=app.title, version=app.version, routes=app.routes), ensure_ascii=False, indent=2) + "\n"
