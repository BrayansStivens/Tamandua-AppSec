"""Rutas declaradas en tabla (`@route`), servidas por FastAPI.

Cada ruta declara en su registro todo lo que la protege —si es pública, si exige administrador, si sirve durante el
enrolamiento TOTP, la cabecera de acción CSRF y el tamaño máximo del cuerpo— y `mount` la registra en la aplicación
con la tubería de `security.authorize` delante. Los manejadores viven en `routes/<área>.py` y reciben un `Request`:
no leen cabeceras ni cookies por su cuenta. Las rutas nuevas se escriben tipadas (`deps.guard` + Pydantic).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable
from urllib.parse import parse_qs

from starlette.concurrency import run_in_threadpool
from starlette.requests import Request as HttpRequest
from starlette.responses import Response

from tamandua.app.api.security import Denied, State, authorize, public_url
from tamandua.shared.i18n import localize, msg, negotiate


@dataclass(frozen=True)
class Route:
    method: str
    path: str
    handler: Callable
    public: bool = False       # accesible sin sesión
    admin: bool = False        # solo administradores
    enrolment: bool = False    # accesible aunque la política TOTP esté pendiente
    action: str | None = None  # cabecera X-Tamandua-Action exigida (POST)
    body: int = 256            # tamaño máximo del cuerpo JSON (POST)
    prefix: bool = False       # la ruta cubre todo lo que empiece por `path`


ROUTES: dict[tuple[str, str], Route] = {}
PREFIXES: list[Route] = []


def route(method: str, path: str, **options):
    """Registra un manejador. Un POST sin `action` es un error de programación."""
    if method == "POST" and not options.get("action"):
        raise ValueError(f"POST {path} needs an action header")

    def register(function):
        entry = Route(method, path, function, **options)
        if entry.prefix:
            PREFIXES.append(entry)
        else:
            ROUTES[(method, path)] = entry
        return function
    return register


def _response(status: int, payload: bytes, content_type: str, *, csp: str | None = None, cookie: str | None = None) -> Response:
    headers = {"content-type": content_type}
    if csp:
        headers["content-security-policy"] = csp  # el middleware pone la de siempre si no hay otra
    if cookie is not None:
        headers["set-cookie"] = cookie
    return Response(payload, status_code=status, headers=headers)


def problem(exc: Exception):
    """What an exception tells the reader: its message (rendered per request) or, failing that, its text."""
    message = getattr(exc, "message", None)
    if message:
        return message
    first = exc.args[0] if exc.args else None
    return first if isinstance(first, dict) else str(exc)


def error(status: int, message, locale: str, **extra) -> Response:
    return _response(status, json.dumps(localize({"error": message, **extra}, locale), ensure_ascii=False).encode("utf-8"),
                     "application/json; charset=utf-8")


class Request:
    """Vista de una petición ya autorizada, con atajos para responder."""

    def __init__(self, http: HttpRequest, state: State, user: dict | None, session: dict | None, payload=None):
        self.state, self.user, self.session, self.payload = state, user, session, payload
        self.data_dir, self.auth, self.log = state.data_dir, state.auth, state.log
        self.path = http.url.path
        self.query = parse_qs(http.url.query)
        self.client = http.client.host if http.client else ""
        self.cookie_header = http.headers.get("cookie")
        self.locale = negotiate(http.headers.get("accept-language"))
        self.port: int = http.app.state.port

    def arg(self, name: str, default: str | None = None) -> str | None:
        return (self.query.get(name) or [default])[0]

    @property
    def secure_cookies(self) -> bool:
        return public_url(self.port).startswith("https://")

    def json(self, status: int, data, *, cookie: str | None = None) -> Response:
        return _response(status, json.dumps(localize(data, self.locale), ensure_ascii=False).encode("utf-8"),
                         "application/json; charset=utf-8", cookie=cookie)

    def send(self, status: int, payload: bytes, content_type: str, *, csp: str | None = None, cookie: str | None = None) -> Response:
        return _response(status, payload, content_type, csp=csp, cookie=cookie)

def _endpoint(entry: Route):
    async def endpoint(http: HttpRequest) -> Response:
        state: State = http.app.state.core
        locale = negotiate(http.headers.get("accept-language"))
        verdict = await run_in_threadpool(authorize, state, entry, method=entry.method, port=http.app.state.port,
                                          origin=http.headers.get("origin"), action=http.headers.get("x-tamandua-action"),
                                          cookie=http.headers.get("cookie"))
        if isinstance(verdict, Denied):
            return error(verdict.status, verdict.message, locale, **verdict.extra)
        payload = None
        if entry.method == "POST":
            # El límite se mira antes de leer: un cuerpo mayor que lo declarado ni siquiera se recibe.
            try:
                length = int(http.headers.get("content-length", "0"))
            except ValueError:
                length = 0
            if length < 2 or length > entry.body:
                return error(400, msg("api.invalid_request"), locale)
            try:
                payload = json.loads(await http.body())
            except (json.JSONDecodeError, UnicodeDecodeError):
                return error(400, msg("api.invalid_json"), locale)
        user, session = verdict
        response = await run_in_threadpool(entry.handler, Request(http, state, user, session, payload))
        if not isinstance(response, Response):
            raise TypeError(f"{entry.method} {entry.path} did not return a response")
        return response
    endpoint.__name__ = entry.handler.__name__
    return endpoint


def mount(app) -> None:
    """Registra la tabla en la aplicación: primero las rutas exactas y luego los prefijos (el orden decide)."""
    for entry in [*ROUTES.values(), *PREFIXES]:
        path = entry.path + "{rest:path}" if entry.prefix else entry.path
        app.add_api_route(path, _endpoint(entry), methods=[entry.method], include_in_schema=False)
