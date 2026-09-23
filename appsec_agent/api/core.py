"""Núcleo HTTP del panel: una tabla de rutas y una sola tubería de seguridad.

Cada ruta declara en su registro todo lo que la protege —si es pública, si
exige administrador, si sirve durante el enrolamiento TOTP, la cabecera de
acción CSRF y el tamaño máximo del cuerpo—, y ``Handler`` lo aplica siempre en
el mismo orden antes de llamar al manejador:

    host permitido → sesión → política TOTP → rol → Origin + acción → cuerpo

Los manejadores viven en ``routes_*.py`` por área y reciben un ``Request``: no
leen cabeceras ni cookies por su cuenta.
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qs, urlsplit

from .. import logging_setup
from ..auth import Authenticator
from ..jobs import ScanJobs

DEFAULT_CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; connect-src 'self'; "
               "img-src 'self'; base-uri 'none'; frame-ancestors 'none'")
VERSION = "0.9"


def allowed_origins(port: int) -> list[str]:
    configured = [item.strip().rstrip("/") for item in os.environ.get("APPSEC_AGENT_ALLOWED_ORIGINS", "").split(",") if item.strip()]
    return configured or [f"http://127.0.0.1:{port}", f"http://localhost:{port}"]


def public_url(port: int) -> str:
    return os.environ.get("APPSEC_AGENT_PUBLIC_URL", "").strip().rstrip("/") or allowed_origins(port)[0]


@dataclass
class State:
    """Lo que comparten todas las peticiones de un servidor."""
    data_dir: Path
    log: object
    jobs: ScanJobs
    auth: Authenticator
    domain_lock: threading.Lock = field(default_factory=threading.Lock)
    code_lock: threading.Lock = field(default_factory=threading.Lock)
    code_tokens: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Route:
    method: str
    path: str
    handler: Callable
    public: bool = False       # accesible sin sesión
    admin: bool = False        # solo administradores
    enrolment: bool = False    # accesible aunque la política TOTP esté pendiente
    action: str | None = None  # cabecera X-AppSec-Agent-Action exigida (POST)
    body: int = 256            # tamaño máximo del cuerpo JSON (POST)
    prefix: bool = False       # la ruta cubre todo lo que empiece por `path`


ROUTES: dict[tuple[str, str], Route] = {}
PREFIXES: list[Route] = []


def route(method: str, path: str, **options):
    """Registra un manejador. Un POST sin `action` es un error de programación."""
    if method == "POST" and not options.get("action"):
        raise ValueError(f"POST {path} necesita cabecera de acción")

    def register(function):
        entry = Route(method, path, function, **options)
        if entry.prefix:
            PREFIXES.append(entry)
        else:
            ROUTES[(method, path)] = entry
        return function
    return register


def find(method: str, path: str) -> Route | None:
    entry = ROUTES.get((method, path))
    if entry is not None:
        return entry
    return next((item for item in PREFIXES if item.method == method and path.startswith(item.path)), None)


class Request:
    """Vista de una petición ya autorizada, con atajos para responder."""

    def __init__(self, handler: "Handler", state: State, path: str, user: dict | None, session: dict | None,
                 payload=None):
        self.handler, self.state, self.path = handler, state, path
        self.user, self.session, self.payload = user, session, payload
        self.data_dir, self.auth, self.log = state.data_dir, state.auth, state.log
        self._query = None

    @property
    def query(self) -> dict:
        if self._query is None:
            self._query = parse_qs(urlsplit(self.handler.path).query)
        return self._query

    def arg(self, name: str, default: str | None = None) -> str | None:
        return (self.query.get(name) or [default])[0]

    @property
    def client(self) -> str:
        return self.handler.client_address[0]

    @property
    def cookie_header(self) -> str | None:
        return self.handler.headers.get("Cookie")

    @property
    def port(self) -> int:
        return self.handler.server.server_port

    @property
    def secure_cookies(self) -> bool:
        return public_url(self.port).startswith("https://")

    def json(self, status: int, data, *, cookie: str | None = None):
        return self.handler.send(status, json.dumps(data, ensure_ascii=False).encode("utf-8"),
                                 "application/json; charset=utf-8", cookie=cookie)

    def send(self, status: int, payload: bytes, content_type: str, *, csp: str | None = None, cookie: str | None = None):
        return self.handler.send(status, payload, content_type, csp=csp, cookie=cookie)

    def redirect(self, location: str):
        self.handler.send_response(302)
        self.handler.send_header("Location", location)
        self.handler.send_header("Content-Length", "0")
        self.handler.send_header("Cache-Control", "no-store")
        self.handler.end_headers()


def build_handler(state: State):
    log = state.log

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):  # noqa: A002 — firma de BaseHTTPRequestHandler
            return None  # el acceso se registra estructurado en send

        def send(self, status: int, payload: bytes, content_type: str, csp: str | None = None, cookie: str | None = None):
            self.send_response(status)
            if cookie is not None:
                self.send_header("Set-Cookie", cookie)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", csp or DEFAULT_CSP)
            # Los códigos de OAuth viajan en la URL: que ninguna navegación los filtre en el Referer.
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
            if public_url(self.server.server_port).startswith("https://"):
                self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
            self.end_headers()
            self.wfile.write(payload)
            path = urlsplit(self.path).path
            if not path.startswith("/assets/"):
                log.info("http", extra={"method": self.command, "path": path, "status": status,
                                        "client": self.client_address[0],
                                        "duration_ms": round((time.time() - getattr(self, "_started", time.time())) * 1000)})

        def fail(self, status: int, message: str, **extra):
            return self.send(status, json.dumps({"error": message, **extra}, ensure_ascii=False).encode("utf-8"),
                             "application/json; charset=utf-8")

        def do_GET(self):
            self._dispatch("GET")

        def do_POST(self):
            self._dispatch("POST")

        def _dispatch(self, method: str):
            self._started = time.time()
            hosts = {urlsplit(origin).netloc for origin in allowed_origins(self.server.server_port)}
            if self.headers.get("Host") not in hosts:
                return self.fail(403, "Host no permitido")
            path = urlsplit(self.path).path
            entry = find(method, path)
            if entry is None:
                return self.fail(404, "Ruta no encontrada")
            if method == "POST":
                # CSRF antes que nada: un POST de otro origen no llega ni a mirar la sesión.
                if (self.headers.get("Origin") not in allowed_origins(self.server.server_port)
                        or self.headers.get("X-AppSec-Agent-Action") != entry.action):
                    return self.fail(403, "Origen o acción no permitidos")
            user, session = state.auth.current(self.headers.get("Cookie"))
            if user is not None and user.get("totp", {}).get("enabled") and not (session or {}).get("mfa"):
                user, session = None, None
            if user is None and not entry.public:
                return self.fail(401, "Inicia sesión para continuar")
            if user is not None and not entry.enrolment and state.auth.needs_totp(user):
                return self.fail(403, "Activa el segundo factor para continuar", code="totp_required")
            if entry.admin and (user is None or user["role"] != "admin"):
                return self.fail(403, "Solo un administrador puede hacer esto")
            payload = None
            if method == "POST":
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    length = 0
                if length < 2 or length > entry.body:
                    return self.fail(400, "Solicitud inválida")
                try:
                    payload = json.loads(self.rfile.read(length))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    return self.fail(400, "JSON inválido")
            return entry.handler(Request(self, state, path, user, session, payload))

    Handler.state = state  # para el arranque (código de configuración) y las pruebas
    return Handler
