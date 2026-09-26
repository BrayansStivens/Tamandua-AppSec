"""La tubería de seguridad del panel, en un solo sitio para todas las rutas.

    host permitido (middleware) → CSRF en POST (Origin + cabecera de acción) → sesión → segundo factor
    → política TOTP → rol → límites de cuerpo (routing)

Las rutas tipadas la aplican con `deps.guard(Policy)` y las de la tabla `@route` con `routing.mount`: las dos llaman a
`authorize`, así que no hay dos criterios.
"""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from tamandua.modules.identity.auth import Authenticator
from tamandua.modules.runs.jobs import ScanJobs

DEFAULT_CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; connect-src 'self'; "
               "img-src 'self'; base-uri 'none'; frame-ancestors 'none'")


def allowed_origins(port: int) -> list[str]:
    configured = [item.strip().rstrip("/") for item in os.environ.get("APPSEC_AGENT_ALLOWED_ORIGINS", "").split(",") if item.strip()]
    return configured or [f"http://127.0.0.1:{port}", f"http://localhost:{port}"]


def public_url(port: int) -> str:
    return os.environ.get("APPSEC_AGENT_PUBLIC_URL", "").strip().rstrip("/") or allowed_origins(port)[0]


def host_allowed(port: int, host: str | None) -> bool:
    return host in {urlsplit(origin).netloc for origin in allowed_origins(port)}


@dataclass
class State:
    """Lo que comparten todas las peticiones de un servidor."""
    data_dir: Path
    log: object
    jobs: ScanJobs
    auth: Authenticator
    code_lock: threading.Lock = field(default_factory=threading.Lock)
    code_tokens: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Denied:
    """Respuesta de la tubería de seguridad cuando no deja pasar."""
    status: int
    message: str
    extra: dict = field(default_factory=dict)


def authorize(state: State, entry, *, method: str, port: int, origin: str | None, action: str | None,
              cookie: str | None) -> tuple[dict | None, dict | None] | Denied:
    """`entry` es una `routing.Route` o una `deps.Policy` (public, admin, enrolment, action)."""
    if method == "POST":
        # CSRF antes que nada: un POST de otro origen no llega ni a mirar la sesión.
        if origin not in allowed_origins(port) or action != entry.action:
            return Denied(403, "Origen o acción no permitidos")
    user, session = state.auth.current(cookie)
    if user is not None and user.get("totp", {}).get("enabled") and not (session or {}).get("mfa"):
        user, session = None, None
    if user is None and not entry.public:
        return Denied(401, "Inicia sesión para continuar")
    if user is not None and not entry.enrolment and state.auth.needs_totp(user):
        return Denied(403, "Activa el segundo factor para continuar", {"code": "totp_required"})
    if entry.admin and (user is None or user["role"] != "admin"):
        return Denied(403, "Solo un administrador puede hacer esto")
    return user, session
