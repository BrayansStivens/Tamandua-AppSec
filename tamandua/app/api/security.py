"""La tubería de seguridad del panel, en un solo sitio para todas las rutas.

    host permitido (middleware) → CSRF en POST (Origin + cabecera de acción) → sesión → segundo factor
    → política TOTP → rol → límites de cuerpo (deps.guard)

Todas las rutas la aplican con `deps.guard(Policy)`, que llama a
`authorize`, así que no hay dos criterios.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from tamandua.shared import settings
from tamandua.modules.identity.auth import Authenticator
from tamandua.shared.i18n import msg
from tamandua.modules.runs.jobs import ScanJobs

DEFAULT_CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; connect-src 'self'; "
               "img-src 'self'; base-uri 'none'; frame-ancestors 'none'")


def allowed_origins(port: int) -> list[str]:
    configured = settings.items("TAMANDUA_ALLOWED_ORIGINS")
    return configured or [f"http://127.0.0.1:{port}", f"http://localhost:{port}"]


def public_url(port: int) -> str:
    return settings.text("TAMANDUA_PUBLIC_URL").rstrip("/") or allowed_origins(port)[0]


def host_allowed(port: int, host: str | None) -> bool:
    return host in {urlsplit(origin).netloc for origin in allowed_origins(port)}


@dataclass
class State:
    """Lo que comparten todas las peticiones de un servidor."""
    data_dir: Path
    log: logging.Logger
    jobs: ScanJobs
    auth: Authenticator


@dataclass(frozen=True)
class Denied:
    """Respuesta de la tubería de seguridad cuando no deja pasar."""
    status: int
    message: dict
    extra: dict = field(default_factory=dict)


def authorize(state: State, entry, *, method: str, port: int, origin: str | None, action: str | None,
              cookie: str | None) -> tuple[dict | None, dict | None] | Denied:
    """`entry` is a `deps.Policy` (public, admin, enrolment, action)."""
    if method == "POST":
        # CSRF antes que nada: un POST de otro origen no llega ni a mirar la sesión.
        if origin not in allowed_origins(port) or action != entry.action:
            return Denied(403, msg("api.csrf_denied"))
    user, session = state.auth.current(cookie)
    if user is not None and user.get("totp", {}).get("enabled") and not (session or {}).get("mfa"):
        user, session = None, None
    if user is None and not entry.public:
        return Denied(401, msg("api.login_required"))
    if user is not None and not entry.enrolment and state.auth.needs_totp(user):
        return Denied(403, msg("api.totp_required"), {"code": "totp_required"})
    if entry.admin and (user is None or user["role"] != "admin"):
        return Denied(403, msg("api.admin_only"))
    return user, session
