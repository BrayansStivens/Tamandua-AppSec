"""Seguridad y contexto de las rutas tipadas: la misma tubería que las de tabla (security.authorize)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from fastapi import Request

from tamandua.app.api.security import Denied, State, authorize
from tamandua.shared.i18n import localize, msg, negotiate


class ApiError(Exception):
    """Error con la forma de siempre: {"error": mensaje, …extra}."""

    def __init__(self, status: int, message, **extra):
        super().__init__(message)
        self.status, self.message, self.extra = status, message, extra


@dataclass(frozen=True)
class Policy:
    """Lo que protege una ruta; mismos campos que routing.Route."""
    public: bool = False
    admin: bool = False
    enrolment: bool = False
    action: str | None = None
    body: int = 256  # maximum JSON body (POST), as declared by the Content-Length


@dataclass(frozen=True)
class Context:
    """Petición ya autorizada: quién es y dónde están los datos. El negocio recibe esto, nunca el Request."""
    state: State
    user: dict | None
    session: dict | None
    locale: str

    def render(self, value):
        """Renders the messages in a module result for this reader."""
        return localize(value, self.locale)

    @property
    def data_dir(self) -> Path:
        return self.state.data_dir


def guard(policy: Policy = Policy()):
    """Dependencia FastAPI: aplica la política y devuelve el Context, o corta con el error de siempre."""
    def dependency(request: Request) -> Context:
        state: State = request.app.state.core
        verdict = authorize(state, policy, method=request.method, port=request.app.state.port,
                            origin=request.headers.get("origin"), action=request.headers.get("x-tamandua-action"),
                            cookie=request.headers.get("cookie"))
        if isinstance(verdict, Denied):
            raise ApiError(verdict.status, verdict.message, **verdict.extra)
        if request.method == "POST":
            try:
                length = int(request.headers.get("content-length", "0"))
            except ValueError:
                length = 0
            if length < 2 or length > policy.body:
                raise ApiError(400, msg("api.invalid_request"))
        user, session = verdict
        return Context(state, user, session, negotiate(request.headers.get("accept-language")))
    return dependency
