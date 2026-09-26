"""Seguridad y contexto de las rutas FastAPI: la misma tubería que el router clásico (core.authorize)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from fastapi import Request

from tamandua.app.http.core import Denied, State, authorize


class ApiError(Exception):
    """Error con la forma de siempre: {"error": mensaje, …extra}."""

    def __init__(self, status: int, message: str, **extra):
        super().__init__(message)
        self.status, self.message, self.extra = status, message, extra


@dataclass(frozen=True)
class Policy:
    """Lo que protege una ruta; mismos campos que core.Route."""
    public: bool = False
    admin: bool = False
    enrolment: bool = False
    action: str | None = None


@dataclass(frozen=True)
class Context:
    """Petición ya autorizada: quién es y dónde están los datos. El negocio recibe esto, nunca el Request."""
    state: State
    user: dict | None
    session: dict | None

    @property
    def data_dir(self) -> Path:
        return self.state.data_dir


def guard(policy: Policy = Policy()):
    """Dependencia FastAPI: aplica la política y devuelve el Context, o corta con el error de siempre."""
    def dependency(request: Request) -> Context:
        state: State = request.app.state.legacy
        verdict = authorize(state, policy, method=request.method, port=request.app.state.port,
                            origin=request.headers.get("origin"), action=request.headers.get("x-appsec-agent-action"),
                            cookie=request.headers.get("cookie"))
        if isinstance(verdict, Denied):
            raise ApiError(verdict.status, verdict.message, **verdict.extra)
        user, session = verdict
        return Context(state, user, session)
    return dependency
