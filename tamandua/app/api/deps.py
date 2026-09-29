"""Route security and context: every route applies `guard(Policy)`, which runs `security.authorize`."""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, TypeVar

from fastapi import Depends, Request
from pydantic import BaseModel, TypeAdapter, ValidationError

from tamandua.app.api.security import Denied, State, authorize
from tamandua.shared.i18n import localize, msg, negotiate


class ApiError(Exception):
    """Error in the usual shape: {"error": message, …extra}."""

    def __init__(self, status: int, message, **extra):
        super().__init__(message)
        self.status, self.message, self.extra = status, message, extra


@dataclass(frozen=True)
class Policy:
    """What protects a route: public, admin, TOTP enrolment, CSRF action and body limit."""
    public: bool = False
    admin: bool = False
    enrolment: bool = False
    action: str | None = None
    body: int = 256  # maximum JSON body (POST), as declared by the Content-Length


@dataclass(frozen=True)
class Context:
    """An authorized request: who is asking and where the data lives. Business code gets this, never the Request."""
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
    """FastAPI dependency: applies the policy and returns the Context, or stops with the usual error."""
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
    dependency.policy = policy  # lets the tests walk every route with what protects it
    return dependency


Model =TypeVar("Model", bound=BaseModel)


async def json_body(request: Request) -> Any:
    """The JSON body whatever its Content-Type, as the table routes read it; not JSON is the usual 400. Declare it after
    the route's guard: FastAPI solves dependencies in order, so the body is only read once the request is authorized."""
    try:
        return json.loads(await request.body())
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ApiError(400, msg("api.invalid_json")) from exc


@lru_cache(maxsize=None)
def _adapter(schema) -> TypeAdapter:
    return TypeAdapter(schema)


def parse(schema, payload, invalid):
    """`payload` as `schema` (a Pydantic model or a union of them), or a 400 with the route's own `invalid` message."""
    try:
        return _adapter(schema).validate_python(payload)
    except ValidationError as exc:
        raise ApiError(400, invalid) from exc


def body(model: type[Model], invalid):
    """Dependency: the JSON body validated by `model`; one that doesn't fit is a 400 with the route's own `invalid`."""
    def dependency(data: Any = Depends(json_body)) -> Model:
        return parse(model, data, invalid)
    return dependency


def _inline(schema, definitions: dict):
    if isinstance(schema, dict):
        reference = schema.get("$ref", "")
        if reference.startswith("#/$defs/"):
            return _inline(definitions[reference.removeprefix("#/$defs/")], definitions)
        return {key: _inline(value, definitions) for key, value in schema.items() if key != "$defs"}
    if isinstance(schema, list):
        return [_inline(item, definitions) for item in schema]
    return schema


def documented(*models) -> dict:
    """`openapi_extra` for a body read with `json_body`/`body` (FastAPI doesn't see it): one model, or any of several."""
    schemas = []
    for model in models:
        schema = model.model_json_schema()
        schemas.append(_inline(schema, schema.get("$defs", {})))
    schema = schemas[0] if len(schemas) == 1 else {"anyOf": schemas}
    return {"requestBody": {"required": True, "content": {"application/json": {"schema": schema}}}}


def problem(exc: Exception):
    """What an exception tells the reader: its message (rendered per request) or, failing that, its text."""
    message = getattr(exc, "message", None)
    if message:
        return message
    first = exc.args[0] if exc.args else None
    return first if isinstance(first, dict) else str(exc)
