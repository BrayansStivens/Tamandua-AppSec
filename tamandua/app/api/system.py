"""Salud del servicio."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from tamandua.app.api.deps import Context, Policy, guard
from tamandua.modules.scanning.engines import docker_available
from tamandua.version import VERSION

router = APIRouter(tags=["sistema"])


class Health(BaseModel):
    status: str
    version: str
    docker: bool | None = None
    queued: int | None = None


@router.get("/api/health", response_model=Health, response_model_exclude_none=True)
def health(context: Context = Depends(guard(Policy(public=True, enrolment=True)))) -> Health:
    # Sin sesión la salud solo confirma que el proceso responde: nada del estado interno.
    if context.user is None:
        return Health(status="ok", version=VERSION)
    return Health(status="ok", version=VERSION, docker=docker_available(), queued=context.state.jobs.pending())
