"""Salud del servicio."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from tamandua.app.api.deps import Context, Policy, guard
from tamandua.modules.runs import queue
from tamandua.version import VERSION

router = APIRouter(tags=["sistema"])


class Health(BaseModel):
    status: str
    version: str
    docker: bool | None = None   # algún worker vivo puede lanzar los motores
    workers: int | None = None   # workers con latido reciente
    queued: int | None = None


@router.get("/api/health", response_model=Health, response_model_exclude_none=True)
def health(context: Context = Depends(guard(Policy(public=True, enrolment=True)))) -> Health:
    # Sin sesión la salud solo confirma que el proceso responde: nada del estado interno.
    if context.user is None:
        return Health(status="ok", version=VERSION)
    # Los motores los lanza el worker (el API puede no tener Docker): la salud sale de su latido.
    alive = queue.workers_alive(context.data_dir)
    return Health(status="ok", version=VERSION, docker=any(worker["docker"] for worker in alive), workers=len(alive),
                  queued=context.state.jobs.pending())
