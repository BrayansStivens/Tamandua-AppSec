"""Service health."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from tamandua.app.api.deps import Context, Policy, guard
from tamandua.modules.runs import queue
from tamandua.version import VERSION

router = APIRouter(tags=["system"])


class Health(BaseModel):
    status: str                  # ok · degraded (signed in only: no worker heartbeat, so nothing gets scanned)
    version: str
    docker: bool | None = None   # some live worker can launch the engines
    workers: int | None = None   # workers with a recent heartbeat
    queued: int | None = None


# Public: without a session it only says it responds; with one, also the workers' state.
@router.get("/api/health", response_model=Health, response_model_exclude_none=True,
            openapi_extra={"security": [{}, {"session": []}]})
def health(context: Context = Depends(guard(Policy(public=True, enrolment=True)))) -> Health:
    # Without a session, health only confirms the process responds: nothing about internal state.
    if context.user is None:
        return Health(status="ok", version=VERSION)
    # The worker launches the engines (the API may have no Docker): health comes from its heartbeat.
    alive = queue.workers_alive(context.data_dir)
    # Still 200: the API itself works (the container healthcheck restarts only a dead API, not one waiting for a worker).
    return Health(status="ok" if alive else "degraded", version=VERSION, docker=any(worker["docker"] for worker in alive),
                  workers=len(alive), queued=context.state.jobs.pending())
