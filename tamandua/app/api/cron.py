"""One round of the periodic tasks, for an external scheduler (TAMANDUA_PERIODIC=external), e.g. Vercel Cron.

Off unless `TAMANDUA_CRON_TOKEN` (or `CRON_SECRET`, what Vercel sends) is set: until then the route answers 404. The
scheduler sends `Authorization: Bearer <token>`, compared in constant time. No session and no CSRF: it's a GET (as
Vercel Cron calls it) that only runs what is due and answers task names, never data. Tasks that need the engines are
queued for a worker.
"""

from __future__ import annotations

import hmac

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from tamandua.app.api.deps import ApiError
from tamandua.modules.runs import periodic
from tamandua.shared import settings
from tamandua.shared.i18n import localize, msg, negotiate

router = APIRouter(tags=["system"])
MIN_TOKEN = 32


class Round(BaseModel):
    ran: list[str] = Field(max_length=len(periodic.TASKS))
    queued: list[str] = Field(max_length=len(periodic.TASKS))
    failed: list[str] = Field(max_length=len(periodic.TASKS))


def _tokens() -> list[str]:
    return [token for token in (settings.text("TAMANDUA_CRON_TOKEN"), settings.text("CRON_SECRET")) if len(token) >= MIN_TOKEN]


@router.get("/api/cron", response_model=Round, openapi_extra={"security": [{"cron": []}]},
            responses={401: {"description": "Missing or wrong bearer token"},
                       404: {"description": "Off: no TAMANDUA_CRON_TOKEN / CRON_SECRET"}})
def cron(request: Request):
    tokens = _tokens()
    if not tokens:
        raise ApiError(404, msg("api.not_found"))
    scheme, _, presented = (request.headers.get("authorization") or "").partition(" ")
    if scheme.lower() != "bearer" or not any(hmac.compare_digest(presented.strip().encode(), token.encode()) for token in tokens):
        body = localize({"error": msg("api.cron_token_required")}, negotiate(request.headers.get("accept-language")))
        return JSONResponse(body, status_code=401, headers={"www-authenticate": 'Bearer realm="tamandua-cron"'})
    state = request.app.state.core
    return periodic.run_round(state.data_dir, state.jobs, here_only=True)
