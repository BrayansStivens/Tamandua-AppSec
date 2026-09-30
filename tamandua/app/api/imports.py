"""Findings from other tools (SARIF 2.1.0) into an existing asset: from the panel, or from CI with a token.

`POST /api/imports/sarif` is the panel's: session, CSRF action `import-sarif`, any member (like launching a scan).
`POST /api/ci/sarif` is for pipelines: no session and no CSRF, `Authorization: Bearer <TAMANDUA_IMPORT_TOKEN>`
compared in constant time; off (404) until that token is set with at least 32 characters. Its body is the same
envelope as the panel's or, when the query names the asset (`?asset=…`), the SARIF document itself. Both accept
up to 10 MB (`MAX_BYTES`), the one exception to the API's global body cap.
"""

from __future__ import annotations

import hmac
import json
import re
from typing import Any, Literal

from fastapi import APIRouter, Depends, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, StrictStr

from tamandua.app.api.deps import ApiError, Context, Policy, body, documented, guard, parse
from tamandua.modules.runs.imports import ASSET_MAX, ImportRefused, import_sarif
from tamandua.modules.scanning.sarif_import import MAX_BYTES, MAX_RUNS, TOOL_MAX
from tamandua.shared import settings
from tamandua.shared.i18n import localize, msg, negotiate

router = APIRouter(tags=["imports"])
MIN_TOKEN = 32
PATHS = ("/api/imports/sarif", "/api/ci/sarif")
QUERY = ("asset", "tool", "scope", "commit", "branch")


class SarifImportIn(BaseModel):
    """Where the findings go and how far the import vouches for the tool (`full` fixes what it no longer reports)."""
    model_config = ConfigDict(extra="forbid")
    asset: StrictStr = Field(min_length=1, max_length=ASSET_MAX, description="Asset key or name (e.g. owner/repo)")
    tool: StrictStr | None = Field(None, min_length=1, max_length=TOOL_MAX, description="Overrides runs[].tool.driver.name")
    scope: Literal["full", "partial"] = "full"
    commit: StrictStr | None = Field(None, min_length=7, max_length=64)
    branch: StrictStr | None = Field(None, min_length=1, max_length=255)
    sarif: dict[str, Any] = Field(description="SARIF 2.1.0 document")


class SarifDocument(BaseModel):
    """A bare SARIF 2.1.0 document (CI route, with the asset in the query)."""
    version: Literal["2.1.0"]
    runs: list[dict[str, Any]] = Field(max_length=MAX_RUNS)


class ImportedRun(BaseModel):
    """The `sarif_import` run created for one tool, and what it changed in the asset's registry."""
    id: str
    tool: str
    version: str | None
    scope: str
    status: str
    findings: int
    excluded: int
    skipped: int
    opened: int
    fixed: int


class SarifImportResult(BaseModel):
    asset: str
    name: str
    runs: list[ImportedRun] = Field(max_length=MAX_RUNS)


def _run(context_data_dir, data: SarifImportIn, requested_by: str) -> dict:
    try:
        return import_sarif(context_data_dir, data.sarif, asset=data.asset, tool=data.tool, scope=data.scope, commit=data.commit,
                            branch=data.branch, requested_by=requested_by)
    except ImportRefused as exc:
        raise ApiError(exc.status, exc.message) from exc


RESPONSES: dict[int | str, dict[str, Any]] = {404: {"description": "Unknown asset"}, 409: {"description": "The name matches several assets"}}


@router.post("/api/imports/sarif", response_model=SarifImportResult, openapi_extra=documented(SarifImportIn), responses=RESPONSES)
def panel_import(context: Context = Depends(guard(Policy(action="import-sarif", body=MAX_BYTES))),
                 data: SarifImportIn = Depends(body(SarifImportIn, msg("runs.imports.errors.invalid_request")))) -> dict:
    """Imports another tool's findings into an asset that already exists; one run per tool in the document."""
    return context.render(_run(context.data_dir, data, (context.user or {}).get("username") or "?"))


def _token() -> str | None:
    token = settings.text("TAMANDUA_IMPORT_TOKEN")
    return token if len(token) >= MIN_TOKEN else None


def _actor(value: str | None) -> str:
    actor = re.sub(r"[^A-Za-z0-9._@/+-]", "", value or "")[:64]
    return f"ci:{actor}" if actor else "ci"


CI_EXTRA = {**documented(SarifImportIn, SarifDocument), "security": [{"import": []}],
            "parameters": [{"name": name, "in": "query", "required": False, "schema": {"type": "string", "maxLength": 255},
                            "description": "With a bare SARIF body: " + name} for name in QUERY]
            + [{"name": "X-Tamandua-Actor", "in": "header", "required": False, "schema": {"type": "string", "maxLength": 64},
                "description": "Who triggered the pipeline, recorded as requested_by ci:<actor>"}]}


@router.post("/api/ci/sarif", response_model=SarifImportResult, openapi_extra=CI_EXTRA,
             responses={**RESPONSES, 401: {"description": "Missing or wrong bearer token"},
                        404: {"description": "Off (no TAMANDUA_IMPORT_TOKEN), or unknown asset"}})
async def ci_import(request: Request):
    """The same import for a pipeline, authenticated by TAMANDUA_IMPORT_TOKEN instead of a session."""
    token = _token()
    if token is None:
        raise ApiError(404, msg("api.not_found"))
    scheme, _, presented = (request.headers.get("authorization") or "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(presented.strip().encode(), token.encode()):
        payload = localize({"error": msg("api.import_token_required")}, negotiate(request.headers.get("accept-language")))
        return JSONResponse(payload, status_code=401, headers={"www-authenticate": 'Bearer realm="tamandua-import"'})
    try:
        length = int(request.headers.get("content-length", "0"))
    except ValueError:
        length = 0
    if length < 2 or length > MAX_BYTES:
        raise ApiError(400, msg("api.invalid_request"))
    try:
        document = json.loads(await request.body())
    except (ValueError, RecursionError) as exc:  # not JSON, not UTF-8, or nested too deep
        raise ApiError(400, msg("api.invalid_json")) from exc
    invalid = msg("runs.imports.errors.invalid_request")
    query = request.query_params
    if "asset" in query:
        envelope = {name: query[name] for name in QUERY if name in query} | {"sarif": document}
    else:
        envelope = document
    data = parse(SarifImportIn, envelope, invalid)
    result = await run_in_threadpool(_run, request.app.state.core.data_dir, data, _actor(request.headers.get("x-tamandua-actor")))
    return localize(result, negotiate(request.headers.get("accept-language")))
