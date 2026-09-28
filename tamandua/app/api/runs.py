"""Runs: the list, one run and its downloads (reports, SARIF, SBOM, VEX, tickets). The asset exports reuse `download`."""

from __future__ import annotations

import json
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

from tamandua.app.api.deps import ApiError, Context, guard
from tamandua.app.api.schemas import AS_RETURNED, MANY, RunDetail, RunRow
from tamandua.modules.compliance import sbom, vex
from tamandua.modules.findings import triage
from tamandua.modules.findings import tickets
from tamandua.modules.reporting.pdf import render_pdf
from tamandua.modules.reporting.technical import render_technical_pdf
from tamandua.modules.findings.kinds import FINDING_RUNS, FULL_SCANS
from tamandua.modules.runs.store import artifact as store_artifact, find_runs, load_run, page_runs, profile_pdf_titles
from tamandua.modules.runs.store import render_asset_report, render_profile_report, render_repository_report, render_repository_sarif
from tamandua.modules.runs.store import render_tickets
from tamandua.shared.i18n import msg
from tamandua.version import VERSION

router = APIRouter(tags=["runs"])

PROFILE_REPORTS = ("report-soc2.md", "report-iso27001.md", "report-custom.md",
                   "report-soc2.pdf", "report-iso27001.pdf", "report-custom.pdf")
SBOM_FILE, VEX_FILE = "sbom.cdx.json", "vex.openvex.json"
MARKDOWN = "text/markdown; charset=utf-8"
PAGE_MAX = 200  # page_runs caps a page here


def _binary(limit: int) -> dict:
    return {"schema": {"type": "string", "format": "binary", "maxLength": limit}}


DOWNLOADS = {200: {"description": "The file: Markdown or PDF report, SARIF, CycloneDX SBOM, OpenVEX or Jira tickets (JSON)",
                   "content": {"application/json": {"schema": {}}, "text/markdown": _binary(50_000_000),
                               "application/pdf": _binary(50_000_000), "application/sarif+json": _binary(100_000_000),
                               "application/vnd.cyclonedx+json": _binary(100_000_000)}},
             404: {"description": "Run not found, or that format isn't available for it"}}


def _json_file(payload: dict, content_type: str) -> Response:
    return Response(json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8"), headers={"content-type": content_type})


def _send(payload: bytes, content_type: str) -> Response:
    return Response(payload, headers={"content-type": content_type})


def download(context: Context, record: dict, artifact: str, title: str) -> Response:
    """A run's (or an asset state's) file, rendered in the reader's language."""
    locale, data_dir = context.locale, context.data_dir
    repository = record.get("type") in FINDING_RUNS or record.get("type") == "asset_state"
    if artifact == "tickets.json" and repository:
        return JSONResponse(context.render(render_tickets(record, locale=locale)))
    if artifact in ("report.md", "report.pdf") and repository:
        if artifact.endswith(".pdf"):
            return _send(render_technical_pdf(record, version=VERSION, locale=locale), "application/pdf")
        report = (render_asset_report(record, locale=locale) if record["type"] == "asset_state"
                  else render_repository_report(record, locale=locale))
        return _send(report.encode("utf-8"), MARKDOWN)
    if artifact == "findings.sarif" and repository:
        return _send(json.dumps(render_repository_sarif(record, locale=locale), ensure_ascii=False, indent=2).encode("utf-8"),
                     "application/sarif+json")
    if artifact == SBOM_FILE and repository:
        scan = sbom.latest_scan(data_dir, record["source"]["id"]) if record["type"] == "asset_state" else record
        if scan is None or scan.get("type") not in FULL_SCANS or scan.get("status") != "completed":
            raise ApiError(404, msg("compliance.sbom.needs_full_scan"))
        return _json_file(sbom.cyclonedx(scan, version=VERSION, locale=locale), "application/vnd.cyclonedx+json")
    if artifact == VEX_FILE and repository:
        return _json_file(vex.openvex(record, version=VERSION, locale=locale), "application/json")
    if artifact in PROFILE_REPORTS:
        profile = artifact.removeprefix("report-").rsplit(".", 1)[0]
        report = render_profile_report(record, profile, title, locale=locale)
        if artifact.endswith(".pdf"):
            return _send(render_pdf(report, **profile_pdf_titles(profile, locale=locale), reference=record["id"], locale=locale),
                         "application/pdf")
        return _send(report.encode("utf-8"), MARKDOWN)
    if artifact in ("report.md", "findings.sarif"):
        return _send(store_artifact(data_dir, record["id"], artifact), MARKDOWN if artifact == "report.md" else "application/sarif+json")
    raise ApiError(404, msg("api.format_unavailable_run"))


class RunPage(BaseModel):
    items: list[RunRow] = Field(max_length=PAGE_MAX)
    total: int
    limit: int
    offset: int


@router.get("/api/runs", response_model=Annotated[list[RunRow], Field(max_length=MANY)], **AS_RETURNED)
def runs(context: Context = Depends(guard())) -> list[dict]:
    """The rows of the newest runs (at most 10 000), newest first. To go through all of them, /api/runs/page."""
    return context.render(find_runs(context.data_dir, limit=MANY))


@router.get("/api/runs/page", response_model=RunPage, **AS_RETURNED)
def runs_page(limit: str = "25", offset: str = "0", status: str = "", kind: str = Query("", alias="type"), q: str = "",
              asset: str = "", context: Context = Depends(guard())) -> dict:
    """`type` accepts several kinds separated by commas. Paging values out of range are clamped."""
    try:
        size, start = int(limit or "25"), int(offset or "0")
    except ValueError:
        raise ApiError(400, msg("api.invalid_paging")) from None
    return context.render(page_runs(context.data_dir, limit=size, offset=start, status=status or None, kind=kind or None,
                                    query=q[:100] or None, asset=asset[:200] or None))


def _record(context: Context, run_id: str) -> dict:
    # A code review's views reflect the current triage, not the one on the day of the scan.
    return tickets.annotate(context.data_dir, triage.annotate(context.data_dir, load_run(context.data_dir, run_id)))


@router.get("/api/runs/{run_id}", response_model=RunDetail, **AS_RETURNED)
def run_detail(run_id: str, context: Context = Depends(guard())) -> dict[str, Any]:
    try:
        return context.render(_record(context, run_id))
    except (ValueError, OSError, json.JSONDecodeError):
        raise ApiError(404, msg("api.run_not_found")) from None


@router.get("/api/runs/{run_id}/{artifact:path}", response_class=Response, responses=DOWNLOADS)
def run_artifact(run_id: str, artifact: str, title: str = "", context: Context = Depends(guard())) -> Response:
    """`title` names a compliance profile report (report-<profile>.md|pdf)."""
    try:
        return download(context, _record(context, run_id), artifact, title)
    except (ValueError, OSError, json.JSONDecodeError):
        raise ApiError(404, msg("api.run_not_found")) from None


@router.get("/api/runs/{rest:path}", include_in_schema=False)
def run_unknown(context: Context = Depends(guard())) -> None:
    """Anything else under /api/runs/ (an empty ID) is a run that doesn't exist, as before."""
    raise ApiError(404, msg("api.run_not_found"))
