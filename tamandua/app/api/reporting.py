"""Resumen (dashboard) e informe de evidencia para auditoría."""

from __future__ import annotations

import re
from typing import Any, Literal

from fastapi import APIRouter, Depends
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field

from tamandua.app.api.deps import ApiError, Context, Policy, documented, guard, json_body
from tamandua.app.api.deps import problem
from tamandua.modules.compliance import cra, evidence
from tamandua.modules.findings import registry as findings_registry
from tamandua.modules.findings import triage
from tamandua.modules.integrations.github import GitHubAppError
from tamandua.modules.integrations.installations import github_installations
from tamandua.modules.reporting import dashboard as summary
from tamandua.modules.reporting.audit import ReportError, render_audit_pdf, render_portfolio_pdf, validate_options
from tamandua.modules.findings.kinds import FINDING_RUNS
from tamandua.modules.runs.store import load_run
from tamandua.modules.runs.assets import overview as assets_overview
from tamandua.shared.i18n import msg, text
from tamandua.version import VERSION

router = APIRouter(tags=["dashboard"])
WINDOWS = (7, 30, 90, 365)
DAYS_SHOWN = max(WINDOWS) + 1  # a window's series has one point per day, today included


class Dashboard(BaseModel):
    window_days: int
    generated_at: str
    kpis: dict[str, Any]
    issues_over_time: list[dict[str, Any]] = Field(max_length=DAYS_SHOWN)
    open_vs_fixed: list[dict[str, Any]] = Field(max_length=DAYS_SHOWN)
    top_assets: list[dict[str, Any]] = Field(max_length=summary.TOP_ASSETS)
    by_cwe: list[dict[str, Any]] = Field(max_length=summary.TOP_CWES)
    exploitability: dict[str, Any]
    activity: list[dict[str, Any]] = Field(max_length=summary.ACTIVITY_DAYS)
    recent_runs: list[dict[str, Any]] = Field(max_length=summary.RECENT_RUNS)
    top_issues: list[dict[str, Any]] = Field(max_length=summary.TOP_ISSUES)
    kev_news: dict[str, Any]
    cve_news: dict[str, Any]
    tools: list[dict[str, Any]] = Field(max_length=summary.MAX_TOOLS)


@router.get("/api/dashboard", response_model=Dashboard)
def dashboard(days: int = 30, tz: str | None = None, context: Context = Depends(guard())) -> dict:
    # Entero y comprobado a mano: un Literal[7, 30, …] rechazaba el «30» que llega como texto en la URL.
    if days not in WINDOWS:
        raise ApiError(400, msg("api.invalid_window"))
    return context.render(summary.cached(context.data_dir, days, summary.zone(tz)))


MAX_FINGERPRINTS, MAX_ASSETS = 5000, 500
SCOPES = ("run_id", "asset", "account", "assets")


class AuditReportIn(BaseModel):
    """Exactly one scope: a run, an asset's state, an organization (`account`) or a selection of assets."""
    model_config = ConfigDict(extra="forbid")
    run_id: str | None = Field(None, pattern="^[0-9a-f]{32}$")
    asset: str | None = Field(None, max_length=200)
    account: str | None = Field(None, max_length=100)
    assets: list[str] | None = Field(None, min_length=1, max_length=MAX_ASSETS)
    status: Literal["open", "fixed", "all"] | None = None
    fingerprints: list[str] | None = Field(None, max_length=MAX_FINGERPRINTS)
    options: dict[str, Any] | None = None


PDF = {200: {"description": "Audit evidence (PDF)",
             "content": {"application/pdf": {"schema": {"type": "string", "format": "binary", "maxLength": 50_000_000}}}}}


@router.post("/api/reports/audit", response_class=Response, responses=PDF, openapi_extra=documented(AuditReportIn))
def audit_report(context: Context = Depends(guard(Policy(action="audit-report", body=400_000))),
                 data: Any = Depends(json_body)) -> Response:
    """Audit evidence of a run or an asset's state, with the chosen findings (`fingerprints`; all of the scope without it).

    Same access as seeing that run or asset."""
    if not isinstance(data, dict) or not set(data) <= set(AuditReportIn.model_fields) or sum(key in data for key in SCOPES) != 1:
        raise ApiError(400, msg("api.audit_scope"))
    if "account" in data or "assets" in data:
        return _portfolio_report(context, data)
    chosen = data.get("fingerprints")
    if chosen is not None and (not isinstance(chosen, list) or len(chosen) > MAX_FINGERPRINTS
                               or not all(isinstance(item, str) and 0 < len(item) <= 128 for item in chosen)):
        raise ApiError(400, msg("api.invalid_selection", max=MAX_FINGERPRINTS))
    try:
        if "run_id" in data:
            run_id = data["run_id"]
            if not isinstance(run_id, str) or not re.fullmatch(r"[0-9a-f]{32}", run_id):
                raise ApiError(400, msg("api.invalid_run"))
            record = triage.annotate(context.data_dir, load_run(context.data_dir, run_id))
            if record.get("type") not in FINDING_RUNS:
                raise ApiError(400, msg("api.run_without_findings"))
        else:
            key, status = data["asset"], data.get("status", "open")
            if not isinstance(key, str) or not key or len(key) > 200 or status not in ("open", "fixed", "all"):
                raise ApiError(400, msg("api.invalid_asset_status"))
            if not any(row["key"] == key for row in assets_overview(context.data_dir)):
                raise ApiError(404, msg("api.asset_not_found"))
            record = findings_registry.view(context.data_dir, key, status=status)
    except (FileNotFoundError, ValueError):
        raise ApiError(404, msg("api.run_not_found")) from None
    findings = record.get("findings") or []
    if chosen is not None:
        wanted = set(chosen)
        findings = [item for item in findings if item.get("fingerprint") in wanted]
    user = context.user
    try:
        options = validate_options(data.get("options"), default_by=user.get("display_name") or user["username"])
        cra.check_framework(context.data_dir, options["framework"])
        pdf = render_audit_pdf(record, findings, options, version=VERSION, locale=context.locale)
    except (ReportError, cra.CraError) as exc:
        raise ApiError(400, problem(exc)) from exc
    context.state.log.info("audit_report", extra={"user": user["username"], "reason": f"{record['id']}: {len(findings)} hallazgos, {options['framework']}"})
    return Response(pdf, headers={"content-type": "application/pdf"})


def _portfolio_report(context: Context, data: dict) -> Response:
    """Consolidated report: an organization (with its coverage against GitHub) or a selection of repositories."""
    rows = assets_overview(context.data_dir)
    coverage: dict = {"total": None, "missing": []}
    if "account" in data:
        account = data["account"]
        if not isinstance(account, str) or not account or len(account) > 100:
            raise ApiError(400, msg("api.invalid_organization"))
        prefix = f"{account.casefold()}/"
        chosen = [row for row in rows if (row.get("name") or "").casefold().startswith(prefix)]
        scope = text(msg("api.scope.organization", account=account), context.locale)
        # Is everything analyzed? Checked against the organization's real list in the GitHub App.
        from tamandua.modules.integrations.github import installation_info, installation_repositories
        for installation in github_installations(context.data_dir):
            try:
                if (installation_info(installation).get("account") or "").casefold() != account.casefold():
                    continue
                names = [repo["name"] for repo in installation_repositories(installation) if not repo.get("archived")]
            except GitHubAppError:
                break
            analysed = {(row.get("name") or "").casefold() for row in chosen}
            coverage = {"total": len(names), "missing": sorted(name for name in names if name.casefold() not in analysed)}
            break
    else:
        keys = data["assets"]
        if not isinstance(keys, list) or not 1 <= len(keys) <= MAX_ASSETS or not all(isinstance(key, str) and len(key) <= 200 for key in keys):
            raise ApiError(400, msg("api.choose_repositories", max=MAX_ASSETS))
        wanted = set(keys)
        chosen = [row for row in rows if row["key"] in wanted]
        scope = text(msg("api.scope.repositories", count=len(chosen)), context.locale)
    if not chosen:
        raise ApiError(404, msg("api.no_analyzed_in_scope"))
    status = data.get("status", "all")
    if status not in ("open", "all"):
        raise ApiError(400, msg("api.invalid_status"))
    items = evidence.portfolio(context.data_dir, chosen, status=status)
    user = context.user
    try:
        options = validate_options(data.get("options"), default_by=user.get("display_name") or user["username"])
        cra.check_framework(context.data_dir, options["framework"])
        pdf = render_portfolio_pdf(items, options, version=VERSION, scope_label=scope, coverage=coverage, locale=context.locale)
    except (ReportError, cra.CraError) as exc:
        raise ApiError(400, problem(exc)) from exc
    context.state.log.info("audit_report", extra={"user": user["username"], "reason": f"{scope}: {len(items)} repositorios, {options['framework']}"})
    return Response(pdf, headers={"content-type": "application/pdf"})
