"""Resumen (dashboard)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from tamandua.app.api.deps import ApiError, Context, guard
from tamandua.modules.reporting import dashboard as summary
from tamandua.shared.i18n import msg

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
