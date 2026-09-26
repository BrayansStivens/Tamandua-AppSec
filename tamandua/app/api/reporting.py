"""Resumen (dashboard)."""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from tamandua.app.api.deps import Context, guard
from tamandua.modules.reporting.dashboard import cached, zone

router = APIRouter(tags=["resumen"])


class Dashboard(BaseModel):
    window_days: int
    generated_at: str
    kpis: dict[str, Any]
    issues_over_time: list[dict[str, Any]]
    open_vs_fixed: list[dict[str, Any]]
    top_assets: list[dict[str, Any]]
    by_cwe: list[dict[str, Any]]
    exploitability: dict[str, Any]
    activity: list[dict[str, Any]]
    recent_runs: list[dict[str, Any]]
    top_issues: list[dict[str, Any]]
    kev_news: dict[str, Any]
    cve_news: dict[str, Any]
    tools: list[dict[str, Any]]


@router.get("/api/dashboard", response_model=Dashboard)
def dashboard(days: Literal[7, 30, 90, 365] = 30, tz: str | None = None, context: Context = Depends(guard())) -> dict:
    return cached(context.data_dir, days, zone(tz))
