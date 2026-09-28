"""First steps, worked out from the real state (nothing is ticked by hand): the Summary shows them until they are done."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from tamandua.app.api.deps import Context, guard
from tamandua.app.demo import DEMO_SOURCE_ID
from tamandua.modules.integrations import notifications
from tamandua.modules.integrations.installations import github_installations
from tamandua.modules.pullrequests import watch as pr_watch
from tamandua.modules.findings.kinds import FULL_SCANS
from tamandua.modules.runs.store import find_runs

router = APIRouter(tags=["onboarding"])


class Onboarding(BaseModel):
    mfa: bool
    github: bool
    analyzed: bool  # a completed full scan of your own code (the demo doesn't count)
    demo: bool
    watching: bool
    alerts: bool
    admin: bool


@router.get("/api/onboarding", response_model=Onboarding)
def onboarding(context: Context = Depends(guard())) -> dict:
    user, data_dir = context.user, context.data_dir
    runs = find_runs(data_dir, types=FULL_SCANS)
    try:
        alerts = bool(notifications.channels())
    except Exception:  # noqa: BLE001 — without a readable vault the step simply stays pending
        alerts = False
    return {
        "mfa": bool((user.get("totp") or {}).get("enabled")),
        "github": bool(github_installations(data_dir)),
        "analyzed": any(row["type"] in FULL_SCANS and row["status"] == "completed"
                        and (row.get("source") or {}).get("id") != DEMO_SOURCE_ID for row in runs),
        "demo": any((row.get("source") or {}).get("id") == DEMO_SOURCE_ID for row in runs),
        "watching": any(config.get("enabled") for config in pr_watch.load(data_dir, reviews=False)["repositories"].values()),
        "alerts": alerts, "admin": user.get("role") == "admin"}
