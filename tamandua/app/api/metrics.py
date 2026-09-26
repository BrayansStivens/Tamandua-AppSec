"""Prometheus metrics for operators: queue, workers and recent runs.

Off unless `TAMANDUA_METRICS_TOKEN` is set (until then the route answers 404, as if it didn't exist). The scraper
sends the token as `Authorization: Bearer …`, compared in constant time. No session and no CSRF: it's a GET that
returns aggregates only (no identifiers, repository names or findings).
"""

from __future__ import annotations

import hmac
import os

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from tamandua.app.api.deps import ApiError
from tamandua.modules.runs import metrics
from tamandua.shared import log as logging_setup
from tamandua.shared.i18n import localize, msg, negotiate
from tamandua.version import VERSION

router = APIRouter(tags=["system"])

MIN_TOKEN = 32  # characters; `openssl rand -hex 32` gives 64
CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"
_warned: set[str] = set()


class Exposition(PlainTextResponse):
    media_type = CONTENT_TYPE


def configured_token() -> str | None:
    """The token, or None when metrics are off (unset, or too short to be a secret)."""
    token = os.environ.get("TAMANDUA_METRICS_TOKEN", "").strip()
    if len(token) >= MIN_TOKEN:
        return token
    if token and "short" not in _warned:
        _warned.add("short")
        logging_setup.get("metrics").warning("metrics_disabled: TAMANDUA_METRICS_TOKEN is shorter than %d characters", MIN_TOKEN)
    return None


def authorized(authorization: str | None) -> bool:
    token = configured_token()
    scheme, _, presented = (authorization or "").partition(" ")
    return token is not None and scheme.lower() == "bearer" and hmac.compare_digest(presented.strip().encode(), token.encode())


@router.get("/api/metrics", response_class=Exposition, openapi_extra={"security": [{"metrics": []}]},
            responses={200: {"description": "Prometheus text exposition format"},
                       401: {"description": "Missing or wrong bearer token"},
                       404: {"description": "Metrics are off (TAMANDUA_METRICS_TOKEN is not set)"}})
def prometheus(request: Request):
    if configured_token() is None:
        raise ApiError(404, msg("api.not_found"))
    if not authorized(request.headers.get("authorization")):
        body = localize({"error": msg("api.metrics_token_required")}, negotiate(request.headers.get("accept-language")))
        return JSONResponse(body, status_code=401, headers={"www-authenticate": 'Bearer realm="tamandua-metrics"'})
    return Exposition(render(metrics.snapshot(request.app.state.core.data_dir)))


def _number(value) -> str:
    if value is None:
        return "NaN"
    return repr(float(value)) if isinstance(value, float) else str(int(value))


def _label(value) -> str:
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def render(data: dict) -> str:
    """Text exposition format 0.0.4: HELP and TYPE per family, then its samples."""
    lines: list[str] = []

    def family(name: str, help_text: str, samples: list[tuple[dict, object]]) -> None:
        lines.extend((f"# HELP {name} {help_text}", f"# TYPE {name} gauge"))
        for labels, value in samples:
            rendered = ",".join(f'{key}="{_label(item)}"' for key, item in labels.items())
            lines.append(f"{name}{{{rendered}}} {_number(value)}" if rendered else f"{name} {_number(value)}")

    workers, runs = data["workers"], data["runs"]
    family("tamandua_info", "Tamandua version serving this endpoint.", [({"version": VERSION}, 1)])
    family("tamandua_jobs", "Jobs in the queue by status.", [({"status": status}, count) for status, count in data["jobs"].items()])
    family("tamandua_jobs_failed_24h", "Jobs that failed in the last 24 hours.", [({}, data["jobs_failed_window"])])
    family("tamandua_jobs_oldest_queued_age_seconds", "Age of the oldest queued job; 0 when nothing is waiting.",
           [({}, data["oldest_queued_seconds"])])
    family("tamandua_workers_alive", "Workers with a recent heartbeat.", [({}, workers["alive"])])
    family("tamandua_workers_docker", "Live workers that can start the analysis engines (Docker reachable).",
           [({}, workers["docker"])])
    family("tamandua_worker_last_heartbeat_age_seconds", "Seconds since the most recent worker heartbeat; NaN if none ever.",
           [({}, workers["last_heartbeat_seconds"])])
    family("tamandua_runs_24h", "Runs created in the last 24 hours by type and status.",
           [({"type": row["type"], "status": row["status"]}, row["total"]) for row in runs])
    family("tamandua_run_duration_seconds_24h", "Duration of the runs created in the last 24 hours that finished: "
           "quantiles 0.5 and 0.95, and the maximum as quantile 1.",
           [({"type": row["type"], "status": row["status"], "quantile": f"{q:g}"}, value)
            for row in runs if row["timed"] for q, value in (*row["quantiles"].items(), (1, row["max"]))])
    return "\n".join(lines) + "\n"
