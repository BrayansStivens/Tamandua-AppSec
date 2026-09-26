"""Kit CRA: productos bajo el Reglamento de Ciberresiliencia y relojes de notificación (ver appsec_agent/cra.py)."""

from __future__ import annotations

from .. import cra
from ..assets import asset_key, overview as assets_overview
from ..kinds import FULL_SCANS
from ..store import list_runs
from .core import Request, route


@route("GET", "/api/cra")
def cra_state(request: Request):
    """Lo ve cualquier sesión (el equipo necesita saber qué vence); solo un administrador lo cambia."""
    assets = {row["key"]: row.get("name") or row["key"] for row in assets_overview(request.data_dir)}
    # Sin un análisis completo terminado, «nada por notificar» no significaría nada: se dice por producto.
    complete: dict[str, str] = {}
    for row in list_runs(request.data_dir):  # de más reciente a más antiguo
        if row["type"] in FULL_SCANS and row["status"] == "completed":
            complete.setdefault(asset_key(row), row["created_at"])
    products = [{"key": key, **product, "asset": assets.get(key, key), "last_complete": complete.get(key)}
                for key, product in cra.load(request.data_dir)["products"].items()]
    events = [{**event, "draft": cra.draft(event)} for event in cra.events(request.data_dir)]
    return request.json(200, {"products": products, "events": events, "reporting_page": cra.REPORTING_PAGE,
                              "assets": [{"key": key, "name": name} for key, name in assets.items()]})


@route("POST", "/api/cra", admin=True, action="cra", body=2048)
def cra_change(request: Request):
    payload = request.payload
    if not isinstance(payload, dict) or payload.get("op") not in ("product", "unproduct", "mark"):
        return request.json(400, {"error": "Solicitud inválida"})
    try:
        if payload["op"] == "mark":
            if set(payload) != {"op", "event", "stage", "sent"} or not isinstance(payload["sent"], bool):
                return request.json(400, {"error": "Solicitud inválida"})
            cra.mark(request.data_dir, payload["event"], payload["stage"], sent=payload["sent"], user=request.user)
        else:
            fields = {"op", "key", "name", "support_until"} if payload["op"] == "product" else {"op", "key"}
            key = payload.get("key")
            if set(payload) != fields or not isinstance(key, str) or not any(row["key"] == key for row in assets_overview(request.data_dir)):
                return request.json(400, {"error": "Solicitud inválida"})
            if payload["op"] == "product":
                cra.set_product(request.data_dir, key, name=payload["name"], support_until=payload["support_until"], user=request.user)
            else:
                cra.remove_product(request.data_dir, key, user=request.user)
    except cra.CraError as exc:
        return request.json(400, {"error": str(exc)})
    return cra_state(request)
