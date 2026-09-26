"""Kit CRA: cambios (POST). La lectura (GET /api/cra) ya está en FastAPI: tamandua/app/api/compliance.py."""

from __future__ import annotations

from tamandua.modules.compliance import cra
from tamandua.modules.sources.assets import overview as assets_overview
from tamandua.app.api.routing import Request, problem, route
from tamandua.shared.i18n import msg


@route("POST", "/api/cra", admin=True, action="cra", body=2048)
def cra_change(request: Request):
    payload = request.payload
    if not isinstance(payload, dict) or payload.get("op") not in ("product", "unproduct", "mark"):
        return request.json(400, {"error": msg("api.invalid_request")})
    try:
        if payload["op"] == "mark":
            if set(payload) != {"op", "event", "stage", "sent"} or not isinstance(payload["sent"], bool):
                return request.json(400, {"error": msg("api.invalid_request")})
            cra.mark(request.data_dir, payload["event"], payload["stage"], sent=payload["sent"], user=request.user)
        else:
            fields = {"op", "key", "name", "support_until"} if payload["op"] == "product" else {"op", "key"}
            key = payload.get("key")
            if set(payload) != fields or not isinstance(key, str) or not any(row["key"] == key for row in assets_overview(request.data_dir)):
                return request.json(400, {"error": msg("api.invalid_request")})
            if payload["op"] == "product":
                cra.set_product(request.data_dir, key, name=payload["name"], support_until=payload["support_until"], user=request.user)
            else:
                cra.remove_product(request.data_dir, key, user=request.user)
    except cra.CraError as exc:
        return request.json(400, {"error": problem(exc)})
    return request.json(200, cra.overview(request.data_dir))
