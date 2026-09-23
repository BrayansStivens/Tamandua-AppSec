"""CVE tracker: búsqueda paginada en la copia local de NVD, con KEV y EPSS."""

from __future__ import annotations

import re
from datetime import datetime, timezone

from .. import cve_db
from ..findings_registry import assets_with_cve
from .core import Request, route

MAX_OFFSET = 10_000  # más allá, que se acote con filtros: evita OFFSET caros


@route("GET", "/api/cve-db")
def cve_search(request: Request):
    query = (request.arg("q", "") or "").strip()
    severity = request.arg("severity") or None
    sort = request.arg("sort", "published")
    try:
        year = int(request.arg("year")) if request.arg("year") else None
        limit, offset = int(request.arg("limit", "25")), int(request.arg("offset", "0"))
    except ValueError:
        return request.json(400, {"error": "Parámetros inválidos"})
    if (len(query) > 100 or (severity and severity not in cve_db.SEVERITIES) or sort not in cve_db.SORTS
            or not 1 <= limit <= 100 or not 0 <= offset <= MAX_OFFSET
            or (year is not None and not 1999 <= year <= datetime.now(timezone.utc).year + 1)):
        return request.json(400, {"error": "Parámetros inválidos"})
    return request.json(200, cve_db.search(request.data_dir, query=query, severity=severity, kev=request.arg("kev") == "1",
                                           year=year, sort=sort, limit=limit, offset=offset))


@route("GET", "/api/cve-db/overview")
def cve_overview(request: Request):
    return request.json(200, cve_db.overview(request.data_dir))


@route("GET", "/api/cve-db/item")
def cve_item(request: Request):
    identifier = (request.arg("id", "") or "").strip().upper()
    if not re.fullmatch(r"CVE-\d{4}-\d{4,7}", identifier):
        return request.json(400, {"error": "Identificador de CVE inválido"})
    item = cve_db.detail(request.data_dir, identifier)
    if item is None:
        return request.json(404, {"error": "CVE no encontrado en la copia local"})
    return request.json(200, {**item, "affected": assets_with_cve(request.data_dir, identifier)})
