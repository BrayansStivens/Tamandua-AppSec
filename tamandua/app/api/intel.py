"""CVE tracker: búsqueda paginada en la copia local de NVD, con KEV, EPSS y EUVD."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from tamandua.app.api.deps import ApiError, Context, guard
from tamandua.app.api.paging import MAX_LIMIT, MAX_OFFSET, Page, Paging, paging
from tamandua.modules.findings.registry import PACKAGES_SHOWN, assets_with_cve, open_cves
from tamandua.modules.intel import cve_db, euvd
from tamandua.shared.i18n import msg

router = APIRouter(tags=["intel"])
CVE_ID = re.compile(r"CVE-\d{4}-\d{4,7}")


class CveRow(BaseModel):
    id: str
    published: str | None
    severity: str | None
    score: float | None
    version: str | None
    description: str
    status: str | None = None
    kev: bool
    epss: float | None
    epss_percentile: float | None
    affects: bool = False


class CvePage(BaseModel):
    items: list[CveRow] = Field(max_length=MAX_LIMIT)
    total: int
    limit: int
    offset: int
    mine_total: int


class Euvd(BaseModel):
    id: str
    url: str | None
    score: float | None
    version: str | None
    vector: str | None
    severity: str | None
    exploited_since: str | None
    published: str | None


class AffectedAsset(BaseModel):
    asset: str
    name: str
    open: int
    fixed: int
    packages: list[str] = Field(max_length=PACKAGES_SHOWN)


class AffectedAssetPage(Page[AffectedAsset]):
    pass


class CveDetail(CveRow):
    vector: str | None
    modified: str | None
    cwe: list[str] = Field(max_length=cve_db.MAX_CWES)
    references: list[dict[str, Any]] = Field(max_length=cve_db.MAX_REFERENCES)
    kev_detail: dict[str, Any] | None
    score_source: str | None
    euvd: Euvd | None


def _cve_id(value: str) -> str:
    identifier = value.strip().upper()
    if not CVE_ID.fullmatch(identifier):
        raise ApiError(400, msg("api.invalid_cve"))
    return identifier


@router.get("/api/cve-db", response_model=CvePage)
def search(q: str = "", severity: str | None = None, sort: str = "published", year: int | None = None,
           limit: int = Query(25), offset: int = Query(0), kev: str | None = None, mine: str | None = None,
           context: Context = Depends(guard())) -> dict:
    query = q.strip()
    severity = severity or None
    if (len(query) > 100 or (severity and severity not in cve_db.SEVERITIES) or sort not in cve_db.SORTS
            or not 1 <= limit <= MAX_LIMIT or not 0 <= offset <= MAX_OFFSET
            or (year is not None and not 1999 <= year <= datetime.now(timezone.utc).year + 1)):
        raise ApiError(400, msg("api.invalid_parameters"))
    own = open_cves(context.data_dir)
    page = cve_db.search(context.data_dir, query=query, severity=severity, kev=kev == "1", year=year, sort=sort,
                         limit=limit, offset=offset, mine=own, only=own if mine == "1" else None)
    return context.render(page | {"mine_total": len(own)})


@router.get("/api/cve-db/overview")
def overview(context: Context = Depends(guard())) -> dict[str, Any]:
    return context.render(cve_db.overview(context.data_dir))


@router.get("/api/cve-db/item", response_model=CveDetail)
def item(id: str = "", context: Context = Depends(guard())) -> dict:  # noqa: A002 — nombre del parámetro público
    identifier = _cve_id(id)
    detail = cve_db.detail(context.data_dir, identifier)
    if detail is None:
        raise ApiError(404, msg("api.cve_not_found"))
    # NVD ya no puntúa todos los CVE: EUVD (ENISA) completa la puntuación y dice si se explota activamente.
    europe = euvd.lookup(context.data_dir, identifier)
    detail["score_source"] = "nvd" if detail.get("score") is not None else None
    if detail.get("score") is None and europe and europe.get("score") is not None:
        detail.update(score=europe["score"], severity=europe["severity"], version=europe["version"],
                      vector=detail.get("vector") or europe["vector"], score_source="euvd")
    return context.render({**detail, "euvd": europe})


@router.get("/api/cve-db/affected", response_model=AffectedAssetPage)
def affected(id: str = "", page: Paging = Depends(paging(10)),  # noqa: A002 — public parameter name
             context: Context = Depends(guard())) -> dict:
    """Your repositories with a finding that cites this CVE (open or fixed), one page at a time."""
    return context.render(assets_with_cve(context.data_dir, _cve_id(id), limit=page.limit, offset=page.offset))
