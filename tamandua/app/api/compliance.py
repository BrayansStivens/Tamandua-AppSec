"""Kit CRA (lectura). Los cambios (POST /api/cra) están en routes/cra.py."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from tamandua.app.api.deps import Context, guard
from tamandua.app.api.paging import Page, Paging, paging
from tamandua.modules.compliance import cra

router = APIRouter(tags=["compliance"])


class CraStage(BaseModel):
    id: str
    label: str
    due: str | None
    state: str
    sent: dict[str, str] | None


class CraEvent(BaseModel):
    id: str
    asset: str
    product: str
    support_until: str | None
    cve: str
    title: str | None
    severity: str | None
    packages: list[str] = Field(max_length=cra.PACKAGES_SHOWN)
    kev: dict[str, object]
    aware_at: str | None
    status: str
    fixed_at: str | None
    stages: list[CraStage] = Field(max_length=len(cra.STAGES))
    done: bool
    draft: str


class CraProduct(BaseModel):
    key: str
    name: str
    asset: str
    support_until: str | None
    last_complete: str | None
    by: str | None = None
    at: str | None = None


class CraAsset(BaseModel):
    key: str
    name: str


class CraProductPage(Page[CraProduct]):
    pass


class CraEventPage(Page[CraEvent]):
    pass


class CraAssetPage(Page[CraAsset]):
    pass


class CraCounts(BaseModel):
    products: int
    unscanned: int  # products without a complete scan
    events: int
    pending: int  # events with a stage not yet sent
    assets: int
    candidates: int  # assets that can still be marked as products


class CraOverview(BaseModel):
    reporting_page: str
    counts: CraCounts


# Any session can read the CRA kit (the team needs to know what is due); only an administrator changes it (routes/cra.py).

@router.get("/api/cra", response_model=CraOverview)
def overview(context: Context = Depends(guard())) -> dict:
    return context.render(cra.overview(context.data_dir))


@router.get("/api/cra/products", response_model=CraProductPage)
def products(page: Paging = Depends(paging()), context: Context = Depends(guard())) -> dict:
    return context.render(page.slice(cra.products(context.data_dir)))


@router.get("/api/cra/events", response_model=CraEventPage)
def events(page: Paging = Depends(paging(10)), context: Context = Depends(guard())) -> dict:
    """Most urgent first. The ENISA draft is only built for the events on the page."""
    result = page.slice(cra.events(context.data_dir))
    return context.render({**result, "items": [cra.with_draft(event) for event in result["items"]]})


@router.get("/api/cra/assets", response_model=CraAssetPage)
def assets(q: str = Query("", max_length=100), page: Paging = Depends(paging()), context: Context = Depends(guard())) -> dict:
    """Analyzed assets that can still be marked as products, filtered by name."""
    return context.render(page.slice(cra.candidates(context.data_dir, query=q)))
