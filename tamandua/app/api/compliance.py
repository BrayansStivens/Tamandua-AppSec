"""Kit CRA (lectura). Los cambios (POST /api/cra) siguen en el router clásico."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from tamandua.app.api.deps import Context, guard
from tamandua.modules.compliance import cra

router = APIRouter(tags=["cumplimiento"])


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
    packages: list[str]
    kev: dict[str, object]
    aware_at: str | None
    status: str
    fixed_at: str | None
    stages: list[CraStage]
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


class CraOverview(BaseModel):
    products: list[CraProduct]
    events: list[CraEvent]
    assets: list[CraAsset]
    reporting_page: str


@router.get("/api/cra", response_model=CraOverview)
def overview(context: Context = Depends(guard())) -> dict:
    """Lo ve cualquier sesión (el equipo necesita saber qué vence); solo un administrador lo cambia."""
    return cra.overview(context.data_dir)
