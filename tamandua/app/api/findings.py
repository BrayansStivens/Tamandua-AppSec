"""Plazos de corrección (lectura). El cambio (POST /api/sla) está en routes/runs.py."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from tamandua.app.api.deps import Context, guard
from tamandua.modules.findings import sla

router = APIRouter(tags=["hallazgos"])


class SlaDays(BaseModel):
    """Días por severidad; None = esa severidad no vence."""
    critical: int | None
    high: int | None
    medium: int | None
    low: int | None


class SlaDefaults(BaseModel):
    critical: int
    high: int
    medium: int
    low: int


class SlaPolicy(BaseModel):
    days: SlaDays
    defaults: SlaDefaults
    updated_by: str | None
    updated_at: str | None


@router.get("/api/sla", response_model=SlaPolicy)
def policy(context: Context = Depends(guard())) -> dict:
    """Los ve cualquiera (explican las fechas límite); los cambia un administrador."""
    return context.render(sla.policy(context.data_dir))
