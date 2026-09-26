"""Compliance: the evidence hub (for everyone) and the CRA kit (only when the workspace policy turns it on)."""

from __future__ import annotations

from typing import Annotated, Literal, Union

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field, StrictBool

from tamandua.app.api.deps import ApiError, Context, Policy, guard
from tamandua.app.api.paging import Page, Paging, paging
from tamandua.modules.compliance import cra, evidence
from tamandua.modules.reporting.audit import FRAMEWORKS, ReportError, render_portfolio_pdf, validate_options
from tamandua.modules.sources.assets import overview as assets_overview
from tamandua.shared.i18n import msg, text
from tamandua.version import VERSION

router = APIRouter(tags=["compliance"])
EventId = Annotated[str, Field(max_length=300)]
Reason = Annotated[str, Field(max_length=cra.REASON_MAX)]


# --- Policy: "we sell products with software in the EU" ------------------------------------------------------------

class CraPolicyChange(BaseModel):
    enabled: bool
    by: str | None
    at: str | None
    reason: str | None


class CraPolicy(CraPolicyChange):
    history: list[CraPolicyChange] = Field(max_length=cra.HISTORY)


class CraPolicyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: StrictBool
    reason: Reason


@router.get("/api/policies/cra", response_model=CraPolicy)
def cra_policy(context: Context = Depends(guard())) -> dict:
    """Anyone can read it (the panel shows or hides the CRA kit with it); an administrator changes it."""
    return context.render(cra.policy(context.data_dir))


@router.post("/api/policies/cra", response_model=CraPolicy)
def set_cra_policy(body: CraPolicyIn, context: Context = Depends(guard(Policy(admin=True, action="cra-policy", body=2048)))) -> dict:
    """Turns the CRA kit on or off, with a reason kept in the history. Off keeps products and decisions."""
    try:
        return context.render(cra.set_policy(context.data_dir, body.enabled, reason=body.reason, user=context.user))
    except cra.CraError as exc:
        raise ApiError(400, exc.message) from exc


# --- CRA kit --------------------------------------------------------------------------------------------------------

def _enabled_or_404(context: Context) -> Context:
    if not cra.enabled(context.data_dir):
        raise ApiError(404, msg("compliance.cra.errors.disabled"))
    return context


def cra_reader(context: Context = Depends(guard())) -> Context:
    return _enabled_or_404(context)


def cra_admin(context: Context = Depends(guard(Policy(admin=True, action="cra", body=2048)))) -> Context:
    return _enabled_or_404(context)


class CraStage(BaseModel):
    id: Literal["early_warning", "notification", "final_report"]
    label: str
    due: str | None
    state: Literal["overdue", "pending", "waiting", "sent"]
    sent: dict[str, str] | None


class CraKev(BaseModel):
    date_added: str | None
    ransomware: bool
    name: str | None


class CraAssessment(BaseModel):
    by: str | None
    at: str | None
    reason: str | None
    legacy: bool  # reported before assessments existed: read as exploited from the original signal


class CraEvent(BaseModel):
    id: str
    asset: str
    product: str
    support_until: str | None
    cve: str
    title: str | None
    severity: str | None
    packages: list[str] = Field(max_length=cra.PACKAGES_SHOWN)
    kev: CraKev
    signal_at: str | None  # the KEV match: a signal, not the awareness time
    state: Literal["to_assess", "not_affected", "exploited"]
    assessment: CraAssessment | None
    aware_at: str | None  # only once exploited in the product: the clocks count from here
    status: Literal["open", "fixed"]
    fixed_at: str | None
    stages: list[CraStage] = Field(max_length=len(cra.STAGES))  # empty until exploited
    done: bool
    draft: str | None


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
    pending: int  # events not closed: to assess, or a stage not yet sent
    to_assess: int
    assets: int
    candidates: int  # assets that can still be marked as products


class CraOverview(BaseModel):
    reporting_page: str
    counts: CraCounts


class ProductIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    op: Literal["product"]
    key: str = Field(max_length=200)
    name: str = Field(max_length=200)
    support_until: str | None = Field(max_length=10)


class UnproductIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    op: Literal["unproduct"]
    key: str = Field(max_length=200)


class MarkIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    op: Literal["mark"]
    event: EventId
    stage: Literal["early_warning", "notification", "final_report"]
    sent: StrictBool


class AssessIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    op: Literal["assess"]
    event: EventId
    verdict: Literal["not_affected", "exploited"]
    reason: Reason | None = None


class ReopenIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    op: Literal["reopen"]
    event: EventId


CraChange = Annotated[Union[ProductIn, UnproductIn, MarkIn, AssessIn, ReopenIn], Field(discriminator="op")]


# Any session reads the kit (the team needs to know what is due); only an administrator changes it.

@router.get("/api/cra", response_model=CraOverview)
def overview(context: Context = Depends(cra_reader)) -> dict:
    return context.render(cra.overview(context.data_dir))


@router.post("/api/cra", response_model=CraOverview)
def change(body: CraChange, context: Context = Depends(cra_admin)) -> dict:
    """Marks products, records the assessment of an event (only "exploited in our product" starts the clocks) and
    which stages were sent. Answers the new overview."""
    data_dir, user = context.data_dir, context.user
    try:
        if isinstance(body, (ProductIn, UnproductIn)):
            if not any(row["key"] == body.key for row in assets_overview(data_dir)):
                raise ApiError(400, msg("api.invalid_request"))
            if isinstance(body, ProductIn):
                cra.set_product(data_dir, body.key, name=body.name, support_until=body.support_until, user=user)
            else:
                cra.remove_product(data_dir, body.key, user=user)
        elif isinstance(body, MarkIn):
            cra.mark(data_dir, body.event, body.stage, sent=body.sent, user=user)
        elif isinstance(body, AssessIn):
            cra.assess(data_dir, body.event, body.verdict, reason=body.reason, user=user)
        else:
            cra.reopen(data_dir, body.event, user=user)
    except cra.CraError as exc:
        raise ApiError(400, exc.message) from exc
    return context.render(cra.overview(data_dir))


@router.get("/api/cra/products", response_model=CraProductPage)
def products(page: Paging = Depends(paging()), context: Context = Depends(cra_reader)) -> dict:
    return context.render(page.slice(cra.products(context.data_dir)))


@router.get("/api/cra/events", response_model=CraEventPage)
def events(page: Paging = Depends(paging(10)), context: Context = Depends(cra_reader)) -> dict:
    """Most urgent first. The ENISA draft is only built for the exploited events on the page."""
    result = page.slice(cra.events(context.data_dir))
    return context.render({**result, "items": [cra.with_draft(event) for event in result["items"]]})


@router.get("/api/cra/assets", response_model=CraAssetPage)
def assets(q: str = Query("", max_length=100), page: Paging = Depends(paging()), context: Context = Depends(cra_reader)) -> dict:
    """Analyzed assets that can still be marked as products, filtered by name."""
    return context.render(page.slice(cra.candidates(context.data_dir, query=q)))


# --- Evidence hub ---------------------------------------------------------------------------------------------------
# The files come from the existing exports: /api/assets/export (SBOM, VEX, technical report) and /api/reports/audit
# (audit evidence of one asset). Only the portfolio-wide audit evidence needs its own route.

class EvidenceOverview(BaseModel):
    assets: int  # analyzed repositories and images
    complete: int  # with a completed full scan (what an SBOM needs)


class EvidenceAsset(BaseModel):
    key: str
    name: str
    kind: Literal["repository", "image"]
    last_complete: str | None
    sbom: bool


class EvidenceAssetPage(Page[EvidenceAsset]):
    pass


class PortfolioEvidenceIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    framework: Literal[tuple(FRAMEWORKS)]  # type: ignore[valid-type]


@router.get("/api/evidence", response_model=EvidenceOverview)
def evidence_overview(context: Context = Depends(guard())) -> dict:
    return evidence.overview(context.data_dir)


@router.get("/api/evidence/assets", response_model=EvidenceAssetPage)
def evidence_assets(q: str = Query("", max_length=100), page: Paging = Depends(paging(20)), context: Context = Depends(guard())) -> dict:
    """The asset picker: analyzed assets by name, with whether each has what an SBOM needs."""
    return page.slice(evidence.assets(context.data_dir, query=q))


@router.post("/api/evidence/portfolio", response_class=Response,
             responses={200: {"description": "Audit evidence (PDF) of every analyzed asset",
                              "content": {"application/pdf": {"schema": {"type": "string", "format": "binary", "maxLength": 50_000_000}}}}})
def portfolio_evidence(body: PortfolioEvidenceIn,
                       context: Context = Depends(guard(Policy(action="audit-report", body=256)))) -> Response:
    """Consolidated audit evidence of every analyzed asset (open, fixed and exceptions), for one framework."""
    chosen = evidence.catalog(context.data_dir)
    if not chosen:
        raise ApiError(404, msg("api.no_analyzed_in_scope"))
    user = context.user
    scope = text(msg("api.scope.repositories", count=len(chosen)), context.locale)
    try:
        options = validate_options({"framework": body.framework}, default_by=user.get("display_name") or user["username"])
        pdf = render_portfolio_pdf(evidence.portfolio(context.data_dir, chosen), options, version=VERSION, scope_label=scope,
                                   coverage={"total": None, "missing": []}, locale=context.locale)
    except ReportError as exc:
        raise ApiError(400, exc.message) from exc
    context.state.log.info("audit_report", extra={"user": user["username"], "reason": f"{scope}: {len(chosen)} assets, {body.framework}"})
    return Response(pdf, media_type="application/pdf")
