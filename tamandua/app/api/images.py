"""Container image scans (one, or several in a batch) and the read-only credentials of private registries."""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field, StrictStr

from tamandua.shared import settings
from tamandua.app.api.deps import ApiError, Context, Policy, body, documented, guard, json_body
from tamandua.app.api.repositories import QUEUE_LIMIT, BatchSummary
from tamandua.app.api.deps import problem
from tamandua.modules.runs import batches
from tamandua.modules.scanning.image import ImageError, check_registry_address, forget_registry, parse_reference, registries, save_registry
from tamandua.shared.i18n import msg, text

router = APIRouter(tags=["images"])


class ImageScanIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reference: StrictStr
    context: StrictStr = ""


class QueuedImageScan(BaseModel):
    run: dict[str, Any]
    image: dict[str, Any]


@router.post("/api/images/scans", status_code=202, response_model=QueuedImageScan, openapi_extra=documented(ImageScanIn))
def image_scan(context: Context = Depends(guard(Policy(action="scan-image", body=1024))),
               data: ImageScanIn = Depends(body(ImageScanIn, msg("api.invalid_image")))) -> dict:
    """Queues the scan of a container image, pulled from its registry."""
    try:
        image = parse_reference(data.reference)
        check_registry_address(image["registry"])
    except ImageError as exc:
        raise ApiError(400, problem(exc)) from exc
    if context.state.jobs.pending() >= QUEUE_LIMIT:
        raise ApiError(429, msg("api.queue_full"))
    queued = context.state.jobs.enqueue_image_scan(image=image, context=data.context, requested_by=context.user["username"])
    return context.render({"run": queued, "image": image})


class ImageBatchIn(BaseModel):
    """Blank and repeated references are dropped before counting."""
    model_config = ConfigDict(extra="forbid")
    references: list[str] = Field(max_length=batches.MAX_SELECTED)
    context: str = ""


@router.post("/api/images/batches", status_code=202, response_model=BatchSummary, openapi_extra=documented(ImageBatchIn))
def image_batch(context: Context = Depends(guard(Policy(action="scan-image-batch", body=64_000))),
                data: Any = Depends(json_body)) -> dict:
    """Several images at once (up to 100), in a batch that moves on when the server is free."""
    if (not isinstance(data, dict) or not set(data) <= set(ImageBatchIn.model_fields) or not isinstance(data.get("references"), list)
            or not isinstance(data.get("context", ""), str)):
        raise ApiError(400, msg("api.images_required"))
    if any(not isinstance(item, str) for item in data["references"]):
        raise ApiError(400, msg("api.invalid_image_reference"))
    references = list(dict.fromkeys(item.strip() for item in data["references"] if item.strip()))
    if not 1 <= len(references) <= batches.MAX_SELECTED:
        raise ApiError(400, msg("api.choose_images", max=batches.MAX_SELECTED))
    items = []
    for reference in references:
        try:
            image = parse_reference(reference)
            check_registry_address(image["registry"])
        except ImageError as exc:
            raise ApiError(400, msg("api.image_error", reference=reference[:120], detail=problem(exc))) from exc
        items.append({"kind": "image", "image": image})
    user = context.user
    label = text(msg("api.scope.images", count=len(items)), context.locale)
    try:
        batch = batches.create(context.data_dir, items, by=user["username"], label=label, context=data.get("context", ""))
    except batches.BatchError as exc:
        raise ApiError(409, problem(exc)) from exc
    context.state.log.info("scan_image_batch", extra={"user": user["username"], "reason": label})
    return context.render(batches.summary(context.data_dir, batch))


@router.get("/api/registries")
def registry_list(context: Context = Depends(guard())) -> dict[str, Any]:
    """Registries with saved credentials (never the token), and whether private addresses are allowed."""
    return context.render({"registries": registries(), "allow_private": settings.flag("TAMANDUA_ALLOW_PRIVATE_REGISTRIES")})


class RegistryIn(BaseModel):
    """`save` needs `username` and `token`; `remove` only the registry."""
    model_config = ConfigDict(extra="forbid")
    action: Literal["save", "remove"]
    registry: str = Field(max_length=200)
    username: str | None = Field(None, max_length=200)
    token: str | None = None


@router.post("/api/registries", openapi_extra=documented(RegistryIn))
def registry_save(context: Context = Depends(guard(Policy(admin=True, action="save-registry", body=6000))),
                  data: Any = Depends(json_body)) -> dict[str, Any]:
    """Read-only credentials of a private registry: stored encrypted, never sent back to the browser."""
    if not isinstance(data, dict) or data.get("action") not in ("save", "remove") or not isinstance(data.get("registry"), str):
        raise ApiError(400, msg("api.invalid_request"))
    try:
        if data["action"] == "remove":
            return context.render({"registries": forget_registry(data["registry"])})
        if set(data) != set(RegistryIn.model_fields):
            raise ApiError(400, msg("api.invalid_request"))
        return context.render({"registries": save_registry(data["registry"], data["username"], data["token"], by=context.user["username"])})
    except ImageError as exc:
        raise ApiError(400, problem(exc)) from exc
