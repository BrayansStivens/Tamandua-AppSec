"""Notification channels (Slack, Teams, signed webhook): administrators only."""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field

from tamandua.app.api.deps import ApiError, Context, Policy, documented, guard, json_body
from tamandua.app.api.deps import problem
from tamandua.modules.integrations import notifications
from tamandua.shared.i18n import msg

router = APIRouter(tags=["notifications"])


class Channels(BaseModel):
    """Never the channel's URL nor its signing secret: the host and what it is sent."""
    channels: list[dict[str, Any]] = Field(max_length=notifications.MAX_CHANNELS)
    kinds: dict[str, str]
    events: dict[str, str]
    thresholds: list[str] = Field(max_length=len(notifications.THRESHOLDS))
    links: bool  # the messages can link to the panel (TAMANDUA_PUBLIC_URL)


@router.get("/api/notifications", response_model=Channels)
def channel_list(context: Context = Depends(guard(Policy(admin=True)))) -> dict:
    return context.render({"channels": notifications.channels(), "kinds": notifications.KINDS, "events": notifications.EVENTS,
                           "thresholds": list(notifications.THRESHOLDS), "links": bool(notifications.panel_link())})


SAVE_FIELDS = {"op", "kind", "name", "url", "events", "threshold"}


class ChannelSaveIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    op: Literal["save"]
    kind: Literal[tuple(notifications.KINDS)]  # type: ignore[valid-type]
    name: str = Field(max_length=60)
    url: str = Field(max_length=2048)
    events: list[Literal[tuple(notifications.EVENTS)]] = Field(min_length=1, max_length=len(notifications.EVENTS))  # type: ignore[valid-type]
    threshold: Literal[notifications.THRESHOLDS]  # type: ignore[valid-type]


class ChannelIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    op: Literal["remove", "test"]
    id: str


class ChannelSaved(BaseModel):
    """A saved channel and, for a webhook, its signing secret: shown this once."""
    model_config = ConfigDict(extra="forbid")  # one answer per operation: the union picks it by shape
    channel: dict[str, Any]
    secret: str | None


class ChannelsLeft(BaseModel):
    model_config = ConfigDict(extra="forbid")  # one answer per operation: the union picks it by shape
    channels: list[dict[str, Any]] = Field(max_length=notifications.MAX_CHANNELS)


class ChannelTested(BaseModel):
    """Whether the test delivery worked (a 200 also when it didn't), why, and the channels with their last result."""
    model_config = ConfigDict(extra="forbid")  # one answer per operation: the union picks it by shape
    ok: bool
    detail: str
    channels: list[dict[str, Any]] = Field(max_length=notifications.MAX_CHANNELS)


@router.post("/api/notifications", openapi_extra=documented(ChannelSaveIn, ChannelIn),
             response_model=ChannelSaved | ChannelTested | ChannelsLeft)
def channel_change(context: Context = Depends(guard(Policy(admin=True, action="notifications", body=4096))),
                   data: Any = Depends(json_body)) -> dict[str, Any]:
    """`save` answers the channel and, for a webhook, its signing secret (shown once); `remove` the channels left;
    `test` whether the delivery worked, with its detail (also a 200 when it fails) and the updated channels."""
    if not isinstance(data, dict) or data.get("op") not in ("save", "remove", "test"):
        raise ApiError(400, msg("api.invalid_request"))
    by = context.user["username"]
    try:
        if data["op"] == "save":
            if set(data) != SAVE_FIELDS:
                raise ApiError(400, msg("api.invalid_request"))
            row, secret = notifications.save(data["kind"], data["name"], data["url"], data["events"], data["threshold"], by=by)
            return context.render({"channel": row, "secret": secret})
        if set(data) != {"op", "id"} or not isinstance(data["id"], str):
            raise ApiError(400, msg("api.invalid_request"))
        if data["op"] == "remove":
            notifications.remove(data["id"], by=by)
            return context.render({"channels": notifications.channels()})
        ok, detail = notifications.test(data["id"])
        return context.render({"ok": ok, "detail": detail, "channels": notifications.channels()})
    except notifications.NotificationError as exc:
        raise ApiError(400, problem(exc)) from exc
