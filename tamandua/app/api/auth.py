"""Session, second factor, invitation/reset links and user administration.

Bodies are read after the guard with the messages the panel already knows (`api.invalid_json`, then the route's own
400); their fields are as permissive as the domain: a value of the wrong type is the domain's error (for example, bad
credentials), not a validation error."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, ConfigDict, Field, WithJsonSchema, model_validator

from tamandua.app.api.deps import ApiError, Context, Policy, body, documented, guard
from tamandua.app.api.deps import problem
from tamandua.app.api.security import public_url
from tamandua.modules.identity.auth import BACKUP_CODES, AuthError, Locked, verify_password
from tamandua.shared.i18n import msg

router = APIRouter(tags=["auth"])

Text = Annotated[Any, WithJsonSchema({"type": "string"})]
MAX_USERS = 10_000
LINK_HOURS = 72


def _invalid(model):
    return Depends(body(model, msg("api.invalid_request")))


class Fields(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SetupIn(Fields):
    code: str
    username: str
    password: str
    display_name: str


class LoginIn(Fields):
    username: Text
    password: Text


class SecondFactorIn(Fields):
    challenge: Text
    code: Text


class PasswordIn(Fields):
    current: Text
    new: Text


class CodeIn(Fields):
    code: Text


class PasswordOnlyIn(Fields):
    password: Text


class TokenIn(Fields):
    token: Text


class LinkIn(Fields):
    token: Text
    password: Text


class EmptyIn(Fields):
    """`{}`."""


USER_ACTIONS = {"invite": {"action", "username", "role", "display_name"}, "reset": {"action", "user_id"},
                "role": {"action", "user_id", "role"}, "disable": {"action", "user_id"},
                "enable": {"action", "user_id"}, "reset_totp": {"action", "user_id"}}


class UserChangeIn(Fields):
    """`invite` takes username, role and display_name; `role` takes user_id and role; the rest, only user_id."""
    action: Literal["invite", "reset", "role", "disable", "enable", "reset_totp"]
    username: Text = None
    display_name: Text = None
    role: Text = None
    user_id: Text = None

    @model_validator(mode="before")
    @classmethod
    def _fields_of_action(cls, data):
        if isinstance(data, dict) and isinstance(data.get("action"), str) and not set(data) <= USER_ACTIONS.get(data["action"], set()):
            raise ValueError("fields that don't belong to this action")
        return data


class PublicUser(BaseModel):
    id: str
    username: str
    display_name: str
    role: str
    totp_enabled: bool
    disabled: bool
    created_at: str
    last_login_at: str | None
    has_password: bool
    pending_link: str | None


class NoSession(BaseModel):
    authenticated: Literal[False]
    setup_required: bool


class ActiveSession(BaseModel):
    authenticated: Literal[True]
    user: PublicUser
    mfa: bool
    totp_required: bool
    totp_policy: str


class SignedIn(BaseModel):
    step: Literal["done"]
    user: PublicUser


class TotpStep(BaseModel):
    """The password was right; the account has TOTP: send the code with this challenge to /api/auth/totp."""
    step: Literal["totp"]
    challenge: str


class SignedOut(BaseModel):
    authenticated: bool


class PasswordChanged(BaseModel):
    changed: bool


class TotpEnrolment(BaseModel):
    secret: str
    uri: str


class TotpEnabled(BaseModel):
    enabled: bool
    backup_codes: list[str] = Field(max_length=BACKUP_CODES)


class TotpDisabled(BaseModel):
    enabled: bool


class LinkInfo(BaseModel):
    username: str
    display_name: str
    purpose: str


class UserList(BaseModel):
    users: list[PublicUser] = Field(max_length=MAX_USERS)
    totp_policy: str


class UserLink(BaseModel):
    """The one-time link to hand to the person (invitation or password reset)."""
    user: PublicUser
    link: str
    expires_in_hours: int


class UserChanged(BaseModel):
    model_config = ConfigDict(extra="forbid")
    user: PublicUser


@contextmanager
def _auth_errors(*, sign_in: bool = False):
    """Domain errors as responses: 429 with the wait, 401 when signing in, 400 otherwise."""
    try:
        yield
    except Locked as exc:
        raise ApiError(429, problem(exc), retry_in=exc.retry_in) from exc
    except AuthError as exc:
        raise ApiError(401 if sign_in else 400, problem(exc), **({"code": exc.code} if exc.code else {})) from exc
    except OSError as exc:
        raise ApiError(500, msg("api.save_failed")) from exc


def _client(request: Request) -> str:
    return request.client.host if request.client else ""


def _set_cookie(request: Request, response: Response, value: str, *, clear: bool = False) -> None:
    secure = public_url(request.app.state.port).startswith("https://")
    response.headers["set-cookie"] = request.app.state.core.auth.sessions.cookie(value, secure=secure, clear=clear)


def _signed_in(request: Request, response: Response, result: dict) -> dict:
    _set_cookie(request, response, result["session"])
    return {"step": "done", "user": result["user"]}


@router.get("/api/auth/session", response_model=ActiveSession | NoSession)
def session(context: Context = Depends(guard(Policy(public=True, enrolment=True)))) -> dict:
    auth, user = context.state.auth, context.user
    if user is None:
        return {"authenticated": False, "setup_required": auth.setup_required()}
    return {"authenticated": True, "user": auth.users.public(user), "mfa": context.session["mfa"],
            "totp_required": auth.needs_totp(user), "totp_policy": auth.totp_policy()}


@router.post("/api/auth/setup", response_model=SignedIn, openapi_extra=documented(SetupIn))
def setup_admin(request: Request, response: Response,
                context: Context = Depends(guard(Policy(public=True, enrolment=True, action="setup-admin", body=900))),
                data: SetupIn = _invalid(SetupIn)) -> dict:
    """First administrator from the web, with the one-time code the server printed."""
    with _auth_errors():
        result = context.state.auth.setup_admin(data.code, data.username, data.password, data.display_name, _client(request))
    return _signed_in(request, response, result)


@router.post("/api/auth/login", response_model=SignedIn | TotpStep, openapi_extra=documented(LoginIn))
def login(request: Request, response: Response,
          context: Context = Depends(guard(Policy(public=True, enrolment=True, action="login", body=640))),
          data: LoginIn = _invalid(LoginIn)) -> dict:
    with _auth_errors(sign_in=True):
        result = context.state.auth.login(data.username, data.password, _client(request))
    if "challenge" in result:
        return {"step": "totp", "challenge": result["challenge"]}
    return _signed_in(request, response, result)


@router.post("/api/auth/totp", response_model=SignedIn, openapi_extra=documented(SecondFactorIn))
def second_factor(request: Request, response: Response,
                  context: Context = Depends(guard(Policy(public=True, enrolment=True, action="totp"))),
                  data: SecondFactorIn = _invalid(SecondFactorIn)) -> dict:
    """An expired or unknown challenge is a 401 with `code: challenge_expired`: sign in again from the password."""
    with _auth_errors(sign_in=True):
        result = context.state.auth.second_factor(data.challenge, data.code, _client(request))
    return _signed_in(request, response, result)


@router.post("/api/auth/logout", response_model=SignedOut)
def logout(request: Request, response: Response, context: Context = Depends(guard(Policy(enrolment=True, action="logout")))) -> dict:
    context.state.auth.logout(request.headers.get("cookie"))
    _set_cookie(request, response, "", clear=True)
    return {"authenticated": False}


@router.post("/api/auth/password", response_model=PasswordChanged, openapi_extra=documented(PasswordIn))
def change_password(request: Request, response: Response,
                    context: Context = Depends(guard(Policy(enrolment=True, action="change-password", body=900))),
                    data: PasswordIn = _invalid(PasswordIn)) -> dict:
    with _auth_errors():
        fresh = context.state.auth.change_password(context.user, data.current, data.new, request.headers.get("cookie"))
    _set_cookie(request, response, fresh)
    return {"changed": True}


@router.post("/api/auth/totp/setup", response_model=TotpEnrolment, openapi_extra=documented(EmptyIn))
def totp_setup(context: Context = Depends(guard(Policy(enrolment=True, action="totp-setup"))),
               _: EmptyIn = _invalid(EmptyIn)) -> dict:
    if context.user["totp"].get("enabled"):
        raise ApiError(409, msg("auth.errors.totp_already_on"))
    with _auth_errors():
        return context.state.auth.users.begin_totp(context.user["id"])


@router.post("/api/auth/totp/confirm", response_model=TotpEnabled, openapi_extra=documented(CodeIn))
def totp_confirm(request: Request, response: Response,
                 context: Context = Depends(guard(Policy(enrolment=True, action="totp-confirm", body=64))),
                 data: CodeIn = _invalid(CodeIn)) -> dict:
    auth, user_id = context.state.auth, context.user["id"]
    with _auth_errors():
        codes = auth.users.confirm_totp(user_id, data.code)
        # Every earlier session had no second factor: close them and reissue this one with it.
        auth.sessions.revoke_user(user_id)
        fresh = auth.sessions.issue(auth.users.by_id(user_id), mfa=True)
    _set_cookie(request, response, fresh)
    return {"enabled": True, "backup_codes": codes}


@router.post("/api/auth/totp/disable", response_model=TotpDisabled, openapi_extra=documented(PasswordOnlyIn))
def totp_disable(context: Context = Depends(guard(Policy(enrolment=True, action="totp-disable", body=640))),
                 data: PasswordOnlyIn = _invalid(PasswordOnlyIn)) -> dict:
    user = context.user
    if not user["totp"].get("enabled"):
        raise ApiError(409, msg("auth.errors.totp_not_on"))
    if not verify_password(user["password"], data.password if isinstance(data.password, str) else ""):
        raise ApiError(400, msg("auth.errors.password_mismatch"))
    with _auth_errors():
        context.state.auth.users.reset_totp(user["id"])
    return {"enabled": False}


def _throttled_link(context: Context, client: str, token) -> dict | None:
    """Links are tried with a per-address attempt limit, like signing in."""
    auth, key = context.state.auth, f"link:{client}"
    wait = auth.throttle.reserve(key)
    if wait:
        raise Locked(wait)
    found = auth.users.peek_link(token)
    if found is not None:
        auth.throttle.succeeded(key)
    return found


@router.post("/api/auth/link/check", response_model=LinkInfo, openapi_extra=documented(TokenIn))
def link_check(request: Request, context: Context = Depends(guard(Policy(public=True, enrolment=True, action="check-link", body=160))),
               data: TokenIn = _invalid(TokenIn)) -> dict:
    with _auth_errors():
        found = _throttled_link(context, _client(request), data.token)
    if found is None:
        raise ApiError(404, msg("auth.errors.link_expired"))
    return found


@router.post("/api/auth/link", response_model=SignedIn | TotpStep, openapi_extra=documented(LinkIn))
def link_accept(request: Request, response: Response,
                context: Context = Depends(guard(Policy(public=True, enrolment=True, action="accept-link", body=512))),
                data: LinkIn = _invalid(LinkIn)) -> dict:
    auth, client = context.state.auth, _client(request)
    with _auth_errors():
        _throttled_link(context, client, data.token)
        redeemed = auth.users.redeem_link(data.token, data.password)
        # A new password invalidates every earlier session of that user.
        auth.sessions.revoke_user(redeemed["id"])
        result = auth.second_factor_for_link(redeemed, client)
    if "challenge" in result:
        return {"step": "totp", "challenge": result["challenge"]}
    return _signed_in(request, response, result)


@router.get("/api/users", response_model=UserList)
def list_users(context: Context = Depends(guard(Policy(admin=True)))) -> dict:
    return {"users": context.state.auth.users.list(), "totp_policy": context.state.auth.totp_policy()}


@router.post("/api/users", response_model=UserLink | UserChanged, openapi_extra=documented(UserChangeIn))
def manage_users(request: Request, context: Context = Depends(guard(Policy(admin=True, action="manage-users", body=512))),
                 data: UserChangeIn = Depends(body(UserChangeIn, msg("auth.errors.invalid_user_request")))) -> dict:
    """Invitations and account administration."""
    payload, auth, actor, log = data.model_dump(exclude_unset=True), context.state.auth, context.user, context.state.log
    action = payload["action"]

    def link_url(token: str) -> str:
        return f"{public_url(request.app.state.port)}/#link={token}"

    try:
        if action == "invite":
            created = auth.users.create(payload.get("username", ""), None, role=payload.get("role", "member"),
                                        display_name=payload.get("display_name", ""))
            token = auth.users.issue_link(created["id"], "invite")
            log.info("user_invited", extra={"user": actor["username"], "role": created["role"], "reason": created["username"]})
            return {"user": auth.users.public(auth.users.by_id(created["id"])), "link": link_url(token), "expires_in_hours": LINK_HOURS}
        target = auth.users.by_id(payload.get("user_id")) if isinstance(payload.get("user_id"), str) else None
        if target is None:
            raise ApiError(404, msg("auth.errors.user_not_found"))
        if action == "reset":
            token = auth.users.issue_link(target["id"], "invite" if target.get("password") is None else "reset")
            return {"user": auth.users.public(auth.users.by_id(target["id"])), "link": link_url(token), "expires_in_hours": LINK_HOURS}
        if action == "role":
            auth.users.set_role(target["id"], payload.get("role"), actor_id=actor["id"])
        elif action == "disable":
            auth.users.set_disabled(target["id"], True, actor_id=actor["id"])
            auth.sessions.revoke_user(target["id"])
        elif action == "enable":
            auth.users.set_disabled(target["id"], False)
        elif action == "reset_totp":
            auth.users.reset_totp(target["id"])
            auth.sessions.revoke_user(target["id"])
        log.info("user_changed", extra={"user": actor["username"], "reason": f"{action}:{target['username']}"})
        return {"user": auth.users.public(auth.users.by_id(target["id"]))}
    except AuthError as exc:
        raise ApiError(400, problem(exc)) from exc
    except OSError as exc:
        raise ApiError(500, msg("api.save_failed")) from exc
