"""Sesión, segundo factor, enlaces de invitación y administración de usuarios."""

from __future__ import annotations

import json

from tamandua.modules.identity.auth import AuthError, Locked, verify_password
from tamandua.app.api.routing import Request, route
from tamandua.app.api.security import public_url


def _fields(request: Request, *names: str) -> dict | None:
    payload = request.payload
    return payload if isinstance(payload, dict) and set(payload) == set(names) else None


def _auth_errors(handler):
    """Errores de dominio a respuestas: 429 con espera, 401 en el acceso, 400 en lo demás."""
    def wrapper(request: Request):
        try:
            return handler(request)
        except Locked as exc:
            return request.json(429, {"error": str(exc), "retry_in": exc.retry_in})
        except AuthError as exc:
            return request.json(401 if request.path in ("/api/auth/login", "/api/auth/totp") else 400, {"error": str(exc)})
        except OSError:
            return request.json(500, {"error": "No se pudo guardar el cambio"})
    wrapper.__name__ = handler.__name__
    return wrapper


def _signed_in(request: Request, result: dict):
    body = json.dumps({"step": "done", "user": result["user"]}, ensure_ascii=False).encode("utf-8")
    return request.send(200, body, "application/json; charset=utf-8",
                        cookie=request.auth.sessions.cookie(result["session"], secure=request.secure_cookies))


@route("GET", "/api/auth/session", public=True, enrolment=True)
def session(request: Request):
    auth, user = request.auth, request.user
    if user is None:
        return request.json(200, {"authenticated": False, "setup_required": auth.setup_required()})
    return request.json(200, {"authenticated": True, "user": auth.users.public(user), "mfa": request.session["mfa"],
                              "totp_required": auth.needs_totp(user), "totp_policy": auth.totp_policy()})


@route("POST", "/api/auth/setup", public=True, enrolment=True, action="setup-admin", body=900)
@_auth_errors
def setup_admin(request: Request):
    """Primer administrador desde la web, con el código de un solo uso que imprimió el servidor."""
    body = _fields(request, "code", "username", "password", "display_name")
    if body is None or not all(isinstance(value, str) for value in body.values()):
        return request.json(400, {"error": "Solicitud inválida"})
    result = request.auth.setup_admin(body["code"], body["username"], body["password"], body["display_name"], request.client)
    return _signed_in(request, result)


@route("POST", "/api/auth/login", public=True, enrolment=True, action="login", body=640)
@_auth_errors
def login(request: Request):
    body = _fields(request, "username", "password")
    if body is None:
        return request.json(400, {"error": "Solicitud inválida"})
    result = request.auth.login(body["username"], body["password"], request.client)
    if "challenge" in result:
        return request.json(200, {"step": "totp", "challenge": result["challenge"]})
    return _signed_in(request, result)


@route("POST", "/api/auth/totp", public=True, enrolment=True, action="totp")
@_auth_errors
def second_factor(request: Request):
    body = _fields(request, "challenge", "code")
    if body is None:
        return request.json(400, {"error": "Solicitud inválida"})
    return _signed_in(request, request.auth.second_factor(body["challenge"], body["code"], request.client))


@route("POST", "/api/auth/logout", enrolment=True, action="logout")
def logout(request: Request):
    request.auth.logout(request.cookie_header)
    return request.send(200, b'{"authenticated": false}', "application/json; charset=utf-8",
                        cookie=request.auth.sessions.cookie("", secure=request.secure_cookies, clear=True))


@route("POST", "/api/auth/password", enrolment=True, action="change-password", body=900)
@_auth_errors
def change_password(request: Request):
    body = _fields(request, "current", "new")
    if body is None:
        return request.json(400, {"error": "Solicitud inválida"})
    fresh = request.auth.change_password(request.user, body["current"], body["new"], request.cookie_header)
    return request.send(200, b'{"changed": true}', "application/json; charset=utf-8",
                        cookie=request.auth.sessions.cookie(fresh, secure=request.secure_cookies))


@route("POST", "/api/auth/totp/setup", enrolment=True, action="totp-setup")
@_auth_errors
def totp_setup(request: Request):
    if request.payload != {}:
        return request.json(400, {"error": "Solicitud inválida"})
    if request.user["totp"].get("enabled"):
        return request.json(409, {"error": "TOTP ya está activo; desactívalo antes de volver a enrolarlo"})
    return request.json(200, request.auth.users.begin_totp(request.user["id"]))


@route("POST", "/api/auth/totp/confirm", enrolment=True, action="totp-confirm", body=64)
@_auth_errors
def totp_confirm(request: Request):
    body = _fields(request, "code")
    if body is None:
        return request.json(400, {"error": "Solicitud inválida"})
    auth = request.auth
    codes = auth.users.confirm_totp(request.user["id"], body["code"])
    # Todas las sesiones anteriores eran sin segundo factor: se cierran y esta se reemite ya con él.
    auth.sessions.revoke_user(request.user["id"])
    fresh = auth.sessions.issue(auth.users.by_id(request.user["id"]), mfa=True)
    return request.json(200, {"enabled": True, "backup_codes": codes},
                        cookie=auth.sessions.cookie(fresh, secure=request.secure_cookies))


@route("POST", "/api/auth/totp/disable", enrolment=True, action="totp-disable", body=640)
@_auth_errors
def totp_disable(request: Request):
    body = _fields(request, "password")
    if body is None:
        return request.json(400, {"error": "Solicitud inválida"})
    if not request.user["totp"].get("enabled"):
        return request.json(409, {"error": "TOTP no está activo"})
    if not verify_password(request.user["password"], body["password"] if isinstance(body["password"], str) else ""):
        return request.json(400, {"error": "La contraseña no coincide"})
    request.auth.users.reset_totp(request.user["id"])
    return request.json(200, {"enabled": False})


def _throttled_link(request: Request, token) -> dict | None:
    """Los enlaces se prueban con límite de intentos por dirección, como el acceso."""
    key = f"link:{request.client}"
    wait = request.auth.throttle.reserve(key)
    if wait:
        raise Locked(wait)
    found = request.auth.users.peek_link(token)
    if found is not None:
        request.auth.throttle.succeeded(key)
    return found


@route("POST", "/api/auth/link/check", public=True, enrolment=True, action="check-link", body=160)
@_auth_errors
def link_check(request: Request):
    body = _fields(request, "token")
    if body is None:
        return request.json(400, {"error": "Solicitud inválida"})
    found = _throttled_link(request, body["token"])
    if found is None:
        return request.json(404, {"error": "El enlace no es válido o ya caducó; pide otro a un administrador"})
    return request.json(200, found)


@route("POST", "/api/auth/link", public=True, enrolment=True, action="accept-link", body=512)
@_auth_errors
def link_accept(request: Request):
    body = _fields(request, "token", "password")
    if body is None:
        return request.json(400, {"error": "Solicitud inválida"})
    _throttled_link(request, body["token"])
    auth = request.auth
    redeemed = auth.users.redeem_link(body["token"], body["password"])
    # Una contraseña nueva invalida cualquier sesión anterior de ese usuario.
    auth.sessions.revoke_user(redeemed["id"])
    result = auth.second_factor_for_link(redeemed, request.client)
    if "challenge" in result:
        return request.json(200, {"step": "totp", "challenge": result["challenge"]})
    return _signed_in(request, result)


@route("GET", "/api/users", admin=True)
def list_users(request: Request):
    return request.json(200, {"users": request.auth.users.list(), "totp_policy": request.auth.totp_policy()})


USER_ACTIONS = {"invite": {"action", "username", "role", "display_name"}, "reset": {"action", "user_id"},
                "role": {"action", "user_id", "role"}, "disable": {"action", "user_id"},
                "enable": {"action", "user_id"}, "reset_totp": {"action", "user_id"}}


@route("POST", "/api/users", admin=True, action="manage-users", body=512)
def manage_users(request: Request):
    """Alta por invitación y administración de cuentas."""
    payload, auth, actor = request.payload, request.auth, request.user
    if (not isinstance(payload, dict) or payload.get("action") not in USER_ACTIONS
            or not set(payload) <= USER_ACTIONS[payload["action"]]):
        return request.json(400, {"error": "Solicitud de usuario inválida"})
    action = payload["action"]
    link_url = lambda token: f"{public_url(request.port)}/#link={token}"
    try:
        if action == "invite":
            created = auth.users.create(payload.get("username", ""), None, role=payload.get("role", "member"),
                                        display_name=payload.get("display_name", ""))
            token = auth.users.issue_link(created["id"], "invite")
            request.log.info("user_invited", extra={"user": actor["username"], "role": created["role"], "reason": created["username"]})
            return request.json(200, {"user": auth.users.public(auth.users.by_id(created["id"])), "link": link_url(token),
                                      "expires_in_hours": 72})
        target = auth.users.by_id(payload.get("user_id")) if isinstance(payload.get("user_id"), str) else None
        if target is None:
            return request.json(404, {"error": "Usuario no encontrado"})
        if action == "reset":
            token = auth.users.issue_link(target["id"], "invite" if target.get("password") is None else "reset")
            return request.json(200, {"user": auth.users.public(auth.users.by_id(target["id"])), "link": link_url(token),
                                      "expires_in_hours": 72})
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
        request.log.info("user_changed", extra={"user": actor["username"], "reason": f"{action}:{target['username']}"})
        return request.json(200, {"user": auth.users.public(auth.users.by_id(target["id"]))})
    except AuthError as exc:
        return request.json(400, {"error": str(exc)})
    except OSError:
        return request.json(500, {"error": "No se pudo guardar el cambio"})
