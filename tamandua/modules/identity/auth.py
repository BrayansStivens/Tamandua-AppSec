"""Identidad y sesiones del panel, solo con la biblioteca estándar.

Tres piezas separadas a propósito, para que SSO/OIDC se enchufe después sin
rehacer nada:

* **Usuarios** (`data/auth/users.json`, 0600): identidad (id, usuario, rol) y sus
  credenciales locales —contraseña con scrypt y, opcionalmente, TOTP con
  códigos de respaldo—. Un proveedor externo añadiría una identidad más al
  usuario, no otro tipo de usuario.
* **Sesiones** (`data/auth/sessions.json`): del lado del servidor, para poder
  revocarlas (cerrar sesión, cambiar contraseña). El navegador solo recibe un
  identificador aleatorio firmado con HMAC en una cookie HttpOnly.
* **Límite de intentos**: por usuario y por dirección de origen, con bloqueo
  progresivo. Vive en memoria: reiniciar el servidor lo reinicia también.

Nunca se guarda ni se registra una contraseña, un código TOTP ni el valor de la
cookie; en los logs solo aparecen usuario, resultado y motivo.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import struct
import threading
import time
import unicodedata
from datetime import datetime, timedelta, timezone
from pathlib import Path
from contextlib import contextmanager

from sqlalchemy import delete, func, select, update
from sqlalchemy.dialects.postgresql import insert

from tamandua.modules.identity.tables import auth_challenges, auth_throttle, sessions, users
from tamandua.shared import db, settings, vault
from tamandua.shared.db import TENANT
from urllib.parse import quote

from tamandua.shared import log as logging_setup
from tamandua.shared.i18n import msg, text


class AuthError(ValueError):
    """`message` is what people read (rendered per reader); str() stays English, for logs."""

    def __init__(self, message, code: str | None = None):
        super().__init__(text(message, "en"))
        self.message, self.code = message, code  # `code`: stable id the panel can match on


ROLES = ("admin", "member")
USERNAME_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9._-]{1,38}[a-z0-9])?")
PASSWORD_MIN, PASSWORD_MAX = 12, 256
SCRYPT = {"n": 2 ** 15, "r": 8, "p": 1}
SESSION_TTL = 12 * 3600
CHALLENGE_TTL = 300
CHALLENGE_FAILURES = 3
TOTP_STEP, TOTP_DIGITS = 30, 6
BACKUP_CODES = 8
LINK_TTL = 72 * 3600
TOTP_POLICIES = ("admins", "all", "none")
LOCK_BASE, LOCK_MAX, LOCK_AFTER = 30, 900, 5
# A key with no attempt for this long (and no lock-out running) is forgotten; at most PRUNE_BATCH per prune.
THROTTLE_IDLE, PRUNE_BATCH = timedelta(hours=1), 500
COOKIE_NAME = "tamandua_session"
_log = logging_setup.get("auth")
_SCRYPT_SLOTS = threading.BoundedSemaphore(8)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------- contraseñas

def hash_password(password: str) -> dict:
    validate_password(password)
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, dklen=32, maxmem=128 * 1024 * 1024, **SCRYPT)
    return {"algorithm": "scrypt", **SCRYPT, "salt": base64.b64encode(salt).decode("ascii"),
            "hash": base64.b64encode(digest).decode("ascii")}


def verify_password(record: dict | None, password: str) -> bool:
    # Con un usuario inexistente se calcula igual sobre un registro fijo: el
    # tiempo de respuesta no dice si el usuario existe.
    record = record or _DUMMY
    try:
        digest = hashlib.scrypt(password.encode("utf-8"), salt=base64.b64decode(record["salt"]), dklen=32,
                                maxmem=128 * 1024 * 1024, n=record["n"], r=record["r"], p=record["p"])
    except (KeyError, ValueError, TypeError):
        return False
    return hmac.compare_digest(digest, base64.b64decode(record["hash"]))


def validate_password(password: str, username: str = "") -> None:
    if not isinstance(password, str) or not PASSWORD_MIN <= len(password) <= PASSWORD_MAX:
        raise AuthError(msg("auth.errors.password_length", min=PASSWORD_MIN, max=PASSWORD_MAX))
    if any(unicodedata.category(character) == "Cc" for character in password):
        raise AuthError(msg("auth.errors.password_control"))
    if len(set(password.lower())) < 5:
        raise AuthError(msg("auth.errors.password_repetitive"))
    if username and username.lower() in password.lower():
        raise AuthError(msg("auth.errors.password_has_username"))


_DUMMY = {"salt": base64.b64encode(b"\0" * 16).decode("ascii"), "hash": base64.b64encode(b"\0" * 32).decode("ascii"),
          **SCRYPT}


# ---------------------------------------------------------------------- TOTP

def totp_code(secret: bytes, moment: int, *, digits: int = TOTP_DIGITS, step: int = TOTP_STEP) -> str:
    counter = struct.pack(">Q", moment // step)
    mac = hmac.new(secret, counter, hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    number = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(number % (10 ** digits)).zfill(digits)


def totp_matches(secret: bytes, code: str, moment: int, last_step: int | None) -> int | None:
    """Devuelve el paso aceptado (±1 de tolerancia) o None. Un paso ya usado no vale dos veces."""
    if not isinstance(code, str) or not re.fullmatch(r"\d{6}", code):
        return None
    current = moment // TOTP_STEP
    for step in (current, current - 1, current + 1):
        if last_step is not None and step <= last_step:
            continue
        if hmac.compare_digest(totp_code(secret, step * TOTP_STEP), code):
            return step
    return None


def otpauth_uri(secret: bytes, username: str, issuer: str = "Tamandua") -> str:
    encoded = base64.b32encode(secret).decode("ascii").rstrip("=")
    return (f"otpauth://totp/{quote(issuer)}:{quote(username)}?secret={encoded}&issuer={quote(issuer)}"
            f"&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_STEP}")


def _hash_backup(code: str) -> str:
    return hashlib.sha256(code.replace("-", "").lower().encode("ascii")).hexdigest()


TOTP_PURPOSE = "totp"


def _seal_totp(encoded: str) -> str:
    """TOTP seeds are sealed with the master key: a database dump alone can't mint codes."""
    return vault.seal(encoded, TOTP_PURPOSE)


def _totp_seed(totp: dict, field: str) -> bytes | None:
    """`field` is "secret" or "pending". Seeds stored in the clear by earlier versions are still read
    (the `seal_totp_seeds` data migration rewrites them)."""
    sealed = totp.get(f"{field}_sealed")
    if sealed:
        return base64.b32decode(vault.unseal(sealed, TOTP_PURPOSE))
    legacy = totp.get(field)
    return base64.b32decode(legacy) if legacy else None


def _seal_clear_seeds(totp: dict) -> bool:
    """Replaces clear seeds with sealed ones in place. True if something changed."""
    changed = False
    for field in ("secret", "pending"):
        if isinstance(totp.get(field), str):
            totp[f"{field}_sealed"] = _seal_totp(totp.pop(field))
            changed = True
    return changed


# ------------------------------------------------------------------- usuarios

class Users:
    """Usuarios en PostgreSQL (tabla users). Los cambios van en transacción con cerrojo: dos altas o cambios a la vez,
    desde el API o la CLI, no se pisan."""

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir

    @contextmanager
    def _locked(self):
        with db.transaction(self.data_dir) as connection:
            db.lock(connection, "users")
            yield

    def _load(self) -> list[dict]:
        with db.transaction(self.data_dir) as connection:
            return list(connection.execute(select(users.c.record).where(users.c.tenant_id == TENANT)
                                           .order_by(users.c.position, users.c.id)).scalars())

    def _save(self, rows: list[dict]) -> None:
        with db.transaction(self.data_dir) as connection:
            connection.execute(delete(users).where(users.c.tenant_id == TENANT, users.c.id.not_in([row["id"] for row in rows])))
            if rows:
                statement = insert(users)
                connection.execute(statement.on_conflict_do_update(
                    index_elements=[users.c.tenant_id, users.c.id],
                    set_={"username": statement.excluded.username, "position": statement.excluded.position,
                          "record": statement.excluded.record, "updated_at": func.now()}),
                    [{"tenant_id": TENANT, "id": row["id"], "username": row["username"], "position": index, "record": row}
                     for index, row in enumerate(rows)])

    def any(self) -> bool:
        return bool(self._load())

    def public(self, user: dict) -> dict:
        return {"id": user["id"], "username": user["username"], "display_name": user["display_name"],
                "role": user["role"], "totp_enabled": bool(user.get("totp", {}).get("enabled")),
                "disabled": bool(user.get("disabled")), "created_at": user["created_at"],
                "last_login_at": user.get("last_login_at"), "has_password": user.get("password") is not None,
                "pending_link": (user.get("link") or {}).get("purpose") if (user.get("link") or {}).get("expires_at", 0) > time.time() else None}

    def list(self) -> list[dict]:
        return [self.public(user) for user in self._load()]

    def get(self, username: str) -> dict | None:
        key = normalize_username(username, strict=False)
        return next((user for user in self._load() if user["username"] == key), None)

    def by_id(self, user_id: str) -> dict | None:
        return next((user for user in self._load() if user["id"] == user_id), None)

    def create_first_admin(self, username: str, password: str, display_name: str = "") -> dict:
        """Como `create`, pero solo si no hay nadie: dos altas simultáneas no crean dos administradores."""
        with self._locked():
            if self.any():
                raise AuthError(msg("auth.errors.workspace_has_admin"))
            return self.create(username, password, role="admin", display_name=display_name)

    def create(self, username: str, password: str | None, *, role: str = "member", display_name: str = "") -> dict:
        """Con contraseña (CLI) o sin ella (invitación: la pone el invitado con su enlace)."""
        key = normalize_username(username)
        if role not in ROLES:
            raise AuthError(msg("auth.errors.invalid_role"))
        if password is not None:
            validate_password(password, key)
        display_name = " ".join(str(display_name or "").split())
        if any(unicodedata.category(character) == "Cc" for character in display_name):
            raise AuthError(msg("auth.errors.name_control"))
        with self._locked():
            rows = self._load()
            if any(user["username"] == key for user in rows):
                raise AuthError(msg("auth.errors.user_exists"))
            user = {"id": secrets.token_hex(12), "username": key, "display_name": (display_name or key)[:80],
                    "role": role, "password": hash_password(password) if password is not None else None, "totp": {"enabled": False},
                    "identities": [{"provider": "local", "subject": key}],
                    "disabled": False, "created_at": _now(), "last_login_at": None, "password_changed_at": _now()}
            rows.append(user)
            self._save(rows)
        _log.info("user_created", extra={"user": key, "role": role})
        return self.public(user)

    def _update(self, user_id: str, mutate, guard=None) -> dict:
        with self._locked():
            rows = self._load()
            user = next((row for row in rows if row["id"] == user_id), None)
            if user is None:
                raise AuthError(msg("auth.errors.user_not_found"))
            if guard is not None:
                guard(rows, user)
            mutate(user)
            self._save(rows)
            return user

    def set_password(self, user_id: str, password: str) -> None:
        def mutate(user):
            validate_password(password, user["username"])
            user["password"] = hash_password(password)
            user["password_changed_at"] = _now()
        user = self._update(user_id, mutate)
        _log.info("password_changed", extra={"user": user["username"]})

    def set_role(self, user_id: str, role: str, *, actor_id: str | None = None) -> None:
        if role not in ROLES:
            raise AuthError(msg("auth.errors.invalid_role"))
        user = self._update(user_id, lambda user: user.update(role=role),
                            guard=lambda rows, target: _admin_guard(rows, target, actor_id, role=role))
        _log.info("role_changed", extra={"user": user["username"], "role": role})

    # -- Enlaces de un solo uso para invitar o restablecer la contraseña: solo se guarda su hash.
    def issue_link(self, user_id: str, purpose: str) -> str:
        if purpose not in ("invite", "reset"):
            raise AuthError(msg("auth.errors.invalid_link"))
        token = secrets.token_urlsafe(32)
        def mutate(user):
            if user.get("disabled"):
                raise AuthError(msg("auth.errors.user_disabled"))
            user["link"] = {"hash": hashlib.sha256(token.encode("ascii")).hexdigest(), "purpose": purpose,
                            "expires_at": time.time() + LINK_TTL}
        user = self._update(user_id, mutate)
        _log.info("link_issued", extra={"user": user["username"], "reason": purpose})
        return token

    def _by_link(self, token) -> dict | None:
        if not isinstance(token, str) or not 20 <= len(token) <= 64:
            return None
        digest = hashlib.sha256(token.encode("ascii", "ignore")).hexdigest()
        for user in self._load():
            link = user.get("link") or {}
            if link.get("hash") and hmac.compare_digest(link["hash"], digest) and link.get("expires_at", 0) > time.time() \
                    and not user.get("disabled"):
                return user
        return None

    def peek_link(self, token) -> dict | None:
        user = self._by_link(token)
        return None if user is None else {"username": user["username"], "display_name": user["display_name"],
                                          "purpose": user["link"]["purpose"]}

    def redeem_link(self, token, password) -> dict:
        user = self._by_link(token)
        if user is None:
            raise AuthError(msg("auth.errors.link_expired"))
        purpose, digest = user["link"]["purpose"], user["link"]["hash"]
        def mutate(row):
            if (row.get("link") or {}).get("hash") != digest or row.get("disabled"):
                raise AuthError(msg("auth.errors.link_expired"))
            validate_password(password, row["username"])
            row["password"] = hash_password(password)
            row["password_changed_at"] = _now()
            row.pop("link", None)
        self._update(user["id"], mutate)
        _log.info("link_redeemed", extra={"user": user["username"], "reason": purpose})
        return self.by_id(user["id"])

    def set_disabled(self, user_id: str, disabled: bool, *, actor_id: str | None = None) -> None:
        user = self._update(user_id, lambda user: user.update(disabled=disabled),
                            guard=(lambda rows, target: _admin_guard(rows, target, actor_id, disable=True)) if disabled else None)
        _log.info("user_disabled" if disabled else "user_enabled", extra={"user": user["username"]})

    def touch_login(self, user_id: str) -> None:
        self._update(user_id, lambda user: user.update(last_login_at=_now()))

    # -- TOTP: se prepara (secreto pendiente), se confirma con un código válido y queda activo.
    def begin_totp(self, user_id: str) -> dict:
        secret = secrets.token_bytes(20)
        def mutate(user):
            user["totp"] = {"enabled": False, "pending_sealed": _seal_totp(base64.b32encode(secret).decode("ascii")),
                            "requested_at": _now()}
        user = self._update(user_id, mutate)
        return {"secret": base64.b32encode(secret).decode("ascii"), "uri": otpauth_uri(secret, user["username"])}

    def confirm_totp(self, user_id: str, code: str, moment: int | None = None) -> list[str]:
        codes = ["-".join((secrets.token_hex(5)[:5], secrets.token_hex(5)[:5])) for _ in range(BACKUP_CODES)]
        def mutate(user):
            secret = _totp_seed(user.get("totp", {}), "pending")
            if not secret:
                raise AuthError(msg("auth.errors.no_totp_setup"))
            step = totp_matches(secret, code, moment or int(time.time()), None)
            if step is None:
                raise AuthError(msg("auth.errors.totp_mismatch"))
            user["totp"] = {"enabled": True, "secret_sealed": _seal_totp(base64.b32encode(secret).decode("ascii")),
                            "last_step": step, "enabled_at": _now(),
                            "backup_codes": [_hash_backup(item) for item in codes]}
        user = self._update(user_id, mutate)
        _log.info("totp_enabled", extra={"user": user["username"]})
        return codes

    def seal_clear_totp(self) -> int:
        """Seals the TOTP seeds that earlier versions stored in the clear. Returns how many users changed."""
        with self._locked():
            rows = self._load()
            changed = sum(1 for row in rows if isinstance(row.get("totp"), dict) and _seal_clear_seeds(row["totp"]))
            if changed:
                self._save(rows)
            return changed

    def reset_totp(self, user_id: str) -> None:
        user = self._update(user_id, lambda user: user.update(totp={"enabled": False}))
        _log.info("totp_reset", extra={"user": user["username"]})

    def verify_totp(self, user_id: str, code: str, moment: int | None = None) -> bool:
        """Acepta un código TOTP o un código de respaldo; consume lo que use."""
        outcome = {"ok": False}
        def mutate(user):
            totp = user.get("totp", {})
            if not totp.get("enabled"):
                return
            seed = _totp_seed(totp, "secret")
            step = totp_matches(seed, code, moment or int(time.time()), totp.get("last_step")) if seed else None
            if step is not None:
                totp["last_step"] = step
                outcome["ok"] = True
                return
            if isinstance(code, str) and re.fullmatch(r"[0-9a-f]{5}-?[0-9a-f]{5}", code.lower()):
                digest = _hash_backup(code)
                if digest in totp.get("backup_codes", []):
                    totp["backup_codes"].remove(digest)
                    outcome["ok"] = True
                    outcome["backup"] = True
        user = self._update(user_id, mutate)
        if outcome.get("backup"):
            _log.warning("backup_code_used", extra={"user": user["username"],
                                                    "remaining": len(user["totp"].get("backup_codes", []))})
        return outcome["ok"]


def _admin_guard(rows: list[dict], target: dict, actor_id: str | None, *, role: str | None = None, disable: bool = False) -> None:
    """Nadie se quita a sí mismo el acceso de administrador y nunca se queda el sistema sin uno activo."""
    demotes = disable or (role is not None and role != "admin")
    if actor_id is not None and target["id"] == actor_id and demotes:
        raise AuthError(msg("auth.errors.self_demote"))
    if demotes and target["role"] == "admin" and not target.get("disabled"):
        if sum(1 for user in rows if user["role"] == "admin" and not user.get("disabled")) <= 1:
            raise AuthError(msg("auth.errors.last_admin"))


def normalize_username(value, *, strict: bool = True) -> str:
    if not isinstance(value, str):
        raise AuthError(msg("auth.errors.invalid_username"))
    key = "".join(character for character in unicodedata.normalize("NFKC", value) if unicodedata.category(character)[0] != "C")
    key = key.strip().lower()
    if strict and not USERNAME_PATTERN.fullmatch(key):
        raise AuthError(msg("auth.errors.username_format"))
    return key[:40]


# ------------------------------------------------------------------- sesiones

SESSION_KEY = "session-key"
SETUP_CODE = "setup-code"


def import_session_key(data_dir: Path) -> int:
    """The session signing key of earlier versions (data/auth/session.key) moves to the vault, so signed-in people
    stay signed in. Returns 1 if it was imported."""
    path = data_dir / "auth" / "session.key"
    try:
        key = path.read_text(encoding="ascii").strip()
    except FileNotFoundError:
        return 0
    stored = vault.put_if_absent(SESSION_KEY, {"session_key": key})
    try:
        path.rename(path.with_name("session.key.imported"))
    except OSError:
        pass
    return int(stored["session_key"] == key)


class Sessions:
    """Sesiones del lado del servidor (tabla sessions) con cookie firmada; el retén (`challenge`) cubre el paso TOTP.
    Validar una cookie es una búsqueda por clave primaria (antes se leía el archivo entero en cada petición)."""

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self._key = self._load_key()

    def _load_key(self) -> bytes:
        """TAMANDUA_SESSION_KEY, or one generated once and kept in the vault (sealed with the master key: whoever reads
        the database alone can't sign sessions), shared by every instance of the API."""
        configured = settings.text("TAMANDUA_SESSION_KEY")
        if configured:
            return base64.b64decode(configured)
        stored = vault.put_if_absent(SESSION_KEY, {"session_key": base64.b64encode(secrets.token_bytes(32)).decode("ascii")})
        return base64.b64decode(stored["session_key"])

    def _sign(self, session_id: str) -> str:
        return hmac.new(self._key, session_id.encode("ascii"), hashlib.sha256).hexdigest()[:32]

    def issue(self, user: dict, *, mfa: bool) -> str:
        session_id = secrets.token_urlsafe(32)
        now = time.time()
        record = {"user_id": user["id"], "created_at": now, "expires_at": now + SESSION_TTL, "mfa": mfa,
                  "password_changed_at": user.get("password_changed_at")}
        with db.transaction(self.data_dir) as connection:
            connection.execute(delete(sessions).where(sessions.c.tenant_id == TENANT, sessions.c.expires_at <= now))
            connection.execute(insert(sessions).values(tenant_id=TENANT, id=hashlib.sha256(session_id.encode("ascii")).hexdigest(),
                                                       user_id=user["id"], expires_at=record["expires_at"], record=record))
        return f"{session_id}.{self._sign(session_id)}"

    def resolve(self, cookie_value: str | None) -> dict | None:
        if not cookie_value or "." not in cookie_value or len(cookie_value) > 120 or not cookie_value.isascii():
            return None
        session_id, _, signature = cookie_value.rpartition(".")
        if not hmac.compare_digest(self._sign(session_id), signature):
            return None
        with db.transaction(self.data_dir) as connection:
            row = connection.execute(select(sessions.c.record).where(
                sessions.c.tenant_id == TENANT, sessions.c.id == hashlib.sha256(session_id.encode("ascii")).hexdigest())).scalar_one_or_none()
        if row is None or row["expires_at"] <= time.time():
            return None
        return {**row, "session_hash": hashlib.sha256(session_id.encode("ascii")).hexdigest()}

    def revoke(self, cookie_value: str | None) -> None:
        session = self.resolve(cookie_value)
        if session is None:
            return
        with db.transaction(self.data_dir) as connection:
            connection.execute(delete(sessions).where(sessions.c.tenant_id == TENANT, sessions.c.id == session["session_hash"]))

    def revoke_user(self, user_id: str, *, keep: str | None = None) -> int:
        with db.transaction(self.data_dir) as connection:
            return connection.execute(delete(sessions).where(sessions.c.tenant_id == TENANT, sessions.c.user_id == user_id,
                                                             sessions.c.id != (keep or ""))).rowcount

    def cookie(self, value: str, *, secure: bool, clear: bool = False) -> str:
        attributes = [f"{COOKIE_NAME}={'' if clear else value}", "Path=/", "HttpOnly", "SameSite=Strict"]
        attributes.append("Max-Age=0" if clear else f"Max-Age={SESSION_TTL}")
        if secure:
            attributes.append("Secure")
        return "; ".join(attributes)

    # -- retén entre contraseña correcta y TOTP: token opaco de vida corta, del lado del servidor.
    def open_challenge(self, user_id: str, client: str) -> str:
        token = secrets.token_urlsafe(32)
        now = time.time()
        with db.transaction(self.data_dir) as connection:
            connection.execute(delete(auth_challenges).where(auth_challenges.c.tenant_id == TENANT, auth_challenges.c.created_at + CHALLENGE_TTL < now))
            if connection.execute(select(func.count()).select_from(auth_challenges).where(auth_challenges.c.tenant_id == TENANT)).scalar_one() >= 200:
                raise AuthError(msg("auth.errors.too_many_logins"))
            connection.execute(insert(auth_challenges).values(tenant_id=TENANT, id=_token_hash(token), user_id=user_id, client=client, created_at=now))
        return token

    def peek_challenge(self, token, client: str) -> str | None:
        if not isinstance(token, str) or len(token) > 64:
            return None
        with db.transaction(self.data_dir) as connection:
            row = connection.execute(select(auth_challenges.c.user_id, auth_challenges.c.client, auth_challenges.c.created_at)
                                     .where(auth_challenges.c.tenant_id == TENANT, auth_challenges.c.id == _token_hash(token))).first()
        if row is None or row.created_at + CHALLENGE_TTL < time.time() or row.client != client:
            return None
        return row.user_id

    def close_challenge(self, token: str) -> None:
        with db.transaction(self.data_dir) as connection:
            connection.execute(delete(auth_challenges).where(auth_challenges.c.tenant_id == TENANT, auth_challenges.c.id == _token_hash(token)))

    def fail_challenge(self, token: str) -> None:
        """Tres códigos fallidos agotan el reto: hay que volver a la contraseña."""
        with db.transaction(self.data_dir) as connection:
            failures = connection.execute(update(auth_challenges).where(auth_challenges.c.tenant_id == TENANT, auth_challenges.c.id == _token_hash(token))
                                          .values(failures=auth_challenges.c.failures + 1).returning(auth_challenges.c.failures)).scalar_one_or_none()
            if failures is not None and failures >= CHALLENGE_FAILURES:
                connection.execute(delete(auth_challenges).where(auth_challenges.c.tenant_id == TENANT, auth_challenges.c.id == _token_hash(token)))


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def parse_cookie(header: str | None) -> str | None:
    for part in (header or "").split(";"):
        name, _, value = part.strip().partition("=")
        if name == COOKIE_NAME and value:
            return value
    return None


# ------------------------------------------------------- límite de intentos

class Throttle:
    """Progressive lock-out per key (user or address): 30 s, 60 s, 120 s… up to 15 min. In the database, so every
    instance of the API counts the same attempts and a restart doesn't reset them."""

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir

    def reserve(self, key: str) -> int:
        """Checks the lock-out and counts the attempt at once: 0 if it may go ahead, else the seconds to wait.

        Counting before verifying closes the race where N simultaneous requests passed the check before any of them
        recorded its failure (the row lock serializes them). A success calls `succeeded`.
        """
        condition = (auth_throttle.c.tenant_id == TENANT, auth_throttle.c.key == key)
        with db.transaction(self.data_dir) as connection:
            connection.execute(insert(auth_throttle).values(tenant_id=TENANT, key=key).on_conflict_do_nothing())
            row = connection.execute(select(auth_throttle.c.failures, auth_throttle.c.until).where(*condition).with_for_update()).one()
            now = time.time()
            if row.failures >= LOCK_AFTER and row.until > now:
                return max(1, int(row.until - now))
            count = row.failures + 1
            penalty = min(LOCK_MAX, LOCK_BASE * (2 ** max(0, count - LOCK_AFTER))) if count >= LOCK_AFTER else 0
            connection.execute(update(auth_throttle).where(*condition).values(failures=count, until=now + penalty, updated_at=func.now()))
            if secrets.randbelow(20) == 0:
                self._prune(connection, now)
            return 0

    @staticmethod
    def _prune(connection, now: float) -> None:
        """Forgets idle keys, a bounded batch at a time (indexed by age): the table can't grow without end, and no
        single sign-in pays for clearing it."""
        idle = (select(auth_throttle.c.key).where(auth_throttle.c.tenant_id == TENANT, auth_throttle.c.until < now,
                                                  auth_throttle.c.updated_at < func.now() - THROTTLE_IDLE)
                .order_by(auth_throttle.c.updated_at).limit(PRUNE_BATCH))
        connection.execute(delete(auth_throttle).where(auth_throttle.c.tenant_id == TENANT, auth_throttle.c.key.in_(idle.scalar_subquery())))

    def succeeded(self, key: str) -> None:
        with db.transaction(self.data_dir) as connection:
            connection.execute(delete(auth_throttle).where(auth_throttle.c.tenant_id == TENANT, auth_throttle.c.key == key))


class Authenticator:
    """Orquesta usuarios, sesiones y bloqueo. Es lo único que toca el servidor."""

    def __init__(self, data_dir: Path):
        self.users = Users(data_dir)
        self.sessions = Sessions(data_dir)
        self.throttle = Throttle(data_dir)

    def setup_required(self) -> bool:
        return not self.users.any()

    def setup_code(self) -> str | None:
        """One-time code to create the first administrator from the web.

        It exists only while there are no users. It is printed on the server's console (and `tamandua setup-code`
        shows it), so only whoever controls the server can claim a freshly started instance. It lives in the vault,
        so every instance of the API accepts the same code.
        """
        if not self.setup_required():
            vault.delete(SETUP_CODE)
            return None
        # `make setup-code` and the logs show it in this format (XXXX-XXXX-XXXX from this alphabet).
        alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
        code = "-".join("".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(3))
        return vault.put_if_absent(SETUP_CODE, {"code": code})["code"]

    def setup_admin(self, code, username, password, display_name, client: str) -> dict:
        wait = self.throttle.reserve("setup")
        if wait:
            raise Locked(wait)
        expected = (vault.get(SETUP_CODE) or {}).get("code")
        if not self.setup_required() or expected is None:
            raise AuthError(msg("auth.errors.workspace_has_admin"))
        given = str(code or "").strip().upper().replace(" ", "")
        if not hmac.compare_digest(given.encode(), expected.encode()):
            raise AuthError(msg("auth.errors.wrong_setup_code"))
        created = self.users.create_first_admin(username, password, display_name)
        user = self.users.by_id(created["id"])  # the stored record: the session must carry its password_changed_at
        vault.delete(SETUP_CODE)
        self.throttle.succeeded("setup")
        _log.info("first_admin_created", extra={"user": user["username"], "client": client})
        return self._complete(user, client, mfa=False)

    @staticmethod
    def totp_policy() -> str:
        value = settings.text("TAMANDUA_REQUIRE_TOTP").lower()
        return value if value in TOTP_POLICIES else "admins"

    def needs_totp(self, user: dict) -> bool:
        """Verdadero si la política exige TOTP a este usuario y aún no lo tiene: solo puede enrolarse."""
        policy = self.totp_policy()
        required = policy == "all" or (policy == "admins" and user.get("role") == "admin")
        return required and not user.get("totp", {}).get("enabled")

    def second_factor_for_link(self, user: dict, client: str) -> dict:
        """Tras canjear un enlace: si la cuenta tiene TOTP, el enlace sustituye la contraseña, no el segundo factor."""
        if user["totp"].get("enabled"):
            return {"challenge": self.sessions.open_challenge(user["id"], client)}
        return self._complete(user, client, mfa=False)

    def login(self, username, password, client: str) -> dict:
        """Primer paso. Devuelve {"session": cookie} o {"challenge": token} si falta TOTP."""
        key = normalize_username(username, strict=False) if isinstance(username, str) else ""
        if not key or not isinstance(password, str) or len(password) > PASSWORD_MAX:
            raise AuthError(msg("auth.errors.bad_credentials"))
        # The address first: once it is locked out, made-up usernames from it add no rows.
        for scope in (f"client:{client}", f"user:{key}"):
            wait = self.throttle.reserve(scope)
            if wait:
                _log.warning("login_blocked", extra={"user": key, "client": client, "retry_in": wait})
                raise Locked(wait)
        user = self.users.get(key)
        # Un número acotado de scrypt a la vez: cada uno reserva 32 MiB.
        with _SCRYPT_SLOTS:
            ok = verify_password(user["password"] if user else None, password) and user is not None and not user.get("disabled")
        if not ok:
            _log.warning("login_failed", extra={"user": key, "client": client,
                                                "reason": "disabled" if user and user.get("disabled") else "credentials"})
            raise AuthError(msg("auth.errors.bad_credentials"))
        if user["totp"].get("enabled"):
            _log.info("login_password_ok", extra={"user": key, "client": client, "next": "totp"})
            return {"challenge": self.sessions.open_challenge(user["id"], client)}
        return self._complete(user, client, mfa=False)

    def second_factor(self, token, code, client: str) -> dict:
        user_id = self.sessions.peek_challenge(token, client)
        if user_id is None:
            raise AuthError(msg("auth.errors.login_expired"), code="challenge_expired")
        user = self.users.by_id(user_id)
        if user is None or user.get("disabled"):
            self.sessions.close_challenge(token)
            raise AuthError(msg("auth.errors.login_expired"), code="challenge_expired")
        wait = self.throttle.reserve(f"totp:{user_id}")
        if wait:
            raise Locked(wait)
        if not self.users.verify_totp(user_id, code):
            self.sessions.fail_challenge(token)
            _log.warning("totp_failed", extra={"user": user["username"], "client": client})
            raise AuthError(msg("auth.errors.wrong_code"))
        self.throttle.succeeded(f"totp:{user_id}")
        self.sessions.close_challenge(token)
        return self._complete(user, client, mfa=True)

    def _complete(self, user: dict, client: str, *, mfa: bool) -> dict:
        self.throttle.succeeded(f"user:{user['username']}")
        self.throttle.succeeded(f"client:{client}")
        self.users.touch_login(user["id"])
        _log.info("login_ok", extra={"user": user["username"], "client": client, "mfa": mfa})
        return {"session": self.sessions.issue(user, mfa=mfa), "user": self.users.public(user)}

    def current(self, cookie_header: str | None) -> tuple[dict | None, dict | None]:
        session = self.sessions.resolve(parse_cookie(cookie_header))
        if session is None:
            return None, None
        user = self.users.by_id(session["user_id"])
        if user is None or user.get("disabled") or user.get("password_changed_at") != session.get("password_changed_at"):
            return None, None
        return user, session

    def logout(self, cookie_header: str | None) -> None:
        self.sessions.revoke(parse_cookie(cookie_header))

    def change_password(self, user: dict, current: str, new: str, cookie_header: str | None) -> str:
        """Cambia la contraseña, cierra las demás sesiones y devuelve una cookie nueva para esta."""
        if not verify_password(user["password"], current if isinstance(current, str) else ""):
            raise AuthError(msg("auth.errors.current_password_mismatch"))
        mfa = bool((self.current(cookie_header)[1] or {}).get("mfa"))
        self.users.set_password(user["id"], new)
        self.sessions.revoke_user(user["id"])
        return self.sessions.issue(self.users.by_id(user["id"]), mfa=mfa)


class Locked(AuthError):
    def __init__(self, retry_in: int):
        super().__init__(msg("auth.errors.locked", seconds=retry_in))
        self.retry_in = retry_in
