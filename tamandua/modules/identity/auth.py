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
import os
import re
import secrets
import struct
import threading
import time
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from contextlib import contextmanager

from sqlalchemy import delete, func, select, update
from sqlalchemy.dialects.postgresql import insert

from tamandua.modules.identity.tables import auth_challenges, sessions, users
from tamandua.shared import db
from tamandua.shared.db import TENANT
from urllib.parse import quote

from tamandua.shared import log as logging_setup


class AuthError(ValueError):
    pass


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
COOKIE_NAME = "appsec_session"
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
        raise AuthError(f"La contraseña debe tener entre {PASSWORD_MIN} y {PASSWORD_MAX} caracteres")
    if any(unicodedata.category(character) == "Cc" for character in password):
        raise AuthError("La contraseña contiene caracteres de control")
    if len(set(password.lower())) < 5:
        raise AuthError("La contraseña es demasiado repetitiva")
    if username and username.lower() in password.lower():
        raise AuthError("La contraseña no puede contener el nombre de usuario")


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
                raise AuthError("Este workspace ya tiene administrador")
            return self.create(username, password, role="admin", display_name=display_name)

    def create(self, username: str, password: str | None, *, role: str = "member", display_name: str = "") -> dict:
        """Con contraseña (CLI) o sin ella (invitación: la pone el invitado con su enlace)."""
        key = normalize_username(username)
        if role not in ROLES:
            raise AuthError("Rol inválido")
        if password is not None:
            validate_password(password, key)
        display_name = " ".join(str(display_name or "").split())
        if any(unicodedata.category(character) == "Cc" for character in display_name):
            raise AuthError("El nombre contiene caracteres de control")
        with self._locked():
            rows = self._load()
            if any(user["username"] == key for user in rows):
                raise AuthError("El usuario ya existe")
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
                raise AuthError("Usuario no encontrado")
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
            raise AuthError("Rol inválido")
        user = self._update(user_id, lambda user: user.update(role=role),
                            guard=lambda rows, target: _admin_guard(rows, target, actor_id, role=role))
        _log.info("role_changed", extra={"user": user["username"], "role": role})

    # -- Enlaces de un solo uso para invitar o restablecer la contraseña: solo se guarda su hash.
    def issue_link(self, user_id: str, purpose: str) -> str:
        if purpose not in ("invite", "reset"):
            raise AuthError("Enlace inválido")
        token = secrets.token_urlsafe(32)
        def mutate(user):
            if user.get("disabled"):
                raise AuthError("El usuario está desactivado")
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
            raise AuthError("El enlace no es válido o ya caducó; pide otro a un administrador")
        purpose, digest = user["link"]["purpose"], user["link"]["hash"]
        def mutate(row):
            if (row.get("link") or {}).get("hash") != digest or row.get("disabled"):
                raise AuthError("El enlace no es válido o ya caducó; pide otro a un administrador")
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
            user["totp"] = {"enabled": False, "pending": base64.b32encode(secret).decode("ascii"),
                            "requested_at": _now()}
        user = self._update(user_id, mutate)
        return {"secret": base64.b32encode(secret).decode("ascii"), "uri": otpauth_uri(secret, user["username"])}

    def confirm_totp(self, user_id: str, code: str, moment: int | None = None) -> list[str]:
        codes = ["-".join((secrets.token_hex(5)[:5], secrets.token_hex(5)[:5])) for _ in range(BACKUP_CODES)]
        def mutate(user):
            pending = user.get("totp", {}).get("pending")
            if not pending:
                raise AuthError("No hay una activación de TOTP en curso")
            secret = base64.b32decode(pending)
            step = totp_matches(secret, code, moment or int(time.time()), None)
            if step is None:
                raise AuthError("El código no coincide; comprueba la hora del dispositivo e inténtalo de nuevo")
            user["totp"] = {"enabled": True, "secret": pending, "last_step": step, "enabled_at": _now(),
                            "backup_codes": [_hash_backup(item) for item in codes]}
        user = self._update(user_id, mutate)
        _log.info("totp_enabled", extra={"user": user["username"]})
        return codes

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
            step = totp_matches(base64.b32decode(totp["secret"]), code, moment or int(time.time()), totp.get("last_step"))
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
        raise AuthError("No puedes desactivarte ni quitarte el rol de administrador a ti mismo")
    if demotes and target["role"] == "admin" and not target.get("disabled"):
        if sum(1 for user in rows if user["role"] == "admin" and not user.get("disabled")) <= 1:
            raise AuthError("Debe quedar al menos un administrador activo")


def normalize_username(value, *, strict: bool = True) -> str:
    if not isinstance(value, str):
        raise AuthError("Nombre de usuario inválido")
    key = "".join(character for character in unicodedata.normalize("NFKC", value) if unicodedata.category(character)[0] != "C")
    key = key.strip().lower()
    if strict and not USERNAME_PATTERN.fullmatch(key):
        raise AuthError("El usuario admite 3-40 caracteres: letras, números, punto, guion y guion bajo")
    return key[:40]


# ------------------------------------------------------------------- sesiones

class Sessions:
    """Sesiones del lado del servidor (tabla sessions) con cookie firmada; el retén (`challenge`) cubre el paso TOTP.
    Validar una cookie es una búsqueda por clave primaria (antes se leía el archivo entero en cada petición)."""

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.key_path = data_dir / "auth" / "session.key"
        self._key = self._load_key()

    def _load_key(self) -> bytes:
        try:
            return base64.b64decode(self.key_path.read_text(encoding="ascii").strip())
        except FileNotFoundError:
            key = secrets.token_bytes(32)
            self.key_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            descriptor = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w", encoding="ascii") as handle:
                handle.write(base64.b64encode(key).decode("ascii"))
            return key

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
                raise AuthError("Demasiados inicios de sesión en curso; inténtalo en unos minutos")
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
    """Bloqueo progresivo por clave (usuario o dirección): 30 s, 60 s, 120 s… hasta 15 min."""

    def __init__(self):
        self._lock = threading.Lock()
        self._failures: dict[str, tuple[int, float]] = {}

    def reserve(self, key: str) -> int:
        """Comprueba el bloqueo y cuenta el intento a la vez: 0 si puede intentarlo, si no los segundos de espera.

        Contar antes de verificar cierra la carrera en la que N peticiones simultáneas pasaban
        la comprobación antes de que ninguna registrase su fallo. Un acierto llama a `succeeded`.
        """
        with self._lock:
            count, until = self._failures.get(key, (0, 0.0))
            now = time.time()
            if count >= LOCK_AFTER and until > now:
                return max(1, int(until - now))
            count += 1
            penalty = min(LOCK_MAX, LOCK_BASE * (2 ** max(0, count - LOCK_AFTER))) if count >= LOCK_AFTER else 0
            self._failures[key] = (count, now + penalty)
            if len(self._failures) > 5000:
                for stale_key, _ in sorted(self._failures.items(), key=lambda item: item[1][1])[:1000]:
                    del self._failures[stale_key]
            return 0

    def succeeded(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)


class Authenticator:
    """Orquesta usuarios, sesiones y bloqueo. Es lo único que toca el servidor."""

    def __init__(self, data_dir: Path):
        self.users = Users(data_dir)
        self.sessions = Sessions(data_dir)
        self.throttle = Throttle()

    def setup_required(self) -> bool:
        return not self.users.any()

    def setup_code(self) -> str | None:
        """Código de un solo uso para crear el primer administrador desde la web.

        Solo existe mientras no hay usuarios y solo en memoria: se imprime en la consola
        del servidor, de modo que únicamente quien controla el servidor puede reclamarlo.
        Evita que el primero que llegue a una instancia recién levantada se quede con ella.
        """
        if not self.setup_required():
            self._setup = None
            return None
        if getattr(self, "_setup", None) is None:
            alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
            self._setup = "-".join("".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(3))
        return self._setup

    def setup_admin(self, code, username, password, display_name, client: str) -> dict:
        wait = self.throttle.reserve("setup")
        if wait:
            raise Locked(wait)
        expected = getattr(self, "_setup", None)
        if not self.setup_required() or expected is None:
            raise AuthError("Este workspace ya tiene administrador")
        given = str(code or "").strip().upper().replace(" ", "")
        if not hmac.compare_digest(given.encode(), expected.encode()):
            raise AuthError("Código de configuración incorrecto: está en la consola del servidor")
        user = self.users.create_first_admin(username, password, display_name)
        self._setup = None
        self.throttle.succeeded("setup")
        _log.info("first_admin_created", extra={"user": user["username"], "client": client})
        return self._complete(user, client, mfa=False)

    @staticmethod
    def totp_policy() -> str:
        value = os.environ.get("APPSEC_AGENT_REQUIRE_TOTP", "admins").strip().lower()
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
            raise AuthError("Usuario o contraseña incorrectos")
        for scope in (f"user:{key}", f"client:{client}"):
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
            raise AuthError("Usuario o contraseña incorrectos")
        if user["totp"].get("enabled"):
            _log.info("login_password_ok", extra={"user": key, "client": client, "next": "totp"})
            return {"challenge": self.sessions.open_challenge(user["id"], client)}
        return self._complete(user, client, mfa=False)

    def second_factor(self, token, code, client: str) -> dict:
        user_id = self.sessions.peek_challenge(token, client)
        if user_id is None:
            raise AuthError("El inicio de sesión caducó; vuelve a introducir la contraseña")
        user = self.users.by_id(user_id)
        if user is None or user.get("disabled"):
            self.sessions.close_challenge(token)
            raise AuthError("El inicio de sesión caducó; vuelve a introducir la contraseña")
        wait = self.throttle.reserve(f"totp:{user_id}")
        if wait:
            raise Locked(wait)
        if not self.users.verify_totp(user_id, code):
            self.sessions.fail_challenge(token)
            _log.warning("totp_failed", extra={"user": user["username"], "client": client})
            raise AuthError("Código incorrecto")
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
            raise AuthError("La contraseña actual no coincide")
        mfa = bool((self.current(cookie_header)[1] or {}).get("mfa"))
        self.users.set_password(user["id"], new)
        self.sessions.revoke_user(user["id"])
        return self.sessions.issue(self.users.by_id(user["id"]), mfa=mfa)


class Locked(AuthError):
    def __init__(self, retry_in: int):
        super().__init__(f"Demasiados intentos; espera {retry_in} segundos")
        self.retry_in = retry_in
