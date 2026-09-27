"""Almacén cifrado de secretos: claves de IA, la GitHub App y el token de Jira.

Cada secreto se cifra por separado con AES-256-GCM y su nombre como dato asociado,
así que un valor no se puede trasplantar a otra entrada sin que falle el descifrado.
El fichero (`secrets.vault`) y la clave maestra (`master.key`) viven en el directorio
de configuración, fuera de `data/` —que es lo que se suele copiar, compartir o subir
con los logs— y con permisos solo del propietario.

La clave maestra puede venir del entorno (`TAMANDUA_MASTER_KEY`, 32 bytes en
base64), que es lo recomendable en un despliegue con gestor de secretos: así el
almacén copiado sin la clave no sirve de nada. Si no, se genera una la primera vez.

Ningún valor sale de aquí hacia el navegador ni hacia los logs: los que se leen se
registran en el filtro de logs para que, si se colaran en un mensaje, se tachen.
"""

from __future__ import annotations

import base64
import fcntl
import json
import os
import secrets
import stat
import threading
from contextlib import contextmanager
from pathlib import Path

from tamandua.shared import paths, settings
from tamandua.shared import log as logging_setup
from tamandua.shared.i18n import msg, text

VAULT_FILE = "secrets.vault"
KEY_FILE = "master.key"
_lock = threading.Lock()


class VaultError(RuntimeError):
    """`message` is what people read (rendered per reader); str() stays English, for logs."""

    def __init__(self, message):
        super().__init__(text(message, "en"))
        self.message = message


def _dir() -> Path:
    return paths.CONFIG_DIR  # se lee en cada llamada: las pruebas lo redirigen a un temporal


def _private_dir() -> Path:
    folder = _dir()
    folder.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(folder, stat.S_IRWXU)
    except OSError:
        pass  # un volumen montado puede no admitirlo; los ficheros siguen siendo 0600
    return folder


def _write_private(path: Path, content: bytes, mode: int = stat.S_IRUSR | stat.S_IWUSR) -> None:
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary, mode)
    os.replace(temporary, path)


def _master_key() -> bytes:
    configured = settings.text("TAMANDUA_MASTER_KEY")
    if configured:
        try:
            key = base64.b64decode(configured, validate=True)
        except ValueError as exc:
            raise VaultError(msg("vault.errors.master_key_not_base64")) from exc
        if len(key) != 32:
            raise VaultError(msg("vault.errors.master_key_length"))
        return key
    path = _private_dir() / KEY_FILE
    try:
        key = base64.b64decode(path.read_text(encoding="ascii").strip(), validate=True)
    except FileNotFoundError:
        key = secrets.token_bytes(32)
        _write_private(path, base64.b64encode(key) + b"\n", stat.S_IRUSR)
        return key
    except (ValueError, OSError) as exc:
        raise VaultError(msg("vault.errors.master_key_unreadable")) from exc
    if len(key) != 32:
        raise VaultError(msg("vault.errors.master_key_damaged"))
    return key


def _load() -> dict:
    try:
        payload = json.loads((_dir() / VAULT_FILE).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (ValueError, OSError) as exc:
        raise VaultError(msg("vault.errors.vault_damaged")) from exc
    return payload if isinstance(payload, dict) else {}


def get(name: str):
    """El valor descifrado (cualquier JSON) o None si no existe."""
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    entry = _load().get(name)
    if not isinstance(entry, dict):
        return None
    try:
        plain = AESGCM(_master_key()).decrypt(base64.b64decode(entry["nonce"]), base64.b64decode(entry["data"]), name.encode())
        value = json.loads(plain)
    except (InvalidTag, KeyError, ValueError, TypeError) as exc:
        raise VaultError(msg("vault.errors.cannot_decrypt")) from exc
    _register(value)
    return value


@contextmanager
def _exclusive():
    """Cerrojo del almacén entre hilos y entre procesos (el API y el worker lo escriben): sin él, dos escrituras a la
    vez podían perder un secreto de la otra."""
    with _lock:
        path = _private_dir() / ".vault.lock"
        with open(path, "a+") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)


def seal(value, purpose: str) -> str:
    """Cifra un valor con la clave maestra para guardarlo fuera del almacén (p. ej. los tokens de un trabajo en la cola).
    `purpose` va como dato asociado: un sellado para una cosa no se puede abrir como otra."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = secrets.token_bytes(12)
    data = AESGCM(_master_key()).encrypt(nonce, json.dumps(value, ensure_ascii=False).encode(), f"sealed:{purpose}".encode())
    return base64.b64encode(nonce + data).decode()


def unseal(sealed: str, purpose: str):
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    try:
        raw = base64.b64decode(sealed, validate=True)
        return json.loads(AESGCM(_master_key()).decrypt(raw[:12], raw[12:], f"sealed:{purpose}".encode()))
    except (InvalidTag, ValueError, TypeError) as exc:
        raise VaultError(msg("vault.errors.cannot_unseal")) from exc


def put(name: str, value) -> None:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = secrets.token_bytes(12)
    data = AESGCM(_master_key()).encrypt(nonce, json.dumps(value, ensure_ascii=False).encode(), name.encode())
    with _exclusive():
        payload = _load()
        payload[name] = {"nonce": base64.b64encode(nonce).decode(), "data": base64.b64encode(data).decode()}
        _write_private(_private_dir() / VAULT_FILE, json.dumps(payload, indent=2).encode())
    _register(value)


def delete(name: str) -> bool:
    with _exclusive():
        payload = _load()
        if payload.pop(name, None) is None:
            return False
        _write_private(_private_dir() / VAULT_FILE, json.dumps(payload, indent=2).encode())
    return True


def names() -> list[str]:
    return sorted(_load())


def _register(value) -> None:
    """Todo valor secreto conocido se tacha de los logs aunque no siga ningún patrón."""
    if isinstance(value, str):
        logging_setup.register_secret(value)
    elif isinstance(value, dict):
        for key, item in value.items():
            if key in SECRET_FIELDS or isinstance(item, dict):  # las claves de IA van anidadas por proveedor
                _register(item)


SECRET_FIELDS = {"api_key", "token", "client_secret", "pem", "webhook_secret"}
