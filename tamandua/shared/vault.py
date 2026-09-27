"""Encrypted secrets: AI keys, the GitHub App, Jira, notification channels, registry credentials and the session
signing key.

Each secret is encrypted on its own with AES-256-GCM and its name as associated data, so a value can't be moved to
another entry without decryption failing. The entries live in PostgreSQL (table `vault_entries`), where every
instance of the API and every worker share them; a database dump without the master key is useless.

The master key comes from `TAMANDUA_MASTER_KEY` (32 bytes in base64), which is what any platform with a secrets
manager should use. Without it, a key is generated once in the configuration folder (`master.key`, owner-only),
which suits a single server. A `secrets.vault` file from earlier versions is imported once (`import_file`).

No value leaves this module towards the browser or the logs: every value read or written is registered with the log
filter, so it is redacted if it ever slips into a message.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import stat
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import Column, DateTime, Table, Text, delete as sql_delete, func, select
from sqlalchemy.dialects.postgresql import insert

from tamandua.shared import db, paths, settings
from tamandua.shared import log as logging_setup
from tamandua.shared.db import TENANT, metadata
from tamandua.shared.i18n import msg, text

VAULT_FILE = "secrets.vault"  # earlier versions; imported once
KEY_FILE = "master.key"

vault_entries = Table(
    "vault_entries", metadata,
    Column("tenant_id", Text, primary_key=True, server_default=TENANT),
    Column("name", Text, primary_key=True),
    Column("nonce", Text, nullable=False),
    Column("data", Text, nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
)
_log = logging_setup.get("vault")


class VaultError(RuntimeError):
    """`message` is what people read (rendered per reader); str() stays English, for logs."""

    def __init__(self, message):
        super().__init__(text(message, "en"))
        self.message = message


def _dir() -> Path:
    return paths.CONFIG_DIR  # read on every call: tests point it at a temporary folder


def _private_dir() -> Path:
    folder = _dir()
    folder.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(folder, stat.S_IRWXU)
    except OSError:
        pass  # a mounted volume may not allow it; the key file is still 0400
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
    path = _dir() / KEY_FILE
    try:
        key = base64.b64decode(path.read_text(encoding="ascii").strip(), validate=True)
    except FileNotFoundError:
        key = secrets.token_bytes(32)
        try:
            _write_private(_private_dir() / KEY_FILE, base64.b64encode(key) + b"\n", stat.S_IRUSR)
        except OSError as exc:  # a read-only filesystem (serverless): the key has to come from the environment
            raise VaultError(msg("vault.errors.master_key_required")) from exc
        return key
    except (ValueError, OSError) as exc:
        raise VaultError(msg("vault.errors.master_key_unreadable")) from exc
    if len(key) != 32:
        raise VaultError(msg("vault.errors.master_key_damaged"))
    return key


@contextmanager
def _transaction():
    # Its own transaction: a secret written while another transaction is open (e.g. delivering the outbox) is kept
    # even if that one rolls back, as it was when the vault was a file.
    with db.separate_transaction(_dir()) as connection:
        yield connection


def _encrypt(name: str, value) -> dict:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = secrets.token_bytes(12)
    data = AESGCM(_master_key()).encrypt(nonce, json.dumps(value, ensure_ascii=False).encode(), name.encode())
    return {"nonce": base64.b64encode(nonce).decode(), "data": base64.b64encode(data).decode()}


def _decrypt(name: str, nonce: str, data: str):
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    try:
        return json.loads(AESGCM(_master_key()).decrypt(base64.b64decode(nonce), base64.b64decode(data), name.encode()))
    except (InvalidTag, KeyError, ValueError, TypeError) as exc:
        raise VaultError(msg("vault.errors.cannot_decrypt")) from exc


def get(name: str):
    """The decrypted value (any JSON), or None if there is none."""
    with _transaction() as connection:
        row = connection.execute(select(vault_entries.c.nonce, vault_entries.c.data)
                                 .where(vault_entries.c.tenant_id == TENANT, vault_entries.c.name == name)).first()
    if row is None:
        return None
    value = _decrypt(name, row.nonce, row.data)
    _register(value)
    return value


def put(name: str, value) -> None:
    statement = insert(vault_entries).values(tenant_id=TENANT, name=name, **_encrypt(name, value))
    with _transaction() as connection:
        connection.execute(statement.on_conflict_do_update(
            index_elements=[vault_entries.c.tenant_id, vault_entries.c.name],
            set_={"nonce": statement.excluded.nonce, "data": statement.excluded.data, "updated_at": func.now()}))
    _register(value)


def put_if_absent(name: str, value):
    """Stores `value` unless `name` already exists, and returns whichever is stored: several processes that start at
    once agree on one value (the session key, the setup code)."""
    with _transaction() as connection:
        connection.execute(insert(vault_entries).values(tenant_id=TENANT, name=name, **_encrypt(name, value))
                           .on_conflict_do_nothing())
    return get(name)


def delete(name: str) -> bool:
    with _transaction() as connection:
        return connection.execute(sql_delete(vault_entries).where(vault_entries.c.tenant_id == TENANT, vault_entries.c.name == name)
                                  .returning(vault_entries.c.name)).first() is not None


def names() -> list[str]:
    with _transaction() as connection:
        return list(connection.execute(select(vault_entries.c.name).where(vault_entries.c.tenant_id == TENANT)
                                       .order_by(vault_entries.c.name)).scalars())


def import_file() -> int:
    """Moves the entries of an earlier version's `secrets.vault` into the database, once: entries already in the
    database win, and the file is renamed so a secret deleted later never comes back. Returns how many were copied."""
    path = _dir() / VAULT_FILE
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return 0
    except (ValueError, OSError) as exc:
        raise VaultError(msg("vault.errors.vault_damaged")) from exc
    rows = [{"tenant_id": TENANT, "name": name, "nonce": entry["nonce"], "data": entry["data"]}
            for name, entry in (payload.items() if isinstance(payload, dict) else [])
            if isinstance(entry, dict) and isinstance(entry.get("nonce"), str) and isinstance(entry.get("data"), str)]
    for row in rows:
        _decrypt(row["name"], row["nonce"], row["data"])  # the right master key, before copying anything
    copied = 0
    with _transaction() as connection:
        for row in rows:
            copied += connection.execute(insert(vault_entries).values(**row).on_conflict_do_nothing()
                                         .returning(vault_entries.c.name)).first() is not None
    try:
        path.rename(path.with_name(f"{VAULT_FILE}.imported"))
    except OSError:
        _log.warning("vault_file_not_renamed", extra={"reason": "the database already has its entries"})
    return copied


def seal(value, purpose: str) -> str:
    """Encrypts a value with the master key to keep it outside the vault (e.g. a job's tokens in the queue).
    `purpose` is associated data: what was sealed for one thing can't be opened as another."""
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


def _register(value) -> None:
    """Every known secret value is redacted from the logs, whatever its shape."""
    if isinstance(value, str):
        logging_setup.register_secret(value)
    elif isinstance(value, dict):
        for key, item in value.items():
            if key in SECRET_FIELDS or isinstance(item, dict):  # AI keys are nested per provider
                _register(item)


SECRET_FIELDS = {"api_key", "token", "client_secret", "pem", "webhook_secret", "session_key", "code"}
