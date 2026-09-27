"""Data format version and ordered data migrations at start-up.

The version lives in PostgreSQL (document `data-version`): a restored database carries its own version, and no process
needs a shared disk to know it. A `data-version.json` left on disk by earlier versions is adopted once.

Rules for whoever changes the format of stored data (see docs/development.md):
1. Readers tolerate the old format (missing fields, old types): reading never breaks.
2. Rewriting data takes a migration appended to MIGRATIONS: idempotent, declaring the data/ paths it touches (they are
   copied first), with a test on old data.
3. A published migration is never reordered or deleted: the version is its position.

A new install starts at the latest version without migrating. Data from a newer version than the code (a rollback)
refuses to start: writing it with the old format could damage it.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from sqlalchemy import select, text as sql

from tamandua.shared import db, documents
from tamandua.shared import log as logging_setup
from tamandua.shared.i18n import msg, text

_log = logging_setup.get("migrations")
VERSION_DOCUMENT = "data-version"
VERSION_FILE = "data-version.json"  # earlier versions kept it on disk: adopted once
BACKUPS = "backups"
KEEP_BACKUPS = 5


@dataclass(frozen=True)
class Migration:
    name: str
    touches: tuple[str, ...]  # rutas relativas a data/ que se copian antes de migrar
    apply: Callable[[Path], object]


# Migraciones de datos (en orden; nunca se reordena ni se borra una publicada). El esquema de las tablas lo llevan
# las migraciones de Alembic; aquí van las transformaciones de datos que no son solo esquema. La lista empieza vacía
# con la primera versión pública (PostgreSQL): no hay instalaciones anteriores que convertir.


def _cra_opt_in(data_dir: Path) -> int:
    """The CRA kit became opt-in (off by default): a workspace that already marked products keeps it on, with a
    history entry that says why. Events need no rewrite: their readers treat a missing assessment as `to_assess`."""
    from tamandua.shared import documents
    with documents.lock(data_dir, "cra"):
        state = documents.load(data_dir, "cra", {})
        if not isinstance(state, dict) or "policy" in state or not isinstance(state.get("products"), dict) or not state["products"]:
            return 0
        entry = {"enabled": True, "by": "tamandua", "at": datetime.now(timezone.utc).isoformat(), "reason": msg("compliance.cra.policy.migrated")}
        documents.save(data_dir, "cra", {**state, "policy": {**entry, "history": [entry]}})
    return 1


def _seal_totp_seeds(data_dir: Path) -> int:
    """TOTP seeds were stored in the clear; they are sealed with the master key."""
    from tamandua.modules.identity.auth import Users
    return Users(data_dir).seal_clear_totp()


MIGRATIONS: tuple[Migration, ...] = (
    Migration("cra_opt_in", (), _cra_opt_in),
    Migration("seal_totp_seeds", (), _seal_totp_seeds),
)
LATEST = len(MIGRATIONS)


class DataTooNew(RuntimeError):
    """`message` is what people read; str() stays English, for logs."""

    def __init__(self, message):
        super().__init__(text(message, "en"))
        self.message = message


def _legacy_version(data_dir: Path) -> int | None:
    try:
        return int(json.loads((data_dir / VERSION_FILE).read_text(encoding="utf-8"))["version"])
    except FileNotFoundError:
        return None
    except (OSError, ValueError, KeyError, TypeError):
        return 0  # unreadable: assume the oldest; migrations are idempotent


def _state(data_dir: Path) -> dict | None:
    state = documents.load(data_dir, VERSION_DOCUMENT)
    return state if isinstance(state, dict) and isinstance(state.get("version"), int) else None


def current(data_dir: Path) -> int | None:
    """The stored version; None on a new install (no version anywhere)."""
    state = _state(data_dir)
    return state["version"] if state else _legacy_version(data_dir)


def _has_data(data_dir: Path) -> bool:
    from tamandua.modules.identity.tables import users
    from tamandua.modules.runs.tables import runs
    with db.transaction(data_dir) as connection:
        return any(connection.execute(select(table.c.tenant_id).where(table.c.tenant_id == db.TENANT).limit(1)).first()
                   for table in (users, runs, documents.documents))


def _write(data_dir: Path, version: int, history: list[dict]) -> None:
    documents.save(data_dir, VERSION_DOCUMENT, {"version": version, "history": history[-50:]})


def _history(data_dir: Path) -> list[dict]:
    state = _state(data_dir)
    if state:
        return list(state.get("history") or [])
    try:
        return list(json.loads((data_dir / VERSION_FILE).read_text(encoding="utf-8")).get("history") or [])
    except (OSError, ValueError, AttributeError):
        return []


@contextmanager
def _locked(data_dir: Path):
    """The API, the workers and a CLI command can start at once: one migrates, the rest wait. A session-level lock
    on its own connection, so each migration still commits on its own and a failure resumes from there."""
    key = int.from_bytes(hashlib.sha256(f"{db.TENANT}\x1fdata-migrations\x1f{db.schema_for(data_dir)}".encode()).digest()[:8],
                         "big", signed=True)
    connection = db.engine().connect()
    try:
        connection.execute(sql("SELECT pg_advisory_lock(:key)"), {"key": key})
        connection.commit()
        yield
    finally:
        connection.execute(sql("SELECT pg_advisory_unlock(:key)"), {"key": key})
        connection.commit()
        connection.close()


def _backup(data_dir: Path, pending: list[tuple[int, Migration]]) -> Path | None:
    """Copia lo que van a tocar las migraciones pendientes. Solo eso: runs/ o la base de CVE pueden pesar gigas."""
    paths = sorted({path for _, migration in pending for path in migration.touches if (data_dir / path).exists()})
    if not paths:
        return None
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    target = data_dir / BACKUPS / f"antes-de-v{pending[-1][0]}-{stamp}"
    for relative in paths:
        source, destination = data_dir / relative, target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir():
            shutil.copytree(source, destination, symlinks=True)
        else:
            shutil.copy2(source, destination)
    old = sorted(path for path in (data_dir / BACKUPS).iterdir() if path.is_dir() and path.name.startswith("antes-de-v"))
    for path in old[:-KEEP_BACKUPS]:
        shutil.rmtree(path, ignore_errors=True)
    return target


def upgrade(data_dir: Path) -> list[str]:
    """Deja la base (esquema de Alembic) y data/ en la última versión. Devuelve lo que migró en data/ (vacío si nada)."""
    from tamandua.app import database
    database.upgrade()  # antes que nada: las migraciones de datos y la aplicación leen de estas tablas
    data_dir.mkdir(parents=True, exist_ok=True)
    state = _state(data_dir)
    if state and state["version"] == LATEST:
        return []
    with _locked(data_dir):
        version = current(data_dir)  # another process may have migrated while this one waited for the lock
        if _state(data_dir) is None and version is not None:
            _write(data_dir, version, _history(data_dir))  # adopt the on-disk version of earlier releases
        if version is None and not _has_data(data_dir):
            _write(data_dir, LATEST, [{"version": LATEST, "at": datetime.now(timezone.utc).isoformat(), "name": "fresh install"}])
            return []
        version = version or 0
        if version > LATEST:
            raise DataTooNew(msg("cli.migrations.data_too_new", path=str(data_dir), version=version, latest=LATEST))
        pending = [(number, migration) for number, migration in enumerate(MIGRATIONS, start=1) if number > version]
        if not pending:
            return []
        backup = _backup(data_dir, pending)
        history = _history(data_dir)
        done = []
        for number, migration in pending:
            result = migration.apply(data_dir)
            history.append({"version": number, "name": migration.name, "at": datetime.now(timezone.utc).isoformat(),
                            "result": result if isinstance(result, (int, str)) else None,
                            "backup": str(backup.relative_to(data_dir)) if backup else None})
            _write(data_dir, number, history)  # tras cada paso: si algo falla, se reanuda desde ahí
            done.append(migration.name)
        _log.warning("data_migrated", extra={"reason": f"datos migrados al formato {LATEST}: {', '.join(done)}"
                                                        + (f" (copia previa en {backup})" if backup else "")})
        return done
