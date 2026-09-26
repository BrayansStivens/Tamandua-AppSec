"""Versión del formato de `data/` y migraciones ordenadas al arrancar.

Regla para quien cambie el formato de algo que ya está en disco (ver docs/development.md):
1. Los lectores toleran el formato viejo (campos que faltan, tipos antiguos): nunca rompen al leer.
2. Si hay que reescribir datos, se añade una migración al final de MIGRATIONS: idempotente (se puede
   repetir sin daño), declara qué rutas toca (se copian antes) y tiene su prueba con datos viejos.
3. Nunca se reordena ni se borra una migración publicada: la versión es su posición.

Una instalación nueva nace en la última versión sin migrar nada. Una existente sin `data-version.json`
es la versión 0 (anterior a este sistema). Si los datos son de una versión más nueva que el código
(se volvió a una versión anterior), no se arranca: escribir con el formato viejo podría estropearlos.
"""

from __future__ import annotations

import fcntl
import json
import os
import shutil
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from tamandua.shared import log as logging_setup
from tamandua.shared.i18n import msg, text

_log = logging_setup.get("migrations")
VERSION_FILE = "data-version.json"
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
MIGRATIONS: tuple[Migration, ...] = ()
LATEST = len(MIGRATIONS)


class DataTooNew(RuntimeError):
    """`message` is what people read; str() stays English, for logs."""

    def __init__(self, message):
        super().__init__(text(message, "en"))
        self.message = message


def _path(data_dir: Path) -> Path:
    return data_dir / VERSION_FILE


def current(data_dir: Path) -> int | None:
    """La versión guardada; None si no hay archivo (instalación nueva o anterior a este sistema)."""
    try:
        state = json.loads(_path(data_dir).read_text(encoding="utf-8"))
        return int(state["version"])
    except FileNotFoundError:
        return None
    except (OSError, ValueError, KeyError, TypeError):
        return 0  # ilegible: se asume lo más viejo; las migraciones son idempotentes


def _has_data(data_dir: Path) -> bool:
    return any((data_dir / name).exists() for name in ("runs", "findings", "triage.json", "pr-watch.json", "threat-models"))


def _write(data_dir: Path, version: int, history: list[dict]) -> None:
    path = _path(data_dir)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps({"version": version, "history": history[-50:]}, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def _history(data_dir: Path) -> list[dict]:
    try:
        return list(json.loads(_path(data_dir).read_text(encoding="utf-8")).get("history") or [])
    except (OSError, ValueError, AttributeError):
        return []


@contextmanager
def _locked(data_dir: Path):
    # El panel y un comando de la CLI (p. ej. `make demo`) pueden arrancar a la vez sobre el mismo data/.
    with open(data_dir / ".migrate.lock", "a+") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


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
    version = current(data_dir)
    if version == LATEST:
        return []
    with _locked(data_dir):
        version = current(data_dir)  # otro proceso pudo migrar mientras se esperaba el cerrojo
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
