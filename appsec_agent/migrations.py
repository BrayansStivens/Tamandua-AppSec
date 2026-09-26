"""Versión del formato de `data/` y migraciones ordenadas al arrancar.

Regla para quien cambie el formato de algo que ya está en disco (ver docs/desarrollo.md):
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

from . import logging_setup

_log = logging_setup.get("migrations")
VERSION_FILE = "data-version.json"
BACKUPS = "backups"
KEEP_BACKUPS = 5


@dataclass(frozen=True)
class Migration:
    name: str
    touches: tuple[str, ...]  # rutas relativas a data/ que se copian antes de migrar
    apply: Callable[[Path], object]


def _repair_incomplete_fixes(data_dir: Path) -> object:
    from .findings_registry import repair_incomplete_fixes
    return repair_incomplete_fixes(data_dir)


def _rebuild_runs_index(data_dir: Path) -> object:
    # Filas del índice escritas antes de que existieran campos como «trigger»: se regeneran desde run.json.
    from .store import rebuild_index
    return len(rebuild_index(data_dir)) if (data_dir / "runs").is_dir() else 0


MIGRATIONS: tuple[Migration, ...] = (
    Migration("reabrir-remediados-por-escaneos-incompletos", ("findings",), _repair_incomplete_fixes),
    Migration("regenerar-indice-de-ejecuciones", ("runs/index.json",), _rebuild_runs_index),
)
LATEST = len(MIGRATIONS)


class DataTooNew(RuntimeError):
    pass


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
    """Deja data/ en la última versión. Devuelve los nombres de lo que migró (vacío si ya estaba al día)."""
    data_dir.mkdir(parents=True, exist_ok=True)
    version = current(data_dir)
    if version == LATEST:
        return []
    with _locked(data_dir):
        version = current(data_dir)  # otro proceso pudo migrar mientras se esperaba el cerrojo
        if version is None and not _has_data(data_dir):
            _write(data_dir, LATEST, [{"version": LATEST, "at": datetime.now(timezone.utc).isoformat(), "name": "instalación nueva"}])
            return []
        version = version or 0
        if version > LATEST:
            raise DataTooNew(f"Los datos de {data_dir} son de una versión más nueva de Tamandua (formato {version}; esta entiende hasta el {LATEST}). "
                             "Actualiza Tamandua o restaura una copia de seguridad anterior.")
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
