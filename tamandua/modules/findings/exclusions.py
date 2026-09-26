"""Rutas excluidas por repositorio: carpetas de pruebas, ejemplos vulnerables a propósito, código generado.

Las decide un administrador en el panel y viven en el servidor (`data/exclusions.json`), no en un
fichero del repositorio: si vivieran en el repositorio, un PR podría excluirse a sí mismo. Cada
cambio guarda quién, cuándo y por qué, y se conservan los últimos cambios como historial.

Qué pasa con lo excluido:

* **Ejecuciones**: los hallazgos en rutas excluidas salen de la ejecución (informe, SARIF, panel,
  revisión de PR y su veredicto) y se cuentan en `excluded` y en los límites, para que se vea que
  existen. Nada se oculta sin decirlo.
* **Registro**: lo que estaba abierto en esas rutas pasa a **excluido**, no a remediado: no se
  arregló, se decidió no mirarlo. Si la ruta deja de estar excluida, vuelve a abierto.

Patrones al estilo glob, relativos a la raíz del repositorio: `fixtures/**`, `docs/*.md`,
`**/testdata/**`. `*` no cruza `/`; `**` sí. No se admiten patrones que lo excluyan todo.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

from tamandua.shared import documents
from tamandua.shared import log as logging_setup

_log = logging_setup.get("exclusions")
MAX_PATTERNS = 50
MAX_LENGTH = 200
PATTERN = re.compile(r"[A-Za-z0-9_.\-/*?]+")
# Claves de activo: github#123, local:appsec-agent, image:ghcr.io/acme/api… Nada que rompa una línea de log.
ASSET_KEY = re.compile(r"[A-Za-z0-9#:_./@+-]{1,200}")
HISTORY = 20


class ExclusionError(ValueError):
    pass


def _load_all(data_dir: Path) -> dict:
    payload = documents.load(data_dir, "exclusions", {})
    return payload if isinstance(payload, dict) else {}


def _write(data_dir: Path, payload: dict) -> None:
    documents.save(data_dir, "exclusions", payload)


def get(data_dir: Path, key: str) -> dict:
    entry = _load_all(data_dir).get(key) or {}
    return {"patterns": list(entry.get("patterns") or []), "reason": entry.get("reason"), "by": entry.get("by"),
            "at": entry.get("at"), "history": list(entry.get("history") or [])}


def patterns(data_dir: Path, key: str) -> list[str]:
    return get(data_dir, key)["patterns"]


def normalize(raw) -> list[str]:
    """Valida y normaliza. `fixtures/` equivale a `fixtures/**`."""
    if not isinstance(raw, list) or len(raw) > MAX_PATTERNS:
        raise ExclusionError(f"Indica como mucho {MAX_PATTERNS} rutas.")
    result = []
    for item in raw:
        if not isinstance(item, str):
            raise ExclusionError("Cada ruta debe ser texto.")
        pattern = item.strip()
        if not pattern:
            continue
        if len(pattern) > MAX_LENGTH or not PATTERN.fullmatch(pattern):
            raise ExclusionError(f"Ruta no válida: «{pattern[:60]}». Usa letras, números, «/», «.», «-», «_», «*» y «?».")
        if pattern.startswith("/") or any(part in ("..", ".") for part in pattern.split("/")):
            raise ExclusionError(f"«{pattern}» debe ser relativa a la raíz del repositorio y sin «..».")
        if pattern.endswith("/"):
            pattern += "**"
        while "**/**" in pattern or "***" in pattern:  # equivalentes y, repetidos, caros de evaluar
            pattern = pattern.replace("**/**", "**").replace("***", "**")
        if matches_everything(pattern):
            raise ExclusionError(f"«{pattern}» excluiría todo el repositorio.")
        if pattern not in result:
            result.append(pattern)
    return result


def matches_everything(pattern: str) -> bool:
    return all(part in ("*", "**") for part in pattern.split("/"))


@lru_cache(maxsize=512)
def _regex(pattern: str) -> re.Pattern:
    out, index = [], 0
    while index < len(pattern):
        if pattern.startswith("**/", index):
            out.append("(?:.*/)?")
            index += 3
        elif pattern.startswith("**", index):
            out.append(".*")
            index += 2
        elif pattern[index] == "*":
            out.append("[^/]*")
            index += 1
        elif pattern[index] == "?":
            out.append("[^/]")
            index += 1
        else:
            out.append(re.escape(pattern[index]))
            index += 1
    return re.compile("".join(out) + r"\Z")


def excluded(path: str, active: list[str]) -> str | None:
    """El primer patrón que excluye esta ruta, o None."""
    clean = str(path or "").removeprefix("./").lstrip("/")
    for pattern in active:
        if _regex(pattern).match(clean):
            return pattern
    return None


def save(data_dir: Path, key: str, raw, *, reason: str | None, user: dict) -> dict:
    active = normalize(raw)
    note = " ".join(str(reason or "").split())[:300]
    if active and len(note) < 5:
        raise ExclusionError("Explica en una frase por qué se excluyen estas rutas (queda en el historial).")
    stamp = datetime.now(timezone.utc).isoformat()
    with documents.lock(data_dir, "exclusions"):
        payload = _load_all(data_dir)
        previous = payload.get(key) or {}
        history = (list(previous.get("history") or []) + [{"at": stamp, "by": user["username"], "patterns": active,
                                                           "reason": note or None}])[-HISTORY:]
        if active:
            payload[key] = {"patterns": active, "reason": note, "by": user["username"], "at": stamp, "history": history}
        elif key in payload:
            payload[key] = {"patterns": [], "reason": None, "by": user["username"], "at": stamp, "history": history}
        _write(data_dir, payload)
    _log.info("exclusions_saved", extra={"user": user["username"], "reason": f"{key}: {len(active)} rutas"})
    return get(data_dir, key)


def forget(data_dir: Path, key: str) -> None:
    with documents.lock(data_dir, "exclusions"):
        payload = _load_all(data_dir)
        if payload.pop(key, None) is not None:
            _write(data_dir, payload)


SUMMARY_SCANNERS = ("sast", "secrets", "sca", "iac", "cicd")


def apply_to_record(data_dir: Path, record: dict, key: str) -> dict:
    """Saca de la ejecución lo que cae en rutas excluidas y rehace las cuentas del resumen."""
    if "excluded" in record:  # ya aplicado (la revisión de PR lo hace antes de clasificar)
        return record
    active = patterns(data_dir, key)
    if not active:
        return record
    kept, dropped, removed = [], {}, []
    for finding in record.get("findings") or []:
        pattern = excluded(finding.get("path", ""), active)
        if pattern is None:
            kept.append(finding)
        else:
            dropped[pattern] = dropped.get(pattern, 0) + 1
            removed.append({**finding, "excluded_by": pattern})
    if not dropped:
        return {**record, "excluded": {"patterns": active, "findings": 0, "by_pattern": {}}}
    total = sum(dropped.values())
    summary = dict(record.get("summary") or {})
    summary.update(candidates=len(kept),
                   severities={level: sum(1 for item in kept if item.get("severity") == level)
                               for level in ("critical", "high", "medium", "low", "info")},
                   priorities={action: sum(1 for item in kept if (item.get("priority") or {}).get("action") == action)
                               for action in ("act", "attend", "track")},
                   kev=sum(1 for item in kept if item.get("kev")),
                   fixable=sum(1 for item in kept if (item.get("package") or {}).get("fixed_version")),
                   excluded=total)
    for scanner in SUMMARY_SCANNERS:
        if scanner in summary:
            summary[scanner] = sum(1 for item in kept if item.get("scanner") == scanner)
    coverage = []
    for row in record.get("owasp_coverage") or []:
        count = sum(1 for item in kept for category in item.get("owasp", []) if category[:3] == row.get("id"))
        reason = re.sub(r"\. (?:\d+ hallazgo\(s\)|Sin hallazgos)\.$", f". {count} hallazgo(s)." if count else ". Sin hallazgos.",
                        str(row.get("reason") or ""))
        coverage.append({**row, "findings": count, "reason": reason})
    limitation = (f"Rutas excluidas por un administrador ({', '.join(active)}): {total} hallazgos quedaron fuera "
                  "de esta ejecución. Se pueden ver en Hallazgos → Excluidos.")
    return {**record, "findings": kept, "summary": summary, "owasp_coverage": coverage or record.get("owasp_coverage"),
            "excluded": {"patterns": active, "findings": total, "by_pattern": dropped}, "excluded_findings": removed,
            "limitations": [*(record.get("limitations") or []), limitation]}
