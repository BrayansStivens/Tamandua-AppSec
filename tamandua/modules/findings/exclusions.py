"""Rutas excluidas por repositorio: carpetas de pruebas, ejemplos vulnerables a propósito, código generado.

Las decide un administrador en el panel y viven en el servidor (en su base de datos), no en un
fichero del repositorio: si vivieran en el repositorio, un PR podría excluirse a sí mismo. Cada
cambio guarda quién, cuándo y por qué, y se conservan los últimos cambios como historial.

Qué pasa con lo excluido:

* **Ejecuciones**: los hallazgos en rutas excluidas salen de la ejecución (informe, SARIF, panel,
  revisión de PR y su veredicto) y se cuentan en `excluded` y en los límites, para que se vea que
  existen. Nada se oculta sin decirlo.
* **Registro**: lo que estaba abierto en esas rutas pasa a **excluido**, no a remediado: no se
  arregló, se decidió no mirarlo. Si la ruta deja de estar excluida, vuelve a abierto.

Patrones al estilo glob, relativos a la raíz del repositorio: `fixtures`, `fixtures/*`, `docs/*.md`,
`**/testdata/**`. `*` no cruza `/`; `**` sí. Como en `.gitignore`, un patrón que coincide con una carpeta
excluye todo lo que hay dentro: `fixtures` o `fixtures/*` excluyen también `fixtures/a/b.py`.
No se admiten patrones que lo excluyan todo.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

from tamandua.modules.findings.errors import LocalizedError
from tamandua.shared import documents
from tamandua.shared import log as logging_setup
from tamandua.shared.i18n import is_msg, msg

_log = logging_setup.get("exclusions")
MAX_PATTERNS = 50
MAX_LENGTH = 200
PATTERN = re.compile(r"[A-Za-z0-9_.\-/*?]+")
# Claves de activo: github#123, local:mi-repo, image:ghcr.io/acme/api… Nada que rompa una línea de log.
ASSET_KEY = re.compile(r"[A-Za-z0-9#:_./@+-]{1,200}")
HISTORY = 20


class ExclusionError(LocalizedError, ValueError):
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
        raise ExclusionError(msg("findings.exclusions.errors.too_many", max=MAX_PATTERNS))
    result = []
    for item in raw:
        if not isinstance(item, str):
            raise ExclusionError(msg("findings.exclusions.errors.not_text"))
        pattern = item.strip()
        if not pattern:
            continue
        if len(pattern) > MAX_LENGTH or not PATTERN.fullmatch(pattern):
            raise ExclusionError(msg("findings.exclusions.errors.invalid", pattern=pattern[:60]))
        if pattern.startswith("/") or any(part in ("..", ".") for part in pattern.split("/")):
            raise ExclusionError(msg("findings.exclusions.errors.not_relative", pattern=pattern))
        if pattern.endswith("/"):
            pattern += "**"
        while "**/**" in pattern or "***" in pattern:  # equivalentes y, repetidos, caros de evaluar
            pattern = pattern.replace("**/**", "**").replace("***", "**")
        if matches_everything(pattern):
            raise ExclusionError(msg("findings.exclusions.errors.everything", pattern=pattern))
        if pattern not in result:
            result.append(pattern)
    return result


def matches_everything(pattern: str) -> bool:
    """Solo comodines de nombre libre (`*`, `?*`, `**/*`…): coincide con cualquier carpeta de la raíz y, al excluir
    carpetas enteras, con todo el repositorio."""
    return all(part == "**" or ("*" in part and set(part) <= {"*", "?"}) for part in pattern.split("/"))


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
    """El primer patrón que excluye esta ruta (o una de sus carpetas), o None."""
    parts = str(path or "").removeprefix("./").lstrip("/").split("/")
    candidates = ["/".join(parts[:end]) for end in range(len(parts), 0, -1)]  # el archivo y cada carpeta que lo contiene
    for pattern in active:
        regex = _regex(pattern)
        if any(regex.match(candidate) for candidate in candidates):
            return pattern
    return None


def save(data_dir: Path, key: str, raw, *, reason: str | None, user: dict) -> dict:
    active = normalize(raw)
    note = " ".join(str(reason or "").split())[:300]
    if active and len(note) < 5:
        raise ExclusionError(msg("findings.exclusions.errors.reason_required"))
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


def _recount(reason, count: int):
    """The coverage reason with its finding count updated: legacy Spanish text, or any `findings` param of a message."""
    if isinstance(reason, str):
        return re.sub(r"\. (?:\d+ hallazgo\(s\)|Sin hallazgos)\.$", f". {count} hallazgo(s)." if count else ". Sin hallazgos.", reason)
    if is_msg(reason):
        params = {name: count if name == "findings" else _recount(value, count) for name, value in (reason.get("params") or {}).items()}
        return {**reason, "params": params} if params else reason
    return reason


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
        reason = _recount(row.get("reason") or "", count)
        coverage.append({**row, "findings": count, "reason": reason})
    limitation = msg("findings.exclusions.limitation", patterns=", ".join(active), count=total)
    # Secrets withheld by the secret detection settings (scanning) may already be there.
    return {**record, "findings": kept, "summary": summary, "owasp_coverage": coverage or record.get("owasp_coverage"),
            "excluded": {"patterns": active, "findings": total, "by_pattern": dropped},
            "excluded_findings": [*(record.get("excluded_findings") or []), *removed],
            "limitations": [*(record.get("limitations") or []), limitation]}
