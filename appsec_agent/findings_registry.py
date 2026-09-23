"""Registro de hallazgos por repositorio: el estado actual y su ciclo de vida.

Una ejecución es una foto; el registro es la película. Cada hallazgo (por su huella
estable) vive aquí con su origen, cuándo se vio por primera y por última vez y si
sigue abierto. Se actualiza solo al terminar cada ejecución:

* **Escaneo completo** (rama principal): lo que aparece queda abierto (y se reabre si
  estaba remediado); lo que estaba abierto desde la rama principal y ya no aparece
  queda **remediado automáticamente**.
* **Revisión de PR**: lo que introduce el PR queda abierto con origen «PR #n»; lo que
  ese mismo PR había introducido y ya no está en su commit nuevo queda remediado.
  Un PR cerrado sin merge retira sus hallazgos; uno mergeado los deja a la espera
  del siguiente escaneo completo, que confirma si llegaron a la rama principal.

La remediación manual es una decisión de triage con justificación obligatoria; si
el hallazgo reaparece en una ejecución posterior, se reabre solo.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from pathlib import Path

from .kinds import FINDING_RUNS, FULL_SCANS
from . import logging_setup, triage
from .assets import asset_key

_log = logging_setup.get("findings")
_lock = threading.Lock()
VIEW_PREFIX = "asset:"


def _path(data_dir: Path, key: str) -> Path:
    return data_dir / "findings" / f"{hashlib.sha256(key.encode()).hexdigest()[:32]}.json"


def load(data_dir: Path, key: str) -> dict:
    try:
        payload = json.loads(_path(data_dir, key).read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError, OSError):
        return {"asset": key, "name": None, "findings": {}}
    return payload if isinstance(payload, dict) else {"asset": key, "name": None, "findings": {}}


def _save(data_dir: Path, payload: dict) -> None:
    target = _path(data_dir, payload["asset"])
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(temporary, target)


def _clean(finding: dict) -> dict:
    return {key: value for key, value in finding.items() if key not in ("triage", "ticket", "lifecycle")}


def _reopen_manual(data_dir: Path, record: dict, fingerprints: set[str]) -> None:
    """Una remediación manual que reaparece no era tal: se reabre y queda en el historial."""
    decisions = triage.load(data_dir).get(asset_key(record), {})
    stamp = record.get("finished_at") or record["created_at"]
    # Solo cuenta si la remediación es anterior a esta ejecución (al reconstruir se reprocesan ejecuciones viejas).
    back = [digest for digest in fingerprints if (decisions.get(digest) or {}).get("status") == "fixed"
            and (decisions[digest].get("at") or "") < stamp]
    if back:
        triage.decide(data_dir, record, back, "open", note=f"Reapareció en la ejecución {record['id'][:12]}",
                      user={"username": "sistema", "role": "admin"})


def apply(data_dir: Path, record: dict) -> dict:
    """Incorpora una ejecución terminada al registro de su repositorio. Idempotente por ejecución."""
    if record.get("type") not in FINDING_RUNS or record.get("status") not in ("completed", "incomplete"):
        return {}
    key = asset_key(record)
    stamp = record.get("finished_at") or record["created_at"]
    pull = record.get("pull_request") or {}
    with _lock:
        state = load(data_dir, key)
        if record["id"] in state.setdefault("applied", []):
            return {"opened": 0, "fixed": 0}
        state["name"] = (record.get("source") or {}).get("name") or state.get("name")
        entries = state["findings"]
        present = {item["fingerprint"]: item for item in record.get("findings", [])}
        opened = fixed = 0
        for digest, finding in present.items():
            entry = entries.get(digest)
            if entry is None:
                entry = entries[digest] = {"first_seen": stamp, "first_run": record["id"],
                                           "origin": {"kind": "pr", "pr": pull.get("number"), "branch": pull.get("head_ref")}
                                           if record["type"] == "pr_review" else {"kind": "scan"}}
                opened += 1
            elif entry["status"] == "fixed":
                opened += 1
                entry["reopened_at"] = stamp
            if record["type"] in FULL_SCANS:
                entry["origin"] = {"kind": "scan"}  # ya está en la rama principal
            entry.update(status="open", finding=_clean(finding), last_seen=stamp, last_run=record["id"])
            entry.pop("fixed", None)
        for digest, entry in entries.items():
            if entry["status"] != "open" or digest in present:
                continue
            origin = entry.get("origin") or {}
            if record["type"] in FULL_SCANS and (origin.get("kind") == "scan" or origin.get("merged")):
                how = f"Ya no aparece en el escaneo completo del {stamp[:10]}"
            elif record["type"] == "pr_review" and origin.get("kind") == "pr" and origin.get("pr") == pull.get("number"):
                how = f"Corregido en el commit {str(pull.get('head_sha') or '')[:7]} del PR #{pull.get('number')}"
            else:
                continue
            entry.update(status="fixed", fixed={"at": stamp, "run_id": record["id"], "how": how, "auto": True})
            fixed += 1
        state["applied"] = state["applied"][-500:] + [record["id"]]
        _save(data_dir, state)
    _reopen_manual(data_dir, record, set(present))
    if opened or fixed:
        _log.info("registry_updated", extra={"run_id": record["id"], "reason": f"{key}: {opened} abiertos, {fixed} remediados"})
    return {"opened": opened, "fixed": fixed}


def pull_closed(data_dir: Path, key: str, number: int, *, merged: bool, when: str) -> int:
    """PR cerrado: sin merge, sus hallazgos se retiran; con merge, esperan al escaneo completo."""
    changed = 0
    with _lock:
        state = load(data_dir, key)
        for entry in state["findings"].values():
            origin = entry.get("origin") or {}
            if entry["status"] != "open" or origin.get("kind") != "pr" or origin.get("pr") != number:
                continue
            if merged:
                origin["merged"] = True
            else:
                entry.update(status="fixed", fixed={"at": when, "run_id": None, "how": f"El PR #{number} se cerró sin merge", "auto": True})
            changed += 1
        if changed:
            _save(data_dir, state)
    return changed


def rebuild(data_dir: Path) -> int:
    """Reconstruye todos los registros desde las ejecuciones, en orden cronológico."""
    from .store import list_runs, load_run
    folder = data_dir / "findings"
    if folder.is_dir():
        for path in folder.glob("*.json"):
            path.unlink()
    applied = 0
    for row in sorted(list_runs(data_dir), key=lambda item: item.get("finished_at") or item["created_at"]):
        try:
            apply(data_dir, load_run(data_dir, row["id"]))
            applied += 1
        except (ValueError, OSError):
            continue
    return applied


def view(data_dir: Path, key: str, *, status: str = "open") -> dict:
    """El estado del repositorio con la forma de una ejecución, para verlo, triagearlo y exportarlo igual.

    `open`: lo que sigue ahí (incluido lo descartado en triage, que la tabla filtra aparte);
    `fixed`: remediado, automática o manualmente; `all`: todo.
    """
    state = load(data_dir, key)
    items = [{**entry["finding"], "lifecycle": {name: entry.get(name) for name in
                                                ("status", "origin", "first_seen", "last_seen", "first_run", "last_run", "fixed", "reopened_at")}}
             for entry in state["findings"].values()]
    record = {"id": f"{VIEW_PREFIX}{key}", "type": "repository_scan", "status": "completed",
              "created_at": max([entry.get("last_seen") or "" for entry in state["findings"].values()] or [""]),
              "source": {"uid": key if key.startswith("github#") else None, "id": key, "name": state.get("name") or key},
              "findings": items, "summary": {}, "steps": [], "owasp_coverage": [], "limitations": []}
    annotated = triage.annotate(data_dir, record)

    def bucket(item: dict) -> str:
        return "fixed" if item["lifecycle"]["status"] == "fixed" or item["triage"]["status"] == "fixed" else "open"
    if status != "all":
        annotated["findings"] = [item for item in annotated["findings"] if bucket(item) == status]
    return {**annotated, "type": "asset_state",
            "summary": {**annotated["summary"], "lifecycle": summarize(data_dir, key), "candidates": len(annotated["findings"])}}


def summarize(data_dir: Path, key: str) -> dict:
    """Abiertos (pendientes de verdad), remediados y descartados, contando el triage."""
    state = load(data_dir, key)
    decisions = triage.load(data_dir).get(key, {})
    counts = {"open": 0, "fixed": 0, "suppressed": 0, "by_severity": {level: 0 for level in ("critical", "high", "medium", "low")}, "from_pr": 0}
    for digest, entry in state["findings"].items():
        manual = (triage.effective(decisions.get(digest)) or {}).get("status", "open")
        if entry["status"] == "fixed" or manual == "fixed":
            counts["fixed"] += 1
        elif manual in triage.SUPPRESSED:
            counts["suppressed"] += 1
        else:
            counts["open"] += 1
            severity = entry["finding"].get("severity")
            if severity in counts["by_severity"]:
                counts["by_severity"][severity] += 1
            if (entry.get("origin") or {}).get("kind") == "pr":
                counts["from_pr"] += 1
    return counts


def resolve(data_dir: Path, run_id: str) -> dict:
    """Una ejecución por su id, o el estado de un repositorio por `asset:<clave>`."""
    from .store import load_run
    if isinstance(run_id, str) and run_id.startswith(VIEW_PREFIX):
        return view(data_dir, run_id[len(VIEW_PREFIX):], status="all")
    return load_run(data_dir, run_id)


def assets_with_cve(data_dir: Path, cve: str) -> list[dict]:
    """Repositorios con un hallazgo que cita este CVE, para responder «¿me afecta?» desde el tracker."""
    folder = data_dir / "findings"
    matches = []
    for path in sorted(folder.glob("*.json")) if folder.is_dir() else []:
        try:
            state = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            continue
        hits = [entry for entry in (state.get("findings") or {}).values() if cve in ((entry.get("finding") or {}).get("cve") or [])]
        if hits:
            matches.append({"asset": state.get("asset"), "name": state.get("name") or state.get("asset"),
                            "open": sum(1 for entry in hits if entry.get("status") == "open"),
                            "fixed": sum(1 for entry in hits if entry.get("status") == "fixed"),
                            "packages": sorted({(entry["finding"].get("package") or {}).get("name") or entry["finding"].get("title", "")
                                                for entry in hits})[:5]})
    return matches
