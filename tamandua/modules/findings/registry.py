"""Registro de hallazgos por repositorio: el estado actual y su ciclo de vida.

Una ejecución es una foto; el registro es la película. Cada hallazgo (por su huella
estable) vive aquí con su origen, cuándo se vio por primera y por última vez y si
sigue abierto. Se actualiza solo al terminar cada ejecución:

* **Escaneo completo** (rama principal): lo que aparece queda abierto (y se reabre si
  estaba remediado); lo que estaba abierto desde la rama principal y ya no aparece
  queda **remediado automáticamente**. Solo si el escaneo terminó entero: en uno
  **incompleto** (un motor no corrió, snapshot truncado) no aparecer no prueba nada, así
  que abre y actualiza pero nunca remedia.
* **Rutas excluidas** (`exclusions`): lo que cae en ellas queda **excluido**, ni abierto ni
  remediado. Si la ruta deja de estar excluida, el siguiente escaneo lo vuelve a abrir.
* **Revisión de PR**: lo que introduce el PR queda abierto con origen «PR #n»; lo que
  ese mismo PR había introducido y ya no está en su commit nuevo queda remediado.
  Un PR cerrado sin merge retira sus hallazgos; uno mergeado los deja a la espera
  del siguiente escaneo completo, que confirma si llegaron a la rama principal.

La remediación manual es una decisión de triage con justificación obligatoria; si
el hallazgo reaparece en una ejecución posterior, se reabre solo.
"""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import delete, func, select
from sqlalchemy.dialects.postgresql import insert

from tamandua.modules.findings.tables import registry_assets, registry_findings
from tamandua.shared import db
from tamandua.shared.db import TENANT

from tamandua.modules.runs.kinds import FINDING_RUNS, FULL_SCANS
from tamandua.shared import log as logging_setup
from tamandua.shared.i18n import msg, text
from tamandua.modules.findings import sla
from tamandua.modules.findings import triage
from tamandua.modules.sources.assets import asset_key

_log = logging_setup.get("findings")
VIEW_PREFIX = "asset:"


def _cves(entry: dict) -> list[str]:
    return [item for item in ((entry.get("finding") or {}).get("cve") or []) if isinstance(item, str)]


def load(data_dir: Path, key: str) -> dict:
    """El estado de un activo: {"asset", "name", "findings": {huella: entrada}, "applied": [ejecuciones]}."""
    with db.transaction(data_dir) as connection:
        head = connection.execute(select(registry_assets.c.name, registry_assets.c.applied)
                                  .where(registry_assets.c.tenant_id == TENANT, registry_assets.c.asset_key == key)).first()
        entries = {digest: entry for digest, entry in connection.execute(
            select(registry_findings.c.fingerprint, registry_findings.c.entry)
            .where(registry_findings.c.tenant_id == TENANT, registry_findings.c.asset_key == key))}
    return {"asset": key, "name": head.name if head else None, "findings": entries, "applied": list(head.applied) if head else []}


def _save(data_dir: Path, payload: dict) -> None:
    key = payload["asset"]
    head = insert(registry_assets).values(tenant_id=TENANT, asset_key=key, name=payload.get("name"), applied=payload.get("applied") or [])
    rows = [{"tenant_id": TENANT, "asset_key": key, "fingerprint": digest, "status": entry.get("status") or "open",
             "cves": _cves(entry), "entry": entry} for digest, entry in (payload.get("findings") or {}).items()]
    with db.transaction(data_dir) as connection:
        connection.execute(head.on_conflict_do_update(index_elements=[registry_assets.c.tenant_id, registry_assets.c.asset_key],
                                                      set_={"name": head.excluded.name, "applied": head.excluded.applied}))
        if rows:
            statement = insert(registry_findings)
            connection.execute(statement.on_conflict_do_update(
                index_elements=[registry_findings.c.tenant_id, registry_findings.c.asset_key, registry_findings.c.fingerprint],
                set_={"status": statement.excluded.status, "cves": statement.excluded.cves, "entry": statement.excluded.entry,
                      "updated_at": func.now()}), rows)


@contextmanager
def _locked(data_dir: Path, key: str):
    """Leer-modificar-guardar el estado de un activo en una transacción con cerrojo (entre procesos, no solo hilos)."""
    with db.transaction(data_dir) as connection:
        db.lock(connection, "registry", key)
        yield load(data_dir, key)


def forget_asset(data_dir: Path, key: str) -> None:
    with db.transaction(data_dir) as connection:
        connection.execute(delete(registry_findings).where(registry_findings.c.tenant_id == TENANT, registry_findings.c.asset_key == key))
        connection.execute(delete(registry_assets).where(registry_assets.c.tenant_id == TENANT, registry_assets.c.asset_key == key))


def is_empty(data_dir: Path) -> bool:
    with db.transaction(data_dir) as connection:
        return connection.execute(select(registry_assets.c.asset_key).where(registry_assets.c.tenant_id == TENANT).limit(1)).first() is None


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
        triage.decide(data_dir, record, back, "open", system_note=msg("findings.registry.reappeared", run=record["id"][:12]),
                      user={"username": "sistema", "role": "admin"})


def apply(data_dir: Path, record: dict) -> dict:
    """Incorpora una ejecución terminada al registro de su repositorio. Idempotente por ejecución."""
    if record.get("type") not in FINDING_RUNS or record.get("status") not in ("completed", "incomplete"):
        return {}
    key = asset_key(record)
    stamp = record.get("finished_at") or record["created_at"]
    pull = record.get("pull_request") or {}
    with _locked(data_dir, key) as state:
        if record["id"] in state.setdefault("applied", []):
            return {"opened": 0, "fixed": 0}
        state["name"] = (record.get("source") or {}).get("name") or state.get("name")
        entries = state["findings"]
        present = {item["fingerprint"]: item for item in record.get("findings", [])}
        opened = fixed = 0
        new: list[str] = []
        for digest, finding in present.items():
            entry = entries.get(digest)
            if entry is None:
                entry = entries[digest] = {"first_seen": stamp, "first_run": record["id"],
                                           "origin": {"kind": "pr", "pr": pull.get("number"), "branch": pull.get("head_ref")}
                                           if record["type"] == "pr_review" else {"kind": "advisory"}
                                           if record["type"] == "advisory_watch" else {"kind": "scan"}}
                opened += 1
                new.append(digest)
            elif entry["status"] == "fixed":
                opened += 1
                new.append(digest)
                entry["reopened_at"] = stamp
            if record["type"] in FULL_SCANS:
                entry["origin"] = {"kind": "scan"}  # ya está en la rama principal
            entry.update(status="open", finding=_clean(finding), last_seen=stamp, last_run=record["id"])
            entry.pop("fixed", None)
            entry.pop("excluded", None)
        if record["type"] in FULL_SCANS:
            for finding in record.get("excluded_findings") or []:
                digest = finding["fingerprint"]
                if digest in present:
                    continue
                entry = entries.setdefault(digest, {"first_seen": stamp, "first_run": record["id"], "origin": {"kind": "scan"}})
                entry.update(status="excluded", finding=_clean({k: v for k, v in finding.items() if k != "excluded_by"}),
                             excluded={"pattern": finding.get("excluded_by"), "at": stamp}, last_seen=stamp, last_run=record["id"])
        # Un escaneo incompleto no puede demostrar que algo desapareció: no remedia nada.
        complete = record.get("status") == "completed"
        for digest, entry in entries.items():
            if entry["status"] != "open" or digest in present or not complete:
                continue
            origin = entry.get("origin") or {}
            # Un aviso nuevo afecta a la rama principal: el siguiente análisis completo sin él lo da por corregido.
            if record["type"] in FULL_SCANS and (origin.get("kind") in ("scan", "advisory") or origin.get("merged")):
                how = msg("findings.registry.gone_from_scan", date=stamp[:10])
            elif record["type"] == "pr_review" and origin.get("kind") == "pr" and origin.get("pr") == pull.get("number"):
                how = msg("findings.registry.fixed_in_pr", commit=str(pull.get("head_sha") or "")[:7], number=pull.get("number"))
            else:
                continue
            entry.update(status="fixed", fixed={"at": stamp, "run_id": record["id"], "how": how, "auto": True})
            fixed += 1
        state["applied"] = state["applied"][-500:] + [record["id"]]
        _save(data_dir, state)
    _reopen_manual(data_dir, record, set(present))
    if opened or fixed:
        _log.info("registry_updated", extra={"run_id": record["id"], "reason": f"{key}: {opened} abiertos, {fixed} remediados"})
    return {"opened": opened, "fixed": fixed, "new": new}


def apply_exclusions(data_dir: Path, key: str, active: list[str], *, when: str) -> dict:
    """Al cambiar las rutas excluidas: lo abierto que cae en ellas pasa a excluido y lo excluido que ya no cae vuelve a abierto."""
    from tamandua.modules.findings.exclusions import excluded
    moved = {"excluded": 0, "reopened": 0}
    with _locked(data_dir, key) as state:
        for entry in state["findings"].values():
            pattern = excluded((entry.get("finding") or {}).get("path", ""), active)
            if entry.get("status") == "open" and pattern:
                entry.update(status="excluded", excluded={"pattern": pattern, "at": when})
                moved["excluded"] += 1
            elif entry.get("status") == "excluded" and not pattern:
                entry["status"] = "open"
                entry.pop("excluded", None)
                moved["reopened"] += 1
        if moved["excluded"] or moved["reopened"]:
            _save(data_dir, state)
    return moved


def pull_closed(data_dir: Path, key: str, number: int, *, merged: bool, when: str) -> int:
    """PR cerrado: sin merge, sus hallazgos se retiran; con merge, esperan al escaneo completo."""
    changed = 0
    with _locked(data_dir, key) as state:
        for entry in state["findings"].values():
            origin = entry.get("origin") or {}
            if entry["status"] != "open" or origin.get("kind") != "pr" or origin.get("pr") != number:
                continue
            if merged:
                origin["merged"] = True
            else:
                entry.update(status="fixed", fixed={"at": when, "run_id": None, "how": msg("findings.registry.pr_closed", number=number), "auto": True})
            changed += 1
        if changed:
            _save(data_dir, state)
    return changed


def rebuild(data_dir: Path) -> int:
    """Reconstruye todos los registros desde las ejecuciones, en orden cronológico."""
    from tamandua.modules.runs.store import list_runs, load_run
    with db.transaction(data_dir) as connection:
        connection.execute(delete(registry_findings).where(registry_findings.c.tenant_id == TENANT))
        connection.execute(delete(registry_assets).where(registry_assets.c.tenant_id == TENANT))
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
    `fixed`: remediado, automática o manualmente; `excluded`: en rutas excluidas; `all`: todo.
    """
    state = load(data_dir, key)
    items = [{**entry["finding"], "lifecycle": {name: entry.get(name) for name in
                                                ("status", "origin", "first_seen", "last_seen", "first_run", "last_run", "fixed", "reopened_at",
                                                 "excluded")}}
             for entry in state["findings"].values()]
    record = {"id": f"{VIEW_PREFIX}{key}", "type": "repository_scan", "status": "completed",
              "created_at": max([entry.get("last_seen") or "" for entry in state["findings"].values()] or [""]),
              "source": {"uid": key if key.startswith("github#") else None, "id": key, "name": state.get("name") or key},
              "findings": items, "summary": {}, "steps": [], "owasp_coverage": [], "limitations": []}
    annotated = triage.annotate(data_dir, record)
    days = sla.policy(data_dir)["days"]
    sla.annotate(annotated["findings"], days)

    def bucket(item: dict) -> str:
        if item["lifecycle"]["status"] == "excluded":
            return "excluded"
        return "fixed" if item["lifecycle"]["status"] == "fixed" or item["triage"]["status"] == "fixed" else "open"
    deadlines = {**sla.counts(annotated["findings"]), "days": days}
    if status != "all":
        annotated["findings"] = [item for item in annotated["findings"] if bucket(item) == status]
    return {**annotated, "type": "asset_state",
            "summary": {**annotated["summary"], "lifecycle": summarize(data_dir, key), "candidates": len(annotated["findings"]),
                        "sla": deadlines}}


def summarize(data_dir: Path, key: str) -> dict:
    """Abiertos (pendientes de verdad), remediados y descartados, contando el triage."""
    state = load(data_dir, key)
    decisions = triage.load(data_dir).get(key, {})
    counts = {"open": 0, "fixed": 0, "suppressed": 0, "excluded": 0, "by_severity": {level: 0 for level in ("critical", "high", "medium", "low")}, "from_pr": 0}
    for digest, entry in state["findings"].items():
        manual = (triage.effective(decisions.get(digest)) or {}).get("status", "open")
        if entry["status"] == "excluded":
            counts["excluded"] += 1
        elif entry["status"] == "fixed" or manual == "fixed":
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
    from tamandua.modules.runs.store import load_run
    if isinstance(run_id, str) and run_id.startswith(VIEW_PREFIX):
        return view(data_dir, run_id[len(VIEW_PREFIX):], status="all")
    return load_run(data_dir, run_id)


PACKAGES_SHOWN = 5  # per affected repository in the CVE tracker


def assets_with_cve(data_dir: Path, cve: str, *, limit: int, offset: int) -> dict:
    """Repositorios con un hallazgo que cita este CVE, para responder «¿me afecta?» desde el tracker (índice GIN).

    One page of repositories, ordered by key: `{items, total, limit, offset}`."""
    cites = (registry_findings.c.tenant_id == TENANT, registry_findings.c.cves.any_() == cve)
    with db.transaction(data_dir) as connection:
        total = connection.execute(select(func.count(func.distinct(registry_findings.c.asset_key))).where(*cites)).scalar_one()
        keys = list(connection.execute(select(registry_findings.c.asset_key).where(*cites).group_by(registry_findings.c.asset_key)
                                       .order_by(registry_findings.c.asset_key).limit(limit).offset(offset)).scalars())
        by_asset: dict[str, list[dict]] = {key: [] for key in keys}
        for key, entry in connection.execute(select(registry_findings.c.asset_key, registry_findings.c.entry)
                                             .where(*cites, registry_findings.c.asset_key.in_(keys))):
            by_asset[key].append(entry)
        names = dict(connection.execute(select(registry_assets.c.asset_key, registry_assets.c.name)
                                        .where(registry_assets.c.tenant_id == TENANT, registry_assets.c.asset_key.in_(keys))).all())

    def packages(hits: list[dict]) -> list:
        # Titles may be messages: dedup and sort by their text, return the values as stored (rendered by the reader).
        labels = {}
        for entry in hits:
            value = (entry["finding"].get("package") or {}).get("name") or entry["finding"].get("title", "")
            labels.setdefault(text(value, "en"), value)
        return [labels[label] for label in sorted(labels)][:PACKAGES_SHOWN]
    items = [{"asset": key, "name": names.get(key) or key,
              "open": sum(1 for entry in hits if entry.get("status") == "open"),
              "fixed": sum(1 for entry in hits if entry.get("status") == "fixed"),
              "packages": packages(hits)}
             for key, hits in by_asset.items()]
    return {"items": items, "total": total, "limit": limit, "offset": offset}


def open_cves(data_dir: Path) -> frozenset[str]:
    """Los CVE que siguen abiertos en algún activo (sin lo descartado en triage), para «solo los míos» en el tracker."""
    decisions = triage.load(data_dir)
    found: set[str] = set()
    with db.transaction(data_dir) as connection:
        for key, digest, cves in connection.execute(select(registry_findings.c.asset_key, registry_findings.c.fingerprint, registry_findings.c.cves)
                                                    .where(registry_findings.c.tenant_id == TENANT, registry_findings.c.status == "open",
                                                           func.cardinality(registry_findings.c.cves) > 0)):
            if (triage.effective((decisions.get(key) or {}).get(digest)) or {}).get("status", "open") in triage.SUPPRESSED:
                continue
            found.update(cve for cve in cves if cve.startswith("CVE-"))
    return frozenset(found)
