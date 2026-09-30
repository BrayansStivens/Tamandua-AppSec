"""Findings registry per repository: the current state and its lifecycle.

A run is a snapshot; the registry is the film. Each finding (by its stable fingerprint)
lives here with its origin, when it was first and last seen, and whether it is still
open. It is updated only when a run finishes:

* **Full scan** (main branch): what shows up stays open (and reopens if it had been
  fixed); what was open from the main branch and no longer shows up is **fixed
  automatically**. Only if the scan finished entirely: in an **incomplete** one (an
  engine didn't run, truncated snapshot) not showing up proves nothing, so it opens and
  updates but never fixes.
* **Excluded paths** (`exclusions`): whatever falls under them is **excluded**, neither open
  nor fixed. If the path stops being excluded, the next scan reopens it.
* **Secrets withheld by the secret detection settings** (allowlist, disabled rule): excluded with the reason, never
  fixed. They reopen when the settings stop withholding them, and are fixed only once a complete scan no longer
  sees them even without the filters.
* **PR review**: what the PR introduces stays open with origin "PR #n"; what that same
  PR had introduced and is no longer in its new commit is fixed. A PR closed without
  merging withdraws its findings; a merged one leaves them waiting for the next full
  scan, which confirms whether they reached the main branch.
* **Imports** (`sarif_import`, findings from another tool): what shows up opens with origin
  "import" and the tool's name. Only a later complete import of the **same tool** with scope
  "full" fixes what that tool no longer reports; a partial import (some files, one module) only
  opens and updates. Tamandua's own scans and PR reviews never fix an imported finding, nor
  does an import fix theirs: each tool vouches only for what it looks at.

Manual remediation is a triage decision with a mandatory justification; if the finding
reappears in a later run, it reopens on its own.
"""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import delete, func, select
from sqlalchemy.dialects.postgresql import insert

from tamandua.modules.findings.tables import registry_assets, registry_findings
from tamandua.shared import db
from tamandua.shared.db import TENANT

from tamandua.modules.findings.kinds import FINDING_RUNS, FULL_SCANS, IMPORT_RUNS
from tamandua.shared import log as logging_setup
from tamandua.shared.i18n import msg, text
from tamandua.modules.findings import sla
from tamandua.modules.findings import triage
from tamandua.modules.sources.assets import asset_key
from tamandua.shared.model import Finding, RunRecord

_log = logging_setup.get("findings")
VIEW_PREFIX = "asset:"


def _cves(entry: dict) -> list[str]:
    return [item for item in ((entry.get("finding") or {}).get("cve") or []) if isinstance(item, str)]


def load(data_dir: Path, key: str) -> dict:
    """An asset's state: {"asset", "name", "findings": {fingerprint: entry}, "applied": [runs]}."""
    with db.transaction(data_dir) as connection:
        head = connection.execute(select(registry_assets.c.name, registry_assets.c.applied)
                                  .where(registry_assets.c.tenant_id == TENANT, registry_assets.c.asset_key == key)).first()
        entries = dict(connection.execute(
            select(registry_findings.c.fingerprint, registry_findings.c.entry)
            .where(registry_findings.c.tenant_id == TENANT, registry_findings.c.asset_key == key)).all())
    return {"asset": key, "name": head.name if head else None, "findings": entries, "applied": list(head.applied) if head else []}


def _save(data_dir: Path, payload: dict, gone: set[str] = frozenset()) -> None:
    """`gone`: fingerprints whose rows go away (the entry moved to a new fingerprint)."""
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
        if gone:
            connection.execute(delete(registry_findings).where(registry_findings.c.tenant_id == TENANT, registry_findings.c.asset_key == key,
                                                               registry_findings.c.fingerprint.in_(sorted(gone))))


@contextmanager
def _locked(data_dir: Path, key: str):
    """Read-modify-write an asset's state in a locked transaction (across processes, not just threads)."""
    with db.transaction(data_dir) as connection:
        db.lock(connection, "registry", key)
        yield load(data_dir, key)


def find_assets(data_dir: Path, wanted: str) -> list[dict]:
    """Assets whose key is `wanted`, or else whose name is (ignoring case): [{"asset", "name"}]."""
    with db.transaction(data_dir) as connection:
        rows = connection.execute(select(registry_assets.c.asset_key, registry_assets.c.name)
                                  .where(registry_assets.c.tenant_id == TENANT, registry_assets.c.asset_key == wanted)).all() \
            or connection.execute(select(registry_assets.c.asset_key, registry_assets.c.name)
                                  .where(registry_assets.c.tenant_id == TENANT, func.lower(registry_assets.c.name) == wanted.lower())
                                  .order_by(registry_assets.c.asset_key)).all()
    return [{"asset": row.asset_key, "name": row.name} for row in rows]


def forget_asset(data_dir: Path, key: str) -> None:
    with db.transaction(data_dir) as connection:
        connection.execute(delete(registry_findings).where(registry_findings.c.tenant_id == TENANT, registry_findings.c.asset_key == key))
        connection.execute(delete(registry_assets).where(registry_assets.c.tenant_id == TENANT, registry_assets.c.asset_key == key))


def is_empty(data_dir: Path) -> bool:
    with db.transaction(data_dir) as connection:
        return connection.execute(select(registry_assets.c.asset_key).where(registry_assets.c.tenant_id == TENANT).limit(1)).first() is None


def _clean(finding: dict) -> dict:
    return {key: value for key, value in finding.items() if key not in ("triage", "ticket", "lifecycle", "excluded_by", "excluded_reason")}


def _exclusion(finding: dict, stamp: str) -> dict:
    reason = finding.get("excluded_reason")
    return {"pattern": finding.get("excluded_by"), "at": stamp, **({"reason": reason} if reason else {})}


def _withheld(entry: dict) -> bool:
    """Excluded by the secret detection settings (it carries their reason), not by an excluded path."""
    return entry.get("status") == "excluded" and bool((entry.get("excluded") or {}).get("reason"))


def _reopen_manual(data_dir: Path, record: dict, fingerprints: set[str]) -> None:
    """A manual fix that reappears wasn't one: it reopens and stays in the history."""
    decisions = triage.load(data_dir).get(asset_key(record), {})
    stamp = record.get("finished_at") or record["created_at"]
    # Only counts if the fix predates this run (a rebuild reprocesses old runs).
    back = [digest for digest in fingerprints if (decisions.get(digest) or {}).get("status") == "fixed"
            and (decisions[digest].get("at") or "") < stamp]
    if back:
        triage.decide(data_dir, record, back, "open", system_note=msg("findings.registry.reappeared", run=record["id"][:12]),
                      user={"username": "sistema", "role": "admin"})


def _rekey(entries: dict, findings: list[Finding]) -> dict[str, str]:
    """Findings whose fingerprint changed formula (they carry the former one in `previous_fingerprint`) keep their
    entry: it moves to the new fingerprint, unless the new one already has its own. Returns {former: new}."""
    moved = {}
    for finding in findings:
        former, digest = finding.get("previous_fingerprint"), finding["fingerprint"]
        if former and former != digest and former in entries and digest not in entries:
            entries[digest] = entries.pop(former)
            moved[former] = digest
    return moved


def carry_over(data_dir: Path, key: str, moved: dict[str, str]) -> None:
    """What hangs off a finding's former fingerprint (triage, Jira issue, requested verification) also answers to
    the new one. Copied, not moved: older runs still show the former fingerprint."""
    if not moved:
        return
    from tamandua.modules.findings import tickets, verifications
    triage.carry_over(data_dir, key, moved)
    tickets.carry_over(data_dir, key, moved)
    verifications.carry_over(data_dir, key, moved)
    _log.info("registry_rekeyed", extra={"reason": f"{key}: {len(moved)}"})


def _origin(record: RunRecord, imported: dict | None) -> dict:
    if imported is not None:
        return {"kind": "import", "tool": imported.get("tool")}
    if record["type"] == "pr_review":
        pull = record.get("pull_request") or {}
        return {"kind": "pr", "pr": pull.get("number"), "branch": pull.get("head_ref")}
    return {"kind": "advisory"} if record["type"] == "advisory_watch" else {"kind": "scan"}


def apply(data_dir: Path, record: RunRecord) -> dict:
    """Adds a finished run to its repository's registry. Idempotent per run."""
    if record.get("type") not in FINDING_RUNS or record.get("status") not in ("completed", "incomplete"):
        return {}
    key = asset_key(record)
    stamp = record.get("finished_at") or record["created_at"]
    pull = record.get("pull_request") or {}
    kind = record["type"]
    imported = (record.get("trigger") or {}) if kind in IMPORT_RUNS else None
    with _locked(data_dir, key) as state:
        if record["id"] in state.setdefault("applied", []):
            return {"opened": 0, "fixed": 0}
        state["name"] = (record.get("source") or {}).get("name") or state.get("name")
        entries = state["findings"]
        moved = _rekey(entries, [*record.get("findings", []), *(record.get("excluded_findings") or [])])
        present = {item["fingerprint"]: item for item in record.get("findings", [])}
        opened = fixed = 0
        new: list[str] = []
        for digest, finding in present.items():
            entry = entries.get(digest)
            if entry is None:
                entry = entries[digest] = {"first_seen": stamp, "first_run": record["id"], "origin": _origin(record, imported)}
                opened += 1
                new.append(digest)
            elif entry["status"] == "fixed":
                opened += 1
                new.append(digest)
                entry["reopened_at"] = stamp
            if record["type"] in FULL_SCANS:
                entry["origin"] = {"kind": "scan"}  # already on the main branch
            entry.update(status="open", finding=_clean(finding), last_seen=stamp, last_run=record["id"])
            entry.pop("fixed", None)
            entry.pop("excluded", None)
        excluded_now = set()
        if record["type"] in FULL_SCANS or imported is not None:
            for finding in record.get("excluded_findings") or []:
                digest = finding["fingerprint"]
                if digest in present:
                    continue
                excluded_now.add(digest)
                entry = entries.setdefault(digest, {"first_seen": stamp, "first_run": record["id"], "origin": _origin(record, imported)})
                entry.update(status="excluded", finding=_clean(finding), excluded=_exclusion(finding, stamp),
                             last_seen=stamp, last_run=record["id"])
        # An incomplete scan can't prove something disappeared: it fixes nothing.
        complete = record.get("status") == "completed"
        for digest, entry in entries.items():
            if digest in present or not complete:
                continue
            # A withheld secret that a complete scan no longer sees, even without the filters, is gone.
            if entry["status"] != "open" and not (record["type"] in FULL_SCANS and _withheld(entry) and digest not in excluded_now):
                continue
            origin = entry.get("origin") or {}
            # A new advisory affects the main branch: the next full scan without it marks it fixed.
            if record["type"] in FULL_SCANS and (origin.get("kind") in ("scan", "advisory") or origin.get("merged")):
                how = msg("findings.registry.gone_from_scan", date=stamp[:10])
            elif record["type"] == "pr_review" and origin.get("kind") == "pr" and origin.get("pr") == pull.get("number"):
                how = msg("findings.registry.fixed_in_pr", commit=str(pull.get("head_sha") or "")[:7], number=pull.get("number"))
            elif imported is not None and imported.get("scope") == "full" and origin.get("kind") == "import" \
                    and str(origin.get("tool") or "").lower() == str(imported.get("tool") or "").lower():
                how = msg("findings.registry.gone_from_import", tool=imported.get("tool"), date=stamp[:10])
            else:
                continue
            entry.update(status="fixed", fixed={"at": stamp, "run_id": record["id"], "how": how, "auto": True})
            entry.pop("excluded", None)
            fixed += 1
        state["applied"] = state["applied"][-500:] + [record["id"]]
        _save(data_dir, state, set(moved))
    carry_over(data_dir, key, moved)
    _reopen_manual(data_dir, record, set(present))
    if opened or fixed:
        _log.info("registry_updated", extra={"run_id": record["id"], "reason": f"{key}: {opened} abiertos, {fixed} remediados"})
    return {"opened": opened, "fixed": fixed, "new": new}


def apply_exclusions(data_dir: Path, key: str, active: list[str], *, when: str) -> dict:
    """Excluded paths changed: open findings under them become excluded; excluded ones no longer under them reopen."""
    from tamandua.modules.findings.exclusions import excluded
    moved = {"excluded": 0, "reopened": 0}
    with _locked(data_dir, key) as state:
        for entry in state["findings"].values():
            pattern = excluded((entry.get("finding") or {}).get("path", ""), active)
            if entry.get("status") == "open" and pattern:
                entry.update(status="excluded", excluded={"pattern": pattern, "at": when})
                moved["excluded"] += 1
            elif entry.get("status") == "excluded" and not pattern and not _withheld(entry):
                entry["status"] = "open"
                entry.pop("excluded", None)
                moved["reopened"] += 1
        if moved["excluded"] or moved["reopened"]:
            _save(data_dir, state)
    return moved


def pull_closed(data_dir: Path, key: str, number: int, *, merged: bool, when: str) -> int:
    """PR closed: unmerged, its findings are withdrawn; merged, they wait for the full scan."""
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


def reset(data_dir: Path) -> None:
    """Empties every asset's registry, before rebuilding it from the runs (`runs/registry.py`)."""
    with db.transaction(data_dir) as connection:
        connection.execute(delete(registry_findings).where(registry_findings.c.tenant_id == TENANT))
        connection.execute(delete(registry_assets).where(registry_assets.c.tenant_id == TENANT))


def view(data_dir: Path, key: str, *, status: str = "open") -> dict:
    """The repository's state shaped like a run, so it is viewed, triaged and exported the same way.

    `open`: what is still there (including what triage dismissed, which the table filters separately);
    `fixed`: fixed, automatically or by hand; `excluded`: under excluded paths; `all`: everything.
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
    """Open (really pending), fixed and dismissed, taking triage into account."""
    state = load(data_dir, key)
    decisions = triage.load(data_dir).get(key, {})
    counts = {"open": 0, "fixed": 0, "suppressed": 0, "excluded": 0, "by_severity": dict.fromkeys(("critical", "high", "medium", "low"), 0), "from_pr": 0}
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


PACKAGES_SHOWN = 5  # per affected repository in the CVE tracker


def assets_with_cve(data_dir: Path, cve: str, *, limit: int, offset: int) -> dict:
    """Repositories with a finding that cites this CVE, to answer "does it affect me?" from the tracker (GIN index).

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
    """CVEs still open in some asset (minus what triage dismissed), for "only mine" in the tracker."""
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
