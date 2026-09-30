"""Findings to Jira issues: manual exports, automatic creation, backfills and the comments on fix and reopen.

* **Routing.** Each finding goes where the first matching rule of its asset says (`integrations/jira_routing.py`), so
  one export may create issues in several projects. No enabled rule: the finding fails with "no destination".
* **One issue per remediation job.** Advisories of one installed package go together; code and secrets, one by one.
* **Idempotent.** Before creating, the stored link (`findings/tickets.py`) and the `appsec-<fingerprint>` label (JQL in
  the destination's project) are checked; exporting or delivering twice doesn't duplicate.
* **Automatic creation.** When a run adds new open findings to the registry, a rule in `auto` mode matching the asset
  queues their creation in the outbox (channel `jira`) for the findings at or above its minimum severity. Runs that
  do: full scans, SARIF imports and the advisory watch (a new advisory against the main branch's dependencies is new
  work on what is deployed, and no scan would bring it sooner). PR reviews don't: the PR comment is their channel, and
  their findings reach the registry's main-branch state only through the next full scan. Findings dismissed in triage
  (false positive, accepted risk, fixed by hand) or excluded are skipped, when queued and again when delivered.
* **Backfill.** Saving or enabling an automatic rule with backfill queues the open findings of its assets that have no
  issue yet, spaced out (Jira's rate limits) and counted per rule (`jira-backfill`).
* **Fix and reopen.** When a full scan or a full import verifies as fixed the findings of a linked issue, Tamandua
  comments on it (never closes it). An issue covering several findings gets the comment when all of them are fixed:
  it is one remediation job (one upgrade), and a comment per finding would be noise. If any of them reappears later,
  it comments that too. Comments speak TAMANDUA_DEFAULT_LOCALE, like everything the team reads.
* **Delivery** is the worker's (`drain`): at least once, with the outbox's retries; Jira being down or throttling
  (429, 5xx) is retried, a request Jira rejects (4xx) fails and says why.
"""

from __future__ import annotations

import re
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert

from tamandua.modules.findings import registry, sla, tickets, triage
from tamandua.modules.runs.jira_brief import brief, severity_label
from tamandua.modules.findings.kinds import ADVISORY_RUNS, FULL_SCANS, IMPORT_RUNS
from tamandua.modules.integrations import jira, jira_routing as routing
from tamandua.modules.integrations.jira_mapping import build
from tamandua.modules.integrations.notifications import RETRY_MINUTES
from tamandua.modules.integrations.tables import JIRA_CHANNEL, outbox
from tamandua.modules.intel.advisories import compare_versions
from tamandua.modules.sources.assets import asset_key
from tamandua.shared import db, documents, settings
from tamandua.shared import log as logging_setup
from tamandua.shared.i18n import default_locale, localize, msg, t, text

_log = logging_setup.get("jira")
AUTO_RUNS = FULL_SCANS + IMPORT_RUNS + ADVISORY_RUNS
VERIFYING_RUNS = FULL_SCANS + IMPORT_RUNS
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
PRIORITY_ORDER = ("Highest", "High", "Medium", "Low")
BACKFILL_DOCUMENT = "jira-backfill"
BACKFILL_MAX = 5000        # findings queued by one backfill; the rest waits for the next one
MANUAL_DOCUMENT = "jira-manual"
MANUAL_MAX = 5000          # findings one person can send at once; above jira.MAX_BATCH they go through the queue
MANUAL_KEPT = 20           # batches whose progress is kept
BACKFILL_SPACING = 2       # seconds between two queued issues of a backfill
PER_DRAIN = 10             # outbox rows delivered per round (the worker runs one every few seconds)
OUTBOX_LEASE = timedelta(minutes=5)
FINGERPRINT = re.compile(r"[0-9a-f]{64}")


def _stamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _rank(severity) -> int:
    return SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else len(SEVERITY_ORDER)


def _reaches(severity, minimum: str) -> bool:
    return _rank(severity) <= _rank(minimum)


def _group_key(item: dict) -> str:
    package = item.get("package") or {}
    return f"pkg:{package.get('ecosystem')}:{package.get('name')}@{package.get('version')}" if package.get("name") else item["fingerprint"]


def _groups(items: list[dict]) -> list[list[dict]]:
    """Advisories of one installed package go together; everything else is one job per finding."""
    found: dict[str, list[dict]] = {}
    for item in items:
        found.setdefault(_group_key(item), []).append(item)
    return list(found.values())


# ------------------------------------------------------------------ the values of one issue

def _asset_link(key: str) -> str | None:
    base = settings.text("TAMANDUA_PUBLIC_URL").rstrip("/")
    if not base.startswith(("https://", "http://")):
        return None
    return f"{base}/#/hallazgos?repo={quote(key, safe='')}"


def _finding_link(key: str, fingerprint: str) -> str | None:
    link = _asset_link(key)
    return f"{link}&finding={fingerprint}" if link else None


def _first_seen(data_dir: Path, key: str, findings: dict, fallback: str) -> dict[str, str]:
    entries = registry.load(data_dir, key)["findings"]
    seen = {}
    for digest, finding in findings.items():
        lifecycle = finding.get("lifecycle") or {}
        seen[digest] = lifecycle.get("first_seen") or (entries.get(digest) or {}).get("first_seen") or fallback
    return seen


def values(group: list[dict], findings: dict, *, key: str, asset: str, first_seen: dict, days: dict, locale: str,
           source: dict | None = None) -> dict:
    """Every Tamandua variable (see `jira_mapping`) for one issue: a ticket group and its localized findings."""
    first = group[0]
    finding = findings.get(first["fingerprint"]) or {}
    severity = min((ticket["severity"] for ticket in group), key=_rank)
    priority = min((ticket["priority"] for ticket in group), key=lambda item: PRIORITY_ORDER.index(item) if item in PRIORITY_ORDER else 9)
    package = first.get("package") or {}
    target = package.get("fixed_version")
    if len(group) > 1 and package.get("name"):
        fixes = [ticket["package"]["fixed_version"] for ticket in group if (ticket.get("package") or {}).get("fixed_version")]
        target = None
        for version in fixes:
            if target is None or compare_versions(version, target) > 0:
                target = version
        names = {"package": package["name"], "version": package.get("version"), "count": len(group)}
        title = (t("integrations.jira.issue.group_title", locale, target=target, **names) if target
                 else t("integrations.jira.issue.group_title_unfixed", locale, **names))
        summary = (t("integrations.jira.issue.group_summary", locale, target=target, severity=severity_label(severity, locale), **names)
                   if target else t("integrations.jira.issue.group_summary_unfixed", locale, severity=severity_label(severity, locale), **names))
    elif package.get("name"):
        # One advisory of a package: the action (update to…), not the advisory's title, like a group.
        identifier = next(iter(finding.get("cve") or finding.get("ghsa") or [finding.get("rule_id") or ""]), "")
        names = {"package": package["name"], "version": package.get("version") or "?", "id": identifier,
                 "severity": severity_label(severity, locale)}
        title = text(finding.get("title"), locale)
        summary = (t("integrations.jira.issue.package_summary", locale, target=target, **names) if target
                   else t("integrations.jira.issue.package_summary_unfixed", locale, **names))
    else:
        title = text(finding.get("title"), locale)
        where = f"{finding.get('path')}:{finding['line']}" if isinstance(finding.get("line"), int) and finding.get("line") else finding.get("path")
        summary = t("integrations.jira.issue.summary", locale, severity=severity_label(severity, locale), title=title, where=where or "?") \
            if where else t("integrations.jira.issue.summary_nowhere", locale, severity=severity_label(severity, locale), title=title)
    written = brief(group, findings, asset=asset, source=source, first_seen=first_seen, days=days,
                    panel_url=_finding_link(key, first["fingerprint"]), locale=locale)
    description = written["text"]
    labels: list[str] = []
    for ticket in group:
        labels.extend(item for item in ticket["labels"] if item not in labels)
    members = [findings.get(ticket["fingerprint"]) or {} for ticket in group]
    cwes = list(dict.fromkeys(f"CWE-{item}" for member in members for item in member.get("cwe") or []))
    cves = list(dict.fromkeys(item for member in members for item in member.get("cve") or []))
    seen = sorted(first_seen[ticket["fingerprint"]] for ticket in group if first_seen.get(ticket["fingerprint"]))
    deadlines = sorted(filter(None, ((sla.deadline(ticket["severity"], first_seen.get(ticket["fingerprint"]), days) or {}).get("due")
                                     for ticket in group)))
    return {"summary": summary, "title": title, "severity": severity, "jira_priority": priority, "description": description,
            "_description_adf": jira.adf_document(written["blocks"]),
            "cwe": ", ".join(cwes) or None, "cve": ", ".join(cves) or None,
            "package": f"{package['name']} {package.get('version') or ''}".strip() if package.get("name") else None,
            "fixed_version": target, "path": finding.get("path"), "line": finding.get("line") if isinstance(finding.get("line"), int) else None,
            "asset": asset, "panel_url": _finding_link(key, first["fingerprint"]), "first_seen": seen[0] if seen else None,
            "due_date": deadlines[0] if deadlines else None, "labels": labels}


def _prepared(data_dir: Path, record: dict, locale: str) -> tuple[dict, dict, dict, dict]:
    """The pending tickets of a record (by fingerprint), its localized findings, when each was first seen and the SLA."""
    from tamandua.modules.runs.store import render_tickets
    by_fingerprint = {ticket["fingerprint"]: ticket for ticket in render_tickets(record, locale=locale)}
    findings = {item["fingerprint"]: item for item in localize(record.get("findings", []), locale)}
    seen = _first_seen(data_dir, asset_key(record), findings, record.get("created_at") or _stamp())
    return by_fingerprint, findings, seen, sla.policy(data_dir)["days"]


# ------------------------------------------------------------------ creating one issue

def _create(destination: dict, fields: dict, http) -> str:
    try:
        return jira.create_issue(fields, http=http)
    except jira.JiraError as exc:
        # Many projects don't put priority on the create screen: a priority Tamandua picked is dropped and retried.
        spec = (destination.get("mapping") or {}).get("priority") or {}
        if exc.status != 400 or "priority" not in str(exc) or "priority" not in fields or spec.get("source") == "fixed":
            raise
        fields.pop("priority")
        return jira.create_issue(fields, http=http)


def _deliver(data_dir: Path, key: str, group: list[dict], issue_values: dict, destination: dict, *, by: str, http,
             force: bool = False) -> tuple[str, dict]:
    """Links or creates the issue of one group. Returns ("created" | "existing", link).

    Its findings stay locked (PostgreSQL, across workers and replicas) from the check to the stored link: two people
    creating the same issue at once wait for each other, and the second finds the first's link. Jira's search lags a
    few seconds behind a new issue, so the stored link is what really prevents the duplicate. `force`: a person asked
    for a new issue although one exists (closed, wrong project): the new link replaces the old one, remembered."""
    prints = [ticket["fingerprint"] for ticket in group]
    with db.transaction(data_dir) as connection:
        for item in sorted(set(prints)):
            db.lock(connection, "jira-issue", key, item)
        known = tickets.load_links(data_dir).get(key, {})
        link = None if force else next((known[item] for item in prints if item in known), None)
        outcome = "existing"
        if link is None:
            found = None if force else jira.search_labels(destination["project"]["key"], prints, http=http)
            if found is None:
                found = _create(destination, build(destination, issue_values, prints), http)
                outcome = "created"
            link = {"key": found, "url": jira.browse_url(found), "linked_at": _stamp(), "by": by, "destination": destination["id"],
                    "project": destination["project"]["key"]}
            previous = sorted({known[item]["key"] for item in prints if isinstance(known.get(item), dict) and known[item].get("key")})
            if force and previous:
                link["replaces"] = previous
        for item in prints:
            if force or item not in known:
                tickets.remember(data_dir, key, item, link)
    return outcome, link


def _prune(data_dir: Path, selections: list[tuple[dict, list]], http) -> int:
    """Before trusting "it already has an issue": asks Jira whether the linked issues still exist and forgets the ones
    that don't (someone deleted them), so their findings are created again. Returns how many findings it relinked."""
    links = tickets.load_links(data_dir)
    keys = {link["key"] for record, prints in selections for item in prints
            if isinstance(link := links.get(asset_key(record), {}).get(item), dict) and link.get("key")}
    if not keys:
        return 0
    gone = jira.missing_issues(sorted(keys), http=http)
    dropped = tickets.forget_issues(data_dir, gone)
    if gone:
        _log.info("jira_links_pruned", extra={"reason": f"{len(gone)} issues gone from Jira, {dropped} findings unlinked"})
    return dropped


def _public(link: dict) -> dict:
    return {name: link.get(name) for name in ("key", "url", "linked_at", "by", "project", "destination")}


def export(data_dir: Path, selections: list[tuple[dict, list]], *, by: str, http=None, locale: str | None = None,
           force: bool = False) -> dict:
    """Creates (or links) the issues of the selected findings: [(record, fingerprints)], a record being a run annotated
    with triage or an asset's state. Returns the created, existing and failed ones, each with its project."""
    locale = locale or default_locale()
    jira.credentials()
    total = sum(len(prints) if isinstance(prints, list) else 0 for _, prints in selections)
    if (not 1 <= total <= jira.MAX_BATCH or any(not isinstance(prints, list) or not prints for _, prints in selections)
            or not all(isinstance(item, str) and FINGERPRINT.fullmatch(item) for _, prints in selections for item in prints)):
        raise jira.JiraError(msg("integrations.jira.batch_size", max=jira.MAX_BATCH))
    relinked = 0 if force else _prune(data_dir, selections, http)
    state = routing.load(data_dir)
    prepared = []
    for record, prints in selections:
        by_fingerprint, findings, seen, days = _prepared(data_dir, record, locale)
        if any(item not in by_fingerprint for item in prints):
            raise jira.JiraError(msg("integrations.jira.not_pending"))
        prepared.append((record, list(dict.fromkeys(prints)), by_fingerprint, findings, seen, days))
    created: list[dict] = []
    existing: list[dict] = []
    failed: list[dict] = []
    for record, prints, by_fingerprint, findings, seen, days in prepared:
        key, name = asset_key(record), (record.get("source") or {}).get("name")
        rule = routing.resolve(state, key, name)
        target = routing.destination(state, rule["destination"]) if rule else None
        if target is None:
            failed.extend({"fingerprint": item, "asset": key, "error": msg("integrations.jira.no_destination")} for item in prints)
            continue
        for group in _groups([by_fingerprint[item] for item in prints]):
            try:
                issue = values(group, findings, key=key, asset=text(name, locale) or key, first_seen=seen, days=days, locale=locale,
                               source=record.get("source"))
                outcome, link = _deliver(data_dir, key, group, issue, target, by=by, http=http, force=force)
            except (jira.JiraError, KeyError, TypeError) as exc:
                message = exc.message if isinstance(exc, jira.JiraError) else msg("integrations.jira.unexpected")
                failed.extend({"fingerprint": ticket["fingerprint"], "asset": key, "error": message} for ticket in group)
                continue
            (created if outcome == "created" else existing).extend(
                {"fingerprint": ticket["fingerprint"], "asset": key, **_public(link)} for ticket in group)
    _log.info("jira_export", extra={"user": by, "reason": f"{len(created)} created, {len(existing)} existing, {len(failed)} failed"})
    return {"created": created, "existing": existing, "failed": failed, "relinked": relinked}


def queue_export(data_dir: Path, selections: list[tuple[dict, list]], *, by: str, user: str = "", force: bool = False) -> dict:
    """A selection too big to create while the browser waits: each issue is queued (spaced, retried, idempotent) and
    `manual_status` follows it. Findings no rule routes fail right away, like in `export`."""
    jira.credentials()
    total = sum(len(prints) if isinstance(prints, list) else 0 for _, prints in selections)
    if (not 1 <= total <= MANUAL_MAX or any(not isinstance(prints, list) or not prints for _, prints in selections)
            or not all(isinstance(item, str) and FINGERPRINT.fullmatch(item) for _, prints in selections for item in prints)):
        raise jira.JiraError(msg("integrations.jira.batch_size", max=MANUAL_MAX))
    relinked = 0 if force else _prune(data_dir, selections, None)
    state, locale = routing.load(data_dir), default_locale()
    queued, links, work, failed, linked = _queued_creates(data_dir), tickets.load_links(data_dir), [], [], 0
    linked_items: list[dict] = []
    for record, prints in selections:
        by_fingerprint, _, _, _ = _prepared(data_dir, record, locale)
        if any(item not in by_fingerprint for item in prints):
            raise jira.JiraError(msg("integrations.jira.not_pending"))
        key, name = asset_key(record), (record.get("source") or {}).get("name")
        rule = routing.resolve(state, key, name)
        target = routing.destination(state, rule["destination"]) if rule else None
        if target is None:
            failed += [{"fingerprint": item, "asset": key, "error": msg("integrations.jira.no_destination")} for item in prints]
            continue
        already = {} if force else links.get(key, {})
        for item in dict.fromkeys(prints):
            if item in already and len(linked_items) < MANUAL_MAX:
                linked_items.append({"fingerprint": item, "asset": key, **_public(already[item])})
        linked += sum(1 for item in dict.fromkeys(prints) if item in already)
        wanted = [by_fingerprint[item] for item in dict.fromkeys(prints) if (key, item) not in queued and item not in already]
        work += [(key, target["id"], [ticket["fingerprint"] for ticket in group]) for group in _groups(wanted)]
    batch, now = uuid.uuid4().hex[:16], datetime.now(timezone.utc)
    rows = [{"payload": {"type": "create", "trigger": "manual", "asset": key, "destination": destination, "batch": batch,
                         "by": str(by)[:80], "force": force, "fingerprints": prints},
             "next_attempt_at": now + timedelta(seconds=index * BACKFILL_SPACING)} for index, (key, destination, prints) in enumerate(work)]
    entry = {"batch": batch, "by": str(by)[:80], "user": str(user)[:80], "force": force, "started_at": _stamp(), "finished_at": None if rows else _stamp(), "queued": len(rows),
             "findings": sum(len(prints) for _, _, prints in work), "linked": linked, "created": 0, "existing": 0, "skipped": 0,
             "failed": 0, "last_error": None}
    with db.transaction(data_dir):
        with documents.edit(data_dir, MANUAL_DOCUMENT, {}) as status:
            status[batch] = entry
            for old in sorted(status, key=lambda item: str(status[item].get("started_at")))[:-MANUAL_KEPT]:
                status.pop(old, None)
        _queue(data_dir, rows)
    _log.info("jira_export_queued", extra={"user": by, "reason": f"{len(rows)} issues, {entry['findings']} findings, {len(failed)} failed"})
    return {**entry, "pending": len(rows), "rejected": failed, "linked_items": linked_items, "relinked": relinked}


def manual_batches(data_dir: Path, user: str) -> list[dict]:
    """This person's recent queued selections, newest first, with their pending counts (the panel's background tasks)."""
    status = documents.load(data_dir, MANUAL_DOCUMENT, {})
    mine = [entry for entry in (status.values() if isinstance(status, dict) else []) if isinstance(entry, dict) and entry.get("user") == user]
    return [found for found in (manual_status(data_dir, entry["batch"]) for entry in
            sorted(mine, key=lambda item: str(item.get("started_at")), reverse=True)) if found is not None]


def manual_status(data_dir: Path, batch: str) -> dict | None:
    entry = documents.load(data_dir, MANUAL_DOCUMENT, {}).get(batch)
    if not isinstance(entry, dict):
        return None
    with db.transaction(data_dir) as connection:
        pending = connection.execute(select(func.count()).select_from(outbox).where(
            outbox.c.tenant_id == db.TENANT, outbox.c.channel_id == JIRA_CHANNEL, outbox.c.status == "pending",
            outbox.c.payload["batch"].astext == batch)).scalar_one()
    return {**entry, "pending": pending}


# ------------------------------------------------------------------ the queue

def _queue(data_dir: Path, rows: list[dict]) -> None:
    if rows:
        with db.transaction(data_dir) as connection:
            connection.execute(insert(outbox), [{"tenant_id": db.TENANT, "id": uuid.uuid4().hex, "channel_id": JIRA_CHANNEL, **row}
                                                for row in rows])


def _queued_creates(data_dir: Path) -> set[tuple[str, str]]:
    """(asset, fingerprint) already waiting to be created: queuing them again would only cost Jira calls."""
    with db.transaction(data_dir) as connection:
        payloads = connection.execute(select(outbox.c.payload).where(
            outbox.c.tenant_id == db.TENANT, outbox.c.channel_id == JIRA_CHANNEL, outbox.c.status == "pending",
            outbox.c.payload["type"].astext == "create")).scalars()
        return {(payload.get("asset"), item) for payload in payloads for item in payload.get("fingerprints") or []}


def on_run(data_dir: Path, record: dict, changes: dict, active: list[dict]) -> None:
    """After a run is applied to the registry: queues the automatic issues of its new findings and the fix/reopen
    comments. Runs inside the run's transaction, so the queue and the registry agree. Never breaks a scan."""
    try:
        if not jira.configured():
            return
        # A savepoint: a failure here rolls back only what this step wrote, never the run and its registry.
        with db.transaction(data_dir) as connection, connection.begin_nested():
            _on_run(data_dir, record, changes, active)
    except Exception:  # noqa: BLE001 — Jira being misconfigured never fails a scan
        _log.exception("jira_queue_failed")


def _on_run(data_dir: Path, record: dict, changes: dict, active: list[dict]) -> None:
    kind, key, name = record.get("type"), asset_key(record), (record.get("source") or {}).get("name")
    rows: list[dict] = []
    if kind in AUTO_RUNS and active:
        state = routing.load(data_dir)
        rule = routing.resolve(state, key, name)
        if rule and rule.get("mode") == "auto":
            linked = tickets.load_links(data_dir).get(key, {})
            queued = _queued_creates(data_dir)
            wanted = [item for item in active if _reaches(item.get("severity"), rule["min_severity"])
                      and item["fingerprint"] not in linked and (key, item["fingerprint"]) not in queued]
            rows += [{"payload": {"type": "create", "trigger": "auto", "asset": key, "rule": rule["id"], "run_id": record["id"],
                                  "fingerprints": [item["fingerprint"] for item in group]}} for group in _groups(wanted)]
    fixed, reopened = set(changes.get("fixed_now") or []), set(changes.get("reopened") or [])
    if kind != "pr_review":
        # A finding fixed by hand (triage) shows up again: the registry never closed it, the issue was told it was fixed.
        reopened |= {item["fingerprint"] for item in record.get("findings") or []}
    if (fixed and kind in VERIFYING_RUNS) or (reopened and kind != "pr_review"):
        rows += _comments(data_dir, record, key, fixed if kind in VERIFYING_RUNS else set(), reopened if kind != "pr_review" else set())
    _queue(data_dir, rows)
    if rows:
        _log.info("jira_queued", extra={"run_id": record["id"], "reason": f"{key}: {len(rows)}"})


def _comments(data_dir: Path, record: dict, key: str, fixed: set[str], reopened: set[str]) -> list[dict]:
    links = tickets.load_links(data_dir).get(key, {})
    issues: dict[str, list[str]] = {}
    for digest, link in links.items():
        if isinstance(link, dict) and link.get("key"):
            issues.setdefault(link["key"], []).append(digest)
    entries = registry.load(data_dir, key)["findings"]
    stamp = str(record.get("finished_at") or record.get("created_at") or _stamp())
    rows = []
    for issue, prints in issues.items():
        state = links[prints[0]].get("sync")
        event = None
        if fixed & set(prints) and state != "fixed" and all((entries.get(item) or {}).get("status", "fixed") == "fixed" for item in prints):
            event = "fixed"
        elif reopened & set(prints) and state in ("fixed", "manual_fixed") and not _manual_fix_is_newer(data_dir, key, prints, stamp):
            event = "reopened"
        if event is None:
            continue
        tickets.mark(data_dir, key, issue, "fixed" if event == "fixed" else "open", record["id"])
        rows.append({"payload": {"type": "comment", "event": event, "asset": key, "key": issue, "run_id": record["id"],
                                 "date": stamp[:10], "count": len(prints)}})
    return rows


def _manual_fix_is_newer(data_dir: Path, key: str, prints: list[str], stamp: str) -> bool:
    """A rebuild replays old runs: a finding marked fixed by hand after this run didn't reappear."""
    decisions = triage.load_asset(data_dir, key)
    return any((decisions.get(item) or {}).get("status") == "fixed" and str((decisions[item].get("at") or "")) >= stamp
               for item in prints)


TRIAGE_EVENTS = {"fixed": "manual_fixed", "false_positive": "false_positive", "accepted": "accepted"}


def on_triage(data_dir: Path, key: str, fingerprints: list[str], status: str, *, by: str, reason: str | None = None,
              expires_at: str | None = None) -> int:
    """A person's triage decision reaches the issues linked to those findings as a comment (never closing them):
    fixed by hand, false positive, accepted risk, or reopened after one of those. Returns how many comments it queued."""
    try:
        if not jira.configured():
            return 0
        links = tickets.load_links(data_dir).get(key, {})
        issues: dict[str, list[str]] = {}
        for digest, link in links.items():
            if isinstance(link, dict) and link.get("key"):
                issues.setdefault(link["key"], []).append(digest)
        chosen, stamp, rows = set(fingerprints), _stamp(), []
        for issue, prints in issues.items():
            touched = [item for item in prints if item in chosen]
            if not touched:
                continue
            state = links[prints[0]].get("sync")
            if status in TRIAGE_EVENTS:
                # "manual_fixed", not "fixed": a later scan that verifies it still tells the issue.
                event, sync = TRIAGE_EVENTS[status], "manual_fixed" if status == "fixed" else "dismissed"
            elif status == "open" and state in ("fixed", "manual_fixed", "dismissed"):
                event, sync = "triage_reopened", "open"
            else:
                continue
            tickets.mark(data_dir, key, issue, sync, f"triage:{stamp}")
            rows.append({"payload": {"type": "comment", "event": event, "asset": key, "key": issue, "run_id": f"triage:{stamp}",
                                     "date": stamp[:10], "by": str(by)[:80], "reason": str(reason or "")[:500],
                                     "expires_at": expires_at, "count": len(touched), "total": len(prints)}})
        _queue(data_dir, rows)
        return len(rows)
    except Exception:  # noqa: BLE001 — Jira never breaks a triage decision
        _log.exception("jira_triage_queue_failed")
        return 0


# ------------------------------------------------------------------ backfill

def _plan(data_dir: Path, state: dict, rule: dict) -> dict:
    """The open findings a backfill of `rule` would queue: in assets this rule wins, active in triage, at or above its
    minimum severity and with no issue yet. Grouped by asset and remediation job."""
    from tamandua.modules.findings.tables import registry_assets
    with db.transaction(data_dir) as connection:
        assets = connection.execute(select(registry_assets.c.asset_key, registry_assets.c.name)
                                    .where(registry_assets.c.tenant_id == db.TENANT).order_by(registry_assets.c.asset_key)).all()
    links = tickets.load_links(data_dir)
    plan: dict = {"assets": 0, "findings": 0, "issues": 0, "linked": 0, "truncated": False, "work": []}
    for key, name in assets:
        winner = routing.resolve(state, key, name)
        if winner is None or winner["id"] != rule["id"]:
            continue
        decisions = triage.load_asset(data_dir, key)
        linked = links.get(key, {})
        candidates = []
        for digest, entry in registry.load(data_dir, key)["findings"].items():
            finding = entry.get("finding") or {}
            if entry.get("status") != "open" or triage.effective(decisions.get(digest))["status"] in triage.SUPPRESSED:
                continue
            if not _reaches(finding.get("severity"), rule["min_severity"]):
                continue
            if digest in linked:
                plan["linked"] += 1
                continue
            candidates.append({**finding, "fingerprint": digest})
        if not candidates:
            continue
        room = BACKFILL_MAX - plan["findings"]
        if room <= 0:
            plan["truncated"] = True
            break
        if len(candidates) > room:
            candidates, plan["truncated"] = candidates[:room], True
        groups = _groups(candidates)
        plan["assets"] += 1
        plan["findings"] += len(candidates)
        plan["issues"] += len(groups)
        plan["work"] += [(key, [item["fingerprint"] for item in group]) for group in groups]
    return plan


def preview(data_dir: Path, payload: dict) -> dict:
    """How many open findings a rule (saved or not) would backfill now. Nothing is queued."""
    state, candidate = routing.preview_state(data_dir, payload)
    plan = _plan(data_dir, state, candidate)
    return {key: plan[key] for key in ("assets", "findings", "issues", "linked", "truncated")}


def backfill(data_dir: Path, rule_id: str, *, by: str) -> dict:
    """Queues the rule's backfill, spaced out. Returns its status."""
    state = routing.load(data_dir)
    rule = routing.rule(state, rule_id)
    if rule is None:
        raise routing.RoutingError(msg("integrations.jira.routing.rule_not_found"))
    if not (rule.get("enabled") and rule.get("mode") == "auto" and rule.get("destination")):
        raise routing.RoutingError(msg("integrations.jira.routing.backfill_not_auto"))
    jira.credentials()
    plan = _plan(data_dir, state, rule)
    queued = _queued_creates(data_dir)
    work = [(key, [item for item in prints if (key, item) not in queued]) for key, prints in plan["work"]]
    work = [(key, prints) for key, prints in work if prints]
    if not work:
        # Nothing new to queue: the backfill in course (or the last one) is the answer.
        current = next((item for item in backfill_status(data_dir) if item["rule"] == rule["id"]), None)
        if current is not None:
            return current
    batch = uuid.uuid4().hex[:16]
    now = datetime.now(timezone.utc)
    rows = [{"payload": {"type": "create", "trigger": "backfill", "asset": key, "rule": rule["id"], "batch": batch, "fingerprints": prints},
             "next_attempt_at": now + timedelta(seconds=index * BACKFILL_SPACING)} for index, (key, prints) in enumerate(work)]
    entry = {"batch": batch, "by": by, "started_at": _stamp(), "finished_at": None if rows else _stamp(), "queued": len(rows),
             "findings": sum(len(prints) for _, prints in work), "created": 0, "existing": 0, "skipped": 0, "failed": 0,
             "truncated": plan["truncated"], "last_error": None}
    with db.transaction(data_dir):
        with documents.edit(data_dir, BACKFILL_DOCUMENT, {}) as status:
            status[rule["id"]] = entry
        _queue(data_dir, rows)
    _log.info("jira_backfill", extra={"user": by, "reason": f"{rule['id']}: {len(rows)} issues, {entry['findings']} findings"})
    return {"rule": rule["id"], **entry, "pending": len(rows)}


def backfill_status(data_dir: Path) -> list[dict]:
    status = documents.load(data_dir, BACKFILL_DOCUMENT, {})
    with db.transaction(data_dir) as connection:
        pending = Counter(connection.execute(
            select(outbox.c.payload["batch"].astext).where(
                outbox.c.tenant_id == db.TENANT, outbox.c.channel_id == JIRA_CHANNEL, outbox.c.status == "pending",
                outbox.c.payload["type"].astext == "create", outbox.c.payload["trigger"].astext == "backfill")).scalars())
    return [{"rule": rule_id, **entry, "pending": pending.get(entry.get("batch"), 0)}
            for rule_id, entry in (status.items() if isinstance(status, dict) else []) if isinstance(entry, dict)]


def _count(data_dir: Path, payload: dict, outcome: str, error=None) -> None:
    if payload.get("trigger") not in ("backfill", "manual"):
        return
    manual = payload["trigger"] == "manual"
    with documents.edit(data_dir, MANUAL_DOCUMENT if manual else BACKFILL_DOCUMENT, {}) as status:
        entry = status.get(payload.get("batch") if manual else payload.get("rule"))
        if not isinstance(entry, dict) or entry.get("batch") != payload.get("batch"):
            return
        entry[outcome] = entry.get(outcome, 0) + 1
        if error is not None:
            entry["last_error"] = error
        if sum(entry.get(name, 0) for name in ("created", "existing", "skipped", "failed")) >= entry.get("queued", 0):
            entry["finished_at"] = _stamp()


# ------------------------------------------------------------------ delivery

def save_rule(data_dir: Path, payload: dict, *, by: str) -> tuple[dict, dict | None]:
    """Saves a rule and, when it asks for one (see `jira_routing.wants_backfill`), starts its backfill."""
    saved, previous = routing.save_rule(data_dir, payload, by=by)
    started = backfill(data_dir, saved["id"], by=by) if routing.wants_backfill(saved, previous) and jira.configured() else None
    return saved, started


def _deliver_create(data_dir: Path, payload: dict, http) -> str:
    key = payload["asset"]
    state = routing.load(data_dir)
    view = registry.view(data_dir, key, status="open")
    name = (view.get("source") or {}).get("name")
    if payload.get("trigger") == "manual":
        # A person chose these findings and where the rules sent them then: that destination, if it still exists.
        target = routing.destination(state, payload.get("destination"))
    else:
        rule = routing.resolve(state, key, name)
        if rule is None or rule["id"] != payload.get("rule") or rule.get("mode") != "auto":
            return "skipped"  # the routing changed while it waited: the current rules no longer create it
        target = routing.destination(state, rule["destination"])
    if target is None:
        return "skipped"
    locale = default_locale()
    by_fingerprint, findings, seen, days = _prepared(data_dir, view, locale)
    group = [by_fingerprint[item] for item in payload.get("fingerprints") or [] if item in by_fingerprint]
    if not group:
        return "skipped"  # fixed, dismissed or excluded meanwhile
    issue = values(group, findings, key=key, asset=text(name, locale) or key, first_seen=seen, days=days, locale=locale,
                   source=view.get("source"))
    outcome, _ = _deliver(data_dir, key, group, issue, target, by=payload.get("by") or "tamandua", http=http,
                          force=bool(payload.get("force")) and payload.get("trigger") == "manual")
    return outcome


def _deliver_comment(data_dir: Path, payload: dict, http) -> str:
    locale = default_locale()
    event = payload["event"]
    if event in ("manual_fixed", "false_positive", "accepted", "triage_reopened"):
        part = (t("integrations.jira.comment.part", locale, count=payload["count"], total=payload["total"])
                if payload.get("total", 1) > 1 and payload.get("count") != payload.get("total") else "")
        body = t(f"integrations.jira.comment.{event}", locale, by=payload.get("by") or "?", date=payload["date"],
                 expires=payload.get("expires_at") or "", part=part)
        if payload.get("reason"):
            body += "\n" + t("integrations.jira.comment.reason", locale, reason=payload["reason"])
    elif event == "fixed":
        body = (t("integrations.jira.comment.fixed_group", locale, count=payload.get("count", 1), run_id=payload["run_id"][:12], date=payload["date"])
                if payload.get("count", 1) > 1 else t("integrations.jira.comment.fixed", locale, run_id=payload["run_id"][:12], date=payload["date"]))
    else:
        body = t("integrations.jira.comment.reopened", locale, run_id=payload["run_id"][:12], date=payload["date"])
    link = _asset_link(payload["asset"])
    if link:
        body += "\n" + t("integrations.jira.comment.panel", locale, url=link)
    written = jira.comment(payload["key"], body, {"event": payload["event"], "run": payload["run_id"]}, http=http)
    return "created" if written else "existing"


def deliver(data_dir: Path, payload: dict, *, http=None) -> str:
    if payload.get("type") == "comment":
        return _deliver_comment(data_dir, payload, http)
    return _deliver_create(data_dir, payload, http)


def drain(data_dir: Path, *, http=None, limit: int = PER_DRAIN) -> int:
    """Delivers the due Jira rows of the outbox (the worker calls it with the notifications). Returns how many it tried.

    Claimed in a short transaction (their next attempt moves past a lease) and delivered outside it. Without a Jira
    credential nothing is claimed: the rows wait, their attempts untouched."""
    if not jira.configured():
        return 0
    with db.transaction(data_dir) as connection:
        rows = connection.execute(select(outbox.c.id, outbox.c.payload, outbox.c.attempts)
                                  .where(outbox.c.tenant_id == db.TENANT, outbox.c.channel_id == JIRA_CHANNEL, outbox.c.status == "pending",
                                         outbox.c.next_attempt_at <= func.now())
                                  .order_by(outbox.c.next_attempt_at, outbox.c.created_at).limit(limit).with_for_update(skip_locked=True)).all()
        if rows:
            connection.execute(update(outbox).where(outbox.c.tenant_id == db.TENANT, outbox.c.id.in_([row.id for row in rows]))
                               .values(next_attempt_at=func.now() + OUTBOX_LEASE))
    for row in rows:
        attempts = row.attempts + 1
        values_: dict = {"attempts": attempts}
        try:
            outcome = deliver(data_dir, row.payload, http=http)
            values_.update(status="sent", last_error=None)
            _count(data_dir, row.payload, outcome)
        except jira.JiraError as exc:
            error = text(exc.message, "en")
            if exc.status == 404 and row.payload.get("type") == "comment":
                tickets.forget_issues(data_dir, {str(row.payload.get("key"))})  # deleted in Jira: nothing to tell it again
            if exc.retryable and attempts < len(RETRY_MINUTES):
                wait = max(RETRY_MINUTES[attempts - 1] * 60, exc.retry_after or 0)
                values_.update(last_error=error, next_attempt_at=func.now() + timedelta(seconds=wait))
            else:
                values_.update(status="failed", last_error=error)
                _count(data_dir, row.payload, "failed", exc.message)
            _log.warning("jira_delivery_failed", extra={"reason": f"{row.payload.get('type')}: {error} (attempt {attempts})"})
        except Exception:  # noqa: BLE001 — one bad row never stops the queue
            _log.exception("jira_delivery_crashed")
            if attempts < len(RETRY_MINUTES):
                values_.update(last_error="Unexpected error", next_attempt_at=func.now() + timedelta(minutes=RETRY_MINUTES[attempts - 1]))
            else:
                values_.update(status="failed", last_error="Unexpected error")
                _count(data_dir, row.payload, "failed", msg("integrations.jira.unexpected"))
        with db.transaction(data_dir) as connection:
            connection.execute(update(outbox).where(outbox.c.tenant_id == db.TENANT, outbox.c.id == row.id).values(**values_))
    return len(rows)
