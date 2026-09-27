"""Persistencia local de ejecuciones, sin aceptar nombres de archivo del usuario."""

from __future__ import annotations
from tamandua.modules.findings.triage import LABELS as TRIAGE_LABELS, SUPPRESSED

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import delete, func, select
from sqlalchemy.dialects.postgresql import insert

from tamandua.modules.runs.tables import runs
from tamandua.shared import db
from tamandua.shared.db import TENANT
from tamandua.shared.i18n import default_locale, localize, msg, t, text


class ReportInputError(ValueError):
    """A report that can't be produced as asked; `message` is a catalog message."""

    def __init__(self, message: dict):
        super().__init__(message)
        self.message = message

    def __str__(self) -> str:
        return text(self.message)


def _check_id(run_id: str) -> str:
    if not isinstance(run_id, str) or len(run_id) != 32 or any(ch not in "0123456789abcdef" for ch in run_id):
        raise ValueError("Invalid run ID")
    return run_id


def _moment(value) -> datetime:
    try:
        moment = datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return datetime.now(timezone.utc)
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def _values(record: dict) -> dict:
    from tamandua.modules.sources.assets import asset_key
    return {"type": record["type"], "status": record.get("status") or "completed", "created_at": _moment(record.get("created_at")),
            "asset_key": asset_key(record) if record.get("source") else None, "row": _row(record), "record": record}


def _persist(data_dir: Path, record: dict, report: str, sarif: dict | None = None, *, replace: bool = False) -> dict:
    values = {**_values(record), "report": report, "sarif": sarif}
    statement = insert(runs).values(tenant_id=TENANT, id=_check_id(record["id"]), **values)
    with db.transaction(data_dir) as connection:
        if replace:
            connection.execute(statement.on_conflict_do_update(index_elements=[runs.c.tenant_id, runs.c.id], set_={**values, "updated_at": func.now()}))
        elif connection.execute(statement.on_conflict_do_nothing().returning(runs.c.id)).first() is None:
            raise FileExistsError(f"Run {record['id']} already exists")
    return record


def save_record(data_dir: Path, record: dict) -> None:
    """Guarda el registro de una ejecución (progreso, estado, resultado) sin tocar su informe ni su SARIF."""
    values = _values(record)
    statement = insert(runs).values(tenant_id=TENANT, id=_check_id(record["id"]), **values)
    with db.transaction(data_dir) as connection:
        connection.execute(statement.on_conflict_do_update(index_elements=[runs.c.tenant_id, runs.c.id], set_={**values, "updated_at": func.now()}))


def _row(record: dict) -> dict:
    item = {key: record.get(key) for key in ("id", "type", "status", "created_at", "target", "summary")}
    for key in ("variant", "source", "context", "started_at", "finished_at", "pull_request", "trigger"):
        if key in record and record[key] is not None:
            item[key] = record[key]
    # La lista no lleva hallazgos: solo lo necesario para una fila.
    if isinstance(item.get("summary"), dict):
        item["summary"] = {key: value for key, value in item["summary"].items() if key != "tools"} | {"tools": item["summary"].get("tools", [])}
    return item


def page_runs(data_dir: Path, *, limit: int = 25, offset: int = 0, status: str | None = None,
              kind: str | None = None, query: str | None = None, asset: str | None = None) -> dict:
    """Filtra, cuenta y pagina en la base (antes se cargaban todas las filas en memoria)."""
    conditions = [runs.c.tenant_id == TENANT]
    if asset:
        conditions.append(runs.c.asset_key == asset)
    if status:
        conditions.append(runs.c.status == status)
    if kind:
        conditions.append(runs.c.type.in_(kind.split(",")))
    if query:
        needle = f"%{query.strip().lower().replace(chr(92), chr(92) * 2).replace('%', chr(92) + '%').replace('_', chr(92) + '_')}%"
        haystack = func.lower(func.concat_ws(" ", runs.c.row["source"]["name"].astext, runs.c.row["target"].astext, runs.c.id, runs.c.row["variant"].astext))
        conditions.append(haystack.like(needle, escape="\\"))
    limit = max(1, min(limit, 200))
    offset = max(0, offset)
    with db.transaction(data_dir) as connection:
        total = connection.execute(select(func.count()).select_from(runs).where(*conditions)).scalar_one()
        rows = connection.execute(select(runs.c.row).where(*conditions).order_by(runs.c.created_at.desc(), runs.c.id.desc())
                                  .limit(limit).offset(offset)).scalars().all()
    return {"items": list(rows), "total": total, "limit": limit, "offset": offset}


def artifact(data_dir: Path, run_id: str, name: str) -> bytes:
    """Informe Markdown o SARIF guardados con la ejecución."""
    column = {"report.md": runs.c.report, "findings.sarif": runs.c.sarif}[name]
    with db.transaction(data_dir) as connection:
        value = connection.execute(select(column).where(runs.c.tenant_id == TENANT, runs.c.id == _check_id(run_id))).scalar_one_or_none()
    if value is None:
        raise FileNotFoundError(name)
    return value.encode("utf-8") if isinstance(value, str) else (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def delete_runs(data_dir: Path, run_ids: list[str]) -> int:
    if not run_ids:
        return 0
    with db.transaction(data_dir) as connection:
        return connection.execute(delete(runs).where(runs.c.tenant_id == TENANT, runs.c.id.in_([_check_id(item) for item in run_ids]))).rowcount


def save_repository_scan(data_dir: Path, scan: dict, *, run_id: str | None = None, created_at: str | None = None) -> dict:
    # Un escaneo en segundo plano ya tiene su identificador y su carpeta desde que se encoló.
    record = {"schema_version": "0.3.0", "id": run_id or uuid.uuid4().hex,
              "created_at": created_at or datetime.now(timezone.utc).isoformat(), **scan}
    # Rutas excluidas por un administrador: salen del informe, del SARIF y del panel, contadas en los límites.
    from tamandua.modules.sources.assets import asset_key
    from tamandua.modules.findings.exclusions import apply_to_record
    from tamandua.modules.findings.kinds import FINDING_RUNS
    if record.get("type") in FINDING_RUNS:
        record = apply_to_record(data_dir, record, asset_key(record))
    from tamandua.modules.findings.registry import apply
    report, sarif = render_repository_report(record), render_repository_sarif(record)
    # The run, the findings registry and the outbox entries land together or not at all.
    with db.transaction(data_dir):
        saved = _persist(data_dir, record, report, sarif, replace=run_id is not None)
        # Toda ejecución terminada, venga de donde venga (trabajador o CLI), actualiza el registro de hallazgos.
        changes = apply(data_dir, saved)
        # Lo nuevo que importa, a los canales configurados (Slack, Teams, webhook), vía el buzón de salida.
        if changes.get("new"):
            from tamandua.modules.integrations import notifications
            from tamandua.modules.findings import triage
            opened = set(changes["new"])
            active = [item for item in triage.annotate(data_dir, saved).get("findings", []) if item["fingerprint"] in opened and triage.is_active(item)]
            notifications.on_run(saved, active, data_dir=data_dir)
    return saved


ACTION_ORDER = {"act": 0, "attend": 1, "track": 2}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
PROFILES = ("soc2", "iso27001", "custom")


def _severity(level, locale: str) -> str:
    return t(f"reports.common.severity.{level}", locale) if level in SEVERITY_ORDER else str(level or "—")


def _action_label(action, locale: str) -> str:
    return t(f"reports.common.action.{action}", locale) if action in ACTION_ORDER else str(action)


def _header(locale: str, *columns: str) -> list[str]:
    """Markdown table header; an empty name leaves a blank spacer column."""
    names = [t(f"reports.columns.{name}", locale) if name else "" for name in columns]
    return ["| " + " | ".join(names) + " |", "|" + "---|" * len(names)]


def _ordered_findings(record: dict) -> list[dict]:
    return sorted(record.get("findings", []), key=lambda item: (
        ACTION_ORDER.get((item.get("priority") or {}).get("action"), 3),
        SEVERITY_ORDER.get(item.get("severity"), 5), str(item.get("title", ""))))


def _finding_block(finding: dict, locale: str) -> list[str]:
    """One finding in Markdown. `finding` is already localized."""
    package = finding.get("package") or {}
    advisory = finding.get("advisory") or {}
    action = (finding.get("priority") or {}).get("action", "track")
    lines = [f"### {finding['title']}", "",
             f"**{finding['severity'].upper()}** · {_action_label(action, locale)} · `{finding['scanner']}` · `{finding['rule_id']}`"]
    identifiers = [*finding.get("cve", []), *[item for item in finding.get("ghsa", []) if item != finding["rule_id"]]]
    if identifiers:
        lines.append(t("reports.markdown.identifiers", locale, list=", ".join(f"`{item}`" for item in identifiers)))
    if package.get("name"):
        fixed = package.get("fixed_version")
        lines.append(t("reports.markdown.package", locale, name=package["name"], version=package.get("version"), ecosystem=package.get("ecosystem"),
                       path=finding["path"], fix=msg("reports.markdown.fixed_in", version=fixed) if fixed else msg("reports.markdown.no_fixed_version")))
    else:
        lines.append(t("reports.markdown.location", locale, where=f"{finding['path']}:{finding['line']}"))
    source = finding.get("source") or {}
    if source.get("name"):
        name = source["name"].replace("[", "(").replace("]", ")")
        label = f"[{name}]({source['url']})" if str(source.get("url") or "").startswith("https://") else name
        lines.append(t("reports.markdown.advisory_source", locale, source=label,
                       license=source.get("license") or msg("reports.markdown.license_unreviewed")))
    if advisory.get("cvss_score") is not None:
        lines.append(f"CVSS {advisory['cvss_score']} · `{advisory.get('cvss_vector')}`")
    if finding.get("kev"):
        kev = finding["kev"]
        lines.append(t("reports.markdown.kev_ransomware" if kev.get("ransomware") else "reports.markdown.kev", locale, date=kev.get("date_added")))
    if finding.get("epss"):
        lines.append(t("reports.markdown.epss", locale, score=f"{finding['epss']['score']:.1%}", percentile=f"{finding['epss']['percentile']:.0%}"))
    if finding.get("cwe"):
        lines.append("CWE: " + ", ".join(f"CWE-{item}" for item in finding["cwe"]))
    triage = finding.get("triage") or {}
    if triage.get("status", "open") != "open" or triage.get("expired"):
        status = text(TRIAGE_LABELS.get(triage["status"], triage["status"]), locale)
        parts = [t("reports.markdown.triage_by", locale, status=status, by=triage["by"], date=(triage.get("at") or "")[:10])
                 if triage.get("by") else t("reports.markdown.triage", locale, status=status)]
        if triage.get("expires_at"):
            parts.append(t("reports.markdown.triage_expires", locale, date=triage["expires_at"]))
        if triage.get("expired"):
            parts.append(t("reports.markdown.triage_expired", locale))
        if triage.get("reason"):
            parts.append(t("reports.markdown.triage_reason", locale, reason=triage["reason"]))
        lines.append(" · ".join(parts))
    lines += ["", t("reports.markdown.why_priority", locale, factors="; ".join((finding.get("priority") or {}).get("factors", []))),
              "", t("reports.markdown.remediation", locale, text=finding["remediation"])]
    from tamandua.modules.findings.fix_guide import guide
    fix = localize(finding.get("fix") or guide(finding), locale)
    if fix and (fix["commands"] or fix["example"] or len(fix["steps"]) > 1):
        # Same order as the panel: steps, the edit (example) and the command last.
        lines += ["", t("reports.markdown.how_to_fix", locale), "",
                  *[f"{index}. {step}" for index, step in enumerate([item for item in fix["steps"] if item], 1)]]
        example = fix["example"]
        if example and example.get("before"):
            lines += ["", t("reports.markdown.before", locale), "", f"```{example['language']}", example["before"], "```", "",
                      t("reports.markdown.after", locale)]
        if example:
            lines += ["", f"```{example['language']}", example["after"], "```"] + ([example["note"]] if example.get("note") else [])
        for command in fix["commands"]:
            lines += ["", f"{command['label']}:", "", "```", command["code"], "```"]
    if advisory.get("details"):
        lines += ["", advisory["details"][:800].replace("\n\n", "\n")]
    if advisory.get("references"):
        lines += ["", t("reports.common.references", locale, list=" · ".join(advisory["references"][:4]))]
    return lines + [""]


def render_repository_report(record: dict, *, locale: str | None = None) -> str:
    locale = locale or default_locale()
    record = localize(record, locale)
    source = record["source"]
    summary = record["summary"]
    severities = summary.get("severities") or {}
    priorities = summary.get("priorities") or {}
    findings = _ordered_findings(record)
    image = source.get("image") or {}
    if image:
        identity = (t("reports.markdown.identity_image_digest", locale, reference=image.get("reference"), digest=image["resolved_digest"])
                    if image.get("resolved_digest") else t("reports.markdown.identity_image", locale, reference=image.get("reference")))
    else:
        identity = t("reports.markdown.identity_snapshot", locale, sha=source.get("sha256"))
    lines = ["# " + t("reports.markdown.title_image" if image else "reports.markdown.title_code", locale, name=source["name"]), "",
             t("reports.markdown.run_line", locale, id=record["id"], date=record["created_at"], provider=source["provider"], identity=identity),
             t("reports.markdown.status_line", locale, status=record["status"], files=summary["files"], dependencies=summary["dependencies"]), "",
             "## " + t("reports.markdown.executive_summary", locale), "",
             *_header(locale, "priority", "count", "", "severity", "count")]
    rows = [(_action_label("act", locale), priorities.get("act", 0), _severity("critical", locale), severities.get("critical", 0)),
            (_action_label("attend", locale), priorities.get("attend", 0), _severity("high", locale), severities.get("high", 0)),
            (_action_label("track", locale), priorities.get("track", 0), _severity("medium", locale), severities.get("medium", 0)),
            ("", "", _severity("low", locale), severities.get("low", 0))]
    lines += [f"| {a} | {b} | | {c} | {d} |" for a, b, c, d in rows]
    lines += ["", "- " + t("reports.markdown.kev_total", locale, count=summary.get("kev", 0)),
              "- " + t("reports.markdown.fixable_total", locale, count=summary.get("fixable", 0)),
              "- " + t("reports.markdown.findings_total", locale, count=len(findings)), ""]
    if record.get("context"):
        lines += ["## " + t("reports.markdown.declared_context", locale), "", record["context"], "",
                  t("reports.markdown.context_note", locale), ""]
    active = [item for item in findings if (item.get("triage") or {}).get("status", "open") not in SUPPRESSED]
    suppressed = [item for item in findings if item not in active]
    lines += _findings_sections([dict(item) for item in active], locale)
    if suppressed:
        # Each decision with who made it and why: the first thing a reviewer asks.
        lines += ["## " + t("reports.markdown.dismissed", locale), "",
                  t("reports.markdown.dismissed_intro", locale, count=len(suppressed)), "",
                  *_header(locale, "finding", "decision", "reason", "by", "expires")]
        for finding in suppressed:
            triage = finding.get("triage") or {}
            lines.append(f"| {_md(finding['title'], 100)} | {_md(triage.get('status'), 20)} | {_md(triage.get('reason') or '—', 200)} | "
                         f"{_md(triage.get('by') or '—', 40)} | {_md(str(triage.get('expires_at') or '—')[:10], 12)} |")
        lines.append("")
    lines += ["## " + t("reports.markdown.coverage", locale), ""]
    for index, step in enumerate(record["steps"], 1):
        lines += [f"{index}. **{step['name']}** · `{step['status']}`. {step['detail']}"]
    lines += ["", "### OWASP Web Top 10:2025", ""]
    for item in record["owasp_coverage"]:
        lines.append(f"- {item['id']} · {item['title']}: `{item['status']}` · {item['reason']}")
    lines += ["", "### " + t("reports.common.limitations", locale), "", *[f"- {item}" for item in record["limitations"]], ""]
    return "\n".join(lines + _sources_section(record.get("findings") or [], locale))


def _md(value, limit: int = 160) -> str:
    """Markdown table cell: one line, bounded, without breaking the table."""
    cell = " ".join(str(value if value is not None else "").split()).replace("|", "\\|")
    return cell if len(cell) <= limit else cell[:limit].rsplit(" ", 1)[0] + "…"


MD_DETAIL_LIMIT, MD_TABLE_LIMIT, MD_ANNEX_LIMIT = 150, 500, 600


def _is_update(command: dict) -> bool:
    return command.get("action") == "update"


def _findings_sections(active: list[dict], locale: str) -> list[str]:
    """Findings as in the technical PDF: what to do first, dependencies grouped by package with their command, code
    with detail only for critical and high, and a compact index. Full detail stays in the panel, the JSON, the SARIF
    and the tickets."""
    from tamandua.modules.findings.fix_guide import attach
    from tamandua.modules.findings.remediation import action, counts_text, fix_groups
    lines = ["## " + t("reports.common.findings", locale), ""]
    if not active:
        return lines + [t("reports.markdown.no_findings", locale), ""]
    attach(active)
    updates = {id(item): [command["code"] for command in (item.get("fix") or {}).get("commands") or [] if _is_update(command)] for item in active}
    for item in active:
        item["fix"] = localize(item.get("fix"), locale)
    groups = fix_groups(active)
    lines += [t("reports.markdown.pending_intro", locale, pending=msg("reports.count.pending_findings", count=len(active)),
                actions=msg("reports.count.actions", count=len(groups))), "",
              "### " + t("reports.common.what_first", locale), "", *_header(locale, "severity", "what", "where", "action")]
    for entry in groups[:15]:
        item = entry["items"][0]
        what = (f"{entry['name']} {entry['version']} · {t('reports.count.advisories', locale, count=len(entry['items']))}"
                if entry["kind"] == "package" else item.get("title"))
        where = entry["path"] if entry["kind"] == "package" else f"{item.get('path')}:{item.get('line')}"
        lines.append(f"| {_severity(entry['severity'], locale)}{' · KEV' if entry['kev'] else ''} | {_md(what, 100)} | "
                     f"`{_md(where, 90)}` | {_md(action(entry, short=True, locale=locale), 160)} |")
    packages = [entry for entry in groups if entry["kind"] == "package"]
    if packages:
        lines += ["", "### " + t("reports.markdown.dependencies", locale, packages=msg("reports.count.packages", count=len(packages)),
                                 advisories=msg("reports.count.advisories", count=sum(len(entry["items"]) for entry in packages))), "",
                  *_header(locale, "severity", "package", "manifest", "advisories", "update_to", "command")]
        for entry in packages:
            commands = updates.get(id(entry["items"][0])) or []
            lines.append(f"| {_severity(entry['severity'], locale)}{' · KEV' if entry['kev'] else ''} | "
                         f"{_md(entry['name'], 60)} {_md(entry['version'], 30)} | `{_md(entry['path'], 80)}` | {_md(counts_text(entry['counts'], locale=locale), 80)} | "
                         f"{_md(entry['target'] or t('reports.markdown.no_fix', locale), 40)} | "
                         f"{('`' + _md(commands[0], 120) + '`') if commands and '`' not in commands[0] else '—'} |")
    code = [item for item in active if not (item.get("scanner") == "sca" and (item.get("package") or {}).get("name"))]
    if code:
        serious = [item for item in code if item.get("severity") in ("critical", "high")]
        rest = [item for item in code if item.get("severity") not in ("critical", "high")]
        lines += ["", "### " + t("reports.common.code_heading", locale, count=len(code)), ""]
        for finding in serious[:MD_DETAIL_LIMIT]:
            lines += _finding_block(finding, locale)
        if len(serious) > MD_DETAIL_LIMIT:
            lines += [t("reports.markdown.detail_truncated", locale, shown=MD_DETAIL_LIMIT, total=len(serious)), ""]
        if rest:
            lines += ["#### " + t("reports.common.medium_low", locale, count=len(rest)), "",
                      *_header(locale, "severity", "finding", "location", "fix")]
            for item in rest[:MD_TABLE_LIMIT]:
                where = f"{item.get('path')}:{item.get('line')}"
                lines.append(f"| {_severity(item.get('severity'), locale)} | {_md(item.get('title'), 100)} | "
                             f"`{_md(where, 90)}` | {_md(item.get('remediation'), 160)} |")
            if len(rest) > MD_TABLE_LIMIT:
                lines.append(f"| | {t('reports.markdown.more_in_panel', locale, count=len(rest) - MD_TABLE_LIMIT)} | | |")
            lines.append("")
    advisories = [item for item in active if item.get("scanner") == "sca"]
    if advisories:
        lines += ["", "### " + t("reports.common.annex", locale, count=len(advisories)), "",
                  *_header(locale, "identifier", "package", "severity", "cvss", "epss", "kev", "fixed_in", "source")]
        for item in sorted(advisories, key=lambda entry: (SEVERITY_ORDER.get(entry.get("severity"), 9),
                                                           str((entry.get("package") or {}).get("name"))))[:MD_ANNEX_LIMIT]:
            package, advisory = item.get("package") or {}, item.get("advisory") or {}
            epss = (item.get("epss") or {}).get("score")
            identifier = ((item.get("cve") or [])[:1] or (item.get("ghsa") or [])[:1] or [item.get("rule_id")])[0]
            lines.append(f"| {_md(identifier, 40)} | {_md(package.get('name'), 60)} {_md(package.get('version'), 30)} | "
                         f"{_severity(item.get('severity'), locale) if item.get('severity') in SEVERITY_ORDER else '—'} | "
                         f"{advisory['cvss_score'] if isinstance(advisory.get('cvss_score'), (int, float)) else '—'} | "
                         f"{f'{epss * 100:.1f} %' if isinstance(epss, (int, float)) else '—'} | {t('reports.common.yes', locale) if item.get('kev') else '—'} | "
                         f"{_md(package.get('fixed_version') or '—', 40)} | {_md((item.get('source') or {}).get('short') or '—', 20)} |")
        if len(advisories) > MD_ANNEX_LIMIT:
            lines.append(f"| {t('reports.markdown.annex_more', locale, count=len(advisories) - MD_ANNEX_LIMIT)} | | | | | | | |")
    return lines + [""]


def _sources_section(findings: list[dict], locale: str | None = None) -> list[str]:
    """Attribution of the advisory databases used (licenses in THIRD_PARTY_NOTICES.md)."""
    from tamandua.modules.intel.data_sources import attribution
    locale = locale or default_locale()
    lines = attribution(findings, locale=locale)
    return ["## " + t("reports.common.sources", locale), "", *[f"- {line}" for line in lines], ""] if lines else []


def render_asset_report(record: dict, *, locale: str | None = None) -> str:
    """Exports the cumulative registry without presenting it as a point-in-time scan."""
    locale = locale or default_locale()
    record = localize(record, locale)
    findings = _ordered_findings(record)
    lifecycle = record.get("summary", {}).get("lifecycle") or {}
    lines = ["# " + t("reports.asset.title", locale, name=record["source"]["name"]), "",
             t("reports.asset.asset_line", locale, id=record["source"]["id"], date=record.get("created_at") or msg("reports.common.no_date")),
             "", "## " + t("reports.common.scope", locale), "",
             t("reports.asset.scope_text", locale), "",
             "## " + t("reports.common.summary", locale), "",
             "- " + t("reports.asset.included", locale, count=len(findings)),
             "- " + t("reports.asset.lifecycle_counts", locale, open=lifecycle.get("open", 0), fixed=lifecycle.get("fixed", 0),
                      suppressed=lifecycle.get("suppressed", 0), excluded=lifecycle.get("excluded", 0)), "",
             "## " + t("reports.common.findings", locale), ""]
    if not findings:
        lines += [t("reports.asset.empty", locale), ""]
    for finding in findings:
        lines += _finding_block(finding, locale)
        state = finding.get("lifecycle") or {}
        lines += [t("reports.asset.lifecycle_line", locale, status=state.get("status") or msg("reports.common.unknown"),
                    first=state.get("first_seen") or "—", last=state.get("last_seen") or "—"), ""]
    lines += ["## " + t("reports.common.limitations", locale), "", "- " + t("reports.asset.limit_tools", locale),
              "- " + t("reports.asset.limit_runs", locale), ""]
    return "\n".join(lines + _sources_section(findings, locale))


def render_tickets(record: dict, *, locale: str | None = None) -> list[dict]:
    """One ticket per finding, with a stable fingerprint: the shape the Jira connector needs."""
    locale = locale or default_locale()
    record = localize(record, locale)
    jira_priority = {"act": "Highest", "attend": "High", "track": "Medium"}
    tickets = []
    for finding in _ordered_findings(record):
        # Dismissed or already fixed findings create no work.
        if (finding.get("triage") or {}).get("status", "open") in SUPPRESSED or (finding.get("lifecycle") or {}).get("status") in ("fixed", "excluded"):
            continue
        package = finding.get("package") or {}
        action = (finding.get("priority") or {}).get("action", "track")
        labels = ["appsec", finding["scanner"], finding["severity"]]
        if finding.get("kev"):
            labels.append("cisa-kev")
        if package.get("fixed_version"):
            labels.append("fix-available")
        tickets.append({
            "fingerprint": finding["fingerprint"], "finding_id": finding["finding_id"],
            "summary": f"[{finding['severity'].upper()}] {finding['title']}"[:255],
            "priority": jira_priority.get(action, "Medium"), "action": action, "severity": finding["severity"],
            "labels": labels, "component": package.get("name") or finding["path"],
            "identifiers": [*finding.get("cve", []), *finding.get("ghsa", [])],
            "package": package or None, "remediation": finding["remediation"],
            "description": "\n".join(_finding_block(finding, locale)),
            "references": (finding.get("advisory") or {}).get("references", []),
            "run_id": record["id"], "source": record["source"]["name"], "detected_at": record["created_at"],
        })
    return tickets


def _sarif_suppression(finding: dict, locale: str) -> dict:
    """SARIF 2.1.0 §3.35: triage dismissals travel as accepted external suppressions."""
    triage = finding.get("triage") or {}
    if triage.get("status") not in SUPPRESSED:
        return {}
    justification = f"{text(TRIAGE_LABELS[triage['status']], locale)}: {triage.get('reason') or ''}".strip()
    return {"suppressions": [{"kind": "external", "status": "accepted", "justification": justification[:500]}]}


# SARIF 2.1.0: result level and `security-severity` (0-10), which GitHub code scanning uses to sort and filter.
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0"}


def render_repository_sarif(record: dict, *, locale: str | None = None) -> dict:
    from tamandua.version import VERSION
    locale = locale or default_locale()
    findings = localize(record["findings"], locale)
    rules = {item["rule_id"]: {"id": item["rule_id"], "shortDescription": {"text": item["title"]},
                               "properties": {"security-severity": SECURITY_SEVERITY.get(item["severity"], "5.5"),
                                              "tags": ["security", item["scanner"]]}}
             for item in findings}
    results = [{"ruleId": item["rule_id"], "level": SARIF_LEVEL.get(item["severity"], "warning"), "message": {"text": item["reason"] or item["title"]},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": item["path"]},
                                                    "region": {"startLine": item["line"]}}}],
                "partialFingerprints": {"tamandua/v1": item["fingerprint"]},
                **_sarif_suppression(item, locale),
                "properties": {"verdict": "candidate", "scanner": item["scanner"], "cwe": item["cwe"],
                               "owasp": item["owasp"]}} for item in findings]
    return {"$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
            "version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Tamandua", "version": VERSION,
                                                     "informationUri": "https://github.com/BrayansStivens/appsec-agent",
                                                     "rules": list(rules.values())}}, "results": results}]}


def profile_pdf_titles(profile: str, *, locale: str | None = None) -> dict:
    """Title and kind for the PDF cover of a profile report."""
    locale = locale or default_locale()
    if profile not in PROFILES:
        raise ReportInputError(msg("reports.errors.unsupported_profile"))
    return {"title": t("reports.profile.heading", locale, framework=msg(f"reports.profile.label.{profile}")),
            "kind": t("reports.profile.pdf_kind", locale)}


def render_profile_report(record: dict, profile: str, title: str = "", *, locale: str | None = None) -> str:
    """Technical dossier; it is not an audit opinion or a certification."""
    locale = locale or default_locale()
    if profile not in PROFILES or record.get("type") not in ("repository_scan", "image_scan", "pr_review", "asset_state"):
        raise ReportInputError(msg("reports.errors.unsupported_profile"))
    if title and (len(title) > 100 or not all(ch.isprintable() and ch not in "#`[]<>" for ch in title)):
        raise ReportInputError(msg("reports.errors.invalid_title"))
    label = t(f"reports.profile.label.{profile}", locale)
    heading = title.strip() if title else t("reports.profile.heading", locale, framework=label)
    is_state = record["type"] == "asset_state"
    technical_report = render_asset_report(record, locale=locale) if is_state else render_repository_report(record, locale=locale)
    source = localize(record["source"], locale)
    if is_state:
        scope = t("reports.profile.scope_state", locale, name=source["name"])
    elif source.get("image"):
        scope = t("reports.profile.scope_image", locale, name=source["name"], reference=source["image"].get("reference"))
    else:
        scope = t("reports.profile.scope_snapshot", locale, name=source["name"], sha=source.get("sha256"))
    rows = [(t(f"reports.profile.rows.{profile}.{row}.aspect", locale), t(f"reports.profile.rows.{profile}.{row}.available", locale),
             t(f"reports.profile.rows.{profile}.{row}.missing", locale)) for row in PROFILE_ROWS[profile]]
    lines = [f"# {heading}", "",
             t("reports.profile.profile_line", locale, profile=label, kind=msg("reports.profile.kind_state" if is_state else "reports.profile.kind_run"),
               id=record["id"], date=record["created_at"]), "",
             "> " + t("reports.profile.disclaimer", locale), "",
             "## " + t("reports.profile.review_context", locale), "",
             "- " + t("reports.profile.owner", locale),
             "- " + t("reports.profile.system_scope", locale, scope=scope),
             "- " + t("reports.profile.evidence_state" if is_state else "reports.profile.evidence_run", locale),
             "- " + t("reports.profile.frequency_state" if is_state else "reports.profile.frequency_run", locale),
             "- " + t("reports.profile.applicability", locale), "",
             "## " + t("reports.profile.matrix", locale), "",
             *_header(locale, "aspect", "evidence_here", "still_needed"),
             *[f"| {aspect} | {available} | {missing} |" for aspect, available, missing in rows], "",
             t("reports.profile.matrix_note", locale), "",
             "## " + t("reports.profile.attached", locale), "", technical_report]
    return "\n".join(lines)


PROFILE_ROWS = {"soc2": ("design", "operation", "exceptions"), "iso27001": ("scope", "risk", "improvement"), "custom": ("scope", "result")}


def load_run(data_dir: Path, run_id: str) -> dict:
    with db.transaction(data_dir) as connection:
        record = connection.execute(select(runs.c.record).where(runs.c.tenant_id == TENANT, runs.c.id == _check_id(run_id))).scalar_one_or_none()
    if record is None:
        raise FileNotFoundError(f"Run {run_id} not found")
    return record


def list_runs(data_dir: Path) -> list[dict]:
    """Las filas de listado, de la más reciente a la más antigua."""
    with db.transaction(data_dir) as connection:
        return list(connection.execute(select(runs.c.row).where(runs.c.tenant_id == TENANT)
                                       .order_by(runs.c.created_at.desc(), runs.c.id.desc())).scalars())
