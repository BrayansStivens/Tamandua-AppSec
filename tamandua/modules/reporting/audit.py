"""Vulnerability management evidence report (SOC 2, ISO/IEC 27001 or general).

What a team hands over when an auditor or a customer asks for evidence: who, which system and which
period; how it was scanned and what was left out; what was found, what state it is in and which
exceptions were approved, with their reason and owner. Concise: the full technical detail stays in
the technical report, the SARIF and the JSON.

It is not an audit opinion or a certification, and it says so. All text coming from the
repository or the form is treated as data: it is escaped before being drawn.
"""

from __future__ import annotations

import html
from datetime import date, datetime, timezone

from reportlab.lib.units import mm
from reportlab.platypus import CondPageBreak, KeepTogether, Paragraph, Spacer, Table

from tamandua.modules.intel.data_sources import attribution
from tamandua.modules.findings.remediation import action, counts_text, fix_groups
from tamandua.modules.reporting.design import (BRAND, BRAND_BG, DANGER_BG, INK, ORDER, SEVERITY, SOFT, STYLE, SUCCESS, SUCCESS_BG, WIDTH,
                            build, bullets, chip as _chip, count as _count, coverage_gaps, day as _day, disclaimer, grid as _grid, h2, header,
                            hexval, kpis as _kpis, listing, meta, signoff, t as _t)
from tamandua.shared import i18n
from tamandua.shared.i18n import default_locale, localize, msg, text

STATUSES = ("open", "in_progress", "fixed", "false_positive", "accepted", "excluded")
# Control ids per framework; their code, name and text live in `reports.frameworks.<framework>.controls.<id>`.
FRAMEWORKS = {
    "soc2": ("cc3_2", "cc7_1", "cc8_1"),
    "iso27001": ("a8_8", "a8_9", "a8_28", "a8_29"),
    "pci": ("r6_2_4", "r6_3_1", "r6_3_2", "r6_3_3"),
    "cra": ("annex_i_ii_1", "annex_i_ii_2", "annex_i_ii_3", "art_14"),
    "br-cmn": ("vulnerabilities", "testing", "traceability"),
    "cl-21663": ("risk", "improvement", "evidence"),
    "co-sfc": ("vulnerabilities", "secure_development", "evidence"),
    "general": (),
}
# Controls whose evidence relies on remediation deadlines.
DEADLINE_CONTROLS = {("pci", "r6_3_3"), ("cra", "annex_i_ii_2"), ("br-cmn", "vulnerabilities"), ("cl-21663", "improvement"),
                     ("co-sfc", "vulnerabilities")}
DETAIL = ("none", "high", "all")
DETAIL_LIMIT = 40  # detail blocks: the findings table is already the complete evidence
TEXT_LIMITS = {"title": 120, "organization": 120, "prepared_by": 80, "prepared_for": 120, "scope": 300}


class ReportError(ValueError):
    """`message` is a catalog message; the API renders it for the reader."""

    def __init__(self, message: dict):
        super().__init__(message)
        self.message = message

    def __str__(self) -> str:
        return text(self.message)


def status_label(status: str, locale: str | None = None) -> str:
    return i18n.t(f"reports.audit.status.{status}", locale) if status in STATUSES else str(status)


def _framework(key: str, locale: str) -> tuple[str, list[tuple[str, str, str, bool]]]:
    """Label and controls (code, name, text, relies on deadlines) of a framework."""
    base = f"reports.frameworks.{key.replace('-', '_')}"
    controls = [(i18n.t(f"{base}.controls.{control}.code", locale), i18n.t(f"{base}.controls.{control}.name", locale),
                 i18n.t(f"{base}.controls.{control}.text", locale), (key, control) in DEADLINE_CONTROLS) for control in FRAMEWORKS[key]]
    return i18n.t(f"{base}.label", locale), controls


def validate_options(raw: dict | None, *, default_by: str) -> dict:
    """Form options, with defaults: the report can be produced without touching anything."""
    raw = raw if isinstance(raw, dict) else {}
    unknown = set(raw) - {"framework", "detail", "include_exceptions", "period_from", "period_to", *TEXT_LIMITS}
    if unknown:
        raise ReportError(msg("reports.errors.invalid_options"))
    framework = raw.get("framework", "general")
    detail = raw.get("detail", "high")
    if framework not in FRAMEWORKS or detail not in DETAIL or not isinstance(raw.get("include_exceptions", True), bool):
        raise ReportError(msg("reports.errors.invalid_options"))
    options = {"framework": framework, "detail": detail, "include_exceptions": raw.get("include_exceptions", True)}
    for key, limit in TEXT_LIMITS.items():
        value = raw.get(key, "")
        if not isinstance(value, str) or len(value) > limit or any(not char.isprintable() for char in value):
            raise ReportError(msg("reports.errors.invalid_field", field=key, limit=limit))
        options[key] = " ".join(value.split())
    options["prepared_by"] = options["prepared_by"] or default_by
    for key in ("period_from", "period_to"):
        value = raw.get(key) or ""
        if value:
            try:
                date.fromisoformat(value)
            except (TypeError, ValueError) as exc:
                raise ReportError(msg("reports.errors.invalid_period_date")) from exc
        options[key] = value
    if options["period_from"] and options["period_to"] and options["period_from"] > options["period_to"]:
        raise ReportError(msg("reports.errors.period_reversed"))
    return options


def status_of(finding: dict) -> str:
    lifecycle = finding.get("lifecycle") or {}
    if lifecycle.get("status") == "excluded":
        return "excluded"
    if lifecycle.get("status") == "fixed":
        return "fixed"
    return (finding.get("triage") or {}).get("status") or "open"


def _risk(finding: dict) -> str:
    """Why it matters. For dependencies, the advisory description: the title already repeats its summary."""
    advisory = finding.get("advisory") or {}
    if finding.get("scanner") == "sca" and advisory.get("details"):
        return advisory["details"]
    return finding.get("reason") or advisory.get("summary") or ""


def _short_title(finding: dict) -> str:
    """«pillow 10.3.0: Pillow: DoS via …» → «DoS via …»: the package is already in the group heading."""
    title = str(finding.get("title") or "")
    parts = [part.strip() for part in title.split(": ")]
    return parts[-1] if finding.get("scanner") == "sca" and len(parts) > 1 else title


def _status_text(items: list[dict], locale: str) -> str:
    states = [status_of(item) for item in items]
    if len(set(states)) == 1:
        return status_label(states[0], locale)
    return ", ".join(i18n.t(f"reports.audit.status_count.{state}", locale, count=states.count(state)) if state in STATUSES else f"{states.count(state)} {state}"
                     for state in dict.fromkeys(states))


def _first_seen(items: list[dict], fallback) -> str:
    seen = sorted(_day((item.get("lifecycle") or {}).get("first_seen") or fallback) for item in items)
    return seen[0] if seen else "—"


def _group_cells(entry: dict, fallback_date, locale: str) -> tuple[str, str]:
    """Text of the finding (or of the package with all its advisories) and its location."""
    items = entry["items"]
    if entry["kind"] == "package" and len(items) > 1:
        summary = i18n.t("reports.audit.package_group", locale, vulnerabilities=msg("reports.count.vulnerabilities", count=len(items)),
                         counts=counts_text(entry["counts"], locale=locale))
        text_ = (f"<b>{_t(entry['name'], 60)} {_t(entry['version'], 30)}</b> · {_t(summary, 200)}"
                 f'<br/><font color="#636363">{_t(listing(entry["ids"], 4, locale=locale), 140)}</font>')
        return text_, _t(entry["path"], 90)
    item = items[0]
    ids = ", ".join((item.get("cve") or [])[:2] or (item.get("ghsa") or [])[:1])
    text_ = _t(item.get("title"), 140) + (f'<br/><font color="#636363">{_t(ids, 60)}</font>' if ids else "")
    where = item.get("path") if item.get("scanner") == "sca" else f"{item.get('path')}:{item.get('line')}"
    return text_, _t(where, 90)


SLA_LEVELS = ("critical", "high", "medium", "low")
SLA_LIMIT = 40


def _deadlines(groups: list[dict], summary: dict | None, locale: str) -> list:
    """Remediation deadlines: the policy and what is outside it. Only in the repository state (it has detection dates)."""
    if not summary or not summary.get("days"):
        return []
    days = summary["days"]
    policy = ", ".join(i18n.t("reports.audit.sla_policy_item", locale, level=msg(f"reports.audit.sla_level.{level}"),
                              days=msg("reports.count.days", count=days[level])) if days.get(level)
                       else i18n.t("reports.audit.sla_policy_none", locale, level=msg(f"reports.audit.sla_level.{level}")) for level in SLA_LEVELS)
    late = []
    for entry in groups:
        overdue = [item["sla"] for item in entry["items"] if (item.get("sla") or {}).get("state") == "overdue"]
        if overdue:
            late.append((min(item["days_left"] for item in overdue), min(item["due"] for item in overdue), entry))
    late.sort(key=lambda row: (row[0], ORDER.get(row[2]["severity"], 9)))
    # Same units as the panel (advisories) and, alongside, the table's actions: one package can gather several advisories.
    items = [item for entry in groups for item in entry["items"]]
    state = lambda wanted: sum(1 for item in items if (item.get("sla") or {}).get("state") == wanted)
    running = sum(1 for item in items if item.get("sla"))
    overdue = state("overdue")
    story = [h2(i18n.t("reports.audit.deadlines_heading", locale, advisories=msg("reports.count.advisories", count=overdue))),
             Paragraph(_t(i18n.t("reports.audit.deadlines_body", locale, policy=policy, running=msg("reports.count.advisories", count=running),
                                 overdue=msg("reports.count.advisories", count=overdue), actions=msg("reports.count.actions", count=len(late)),
                                 soon=msg("reports.count.advisories", count=state("soon"))), 800), STYLE["body"])]
    if not late:
        return story + [Paragraph(_t(i18n.t("reports.audit.none_overdue", locale)), STYLE["body"])]
    rows = [_head(locale, "severity", "finding", "detected", "was_due", "overdue_by")]
    for left, due, entry in late[:SLA_LIMIT]:
        text_, _ = _group_cells(entry, None, locale)
        rows.append([_chip(entry["severity"], locale=locale), Paragraph(text_, STYLE["cell"]), Paragraph(_first_seen(entry["items"], None), STYLE["cellmuted"]),
                     Paragraph(due, STYLE["cellmuted"]), Paragraph(_t(_count("days", -left, locale)), STYLE["cell"])])
    story.append(_grid(rows, [19 * mm, WIDTH - 83 * mm, 22 * mm, 22 * mm, 20 * mm], zebra=True))
    if len(late) > SLA_LIMIT:
        story.append(Paragraph(_t(i18n.t("reports.audit.deadlines_truncated", locale, limit=SLA_LIMIT, total=len(late)), 400), STYLE["note"]))
    return story


def _head(locale: str, *columns: str) -> list:
    return [Paragraph(html.escape(i18n.t(f"reports.columns.{name}", locale)), STYLE["head"]) for name in columns]


def _mark(key: str, locale: str) -> str:
    """The malicious-package or active-exploitation badge under a finding."""
    return f'<br/><font color="#b71824"><b>{_t(i18n.t(key, locale))}</b></font>'


def _marks(entry: dict, locale: str) -> str:
    return ((_mark("reports.common.malicious_mark", locale) if entry.get("malicious") else "")
            + (_mark("reports.common.kev_mark", locale) if entry["kev"] else ""))


def _controls(framework_label: str, controls: list, *, deadlines: bool, locale: str) -> list:
    # When a control relies on deadlines, say whether this report carries them: the evidence must match what is delivered.
    cites = any(relies for _, _, _, relies in controls)
    note = [] if not cites else [Paragraph(_t(i18n.t("reports.audit.deadlines_included" if deadlines else "reports.audit.deadlines_missing", locale), 600),
                                           STYLE["note"])]
    return [h2(i18n.t("reports.audit.controls_heading", locale, framework=framework_label)),
            _grid([_head(locale, "control", "contributes")]
                  + [[Paragraph(f"<b>{html.escape(code)}</b><br/>{html.escape(name)}", STYLE["cell"]), Paragraph(html.escape(text_), STYLE["cell"])]
                     for code, name, text_, _ in controls], [42 * mm, WIDTH - 42 * mm]),
            Paragraph(_t(i18n.t("reports.audit.controls_note", locale), 600), STYLE["note"]), *note]


def _detail_block(entry: dict, locale: str) -> list:
    items = entry["items"]
    item = items[0]
    if entry["kind"] == "package" and len(items) > 1:
        heading = f"<b>{_t(entry['name'], 60)} {_t(entry['version'], 30)} · {_t(_count('vulnerabilities', len(items), locale))}</b>"
        where = f"{entry['path']} · {_status_text(items, locale)} · {listing(entry['ids'], 5, locale=locale)}"
        risks = "; ".join(dict.fromkeys(_short_title(finding) for finding in sorted(items, key=lambda f: ORDER.get(f.get("severity"), 9))[:3]))
        risk = i18n.t("reports.audit.more_advisories", locale, risks=risks, count=len(items) - 3) if len(items) > 3 else risks
    else:
        heading = f"<b>{_t(item.get('title'), 160)}</b>"
        where = f"{item.get('path')}:{item.get('line')} · {status_label(status_of(item), locale)} · {', '.join((item.get('cve') or [])[:3]) or item.get('rule_id')}"
        risk = _risk(item)
    block = [Table([[_chip(entry["severity"], locale=locale), Paragraph(heading, STYLE["body"])]], colWidths=[18 * mm, WIDTH - 18 * mm],
                   style=[("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 0)]),
             Paragraph(_t(where, 240), STYLE["note"]),
             Paragraph(f"<b>{_t(i18n.t('reports.common.risk_label', locale))}</b> " + _t(risk, 450), STYLE["body"]),
             Paragraph(f"<b>{_t(i18n.t('reports.common.fix_label', locale))}</b> " + _t(action(entry, locale=locale), 450), STYLE["body"])]
    references = [url for url in ((item.get("advisory") or {}).get("references") or [])[:2] if str(url).startswith("https://")]
    if references and len(items) == 1:
        block.append(Paragraph(_t(i18n.t("reports.common.references", locale, list=" · ".join(references)), 200), STYLE["note"]))
    return [KeepTogether(block), Spacer(1, 6)]


def render_audit_pdf(record: dict, findings: list[dict], options: dict, *, version: str, locale: str | None = None) -> bytes:
    locale = locale or default_locale()
    record, findings = localize(record, locale), localize(findings, locale)
    framework_label, controls = _framework(options["framework"], locale)
    findings = sorted(findings, key=lambda item: (ORDER.get(item.get("severity"), 9), str(item.get("path")), item.get("line") or 0))
    if len(findings) > 5000:
        raise ReportError(msg("reports.errors.too_many_findings"))
    source = record.get("source") or {}
    system = options["scope"] or source.get("name") or "—"
    issued = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    analysed = _day(record.get("created_at"))
    period = (i18n.t("reports.audit.period_range", locale, start=options["period_from"] or "—", end=options["period_to"] or issued)
              if options["period_from"] or options["period_to"] else i18n.t("reports.audit.period_scan", locale, date=analysed))
    counts = {level: sum(1 for item in findings if item.get("severity") == level) for level in ORDER}
    statuses = [status_of(item) for item in findings]
    fixed = statuses.count("fixed")
    excepted = sum(1 for status in statuses if status in ("accepted", "false_positive"))
    active = sum(1 for status in statuses if status in ("open", "in_progress"))
    kev = sum(1 for item in findings if item.get("kev"))
    groups = fix_groups(findings)
    evidence = i18n.t("reports.audit.evidence", locale)

    story = header(evidence + (f"  ·  {framework_label}" if controls else ""), options["title"] or evidence, system)
    story.append(meta([(i18n.t("reports.audit.meta.organization", locale), options["organization"] or "—"),
                       (i18n.t("reports.audit.meta.system", locale), system), (i18n.t("reports.audit.meta.period", locale), period),
                       (i18n.t("reports.audit.meta.prepared_by", locale), options["prepared_by"] or "—"),
                       (i18n.t("reports.audit.meta.prepared_for", locale), options["prepared_for"] or "—"),
                       (i18n.t("reports.audit.meta.issued", locale), i18n.t("reports.audit.issued_value", locale, date=issued, ref=str(record.get("id", ""))[:24]))]))
    sentences = [i18n.t("reports.audit.summary", locale, findings=msg("reports.count.findings", count=len(findings)),
                        critical=msg("reports.count.critical", count=counts["critical"]), high=msg("reports.count.high", count=counts["high"]),
                        medium=msg("reports.count.medium", count=counts["medium"]),
                        low=msg("reports.count.low_info", count=counts["low"] + counts["info"]), active=active, fixed=fixed, excepted=excepted)]
    if kev:
        sentences.append(i18n.t("reports.audit.summary_kev", locale, count=kev))
    if len(groups) < len(findings):
        sentences.append(i18n.t("reports.audit.summary_grouped", locale, actions=msg("reports.count.actions", count=len(groups))))
    story += [Spacer(1, 10), h2(i18n.t("reports.common.summary", locale)),
              _kpis([(i18n.t("reports.audit.kpi.in_scope", locale), len(findings), INK, SOFT),
                     (i18n.t("reports.audit.kpi.critical", locale), counts["critical"], SEVERITY["critical"][1], DANGER_BG),
                     (i18n.t("reports.audit.kpi.high", locale), counts["high"], SEVERITY["high"][0], SEVERITY["high"][1]),
                     (i18n.t("reports.audit.kpi.open", locale), active, INK, SOFT), (i18n.t("reports.audit.kpi.fixed", locale), fixed, SUCCESS, SUCCESS_BG),
                     (i18n.t("reports.audit.kpi.excepted", locale), excepted, BRAND, BRAND_BG)]),
              Spacer(1, 6), Paragraph(_t(" ".join(sentences), 900), STYLE["body"])]
    if controls:
        story += _controls(framework_label, controls, deadlines=bool(((record.get("summary") or {}).get("sla") or {}).get("days")), locale=locale)
    # Method and coverage: what ran and what didn't, without the technical dump.
    engines = [step for step in record.get("steps") or [] if (step.get("tool") or {}).get("version")]
    method = [i18n.t("reports.audit.method_static", locale, date=analysed)]
    if engines:
        method.append(i18n.t("reports.audit.method_engines", locale, list=", ".join(f"{step['name']}" for step in engines)))
    if source.get("sha256"):
        method.append(i18n.t("reports.audit.method_snapshot", locale, sha=source["sha256"][:16]))
    gaps = coverage_gaps(record.get("steps") or [], locale=locale)
    if record.get("type") == "asset_state":
        method = [i18n.t("reports.audit.method_state", locale, date=analysed)]
    if gaps:
        method.append(i18n.t("reports.audit.method_gaps", locale, gaps=", ".join(gaps)))
    elif engines and all(step.get("status") == "completed" for step in engines):
        method.append(i18n.t("reports.audit.method_complete", locale))
    story += [h2(i18n.t("reports.common.method_coverage", locale)), *[Paragraph("•&nbsp;&nbsp;" + _t(item, 500), STYLE["body"]) for item in method]]
    sources = attribution(findings, locale=locale)
    if sources:
        story += [Paragraph(_t(i18n.t("reports.common.sources", locale)), STYLE["h3"]), *bullets([_t(line, 300) for line in sources], "note")]
    # Findings: one row per action (a dependency with all its advisories, or a code finding).
    story += [CondPageBreak(55 * mm), h2(i18n.t("reports.common.findings_count", locale, count=len(findings)))]  # no orphan heading
    if findings:
        rows = [_head(locale, "severity", "finding", "location", "status", "detected", "recommended_action")]
        for entry in groups:
            text_, where = _group_cells(entry, record.get("created_at"), locale)
            text_ += _marks(entry, locale)
            rows.append([_chip(entry["severity"], locale=locale), Paragraph(text_, STYLE["cell"]), Paragraph(where, STYLE["cellmuted"]),
                         Paragraph(_t(_status_text(entry["items"], locale), 60), STYLE["cell"]),
                         Paragraph(_first_seen(entry["items"], record.get("created_at")), STYLE["cellmuted"]),
                         Paragraph(_t(action(entry, short=True, locale=locale), 180), STYLE["cell"])])
        story.append(_grid(rows, [19 * mm, 52 * mm, 34 * mm, 19 * mm, 17 * mm, WIDTH - 141 * mm], zebra=True))
    else:
        story.append(Paragraph(_t(i18n.t("reports.audit.no_findings", locale)), STYLE["body"]))
    story += _deadlines(groups, (record.get("summary") or {}).get("sla"), locale)
    # Exceptions: the first thing an auditor asks. One by one: each decision has its reason.
    exceptions = [item for item in findings if status_of(item) in ("accepted", "false_positive")]
    if options["include_exceptions"]:
        story.append(h2(i18n.t("reports.audit.exceptions_heading", locale, count=len(exceptions))))
        if exceptions:
            rows = [_head(locale, "finding", "decision", "reason", "decided_by", "date", "expires")]
            for item in exceptions:
                decision = item.get("triage") or {}
                rows.append([Paragraph(_t(item.get("title"), 110), STYLE["cell"]), Paragraph(_t(status_label(status_of(item), locale)), STYLE["cell"]),
                             Paragraph(_t(decision.get("reason") or "—", 220), STYLE["cell"]), Paragraph(_t(decision.get("by") or "—", 40), STYLE["cellmuted"]),
                             Paragraph(_day(decision.get("at")), STYLE["cellmuted"]), Paragraph(_day(decision.get("expires_at")), STYLE["cellmuted"])])
            story.append(_grid(rows, [48 * mm, 22 * mm, WIDTH - 126 * mm, 22 * mm, 17 * mm, 17 * mm]))
        else:
            story.append(Paragraph(_t(i18n.t("reports.audit.no_exceptions_scope", locale)), STYLE["body"]))
    # Detail: only what was asked (by default, critical and high), also grouped.
    detailed = [] if options["detail"] == "none" else groups if options["detail"] == "all" else \
               [entry for entry in groups if entry["severity"] in ("critical", "high")]
    if detailed:
        story.append(h2(i18n.t("reports.audit.detail_high" if options["detail"] == "high" else "reports.audit.detail", locale)))
        for entry in detailed[:DETAIL_LIMIT]:
            story += _detail_block(entry, locale)
        if len(detailed) > DETAIL_LIMIT:
            story.append(Paragraph(_t(i18n.t("reports.audit.detail_truncated", locale, limit=DETAIL_LIMIT, total=len(detailed)), 400), STYLE["note"]))
    story += signoff(options["prepared_by"], locale=locale) + [Spacer(1, 6), Paragraph(_t(disclaimer(locale), 400), STYLE["note"])]
    title = options["title"] or i18n.t("reports.audit.title_with_system", locale, system=system)
    return build(story, title=title, footer=f"{title[:90]}  ·  {options['organization'][:40] or 'Tamandua'}", version=version,
                 author=options["prepared_by"] or "Tamandua", subject=framework_label, locale=locale)


# --- consolidated report (organization or several repositories) -----------------------------

def render_portfolio_pdf(items: list[dict], options: dict, *, version: str, scope_label: str, coverage: dict,
                         locale: str | None = None) -> bytes:
    """An organization (or a selection of repositories) in a single document.

    `items`: [{"name", "findings", "last_complete", "last_status"}] with each repository's registry findings.
    `coverage`: {"total": repositories on GitHub or None, "missing": names without a full scan}.
    What an auditor asks at this level: is everything scanned?, where is the risk?, what is still open?"""
    locale = locale or default_locale()
    items = localize(items, locale)
    framework_label, controls = _framework(options["framework"], locale)
    issued = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    period = (i18n.t("reports.audit.period_range", locale, start=options["period_from"] or "—", end=options["period_to"] or issued)
              if options["period_from"] or options["period_to"] else i18n.t("reports.audit.period_state", locale, date=issued))
    active_states = ("open", "in_progress")
    rows, open_items, exceptions = [], [], []
    totals = {"critical": 0, "high": 0, "open": 0, "fixed": 0, "excepted": 0}
    for item in items:
        findings = [finding for finding in item["findings"] if status_of(finding) != "excluded"]
        states = [status_of(finding) for finding in findings]
        pending = [finding for finding, state in zip(findings, states) if state in active_states]
        counts = {level: sum(1 for finding in pending if finding.get("severity") == level) for level in ORDER}
        fixed, excepted = states.count("fixed"), sum(1 for state in states if state in ("accepted", "false_positive"))
        rows.append((item["name"], counts, len(pending), fixed, excepted, item.get("last_complete"), item.get("last_status")))
        # What to handle first, grouped by fix within each repository.
        open_items += [(item["name"], entry) for entry in fix_groups([finding for finding in pending if finding.get("severity") in ("critical", "high")])]
        exceptions += [(item["name"], finding) for finding, state in zip(findings, states) if state in ("accepted", "false_positive")]
        for name, amount in (("critical", counts["critical"]), ("high", counts["high"]), ("open", len(pending)),
                             ("fixed", fixed), ("excepted", excepted)):
            totals[name] += amount
    rows.sort(key=lambda row: (-row[1]["critical"], -row[1]["high"], -row[2], row[0]))
    open_items.sort(key=lambda pair: (not pair[1]["kev"], ORDER.get(pair[1]["severity"], 9), -len(pair[1]["items"]), pair[0]))
    analysed = sum(1 for row in rows if row[5])
    known_total = coverage.get("total")
    evidence = i18n.t("reports.audit.evidence", locale)

    story = header(i18n.t("reports.audit.evidence_consolidated", locale) + (f"  ·  {framework_label}" if controls else ""),
                   options["title"] or evidence, options["scope"] or scope_label)
    story.append(meta([(i18n.t("reports.audit.meta.organization", locale), options["organization"] or "—"),
                       (i18n.t("reports.common.scope", locale), options["scope"] or scope_label), (i18n.t("reports.audit.meta.period", locale), period),
                       (i18n.t("reports.audit.meta.prepared_by", locale), options["prepared_by"] or "—"),
                       (i18n.t("reports.audit.meta.prepared_for", locale), options["prepared_for"] or "—"),
                       (i18n.t("reports.audit.meta.issued", locale), issued)]))
    story += [Spacer(1, 10), h2(i18n.t("reports.common.summary", locale)),
              _kpis([(i18n.t("reports.audit.kpi.analysed", locale),
                      i18n.t("reports.audit.of_total", locale, done=analysed, total=known_total) if known_total else analysed, INK, SOFT),
                     (i18n.t("reports.audit.kpi.open_critical", locale), totals["critical"], SEVERITY["critical"][1], DANGER_BG),
                     (i18n.t("reports.audit.kpi.open_high", locale), totals["high"], SEVERITY["high"][0], SEVERITY["high"][1]),
                     (i18n.t("reports.audit.kpi.open", locale), totals["open"], INK, SOFT),
                     (i18n.t("reports.audit.kpi.fixed", locale), totals["fixed"], SUCCESS, SUCCESS_BG),
                     (i18n.t("reports.audit.kpi.excepted", locale), totals["excepted"], BRAND, BRAND_BG)]),
              Spacer(1, 6),
              Paragraph(_t(i18n.t("reports.audit.portfolio_summary", locale, repositories=msg("reports.count.repositories", count=len(rows)),
                                  pending=msg("reports.count.pending_findings", count=totals["open"]),
                                  critical=msg("reports.count.are_critical", count=totals["critical"]), high=totals["high"],
                                  fixed=msg("reports.count.fixed_findings", count=totals["fixed"]),
                                  exceptions=msg("reports.count.approved_exceptions", count=totals["excepted"])), 700), STYLE["body"])]
    # Coverage: is everything scanned? The first question at organization level.
    story.append(h2(i18n.t("reports.audit.coverage", locale)))
    incomplete = [row[0] for row in rows if not row[5] and row[6]]
    lines = []
    if known_total:
        lines.append(i18n.t("reports.audit.coverage_known", locale, analysed=analysed, total=known_total, percent=round(100 * analysed / known_total)))
    else:
        lines.append(i18n.t("reports.audit.coverage_report", locale, analysed=analysed, total=len(rows)))
    if incomplete:
        lines.append(i18n.t("reports.audit.coverage_incomplete", locale, list=listing(incomplete, 30, locale=locale)))
    missing = coverage.get("missing") or []
    if missing:
        lines.append(i18n.t("reports.audit.coverage_missing", locale, count=len(missing), list=listing(missing, 40, locale=locale)))
    story += [Paragraph("•&nbsp;&nbsp;" + _t(line, 1200), STYLE["body"]) for line in lines]
    if controls:
        story += _controls(framework_label, controls, deadlines=False, locale=locale)
    sources = attribution([finding for item in items for finding in item["findings"]], locale=locale)
    story += [h2(i18n.t("reports.audit.method", locale)),
              Paragraph("•&nbsp;&nbsp;" + _t(i18n.t("reports.audit.portfolio_method_static", locale), 600), STYLE["body"]),
              Paragraph("•&nbsp;&nbsp;" + _t(i18n.t("reports.audit.portfolio_method_state", locale), 600), STYLE["body"])]
    if sources:
        story += [Paragraph(_t(i18n.t("reports.common.sources", locale)), STYLE["h3"]), *bullets([_t(line, 300) for line in sources], "note")]
    # By repository
    story.append(h2(i18n.t("reports.audit.by_repository", locale, count=len(rows))))
    table = [_head(locale, "repository", "critical_short", "high_plural", "medium_plural", "low_plural", "open_plural", "fixed_short",
                   "exceptions_short", "last_complete")]
    for name, counts, pending, fixed, excepted, last, _ in rows[:1000]:
        table.append([Paragraph(_t(name, 80), STYLE["cell"]),
                      *[Paragraph(f'<font color="{hexval(SEVERITY[level][1 if level == "critical" else 0])}"><b>{counts[level]}</b></font>' if counts[level] else "0",
                                  STYLE["cell"]) for level in ("critical", "high", "medium", "low")],
                      Paragraph(str(pending), STYLE["cell"]), Paragraph(str(fixed), STYLE["cellmuted"]), Paragraph(str(excepted), STYLE["cellmuted"]),
                      Paragraph(_day(last) if last else f'<font color="#b71824">{_t(i18n.t("reports.audit.no_full_scan", locale))}</font>', STYLE["cellmuted"])])
    story.append(_grid(table, [WIDTH - 125 * mm, 11 * mm, 12 * mm, 14 * mm, 12 * mm, 15 * mm, 14 * mm, 13 * mm, 26 * mm], zebra=True))
    # Open critical and high, with the repository and grouped by fix: what to handle first.
    pending_count = sum(len(entry["items"]) for _, entry in open_items)
    story.append(h2(i18n.t("reports.audit.open_heading", locale, count=pending_count)))
    if open_items:
        table = [_head(locale, "severity", "repository", "finding", "detected", "recommended_action")]
        for name, entry in open_items[:400]:
            text_, _ = _group_cells(entry, None, locale)
            text_ += _marks(entry, locale)
            table.append([_chip(entry["severity"], locale=locale), Paragraph(_t(name, 60), STYLE["cellmuted"]), Paragraph(text_, STYLE["cell"]),
                          Paragraph(_first_seen(entry["items"], None), STYLE["cellmuted"]),
                          Paragraph(_t(action(entry, short=True, locale=locale), 160), STYLE["cell"])])
        story.append(_grid(table, [19 * mm, 36 * mm, 57 * mm, 17 * mm, WIDTH - 129 * mm], zebra=True))
        if len(open_items) > 400:
            story.append(Paragraph(_t(i18n.t("reports.audit.open_truncated", locale, shown=400, total=len(open_items)), 400), STYLE["note"]))
    else:
        story.append(Paragraph(_t(i18n.t("reports.audit.no_open", locale)), STYLE["body"]))
    if options["include_exceptions"]:
        story.append(h2(i18n.t("reports.audit.exceptions_heading", locale, count=len(exceptions))))
        if exceptions:
            table = [_head(locale, "repository", "finding", "decision", "reason", "decided_by", "expires")]
            for name, finding in exceptions[:500]:
                decision = finding.get("triage") or {}
                table.append([Paragraph(_t(name, 60), STYLE["cellmuted"]), Paragraph(_t(finding.get("title"), 100), STYLE["cell"]),
                              Paragraph(_t(status_label(status_of(finding), locale)), STYLE["cell"]), Paragraph(_t(decision.get("reason") or "—", 200), STYLE["cell"]),
                              Paragraph(_t(decision.get("by") or "—", 40), STYLE["cellmuted"]), Paragraph(_day(decision.get("expires_at")), STYLE["cellmuted"])])
            story.append(_grid(table, [32 * mm, 42 * mm, 20 * mm, WIDTH - 132 * mm, 21 * mm, 17 * mm]))
        else:
            story.append(Paragraph(_t(i18n.t("reports.audit.no_exceptions", locale)), STYLE["body"]))
    story += signoff(options["prepared_by"], locale=locale) + [Spacer(1, 6), Paragraph(_t(disclaimer(locale), 400), STYLE["note"])]
    title = options["title"] or evidence
    return build(story, title=title, footer=f"{title[:70]}  ·  {scope_label[:50]}", version=version,
                 author=options["prepared_by"] or "Tamandua", subject=framework_label, locale=locale)
