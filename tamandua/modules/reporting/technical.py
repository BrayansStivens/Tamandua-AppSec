"""Informe técnico de hallazgos (PDF) de un análisis o del estado acumulado de un repositorio o imagen.

Para el equipo que corrige, en este orden: cuánto hay y qué hacer primero (una acción por paquete o por
hallazgo de código); las dependencias agrupadas con la versión que cierra todos sus avisos; el código,
secretos e infraestructura (detalle solo de críticos y altos); el método y lo que no se pudo analizar.
El índice completo de vulnerabilidades va en un anexo compacto; el texto íntegro de cada aviso sigue
en el JSON, el SARIF y el panel.
"""

from __future__ import annotations

from datetime import datetime, timezone

from reportlab.lib.units import mm
from reportlab.platypus import KeepTogether, Paragraph, Spacer, Table

from tamandua.modules.reporting.audit import status_label, status_of
from tamandua.modules.intel.data_sources import attribution
from tamandua.modules.findings.remediation import action, counts_text, fix_groups
from tamandua.modules.reporting.design import (ATTENTION, ATTENTION_BG, BRAND, BRAND_BG, DANGER, DANGER_BG, INK, MUTED, ORDER, SEVERITY, SOFT,
                            STYLE, SUCCESS, SUCCESS_BG, WIDTH, GAP_STATES, build, bullets, chip, count, coverage_gaps, day, h2, header,
                            hexval, kpis, listing, meta, severity_label, step_status, t as _t, table)
from tamandua.shared import i18n
from tamandua.shared.i18n import default_locale, localize, msg

KINDS = ("repository_scan", "image_scan", "pr_review", "asset_state")
ACTIVE = ("open", "in_progress")
ANNEX_LIMIT = 600
DETAIL_LIMIT = 150   # detail blocks for critical or high code findings
TABLE_LIMIT = 500    # medium and low rows


def _where(item: dict) -> str:
    return str(item.get("path")) if item.get("scanner") == "sca" else f"{item.get('path')}:{item.get('line')}"


def _columns(locale: str, *names: str) -> list[str]:
    return [_t(i18n.t(f"reports.columns.{name}", locale)) for name in names]


def render_technical_pdf(record: dict, *, version: str, locale: str | None = None) -> bytes:
    locale = locale or default_locale()
    record = localize(record, locale)
    t = lambda key, **params: i18n.t(key, locale, **params)  # noqa: E731
    kev_mark = f'<br/><font color="#b71824"><b>{_t(t("reports.common.kev_mark"))}</b></font>'
    findings = [item for item in record.get("findings") or [] if status_of(item) != "excluded"]
    active = [item for item in findings if status_of(item) in ACTIVE]
    decided = [item for item in findings if status_of(item) in ("accepted", "false_positive")]
    fixed = [item for item in findings if status_of(item) == "fixed"]
    source = record.get("source") or {}
    name = source.get("name") or source.get("id") or "—"
    when = day(record.get("created_at") or record.get("scanned_at"))
    kind = t(f"reports.technical.kind.{record.get('type')}") if record.get("type") in KINDS else t("reports.technical.kind.default")
    counts = {level: sum(1 for item in active if item.get("severity") == level) for level in ORDER}
    groups = fix_groups(active)
    packages = [entry for entry in groups if entry["kind"] == "package"]
    code = sorted([item for item in active if not (item.get("scanner") == "sca" and (item.get("package") or {}).get("name"))],
                  key=lambda item: (ORDER.get(item.get("severity"), 9), str(item.get("path")), item.get("line") or 0))
    kev = sum(1 for item in active if item.get("kev"))
    fixable = sum(1 for entry in packages if entry["target"])

    story = header(t("reports.technical.eyebrow", kind=kind), name,
                   t("reports.technical.subtitle_state" if record.get("type") == "asset_state" else "reports.technical.subtitle_scan", date=when))
    engines = [step for step in record.get("steps") or [] if (step.get("tool") or {}).get("version")]
    story.append(meta([(t("reports.technical.meta.asset"), name), (t("reports.technical.meta.type"), kind), (t("reports.technical.meta.date"), when),
                       (t("reports.technical.meta.revision"), " · ".join(value for value in (source.get("branch"), (source.get("sha256") or "")[:12]) if value) or "—"),
                       (t("reports.technical.meta.engines"), ", ".join(step["name"] for step in engines) or "—"),
                       (t("reports.technical.meta.reference"), str(record.get("id") or "—")[:32])]))
    summary = t("reports.technical.summary", pending=msg("reports.count.pending_findings", count=len(active)),
                 counts=counts_text({k: v for k, v in counts.items() if v}, locale=locale) or msg("reports.common.none"),
                 actions=msg("reports.count.actions", count=len(groups)), packages=msg("reports.count.packages_to_update", count=len(packages)),
                 fixable=fixable, code=msg("reports.count.findings", count=len(code)))
    if decided:
        summary += " " + t("reports.technical.decided", count=len(decided))
    story += [Spacer(1, 10), h2(t("reports.common.summary")),
              kpis([(t("reports.technical.kpi.pending"), len(active), INK, SOFT), (t("reports.audit.kpi.critical"), counts["critical"], SEVERITY["critical"][1], DANGER_BG),
                    (t("reports.audit.kpi.high"), counts["high"], ATTENTION, ATTENTION_BG), (t("reports.technical.kpi.kev"), kev, DANGER, DANGER_BG),
                    (t("reports.technical.kpi.actions"), len(groups), BRAND, BRAND_BG), (t("reports.audit.kpi.fixed"), len(fixed), SUCCESS, SUCCESS_BG)]),
              Spacer(1, 6), Paragraph(_t(summary, 900), STYLE["body"])]
    gaps = coverage_gaps(record.get("steps") or [], locale=locale)
    if gaps:
        story.append(Paragraph(_t(t("reports.technical.incomplete", gaps=", ".join(gaps)), 600), STYLE["note"]))
    if groups:
        story.append(h2(t("reports.common.what_first")))
        body = []
        for entry in groups[:15]:
            item = entry["items"][0]
            what = (f"<b>{_t(entry['name'], 60)} {_t(entry['version'], 30)}</b> · {_t(count('advisories', len(entry['items']), locale))}" if entry["kind"] == "package"
                    else f"<b>{_t(item.get('title'), 120)}</b>")
            body.append([chip(entry["severity"], locale=locale), what + (kev_mark if entry["kev"] else ""),
                         _t(entry["path"] if entry["kind"] == "package" else _where(item), 90), _t(action(entry, short=True, locale=locale), 180)])
        story.append(table(_columns(locale, "severity", "what", "where", "action"), body, [19 * mm, 52 * mm, 42 * mm, WIDTH - 113 * mm]))
        if len(groups) > 15:
            story.append(Paragraph(_t(t("reports.technical.first_truncated", total=len(groups)), 400), STYLE["note"]))
    if packages:
        total = sum(len(entry["items"]) for entry in packages)
        story.append(h2(t("reports.technical.dependencies", packages=msg("reports.count.packages", count=len(packages)),
                           vulnerabilities=msg("reports.count.vulnerabilities", count=total))))
        body = []
        for entry in packages:
            body.append([chip(entry["severity"], locale=locale),
                         f"<b>{_t(entry['name'], 60)}</b> {_t(entry['version'], 30)}<br/><font color=\"#636363\">{_t(entry['ecosystem'], 20)} · {_t(entry['path'], 80)}</font>",
                         _t(counts_text(entry["counts"], locale=locale), 80) + f'<br/><font color="#636363">{_t(listing(entry["ids"], 4, locale=locale), 160)}</font>'
                         + (kev_mark if entry["kev"] else ""),
                         f"<b>{_t(entry['target'], 40)}</b>" + ("" if entry["complete"] else f'<br/><font color="#636363">{_t(t("reports.technical.partial_fix"))}</font>')
                         if entry["target"] else f'<font color="#b71824">{_t(t("reports.technical.no_fixed_version"))}</font>'])
        story.append(table(_columns(locale, "severity", "package", "vulnerabilities", "update_to"), body, [19 * mm, 58 * mm, WIDTH - 117 * mm, 40 * mm]))
        story.append(Paragraph(_t(t("reports.technical.update_note"), 400), STYLE["note"]))
    if code:
        serious = [item for item in code if item.get("severity") in ("critical", "high")]
        rest = [item for item in code if item.get("severity") not in ("critical", "high")]
        story.append(h2(t("reports.common.code_heading", count=len(code))))
        for item in serious[:DETAIL_LIMIT]:
            block = [Table([[chip(item.get("severity", "info"), locale=locale), Paragraph(f"<b>{_t(item.get('title'), 160)}</b>", STYLE["body"])]],
                           colWidths=[18 * mm, WIDTH - 18 * mm], style=[("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 0)]),
                     Paragraph(_t(" · ".join(value for value in (_where(item), item.get("rule_id"), ", ".join(f"CWE-{value}" for value in (item.get("cwe") or [])[:3]),
                                                                 status_label(status_of(item), locale)) if value), 240), STYLE["note"])]
            if item.get("reason"):
                block.append(Paragraph(f"<b>{_t(t('reports.technical.what_label'))}</b> " + _t(item["reason"], 360), STYLE["body"]))
            block.append(Paragraph(f"<b>{_t(t('reports.common.fix_label'))}</b> " + _t(item.get("remediation") or t("reports.technical.fallback_fix"), 420),
                                   STYLE["body"]))
            story += [KeepTogether(block), Spacer(1, 5)]
        if len(serious) > DETAIL_LIMIT:
            story.append(Paragraph(_t(t("reports.technical.detail_truncated", shown=DETAIL_LIMIT, total=len(serious)), 400), STYLE["note"]))
        if rest:
            story.append(Paragraph(_t(t("reports.common.medium_low", count=len(rest))), STYLE["h3"]))
            story.append(table(_columns(locale, "severity", "finding", "location", "fix"),
                               [[chip(item.get("severity", "info"), locale=locale), _t(item.get("title"), 120), _t(_where(item), 90),
                                 _t(action({"kind": "finding", "items": [item]}, short=True, locale=locale), 160)] for item in rest[:TABLE_LIMIT]],
                               [19 * mm, 55 * mm, 45 * mm, WIDTH - 119 * mm]))
            if len(rest) > TABLE_LIMIT:
                story.append(Paragraph(_t(t("reports.technical.table_truncated", shown=TABLE_LIMIT, total=len(rest)), 400), STYLE["note"]))
    if decided:
        story.append(h2(t("reports.technical.decisions", count=len(decided))))
        story.append(table(_columns(locale, "finding", "decision", "reason", "by", "expires"),
                           [[_t(item.get("title"), 110), _t(status_label(status_of(item), locale)), _t((item.get("triage") or {}).get("reason") or "—", 220),
                             _t((item.get("triage") or {}).get("by") or "—", 40), day((item.get("triage") or {}).get("expires_at"))] for item in decided[:400]],
                           [52 * mm, 24 * mm, WIDTH - 130 * mm, 30 * mm, 24 * mm]))
        if len(decided) > 400:
            story.append(Paragraph(_t(t("reports.technical.decisions_truncated", shown=400, total=len(decided)), 400), STYLE["note"]))
    story.append(h2(t("reports.common.method_coverage")))
    lines = []
    for step in record.get("steps") or []:
        status = step_status(step.get("status"), locale)
        colour = hexval(DANGER) if step.get("status") in GAP_STATES else hexval(MUTED)
        lines.append(f"<b>{_t(step.get('name'), 60)}</b> · <font color=\"{colour}\">{_t(status, 30)}</font>"
                     + (f" · {_t(step['detail'], 260)}" if step.get("detail") else ""))
    if record.get("type") == "asset_state":
        lines.insert(0, _t(t("reports.technical.state_note"), 600))
    story += bullets(lines or [_t(t("reports.technical.no_engines"))])
    if record.get("limitations"):
        story += [Paragraph(_t(t("reports.common.limitations")), STYLE["h3"]), *bullets([_t(item, 300) for item in record["limitations"]], "note")]
    sources = attribution(active, locale=locale)
    if sources:
        story += [Paragraph(_t(t("reports.common.sources")), STYLE["h3"]), *bullets([_t(line, 300) for line in sources], "note")]
    # Annex: one row per dependency advisory, to trace every identifier without dumping its description.
    advisories = sorted([item for item in active if item.get("scanner") == "sca"],
                        key=lambda item: (ORDER.get(item.get("severity"), 9), str((item.get("package") or {}).get("name")), str(item.get("rule_id"))))
    if advisories:
        story.append(h2(t("reports.common.annex", count=len(advisories))))
        body = []
        for item in advisories[:ANNEX_LIMIT]:
            package = item.get("package") or {}
            advisory = item.get("advisory") or {}
            epss = (item.get("epss") or {}).get("score")
            body.append([_t(((item.get("cve") or [])[:1] or (item.get("ghsa") or [])[:1] or [item.get("rule_id")])[0], 40),
                         _t(f"{package.get('name', '')} {package.get('version', '')}", 70),
                         _t(severity_label(item.get("severity"), locale)) if item.get("severity") in ORDER else "—",
                         f"{advisory['cvss_score']:.1f}" if isinstance(advisory.get("cvss_score"), (int, float)) else "—",
                         f"{epss * 100:.1f} %" if isinstance(epss, (int, float)) else "—",
                         f'<font color="#b71824"><b>{_t(t("reports.common.yes"))}</b></font>' if item.get("kev") else "—", _t(package.get("fixed_version") or "—", 40),
                         _t((item.get("source") or {}).get("short") or (item.get("source") or {}).get("name") or "—", 20)])
        story.append(table(_columns(locale, "identifier", "package", "severity", "cvss", "epss", "kev", "fixed_in", "source"), body,
                           [32 * mm, WIDTH - 140 * mm, 16 * mm, 11 * mm, 14 * mm, 10 * mm, 36 * mm, 21 * mm]))
        if len(advisories) > ANNEX_LIMIT:
            story.append(Paragraph(_t(t("reports.technical.annex_truncated", shown=ANNEX_LIMIT, total=len(advisories)), 400), STYLE["note"]))
    story += [Spacer(1, 8), Paragraph(_t(t("reports.technical.closing"), 400), STYLE["note"])]
    issued = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return build(story, title=t("reports.technical.title", name=name), footer=t("reports.technical.footer", name=name[:70], date=issued),
                 version=version, subject=kind, locale=locale)
