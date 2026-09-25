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

from .audit_report import STATUS_LABEL, status_of
from .data_sources import attribution
from .remediation import action, counts_text, fix_groups
from .report_design import (ATTENTION, ATTENTION_BG, BRAND, BRAND_BG, DANGER, DANGER_BG, INK, MUTED, ORDER, SEVERITY, SEVERITY_LABEL, SOFT,
                            STEP_STATUS, STYLE, SUCCESS, SUCCESS_BG, WIDTH, GAP_STATES, build, bullets, chip, coverage_gaps, day, h2, header,
                            hexval, kpis, listing, meta, n, t, table)

KINDS = {"repository_scan": "Análisis completo", "image_scan": "Análisis de imagen", "pr_review": "Revisión de pull request",
         "asset_state": "Estado acumulado", "lab_scan": "Análisis de laboratorio"}
ACTIVE = ("open", "in_progress")
ANNEX_LIMIT = 600
DETAIL_LIMIT = 150   # bloques de detalle de código crítico o alto
TABLE_LIMIT = 500    # filas de medios y bajos
KEV = '<br/><font color="#b71824"><b>Explotación activa conocida (CISA KEV)</b></font>'


def _where(item: dict) -> str:
    return str(item.get("path")) if item.get("scanner") == "sca" else f"{item.get('path')}:{item.get('line')}"


def render_technical_pdf(record: dict, *, version: str) -> bytes:
    findings = [item for item in record.get("findings") or [] if status_of(item) != "excluded"]
    active = [item for item in findings if status_of(item) in ACTIVE]
    decided = [item for item in findings if status_of(item) in ("accepted", "false_positive")]
    fixed = [item for item in findings if status_of(item) == "fixed"]
    source = record.get("source") or {}
    name = source.get("name") or source.get("id") or "—"
    when = day(record.get("created_at") or record.get("scanned_at"))
    kind = KINDS.get(record.get("type"), "Análisis")
    counts = {level: sum(1 for item in active if item.get("severity") == level) for level in ORDER}
    groups = fix_groups(active)
    packages = [entry for entry in groups if entry["kind"] == "package"]
    code = sorted([item for item in active if not (item.get("scanner") == "sca" and (item.get("package") or {}).get("name"))],
                  key=lambda item: (ORDER.get(item.get("severity"), 9), str(item.get("path")), item.get("line") or 0))
    kev = sum(1 for item in active if item.get("kev"))
    fixable = sum(1 for entry in packages if entry["target"])

    story = header(f"Informe técnico de hallazgos · {kind}", name,
                   f"{'Estado acumulado al' if record.get('type') == 'asset_state' else 'Análisis del'} {when}")
    engines = [step for step in record.get("steps") or [] if (step.get("tool") or {}).get("version")]
    story.append(meta([("Activo", name), ("Tipo", kind), ("Fecha", when),
                       ("Rama / revisión", " · ".join(value for value in (source.get("branch"), (source.get("sha256") or "")[:12]) if value) or "—"),
                       ("Motores", ", ".join(step["name"] for step in engines) or "—"), ("Referencia", str(record.get("id") or "—")[:32])]))
    story += [Spacer(1, 10), h2("Resumen"),
              kpis([("pendientes", len(active), INK, SOFT), ("críticas", counts["critical"], SEVERITY["critical"][1], DANGER_BG),
                    ("altas", counts["high"], ATTENTION, ATTENTION_BG), ("con explotación activa (KEV)", kev, DANGER, DANGER_BG),
                    ("acciones para cerrarlas", len(groups), BRAND, BRAND_BG), ("remediadas", len(fixed), SUCCESS, SUCCESS_BG)]),
              Spacer(1, 6),
              Paragraph(t(f"{n(len(active), 'hallazgo pendiente', 'hallazgos pendientes')} ({counts_text({k: v for k, v in counts.items() if v}) or 'ninguno'}) "
                          f"que se cierran con {n(len(groups), 'acción', 'acciones')}: {n(len(packages), 'dependencia que actualizar o sustituir', 'dependencias que actualizar o sustituir')} "
                          f"({fixable} con versión corregida) y {n(len(code), 'hallazgo', 'hallazgos')} de código, secretos o infraestructura. "
                          + (f"{n(len(decided), 'decisión', 'decisiones')} del equipo (riesgo aceptado o falso positivo) fuera de la cuenta. " if decided else ""), 900),
                        STYLE["body"])]
    gaps = coverage_gaps(record.get("steps") or [])
    if gaps:
        story.append(Paragraph(t("Cobertura incompleta: " + ", ".join(gaps) + ". Lo que no se analizó no equivale a «sin hallazgos».", 600),
                               STYLE["note"]))
    if groups:
        story.append(h2("Qué hacer primero"))
        body = []
        for entry in groups[:15]:
            item = entry["items"][0]
            what = (f"<b>{t(entry['name'], 60)} {t(entry['version'], 30)}</b> · {n(len(entry['items']), 'aviso', 'avisos')}" if entry["kind"] == "package"
                    else f"<b>{t(item.get('title'), 120)}</b>")
            body.append([chip(entry["severity"]), what + (KEV if entry["kev"] else ""),
                         t(entry["path"] if entry["kind"] == "package" else _where(item), 90), t(action(entry, short=True), 180)])
        story.append(table(["Severidad", "Qué", "Dónde", "Acción"], body, [19 * mm, 52 * mm, 42 * mm, WIDTH - 113 * mm]))
        if len(groups) > 15:
            story.append(Paragraph(f"Las 15 primeras de {len(groups)} acciones, por explotación activa, severidad y alcance. El resto, en las secciones siguientes.",
                                   STYLE["note"]))
    if packages:
        total = sum(len(entry["items"]) for entry in packages)
        story.append(h2(f"Dependencias ({n(len(packages), 'paquete', 'paquetes')} · {n(total, 'vulnerabilidad', 'vulnerabilidades')})"))
        body = []
        for entry in packages:
            body.append([chip(entry["severity"]),
                         f"<b>{t(entry['name'], 60)}</b> {t(entry['version'], 30)}<br/><font color=\"#636363\">{t(entry['ecosystem'], 20)} · {t(entry['path'], 80)}</font>",
                         t(counts_text(entry["counts"]), 80) + f'<br/><font color="#636363">{t(listing(entry["ids"], 4), 160)}</font>' + (KEV if entry["kev"] else ""),
                         f"<b>{t(entry['target'], 40)}</b>" + ("" if entry["complete"] else '<br/><font color="#636363">algún aviso sin corrección</font>')
                         if entry["target"] else '<font color="#b71824">sin versión corregida</font>'])
        story.append(table(["Severidad", "Paquete", "Vulnerabilidades", "Actualizar a"], body, [19 * mm, 58 * mm, WIDTH - 117 * mm, 40 * mm]))
        story.append(Paragraph("«Actualizar a» es la versión más alta entre las que corrigen cada aviso: la que los cierra todos. "
                               "Después regenera el lockfile y vuelve a analizar.", STYLE["note"]))
    if code:
        serious = [item for item in code if item.get("severity") in ("critical", "high")]
        rest = [item for item in code if item.get("severity") not in ("critical", "high")]
        story.append(h2(f"Código, secretos e infraestructura ({len(code)})"))
        for item in serious[:DETAIL_LIMIT]:
            block = [Table([[chip(item.get("severity", "info")), Paragraph(f"<b>{t(item.get('title'), 160)}</b>", STYLE["body"])]],
                           colWidths=[18 * mm, WIDTH - 18 * mm], style=[("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 0)]),
                     Paragraph(t(" · ".join(value for value in (_where(item), item.get("rule_id"), ", ".join(f"CWE-{value}" for value in (item.get("cwe") or [])[:3]),
                                                                STATUS_LABEL.get(status_of(item))) if value), 240), STYLE["note"])]
            if item.get("reason"):
                block.append(Paragraph("<b>Qué:</b> " + t(item["reason"], 360), STYLE["body"]))
            block.append(Paragraph("<b>Corrección:</b> " + t(item.get("remediation") or "Revisar según la guía del hallazgo", 420), STYLE["body"]))
            story += [KeepTogether(block), Spacer(1, 5)]
        if len(serious) > DETAIL_LIMIT:
            story.append(Paragraph(f"Se detallan {DETAIL_LIMIT} de {len(serious)} críticos y altos; el resto está en el JSON, el SARIF y el panel.", STYLE["note"]))
        if rest:
            story.append(Paragraph(f"Medios y bajos ({len(rest)})", STYLE["h3"]))
            story.append(table(["Severidad", "Hallazgo", "Ubicación", "Corrección"],
                               [[chip(item.get("severity", "info")), t(item.get("title"), 120), t(_where(item), 90),
                                 t(action({"kind": "finding", "items": [item]}, short=True), 160)] for item in rest[:TABLE_LIMIT]],
                               [19 * mm, 55 * mm, 45 * mm, WIDTH - 119 * mm]))
            if len(rest) > TABLE_LIMIT:
                story.append(Paragraph(f"Se muestran {TABLE_LIMIT} de {len(rest)}; el resto está en el JSON, el SARIF y el panel.", STYLE["note"]))
    if decided:
        story.append(h2(f"Decisiones del equipo ({len(decided)})"))
        story.append(table(["Hallazgo", "Decisión", "Motivo", "Por", "Vence"],
                           [[t(item.get("title"), 110), STATUS_LABEL[status_of(item)], t((item.get("triage") or {}).get("reason") or "—", 220),
                             t((item.get("triage") or {}).get("by") or "—", 40), day((item.get("triage") or {}).get("expires_at"))] for item in decided[:400]],
                           [52 * mm, 24 * mm, WIDTH - 130 * mm, 30 * mm, 24 * mm]))
        if len(decided) > 400:
            story.append(Paragraph(f"Se muestran 400 de {len(decided)} decisiones; todas están en el panel.", STYLE["note"]))
    story.append(h2("Método y cobertura"))
    lines = []
    for step in record.get("steps") or []:
        status = STEP_STATUS.get(step.get("status"), step.get("status") or "—")
        colour = hexval(DANGER) if step.get("status") in GAP_STATES else hexval(MUTED)
        lines.append(f"<b>{t(step.get('name'), 60)}</b> · <font color=\"{colour}\">{t(status, 30)}</font>"
                     + (f" · {t(step['detail'], 260)}" if step.get("detail") else ""))
    if record.get("type") == "asset_state":
        lines.insert(0, "Estado acumulado: reúne los análisis completos y las revisiones de pull requests; un hallazgo queda remediado cuando "
                        "deja de aparecer en un análisis completo, nunca por uno incompleto.")
    story += bullets(lines or ["Sin detalle de motores en este registro."])
    if record.get("limitations"):
        story += [Paragraph("Límites", STYLE["h3"]), *bullets([t(item, 300) for item in record["limitations"]], "note")]
    sources = attribution(active)
    if sources:
        story += [Paragraph("Fuentes de los avisos", STYLE["h3"]), *bullets([t(line, 300) for line in sources], "note")]
    # Anexo: una fila por aviso de dependencia, para trazar cada identificador sin volcar su descripción.
    advisories = sorted([item for item in active if item.get("scanner") == "sca"],
                        key=lambda item: (ORDER.get(item.get("severity"), 9), str((item.get("package") or {}).get("name")), str(item.get("rule_id"))))
    if advisories:
        story.append(h2(f"Anexo · Índice de vulnerabilidades ({len(advisories)})"))
        body = []
        for item in advisories[:ANNEX_LIMIT]:
            package = item.get("package") or {}
            advisory = item.get("advisory") or {}
            epss = (item.get("epss") or {}).get("score")
            body.append([t(((item.get("cve") or [])[:1] or (item.get("ghsa") or [])[:1] or [item.get("rule_id")])[0], 40),
                         t(f"{package.get('name', '')} {package.get('version', '')}", 70), SEVERITY_LABEL.get(item.get("severity"), "—"),
                         f"{advisory['cvss_score']:.1f}" if isinstance(advisory.get("cvss_score"), (int, float)) else "—",
                         f"{epss * 100:.1f} %" if isinstance(epss, (int, float)) else "—",
                         '<font color="#b71824"><b>sí</b></font>' if item.get("kev") else "—", t(package.get("fixed_version") or "—", 40),
                         t((item.get("source") or {}).get("short") or (item.get("source") or {}).get("name") or "—", 20)])
        story.append(table(["Identificador", "Paquete", "Severidad", "CVSS", "EPSS", "KEV", "Corregida en", "Fuente"], body,
                           [32 * mm, WIDTH - 140 * mm, 16 * mm, 11 * mm, 14 * mm, 10 * mm, 36 * mm, 21 * mm]))
        if len(advisories) > ANNEX_LIMIT:
            story.append(Paragraph(f"Se muestran {ANNEX_LIMIT} de {len(advisories)}; el resto está en el JSON y el SARIF del análisis.", STYLE["note"]))
    story += [Spacer(1, 8), Paragraph("Evidencia técnica generada con herramientas automatizadas: revísala antes de actuar. Los avisos de "
                                      "dependencias no prueban explotación en esta aplicación.", STYLE["note"])]
    issued = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return build(story, title=f"Informe técnico · {name}", footer=f"Informe técnico · {name[:70]} · emitido {issued}", version=version,
                 subject=kind)
