"""Informe de evidencia de gestión de vulnerabilidades (SOC 2, ISO/IEC 27001 o general).

Lo que un equipo entrega cuando un auditor o un cliente pide evidencia: quién, qué sistema y qué
periodo; cómo se analizó y qué quedó fuera; qué se encontró, en qué estado está y qué excepciones
se aprobaron, con su motivo y su responsable. Conciso: el detalle técnico completo sigue en el
informe técnico, el SARIF y el JSON.

No es una opinión de auditoría ni una certificación, y lo dice. Todo texto que llega del
repositorio o del formulario se trata como dato: se escapa antes de dibujarse.
"""

from __future__ import annotations

import html
import io
import re
from datetime import date, datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import CondPageBreak, KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

# Los mismos tokens del panel (web/src/index.css), en hexadecimal para el PDF.
BRAND, BRAND_BG = colors.HexColor("#7342d3"), colors.HexColor("#f4f1ff")
INK, MUTED, LINE, SOFT = colors.HexColor("#171717"), colors.HexColor("#636363"), colors.HexColor("#e5e5e5"), colors.HexColor("#f5f5f5")
SEVERITY = {  # texto, fondo
    "critical": (colors.HexColor("#ffffff"), colors.HexColor("#c21725")),
    "high": (colors.HexColor("#a34100"), colors.HexColor("#fff0e4")),
    "medium": (colors.HexColor("#8a4c00"), colors.HexColor("#fef4df")),
    "low": (colors.HexColor("#00649e"), colors.HexColor("#ebf5fd")),
    "info": (MUTED, SOFT),
}
SUCCESS, SUCCESS_BG = colors.HexColor("#006e42"), colors.HexColor("#e9f8ef")
SEVERITY_LABEL = {"critical": "Crítica", "high": "Alta", "medium": "Media", "low": "Baja", "info": "Info"}
ORDER = {level: index for index, level in enumerate(("critical", "high", "medium", "low", "info"))}
STATUS_LABEL = {"open": "Abierto", "in_progress": "En curso", "fixed": "Remediado", "false_positive": "Falso positivo",
                "accepted": "Riesgo aceptado", "excluded": "Fuera de alcance"}
FRAMEWORKS = {
    "soc2": ("SOC 2 Tipo II", [
        ("CC3.2", "Identificación y análisis de riesgos", "Hallazgos priorizados por severidad, explotación activa (CISA KEV) y probabilidad (EPSS)."),
        ("CC7.1", "Detección de vulnerabilidades y configuraciones", "Análisis del código, dependencias, secretos e infraestructura, con sus motores y cobertura."),
        ("CC8.1", "Gestión de cambios", "Revisión de lo que introduce cada cambio antes de integrarlo, cuando se usa en pull requests o CI."),
    ]),
    "iso27001": ("ISO/IEC 27001:2022", [
        ("A.8.8", "Gestión de vulnerabilidades técnicas", "Vulnerabilidades identificadas, evaluadas y en tratamiento, con su estado y responsable."),
        ("A.8.9", "Gestión de la configuración", "Revisión de infraestructura como código, contenedores y pipelines."),
        ("A.8.28", "Codificación segura", "Análisis estático del código propio y búsqueda de secretos."),
        ("A.8.29", "Pruebas de seguridad en desarrollo", "Pruebas automatizadas de seguridad integradas en el ciclo de desarrollo."),
    ]),
    "general": ("Gestión de vulnerabilidades", []),
}
DETAIL = ("none", "high", "all")
TEXT_LIMITS = {"title": 120, "organization": 120, "prepared_by": 80, "prepared_for": 120, "scope": 300}


class ReportError(ValueError):
    pass


def validate_options(raw: dict | None, *, default_by: str) -> dict:
    """Opciones del formulario, con valores por defecto: el informe se puede generar sin tocar nada."""
    raw = raw if isinstance(raw, dict) else {}
    unknown = set(raw) - {"framework", "detail", "include_exceptions", "period_from", "period_to", *TEXT_LIMITS}
    if unknown:
        raise ReportError("Opciones del informe inválidas")
    framework = raw.get("framework", "general")
    detail = raw.get("detail", "high")
    if framework not in FRAMEWORKS or detail not in DETAIL or not isinstance(raw.get("include_exceptions", True), bool):
        raise ReportError("Opciones del informe inválidas")
    options = {"framework": framework, "detail": detail, "include_exceptions": raw.get("include_exceptions", True)}
    for key, limit in TEXT_LIMITS.items():
        value = raw.get(key, "")
        if not isinstance(value, str) or len(value) > limit or any(not char.isprintable() for char in value):
            raise ReportError(f"Campo «{key}» inválido (hasta {limit} caracteres, sin saltos de línea)")
        options[key] = " ".join(value.split())
    options["prepared_by"] = options["prepared_by"] or default_by
    for key in ("period_from", "period_to"):
        value = raw.get(key) or ""
        if value:
            try:
                date.fromisoformat(value)
            except (TypeError, ValueError) as exc:
                raise ReportError("Fecha del periodo inválida (AAAA-MM-DD)") from exc
        options[key] = value
    if options["period_from"] and options["period_to"] and options["period_from"] > options["period_to"]:
        raise ReportError("El periodo termina antes de empezar")
    return options


def _t(value, limit: int = 400) -> str:
    """Texto sin confianza → marcado seguro de ReportLab (escapado, una línea, acotado)."""
    text = " ".join(str(value or "").split())
    if len(text) > limit:
        text = text[:limit].rsplit(" ", 1)[0] + "…"
    return html.escape(text, quote=False)


def _day(value) -> str:
    text = str(value or "")
    return text[:10] if re.match(r"\d{4}-\d{2}-\d{2}", text) else "—"


def status_of(finding: dict) -> str:
    lifecycle = finding.get("lifecycle") or {}
    if lifecycle.get("status") == "excluded":
        return "excluded"
    if lifecycle.get("status") == "fixed":
        return "fixed"
    return (finding.get("triage") or {}).get("status") or "open"


STYLE = {
    "eyebrow": ParagraphStyle("eyebrow", fontName="Helvetica-Bold", fontSize=8, leading=11, textColor=BRAND, spaceAfter=6),
    "title": ParagraphStyle("title", fontName="Helvetica-Bold", fontSize=20, leading=24, textColor=INK, spaceAfter=4),
    "subtitle": ParagraphStyle("subtitle", fontName="Helvetica", fontSize=9.5, leading=14, textColor=MUTED, spaceAfter=10),
    # Sin keepWithNext: ataría el título a la tabla entera y la mandaría completa a la página siguiente.
    # Antes de cada título hay un salto condicional (CondPageBreak) que evita títulos huérfanos.
    "h2": ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=11.5, leading=15, textColor=INK, spaceBefore=12, spaceAfter=6),
    "body": ParagraphStyle("body", fontName="Helvetica", fontSize=8.8, leading=13, textColor=INK, spaceAfter=4),
    "note": ParagraphStyle("note", fontName="Helvetica", fontSize=7.8, leading=11, textColor=MUTED, spaceAfter=4),
    "cell": ParagraphStyle("cell", fontName="Helvetica", fontSize=7.8, leading=10.5, textColor=INK),
    "cellmuted": ParagraphStyle("cellmuted", fontName="Helvetica", fontSize=7.3, leading=10, textColor=MUTED),
    "head": ParagraphStyle("head", fontName="Helvetica-Bold", fontSize=7.3, leading=10, textColor=MUTED),
    "label": ParagraphStyle("label", fontName="Helvetica", fontSize=7, leading=9, textColor=MUTED),
    "value": ParagraphStyle("value", fontName="Helvetica-Bold", fontSize=8.8, leading=11.5, textColor=INK),
    "kpi": ParagraphStyle("kpi", fontName="Helvetica-Bold", fontSize=17, leading=20),
    "kpilabel": ParagraphStyle("kpilabel", fontName="Helvetica", fontSize=7.3, leading=9.5, textColor=MUTED),
    "chip": ParagraphStyle("chip", fontName="Helvetica-Bold", fontSize=7, leading=9, alignment=1),
}
WIDTH = A4[0] - 36 * mm


def _grid(rows, widths, *, header=True, zebra=False) -> Table:
    table = Table(rows, colWidths=widths, hAlign="LEFT", repeatRows=1 if header else 0)
    style = [("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
             ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4), ("LINEBELOW", (0, 0), (-1, -1), 0.3, LINE)]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), SOFT), ("LINEBELOW", (0, 0), (-1, 0), 0.8, BRAND)]
    if zebra:
        style += [("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fafafa")])]
    table.setStyle(TableStyle(style))
    return table


def _chip(severity: str) -> Table:
    ink, fill = SEVERITY.get(severity, SEVERITY["info"])
    chip = Table([[Paragraph(f'<font color="{ink.hexval().replace("0x", "#")}">{SEVERITY_LABEL.get(severity, severity)}</font>', STYLE["chip"])]],
                 colWidths=[15 * mm], rowHeights=[4.6 * mm])
    chip.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), fill), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                              ("LEFTPADDING", (0, 0), (-1, -1), 1), ("RIGHTPADDING", (0, 0), (-1, -1), 1),
                              ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 0)]))
    return chip


def _kpis(items: list[tuple[str, int, colors.Color, colors.Color]]) -> Table:
    cells = [[Paragraph(f'<font color="{ink.hexval().replace("0x", "#")}">{value}</font>', STYLE["kpi"]), Paragraph(label, STYLE["kpilabel"])]
             for label, value, ink, _ in items]
    table = Table([[cell for cell in cells]], colWidths=[WIDTH / len(items)] * len(items), hAlign="LEFT")
    style = [("VALIGN", (0, 0), (-1, -1), "TOP"), ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
             ("LEFTPADDING", (0, 0), (-1, -1), 8)]
    for index, (_, _, _, fill) in enumerate(items):
        style += [("BACKGROUND", (index, 0), (index, 0), fill), ("LINEAFTER", (index, 0), (index, 0), 2, colors.white)]
    table.setStyle(TableStyle(style))
    return table


def _n(count: int, one: str, many: str) -> str:
    return f"{count} {one if count == 1 else many}"


def _risk(finding: dict) -> str:
    """Por qué importa. En dependencias, la descripción del aviso: el título ya repite su resumen."""
    advisory = finding.get("advisory") or {}
    if finding.get("scanner") == "sca" and advisory.get("details"):
        return advisory["details"]
    return finding.get("reason") or advisory.get("summary") or ""


def _fix(finding: dict) -> str:
    package = finding.get("package") or {}
    if package.get("fixed_version"):
        return f"Actualizar {package.get('name')} a {package['fixed_version']}"
    return finding.get("remediation") or "Revisar y corregir según la guía del hallazgo"


def render_audit_pdf(record: dict, findings: list[dict], options: dict, *, version: str) -> bytes:
    framework_label, controls = FRAMEWORKS[options["framework"]]
    findings = sorted(findings, key=lambda item: (ORDER.get(item.get("severity"), 9), str(item.get("path")), item.get("line") or 0))
    if len(findings) > 5000:
        raise ReportError("Demasiados hallazgos para un informe: filtra o elige menos (hasta 5000)")
    source = record.get("source") or {}
    system = options["scope"] or source.get("name") or "—"
    issued = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    analysed = _day(record.get("created_at"))
    period = (f"{options['period_from'] or '—'} a {options['period_to'] or issued}" if options["period_from"] or options["period_to"]
              else f"Análisis del {analysed}")
    counts = {level: sum(1 for item in findings if item.get("severity") == level) for level in ORDER}
    statuses = [status_of(item) for item in findings]
    fixed = statuses.count("fixed")
    excepted = sum(1 for status in statuses if status in ("accepted", "false_positive"))
    active = sum(1 for status in statuses if status in ("open", "in_progress"))
    kev = sum(1 for item in findings if item.get("kev"))

    eyebrow = "EVIDENCIA DE GESTIÓN DE VULNERABILIDADES" + (f"  ·  {framework_label.upper()}" if controls else "")
    story = [Paragraph(html.escape(eyebrow), STYLE["eyebrow"]),
             Paragraph(_t(options["title"] or "Evidencia de gestión de vulnerabilidades", 120), STYLE["title"]),
             Paragraph(_t(system, 200), STYLE["subtitle"])]
    meta = [("Organización", options["organization"] or "—"), ("Sistema / alcance", system), ("Periodo", period),
            ("Preparado por", options["prepared_by"] or "—"), ("Preparado para", options["prepared_for"] or "—"),
            ("Emitido", f"{issued} · ref. {str(record.get('id', ''))[:24]}")]
    story.append(_grid([[Paragraph(_t(label), STYLE["label"]) for label, _ in meta[:3]], [Paragraph(_t(value, 160), STYLE["value"]) for _, value in meta[:3]],
                        [Paragraph(_t(label), STYLE["label"]) for label, _ in meta[3:]], [Paragraph(_t(value, 160), STYLE["value"]) for _, value in meta[3:]]],
                       [WIDTH / 3] * 3, header=False))
    story += [Spacer(1, 10), Paragraph("Resumen", STYLE["h2"]),
              _kpis([("en el alcance", len(findings), INK, SOFT), ("críticas", counts["critical"], SEVERITY["critical"][1], colors.HexColor("#ffefed")),
                     ("altas", counts["high"], SEVERITY["high"][0], SEVERITY["high"][1]),
                     ("abiertas o en curso", active, INK, SOFT), ("remediadas", fixed, SUCCESS, SUCCESS_BG),
                     ("excepciones aprobadas", excepted, BRAND, BRAND_BG)]),
              Spacer(1, 6),
              Paragraph(_t(f"{_n(len(findings), 'hallazgo', 'hallazgos')} en el alcance de este informe: {_n(counts['critical'], 'crítico', 'críticos')}, "
                           f"{_n(counts['high'], 'alto', 'altos')}, {_n(counts['medium'], 'medio', 'medios')} y "
                           f"{_n(counts['low'] + counts['info'], 'bajo o informativo', 'bajos o informativos')}. "
                           f"Abiertos o en curso: {active}; remediados: {fixed}; con excepción aprobada: {excepted}."
                           + (f" {_n(kev, 'corresponde', 'corresponden')} a vulnerabilidades con explotación activa conocida (CISA KEV)." if kev else ""), 700), STYLE["body"])]
    if controls:
        story += [Paragraph(f"Controles relacionados · {html.escape(framework_label)}", STYLE["h2"]),
                  _grid([[Paragraph("Control", STYLE["head"]), Paragraph("Qué aporta esta evidencia", STYLE["head"])]]
                        + [[Paragraph(f"<b>{html.escape(code)}</b><br/>{html.escape(name)}", STYLE["cell"]), Paragraph(html.escape(text), STYLE["cell"])]
                           for code, name, text in controls], [42 * mm, WIDTH - 42 * mm]),
                  Paragraph("La relación con cada control es orientativa: la eficacia del control la evalúa el auditor con el resto de la "
                            "documentación del equipo (política, responsables, frecuencia y muestras del periodo).", STYLE["note"])]
    # Método y cobertura: qué se ejecutó y qué no, sin el volcado técnico.
    engines = [step for step in record.get("steps") or [] if (step.get("tool") or {}).get("version")]
    method = [f"Análisis estático del {analysed}, sin ejecutar el código ni enviarlo a servicios externos."]
    if engines:
        method.append("Motores: " + ", ".join(f"{step['name']}" for step in engines) + ".")
    if source.get("sha256"):
        method.append(f"Instantánea analizada: SHA-256 {source['sha256'][:16]}…")
    gaps = [step["name"] for step in record.get("steps") or [] if step.get("status") in ("not_tested", "inconclusive")]
    if gaps:
        method.append("No se pudo completar: " + ", ".join(gaps) + ". Esas áreas no equivalen a «sin hallazgos».")
    elif engines:
        method.append("Todos los motores del análisis se completaron.")
    if record.get("type") == "asset_state":
        method = [f"Estado acumulado del repositorio a {analysed}: reúne los análisis completos y las revisiones de pull requests, "
                  "con la fecha en que cada hallazgo se detectó y, si aplica, se remedió."]
    story += [Paragraph("Método y cobertura", STYLE["h2"]), *[Paragraph("•&nbsp;&nbsp;" + _t(item, 500), STYLE["body"]) for item in method]]
    # Hallazgos
    story.append(Paragraph(f"Hallazgos ({len(findings)})", STYLE["h2"]))
    if findings:
        rows = [[Paragraph(label, STYLE["head"]) for label in ("Severidad", "Hallazgo", "Ubicación", "Estado", "Detectado", "Acción recomendada")]]
        for item in findings:
            ids = ", ".join((item.get("cve") or [])[:2] or (item.get("ghsa") or [])[:1])
            rows.append([_chip(item.get("severity", "info")),
                         Paragraph(_t(item.get("title"), 140) + (f'<br/><font color="#636363">{_t(ids, 60)}</font>' if ids else ""), STYLE["cell"]),
                         Paragraph(_t(f"{item.get('path')}:{item.get('line')}" if item.get("scanner") != "sca" else item.get("path"), 90), STYLE["cellmuted"]),
                         Paragraph(STATUS_LABEL.get(status_of(item), status_of(item)), STYLE["cell"]),
                         Paragraph(_day((item.get("lifecycle") or {}).get("first_seen") or record.get("created_at")), STYLE["cellmuted"]),
                         Paragraph(_t(_fix(item), 160), STYLE["cell"])])
        story.append(_grid(rows, [19 * mm, 52 * mm, 34 * mm, 19 * mm, 17 * mm, WIDTH - 141 * mm], zebra=True))
    else:
        story.append(Paragraph("Ningún hallazgo en el alcance elegido.", STYLE["body"]))
    # Excepciones: lo primero que pregunta un auditor.
    exceptions = [item for item in findings if status_of(item) in ("accepted", "false_positive")]
    if options["include_exceptions"]:
        story.append(Paragraph(f"Excepciones y decisiones ({len(exceptions)})", STYLE["h2"]))
        if exceptions:
            rows = [[Paragraph(label, STYLE["head"]) for label in ("Hallazgo", "Decisión", "Motivo", "Decidido por", "Fecha", "Vence")]]
            for item in exceptions:
                decision = item.get("triage") or {}
                rows.append([Paragraph(_t(item.get("title"), 110), STYLE["cell"]), Paragraph(STATUS_LABEL[status_of(item)], STYLE["cell"]),
                             Paragraph(_t(decision.get("reason") or "—", 220), STYLE["cell"]), Paragraph(_t(decision.get("by") or "—", 40), STYLE["cellmuted"]),
                             Paragraph(_day(decision.get("at")), STYLE["cellmuted"]), Paragraph(_day(decision.get("expires_at")), STYLE["cellmuted"])])
            story.append(_grid(rows, [48 * mm, 22 * mm, WIDTH - 126 * mm, 22 * mm, 17 * mm, 17 * mm]))
        else:
            story.append(Paragraph("No hay riesgos aceptados ni falsos positivos declarados en el alcance.", STYLE["body"]))
    # Detalle: solo lo pedido (por defecto, críticos y altos).
    detailed = [] if options["detail"] == "none" else findings if options["detail"] == "all" else \
               [item for item in findings if item.get("severity") in ("critical", "high")]
    if detailed:
        story.append(Paragraph("Detalle" + (" de críticos y altos" if options["detail"] == "high" else ""), STYLE["h2"]))
        for item in detailed:
            references = [url for url in ((item.get("advisory") or {}).get("references") or [])[:2] if str(url).startswith("https://")]
            block = [Table([[_chip(item.get("severity", "info")), Paragraph(f"<b>{_t(item.get('title'), 160)}</b>", STYLE["body"])]],
                           colWidths=[18 * mm, WIDTH - 18 * mm], style=[("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 0)]),
                     Paragraph(_t(f"{item.get('path')}:{item.get('line')} · {STATUS_LABEL.get(status_of(item))} · {', '.join((item.get('cve') or [])[:3]) or item.get('rule_id')}", 200), STYLE["note"]),
                     Paragraph("<b>Riesgo:</b> " + _t(_risk(item), 450), STYLE["body"]),
                     Paragraph("<b>Corrección:</b> " + _t(_fix(item) if (item.get("package") or {}).get("fixed_version") else item.get("remediation"), 450), STYLE["body"])]
            if references:
                block.append(Paragraph("Referencias: " + " · ".join(_t(url, 90) for url in references), STYLE["note"]))
            story += [KeepTogether(block), Spacer(1, 6)]
    # Firmas
    story += [Spacer(1, 8), Paragraph("Revisión y aprobación", STYLE["h2"]),
              _grid([[Paragraph(label, STYLE["head"]) for label in ("Rol", "Nombre", "Firma", "Fecha")]]
                    + [[Paragraph(role, STYLE["cell"]), Paragraph(_t(name, 60), STYLE["cell"]), Paragraph("", STYLE["cell"]), Paragraph("", STYLE["cell"])]
                       for role, name in (("Preparado por", options["prepared_by"]), ("Revisado por", ""), ("Aprobado por", ""))],
                    [32 * mm, 50 * mm, WIDTH - 112 * mm, 30 * mm]),
              Spacer(1, 6),
              Paragraph("Evidencia técnica generada con herramientas automatizadas y revisada por el equipo. No constituye una opinión de "
                        "auditoría, una certificación ni una declaración de cumplimiento.", STYLE["note"])]

    # Un título de sección nunca queda solo al pie: si no caben unas filas debajo, pasa a la página siguiente.
    story = [part for flowable in story for part in ((CondPageBreak(32 * mm), flowable)
                                                     if isinstance(flowable, Paragraph) and flowable.style.name == "h2" else (flowable,))]
    output = io.BytesIO()
    title = options["title"] or f"Evidencia de gestión de vulnerabilidades · {system}"

    def frame(canvas, document):
        canvas.saveState()
        width, height = A4
        canvas.setFillColor(BRAND)
        canvas.rect(0, height - 4, width, 4, stroke=0, fill=1)
        canvas.setStrokeColor(LINE)
        canvas.line(18 * mm, 13 * mm, width - 18 * mm, 13 * mm)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(MUTED)
        canvas.drawString(18 * mm, 8.5 * mm, f"{title[:90]}  ·  {options['organization'][:40] or 'Tamandua'}")
        canvas.drawRightString(width - 18 * mm, 8.5 * mm, f"Tamandua {version}  ·  página {document.page}")
        canvas.restoreState()

    SimpleDocTemplate(output, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=18 * mm,
                      title=title[:120], author=options["prepared_by"][:80] or "Tamandua", subject=framework_label,
                      creator=f"Tamandua {version}").build(story, onFirstPage=frame, onLaterPages=frame)
    return output.getvalue()
