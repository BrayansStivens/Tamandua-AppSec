"""Sistema de diseño de los informes PDF: una sola fuente para todos (técnico, auditoría, amenazas).

Reglas (las mismas del panel; ver .claude/skills/tamandua-design):
- Colores: solo los tokens del panel (web/src/index.css) en hexadecimal; nada de paletas sueltas.
  Texto ≥ 4,5:1 sobre su fondo; bordes y adornos que identifican algo ≥ 3:1.
- Estructura: primero la conclusión (cifras clave y qué hacer), después el detalle; lo exhaustivo va a un
  anexo o se queda en el JSON/SARIF. Se agrupa por acción (un paquete, una regla), no por aviso suelto.
- Nada de títulos huérfanos: antes de cada sección hay un salto condicional.
- Todo texto que llega de un repositorio, de un modelo o de un formulario es dato: se escapa (t()).
"""

from __future__ import annotations

import html
import io
import re

from reportlab.lib import colors
from reportlab.lib.pagesizes import A3, A4, landscape
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (BaseDocTemplate, CondPageBreak, Frame, NextPageTemplate, PageBreak, PageTemplate,
                                Paragraph, Spacer, Table, TableStyle)

# Tokens del panel en modo claro (web/src/index.css), en hexadecimal para el PDF y el SVG.
BRAND, BRAND_BG = colors.HexColor("#7342d3"), colors.HexColor("#f4f1ff")
INK, MUTED, LINE, SOFT = colors.HexColor("#171717"), colors.HexColor("#636363"), colors.HexColor("#e5e5e5"), colors.HexColor("#f5f5f5")
SUCCESS, SUCCESS_BG = colors.HexColor("#006e42"), colors.HexColor("#e9f8ef")
DANGER, DANGER_BG = colors.HexColor("#b71824"), colors.HexColor("#ffefed")
ATTENTION, ATTENTION_BG = colors.HexColor("#a34100"), colors.HexColor("#fff0e4")
SEVERITY = {  # texto, fondo
    "critical": (colors.HexColor("#ffffff"), colors.HexColor("#c21725")),
    "high": (ATTENTION, ATTENTION_BG),
    "medium": (colors.HexColor("#8a4c00"), colors.HexColor("#fef4df")),
    "low": (colors.HexColor("#00649e"), colors.HexColor("#ebf5fd")),
    "info": (MUTED, SOFT),
}
SEVERITY_LABEL = {"critical": "Crítica", "high": "Alta", "medium": "Media", "low": "Baja", "info": "Info"}
ORDER = {level: index for index, level in enumerate(("critical", "high", "medium", "low", "info"))}

STYLE = {
    "eyebrow": ParagraphStyle("eyebrow", fontName="Helvetica-Bold", fontSize=8, leading=11, textColor=BRAND, spaceAfter=6),
    "title": ParagraphStyle("title", fontName="Helvetica-Bold", fontSize=20, leading=24, textColor=INK, spaceAfter=4),
    "subtitle": ParagraphStyle("subtitle", fontName="Helvetica", fontSize=9.5, leading=14, textColor=MUTED, spaceAfter=10),
    # Sin keepWithNext: ataría el título a la tabla entera y la mandaría completa a la página siguiente.
    # Antes de cada título hay un salto condicional (CondPageBreak) que evita títulos huérfanos.
    "h2": ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=11.5, leading=15, textColor=INK, spaceBefore=12, spaceAfter=6),
    "h3": ParagraphStyle("h3", fontName="Helvetica-Bold", fontSize=9.5, leading=13, textColor=INK, spaceBefore=8, spaceAfter=3),
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
MARGIN = 18 * mm
WIDTH = A4[0] - 2 * MARGIN


def hexval(color: colors.Color) -> str:
    return color.hexval().replace("0x", "#")


def t(value, limit: int = 400) -> str:
    """Texto sin confianza → marcado seguro de ReportLab (escapado, una línea, acotado)."""
    text = " ".join(str(value or "").split())
    if len(text) > limit:
        text = text[:limit].rsplit(" ", 1)[0] + "…"
    return html.escape(text, quote=False)


def day(value) -> str:
    text = str(value or "")
    return text[:10] if re.match(r"\d{4}-\d{2}-\d{2}", text) else "—"


def n(count: int, one: str, many: str) -> str:
    return f"{count} {one if count == 1 else many}"


def listing(items: list[str], limit: int = 6) -> str:
    """«a, b, c y 4 más»: una enumeración acotada que no llena media página."""
    items = [item for item in items if item]
    if len(items) <= limit:
        return ", ".join(items[:-1]) + (" y " if len(items) > 1 else "") + (items[-1] if items else "")
    return ", ".join(items[:limit]) + f" y {len(items) - limit} más"


def grid(rows, widths, *, header=True, zebra=False) -> Table:
    table = Table(rows, colWidths=widths, hAlign="LEFT", repeatRows=1 if header else 0)
    style = [("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
             ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4), ("LINEBELOW", (0, 0), (-1, -1), 0.3, LINE)]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), SOFT), ("LINEBELOW", (0, 0), (-1, 0), 0.8, BRAND)]
    if zebra:
        style += [("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fafafa")])]
    table.setStyle(TableStyle(style))
    return table


def table(headers: list[str], rows: list[list], widths: list[float], *, zebra=True) -> Table:
    """Tabla con cabecera: celdas de texto ya marcadas (str) se envuelven en párrafos."""
    body = [[cell if not isinstance(cell, str) else Paragraph(cell, STYLE["cell"]) for cell in row] for row in rows]
    return grid([[Paragraph(label, STYLE["head"]) for label in headers], *body], widths, zebra=zebra)


def chip(severity: str, label: str | None = None) -> Table:
    ink, fill = SEVERITY.get(severity, SEVERITY["info"])
    cell = Table([[Paragraph(f'<font color="{hexval(ink)}">{label or SEVERITY_LABEL.get(severity, severity)}</font>', STYLE["chip"])]],
                 colWidths=[15 * mm], rowHeights=[4.6 * mm])
    cell.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), fill), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                              ("LEFTPADDING", (0, 0), (-1, -1), 1), ("RIGHTPADDING", (0, 0), (-1, -1), 1),
                              ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 0)]))
    return cell


def kpis(items: list[tuple[str, object, colors.Color, colors.Color]], width: float = WIDTH) -> Table:
    """Tarjetas de cifras clave: (etiqueta, valor, color del valor, fondo). Como mucho seis: más, no se leen."""
    cells = [[Paragraph(f'<font color="{hexval(ink)}">{value}</font>', STYLE["kpi"]), Paragraph(label, STYLE["kpilabel"])]
             for label, value, ink, _ in items]
    result = Table([cells], colWidths=[width / len(items)] * len(items), hAlign="LEFT")
    style = [("VALIGN", (0, 0), (-1, -1), "TOP"), ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
             ("LEFTPADDING", (0, 0), (-1, -1), 8)]
    for index, (_, _, _, fill) in enumerate(items):
        style += [("BACKGROUND", (index, 0), (index, 0), fill), ("LINEAFTER", (index, 0), (index, 0), 2, colors.white)]
    result.setStyle(TableStyle(style))
    return result


def severity_kpis(counts: dict, total_label: str, total, extra: list | None = None) -> Table:
    """Las tarjetas habituales: total, críticas, altas y lo que añada cada informe."""
    return kpis([(total_label, total, INK, SOFT), ("críticas", counts.get("critical", 0), SEVERITY["critical"][1], DANGER_BG),
                 ("altas", counts.get("high", 0), ATTENTION, ATTENTION_BG), *(extra or [])])


def meta(pairs: list[tuple[str, str]]) -> Table:
    """Cuadrícula de metadatos (quién, qué, cuándo), de tres en tres."""
    rows = []
    for start in range(0, len(pairs), 3):
        chunk = pairs[start:start + 3] + [("", "")] * (3 - len(pairs[start:start + 3]))
        rows += [[Paragraph(t(label), STYLE["label"]) for label, _ in chunk], [Paragraph(t(value, 160), STYLE["value"]) for _, value in chunk]]
    return grid(rows, [WIDTH / 3] * 3, header=False)


def header(eyebrow: str, title: str, subtitle: str = "") -> list:
    story = [Paragraph(html.escape(eyebrow.upper()), STYLE["eyebrow"]), Paragraph(t(title, 160), STYLE["title"])]
    if subtitle:
        story.append(Paragraph(t(subtitle, 400), STYLE["subtitle"]))
    return story


def h2(text: str) -> Paragraph:
    return Paragraph(html.escape(text), STYLE["h2"])


def bullets(items: list[str], style: str = "body") -> list:
    """Viñetas con texto ya escapado o marcado por el llamador."""
    return [Paragraph("•&nbsp;&nbsp;" + item, STYLE[style]) for item in items]


def signoff(prepared_by: str = "") -> list:
    return [Spacer(1, 8), h2("Revisión y aprobación"),
            grid([[Paragraph(label, STYLE["head"]) for label in ("Rol", "Nombre", "Firma", "Fecha")]]
                 + [[Paragraph(role, STYLE["cell"]), Paragraph(t(name, 60), STYLE["cell"]), Paragraph("", STYLE["cell"]), Paragraph("", STYLE["cell"])]
                    for role, name in (("Preparado por", prepared_by), ("Revisado por", ""), ("Aprobado por", ""))],
                 [32 * mm, 50 * mm, WIDTH - 112 * mm, 30 * mm])]


def wide_page(flowables: list, *, size=None) -> list:
    """Una página apaisada (p. ej. el diagrama) en medio del informe; después se vuelve a A4 vertical."""
    return [NextPageTemplate("wide-a3" if size == "a3" else "wide"), PageBreak(), *flowables, NextPageTemplate("normal"), PageBreak()]


def _guard_headings(story: list) -> list:
    # Un título nunca queda solo al pie: si no caben unas filas debajo, pasa a la página siguiente.
    room = {"h2": 32 * mm, "h3": 22 * mm}
    return [part for flowable in story for part in ((CondPageBreak(room[flowable.style.name]), flowable)
                                                    if isinstance(flowable, Paragraph) and flowable.style.name in room else (flowable,))]


def build(story: list, *, title: str, footer: str, version: str, author: str = "Tamandua", subject: str = "") -> bytes:
    """PDF A4 con la barra de marca, pie con título y página, y páginas apaisadas cuando se piden."""
    output = io.BytesIO()

    def frame(canvas, document):
        canvas.saveState()
        width, height = canvas._pagesize
        canvas.setFillColor(BRAND)
        canvas.rect(0, height - 4, width, 4, stroke=0, fill=1)
        canvas.setStrokeColor(LINE)
        canvas.line(MARGIN, 13 * mm, width - MARGIN, 13 * mm)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(MUTED)
        canvas.drawString(MARGIN, 8.5 * mm, footer[:120])
        canvas.drawRightString(width - MARGIN, 8.5 * mm, f"Tamandua {version}  ·  página {document.page}")
        canvas.restoreState()

    def template(name: str, size) -> PageTemplate:
        body = Frame(MARGIN, 18 * mm, size[0] - 2 * MARGIN, size[1] - 34 * mm, leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
        return PageTemplate(id=name, frames=[body], onPage=frame, pagesize=size)

    document = BaseDocTemplate(output, pagesize=A4, leftMargin=MARGIN, rightMargin=MARGIN, topMargin=16 * mm, bottomMargin=18 * mm,
                               title=title[:120], author=author[:80] or "Tamandua", subject=subject[:120], creator=f"Tamandua {version}")
    document.addPageTemplates([template("normal", A4), template("wide", landscape(A4)), template("wide-a3", landscape(A3))])
    document.build(_guard_headings(story))
    return output.getvalue()


def wide_size(name: str | None) -> tuple[float, float]:
    """Área útil de una página apaisada (para escalar un dibujo antes de colocarlo)."""
    width, height = landscape(A3 if name == "a3" else A4)
    return width - 2 * MARGIN, height - 34 * mm


STEP_STATUS = {"completed": "completado", "partial": "parcial", "not_tested": "no ejecutado", "inconclusive": "no concluyente",
               "failed": "falló", "pending": "pendiente", "skipped": "omitido"}
GAP_STATES = ("partial", "not_tested", "inconclusive", "failed")


def coverage_gaps(steps: list[dict]) -> list[str]:
    """Motores que no terminaron del todo, con su estado: lo que no se analizó no equivale a «sin hallazgos»."""
    return [f"{step.get('name')} ({STEP_STATUS.get(step.get('status'), step.get('status'))})" for step in steps
            if step.get("status") in GAP_STATES and (step.get("tool") or step.get("status") != "partial" or step.get("detail"))]


DISCLAIMER = ("Evidencia técnica generada con herramientas automatizadas y revisada por el equipo. No constituye una opinión de "
              "auditoría, una certificación ni una declaración de cumplimiento.")
