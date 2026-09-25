"""Informes PDF legibles a partir del registro técnico en Markdown.

El texto se trata siempre como datos: los nombres, hallazgos y notas del usuario no
pueden inyectar etiquetas de ReportLab ni cargar recursos externos.
"""

from __future__ import annotations

import html
import io
import re

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

# Los tokens del sistema de diseño de informes (report_design); este renderizador queda para los
# informes que aún son Markdown (dossiers heredados, revisiones de PR).
from .report_design import BRAND as TEAL, INK, LINE, MUTED, SOFT

AMBER = colors.HexColor("#8a4c00")

STYLES = {
    "eyebrow": ParagraphStyle("eyebrow", fontName="Helvetica-Bold", fontSize=9, leading=13, textColor=TEAL, spaceAfter=8),
    "title": ParagraphStyle("title", fontName="Helvetica-Bold", fontSize=25, leading=29, textColor=INK, spaceAfter=11),
    "subtitle": ParagraphStyle("subtitle", fontName="Helvetica", fontSize=10, leading=15, textColor=MUTED, spaceAfter=15),
    "h2": ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=13, leading=18, textColor=INK, spaceBefore=16, spaceAfter=7, keepWithNext=True),
    "h3": ParagraphStyle("h3", fontName="Helvetica-Bold", fontSize=10.5, leading=15, textColor=INK, spaceBefore=11, spaceAfter=5, keepWithNext=True),
    "body": ParagraphStyle("body", fontName="Helvetica", fontSize=9, leading=14, textColor=INK, spaceAfter=6, wordWrap="CJK"),
    "small": ParagraphStyle("small", fontName="Helvetica", fontSize=8, leading=12, textColor=MUTED, spaceAfter=5, wordWrap="CJK"),
    "quote": ParagraphStyle("quote", fontName="Helvetica", fontSize=9, leading=14, textColor=AMBER, leftIndent=10, spaceBefore=5, spaceAfter=9, borderColor=LINE, borderWidth=0.5, borderPadding=8),
    "table": ParagraphStyle("table", fontName="Helvetica", fontSize=7.5, leading=11, textColor=INK, wordWrap="CJK"),
}


def _inline(value: str) -> str:
    # Primero escapar el texto sin confianza; solo después se agregan marcas propias.
    safe = html.escape(value, quote=False)
    safe = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", safe)
    safe = re.sub(r"`([^`]+)`", r'<font color="#7342d3">\1</font>', safe)
    return safe.replace("\n", "<br/>")


def _table(lines: list[str]) -> Table:
    rows = [[Paragraph(_inline(cell.strip()), STYLES["table"]) for cell in line.strip().strip("|").split("|")]
            for line in lines if not re.fullmatch(r"[\s|:-]+", line)]
    width = max(map(len, rows))
    for row in rows:
        row.extend([Paragraph("", STYLES["table"])] * (width - len(row)))
    available = A4[0] - 40 * mm
    table = Table(rows, colWidths=[available / width] * width, hAlign="LEFT", repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), SOFT),
        ("LINEBELOW", (0, 0), (-1, 0), 0.7, TEAL),
        ("LINEBELOW", (0, 1), (-1, -1), 0.3, LINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return table


def render_pdf(markdown: str, *, title: str, kind: str, reference: str = "") -> bytes:
    """Convierte un informe técnico en un PDF paginado; nunca afirma certificación."""
    if len(markdown) > 2_000_000:
        raise ValueError("Informe demasiado grande para exportar")
    output = io.BytesIO()
    doc = SimpleDocTemplate(output, pagesize=A4, rightMargin=20 * mm, leftMargin=20 * mm,
                            topMargin=24 * mm, bottomMargin=20 * mm,
                            title=title[:120], author="Tamandua", subject=kind)
    story = [Paragraph("TAMANDUA", STYLES["eyebrow"]),
             Paragraph(_inline(title), STYLES["title"]),
             Paragraph(_inline(kind + (f"  ·  {reference}" if reference else "")), STYLES["subtitle"]),
             HRFlowable(width="100%", thickness=1.2, color=TEAL, spaceAfter=12)]
    lines = markdown.splitlines()
    index = 0
    # El encabezado Markdown ya aparece en la portada compacta.
    if lines and lines[0].startswith("# "):
        index = 1
    while index < len(lines):
        line = lines[index].strip()
        if not line:
            index += 1
            continue
        if line.startswith("|"):
            group = []
            while index < len(lines) and lines[index].strip().startswith("|"):
                group.append(lines[index]); index += 1
            if len(group) >= 2:
                story += [_table(group), Spacer(1, 7)]
            continue
        if line.startswith("# "):
            story.append(Paragraph(_inline(line[2:]), STYLES["h2"]))
        elif line.startswith("## "):
            story.append(Paragraph(_inline(line[3:]), STYLES["h2"]))
        elif line.startswith("### "):
            story.append(Paragraph(_inline(line[4:]), STYLES["h3"]))
        elif line.startswith("> "):
            story.append(Paragraph(_inline(line[2:]), STYLES["quote"]))
        elif re.match(r"^(?:[-*] |\d+\. )", line):
            story.append(Paragraph("<font color='#7342d3'>•</font>  " + _inline(re.sub(r"^(?:[-*] |\d+\. )", "", line)), STYLES["body"]))
        else:
            story.append(Paragraph(_inline(line), STYLES["body"]))
        index += 1

    def frame(canvas, document):
        canvas.saveState()
        width, height = A4
        canvas.setFillColor(TEAL)
        canvas.rect(0, height - 4, width, 4, stroke=0, fill=1)
        canvas.setStrokeColor(LINE)
        canvas.line(20 * mm, 14 * mm, width - 20 * mm, 14 * mm)
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(MUTED)
        canvas.drawString(20 * mm, 9 * mm, "Tamandua  ·  Evidencia técnica; revisión humana requerida")
        canvas.drawRightString(width - 20 * mm, 9 * mm, f"{document.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=frame, onLaterPages=frame)
    return output.getvalue()
