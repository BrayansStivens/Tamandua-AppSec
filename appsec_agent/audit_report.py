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
from datetime import date, datetime, timezone

from reportlab.lib.units import mm
from reportlab.platypus import CondPageBreak, KeepTogether, Paragraph, Spacer, Table

from .data_sources import attribution
from .remediation import action, counts_text, fix_groups
from .report_design import (BRAND, BRAND_BG, DANGER_BG, DISCLAIMER, INK, ORDER, SEVERITY, SOFT, STYLE, SUCCESS, SUCCESS_BG, WIDTH,
                            build, bullets, chip as _chip, coverage_gaps, day as _day, grid as _grid, h2, header, hexval, kpis as _kpis, listing, meta,
                            n as _n, signoff, t as _t)

STATUS_LABEL = {"open": "Abierto", "in_progress": "En curso", "fixed": "Remediado", "false_positive": "Falso positivo",
                "accepted": "Riesgo aceptado", "excluded": "Fuera de alcance"}
STATUS_PLURAL = {"open": "abiertos", "in_progress": "en curso", "fixed": "remediados", "false_positive": "falsos positivos",
                 "accepted": "aceptados", "excluded": "fuera de alcance"}
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
    "pci": ("PCI DSS 4.0.1", [
        ("6.2.4", "Prevenir ataques comunes en el software", "Análisis estático del código propio contra inyección, XSS, deserialización y demás fallos comunes."),
        ("6.3.1", "Identificar vulnerabilidades y clasificar su riesgo", "Hallazgos con severidad, explotación activa (CISA KEV) y probabilidad (EPSS)."),
        ("6.3.2", "Inventario del software y sus componentes", "Inventario de dependencias exportable como SBOM (CycloneDX) desde cada análisis."),
        ("6.3.3", "Parches críticos en el plazo de un mes", "Plazos de corrección por severidad y hallazgos fuera de plazo."),
    ]),
    "cra": ("Reglamento de Ciberresiliencia (UE) 2024/2847", [
        ("Anexo I, II.1", "Identificar y documentar vulnerabilidades y componentes", "Hallazgos por análisis e inventario de componentes exportable como SBOM CycloneDX."),
        ("Anexo I, II.2", "Abordar y remediar las vulnerabilidades sin demora", "Estado de cada vulnerabilidad, acción recomendada y plazos de corrección."),
        ("Anexo I, II.3", "Pruebas y revisiones de seguridad periódicas", "Análisis automatizados en cada cambio y en la rama principal, con su cobertura."),
        ("Art. 14", "Notificar vulnerabilidades explotadas activamente", "Insumo: vulnerabilidades del catálogo CISA KEV señaladas como explotación activa. El registro de las notificaciones está en la vista Cumplimiento de Tamandua."),
    ]),
    "br-cmn": ("Brasil · Res. CMN 4.893 (con los cambios de la 5.274/2025)", [
        ("Vulnerabilidades", "Prevención y tratamiento continuo de vulnerabilidades", "Hallazgos identificados, priorizados y con su estado y plazo de corrección."),
        ("Pruebas", "Pruebas de seguridad y plan de acción", "Análisis automatizados con su cobertura; acciones recomendadas por hallazgo."),
        ("Trazabilidad", "Trazabilidad de decisiones", "Excepciones y decisiones con motivo, responsable, fecha y caducidad."),
    ]),
    "cl-21663": ("Chile · Ley Marco de Ciberseguridad 21.663", [
        ("Gestión de riesgos", "Medidas para prevenir incidentes", "Vulnerabilidades del software identificadas y priorizadas por riesgo y explotación activa."),
        ("Mejora continua", "Revisión periódica de la seguridad", "Análisis en cada cambio y de la rama principal, con su cobertura y los plazos de corrección."),
        ("Evidencia", "Registro de medidas y decisiones", "Decisiones de triage con motivo, responsable y fecha, conservadas como historial."),
    ]),
    "co-sfc": ("Colombia · SFC, riesgo de ciberseguridad (CE 007 de 2018)", [
        ("Vulnerabilidades", "Gestión de vulnerabilidades técnicas", "Vulnerabilidades del código, dependencias e imágenes con severidad, estado y plazo."),
        ("Desarrollo seguro", "Seguridad en el ciclo de desarrollo", "Revisión de lo que introduce cada cambio antes de integrarlo y análisis de la rama principal."),
        ("Evidencia", "Registro para supervisión", "Informe con alcance, método, cobertura y decisiones, listo para revisión."),
    ]),
    "general": ("Gestión de vulnerabilidades", []),
}
DETAIL = ("none", "high", "all")
DETAIL_LIMIT = 40  # bloques de detalle: la tabla de hallazgos ya es la evidencia completa
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


def status_of(finding: dict) -> str:
    lifecycle = finding.get("lifecycle") or {}
    if lifecycle.get("status") == "excluded":
        return "excluded"
    if lifecycle.get("status") == "fixed":
        return "fixed"
    return (finding.get("triage") or {}).get("status") or "open"


def _risk(finding: dict) -> str:
    """Por qué importa. En dependencias, la descripción del aviso: el título ya repite su resumen."""
    advisory = finding.get("advisory") or {}
    if finding.get("scanner") == "sca" and advisory.get("details"):
        return advisory["details"]
    return finding.get("reason") or advisory.get("summary") or ""


def _short_title(finding: dict) -> str:
    """«pillow 10.3.0: Pillow: DoS via …» → «DoS via …»: el paquete ya está en la cabecera del grupo."""
    title = str(finding.get("title") or "")
    parts = [part.strip() for part in title.split(": ")]
    return parts[-1] if finding.get("scanner") == "sca" and len(parts) > 1 else title


def _status_text(items: list[dict]) -> str:
    states = [status_of(item) for item in items]
    if len(set(states)) == 1:
        return STATUS_LABEL.get(states[0], states[0])
    return ", ".join(f"{states.count(state)} {STATUS_PLURAL.get(state, state)}" for state in dict.fromkeys(states))


def _first_seen(items: list[dict], fallback) -> str:
    seen = sorted(_day((item.get("lifecycle") or {}).get("first_seen") or fallback) for item in items)
    return seen[0] if seen else "—"


def _group_cells(entry: dict, fallback_date) -> tuple[str, str]:
    """Texto del hallazgo (o del paquete con todos sus avisos) y su ubicación."""
    items = entry["items"]
    if entry["kind"] == "package" and len(items) > 1:
        text = (f"<b>{_t(entry['name'], 60)} {_t(entry['version'], 30)}</b> · {len(items)} vulnerabilidades ({counts_text(entry['counts'])})"
                f'<br/><font color="#636363">{_t(listing(entry["ids"], 4), 140)}</font>')
        return text, _t(entry["path"], 90)
    item = items[0]
    ids = ", ".join((item.get("cve") or [])[:2] or (item.get("ghsa") or [])[:1])
    text = _t(item.get("title"), 140) + (f'<br/><font color="#636363">{_t(ids, 60)}</font>' if ids else "")
    where = item.get("path") if item.get("scanner") == "sca" else f"{item.get('path')}:{item.get('line')}"
    return text, _t(where, 90)


SLA_NAMES = {"critical": "crítica", "high": "alta", "medium": "media", "low": "baja"}
SLA_LIMIT = 40


def _deadlines(groups: list[dict], summary: dict | None) -> list:
    """Plazos de corrección: la política y lo que está fuera de ella. Solo en el estado del repositorio (con fechas de detección)."""
    if not summary or not summary.get("days"):
        return []
    days = summary["days"]
    policy = ", ".join(f"{SLA_NAMES[level]} {_n(days[level], 'día', 'días')}" if days.get(level) else f"{SLA_NAMES[level]} sin plazo" for level in SLA_NAMES)
    late = []
    for entry in groups:
        overdue = [item["sla"] for item in entry["items"] if (item.get("sla") or {}).get("state") == "overdue"]
        if overdue:
            late.append((min(item["days_left"] for item in overdue), min(item["due"] for item in overdue), entry))
    late.sort(key=lambda row: (row[0], ORDER.get(row[2]["severity"], 9)))
    # Las mismas unidades que el panel (avisos) y, entre paréntesis, las acciones de la tabla: un paquete puede reunir varios avisos.
    items = [item for entry in groups for item in entry["items"]]
    state = lambda wanted: sum(1 for item in items if (item.get("sla") or {}).get("state") == wanted)
    running = sum(1 for item in items if item.get("sla"))
    overdue = state("overdue")
    story = [h2(f"Plazos de corrección ({_n(overdue, 'aviso', 'avisos')} fuera de plazo)"),
             Paragraph(_t(f"Política del espacio de trabajo: {policy}, contados desde la primera detección. Se aplican a lo abierto o "
                          f"en curso; lo remediado y las excepciones aprobadas no vencen. Con plazo corriendo: {_n(running, 'aviso', 'avisos')}; "
                          f"fuera de plazo: {_n(overdue, 'aviso', 'avisos')} en {_n(len(late), 'acción', 'acciones')}; "
                          f"vencen en los próximos 7 días: {_n(state('soon'), 'aviso', 'avisos')}.", 800), STYLE["body"])]
    if not late:
        return story + [Paragraph("Ningún hallazgo pendiente está fuera de plazo.", STYLE["body"])]
    rows = [[Paragraph(label, STYLE["head"]) for label in ("Severidad", "Hallazgo", "Detectado", "Vencía", "Retraso")]]
    for left, due, entry in late[:SLA_LIMIT]:
        text, _ = _group_cells(entry, None)
        rows.append([_chip(entry["severity"]), Paragraph(text, STYLE["cell"]), Paragraph(_first_seen(entry["items"], None), STYLE["cellmuted"]),
                     Paragraph(due, STYLE["cellmuted"]), Paragraph(_n(-left, "día", "días"), STYLE["cell"])])
    story.append(_grid(rows, [19 * mm, WIDTH - 83 * mm, 22 * mm, 22 * mm, 20 * mm], zebra=True))
    if len(late) > SLA_LIMIT:
        story.append(Paragraph(f"Se listan las {SLA_LIMIT} acciones con más retraso de {len(late)}; todas figuran en la tabla de hallazgos.", STYLE["note"]))
    return story


MALICIOUS_MARK = '<br/><font color="#b71824"><b>Paquete malicioso conocido (OpenSSF)</b></font>'
KEV_MARK = '<br/><font color="#b71824"><b>Explotación activa conocida (CISA KEV)</b></font>'


DEADLINE_WORDS = ("plazo", "Plazo")


def _controls(framework_label: str, controls: list, *, deadlines: bool) -> list:
    # Si algún control se apoya en los plazos, se dice si este informe los trae: la evidencia cuadra con lo entregado.
    cites = any(word in text for _, _, text in controls for word in DEADLINE_WORDS)
    note = [] if not cites else [Paragraph(
        "Los plazos de corrección están en la sección «Plazos de corrección» de este informe." if deadlines else
        "Este informe no incluye los plazos de corrección: genéralo desde el estado actual del repositorio (Hallazgos → Estado actual) "
        "para que los traiga.", STYLE["note"])]
    return [h2(f"Controles relacionados · {framework_label}"),
            _grid([[Paragraph("Control", STYLE["head"]), Paragraph("Qué aporta esta evidencia", STYLE["head"])]]
                  + [[Paragraph(f"<b>{html.escape(code)}</b><br/>{html.escape(name)}", STYLE["cell"]), Paragraph(html.escape(text), STYLE["cell"])]
                     for code, name, text in controls], [42 * mm, WIDTH - 42 * mm]),
            Paragraph("La relación con cada control es orientativa: la eficacia del control la evalúa el auditor con el resto de la "
                      "documentación del equipo (política, responsables, frecuencia y muestras del periodo).", STYLE["note"]), *note]


def _detail_block(entry: dict) -> list:
    items = entry["items"]
    item = items[0]
    if entry["kind"] == "package" and len(items) > 1:
        heading = f"<b>{_t(entry['name'], 60)} {_t(entry['version'], 30)} · {len(items)} vulnerabilidades</b>"
        where = f"{entry['path']} · {_status_text(items)} · {listing(entry['ids'], 5)}"
        risks = "; ".join(dict.fromkeys(_short_title(finding) for finding in sorted(items, key=lambda f: ORDER.get(f.get("severity"), 9))[:3]))
        risk = risks + (f"; y {len(items) - 3} avisos más" if len(items) > 3 else "")
    else:
        heading = f"<b>{_t(item.get('title'), 160)}</b>"
        where = f"{item.get('path')}:{item.get('line')} · {STATUS_LABEL.get(status_of(item))} · {', '.join((item.get('cve') or [])[:3]) or item.get('rule_id')}"
        risk = _risk(item)
    block = [Table([[_chip(entry["severity"]), Paragraph(heading, STYLE["body"])]], colWidths=[18 * mm, WIDTH - 18 * mm],
                   style=[("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 0)]),
             Paragraph(_t(where, 240), STYLE["note"]),
             Paragraph("<b>Riesgo:</b> " + _t(risk, 450), STYLE["body"]),
             Paragraph("<b>Corrección:</b> " + _t(action(entry), 450), STYLE["body"])]
    references = [url for url in ((item.get("advisory") or {}).get("references") or [])[:2] if str(url).startswith("https://")]
    if references and len(items) == 1:
        block.append(Paragraph("Referencias: " + " · ".join(_t(url, 90) for url in references), STYLE["note"]))
    return [KeepTogether(block), Spacer(1, 6)]


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
    groups = fix_groups(findings)

    story = header("Evidencia de gestión de vulnerabilidades" + (f"  ·  {framework_label}" if controls else ""),
                   options["title"] or "Evidencia de gestión de vulnerabilidades", system)
    story.append(meta([("Organización", options["organization"] or "—"), ("Sistema / alcance", system), ("Periodo", period),
                       ("Preparado por", options["prepared_by"] or "—"), ("Preparado para", options["prepared_for"] or "—"),
                       ("Emitido", f"{issued} · ref. {str(record.get('id', ''))[:24]}")]))
    story += [Spacer(1, 10), h2("Resumen"),
              _kpis([("en el alcance", len(findings), INK, SOFT), ("críticas", counts["critical"], SEVERITY["critical"][1], DANGER_BG),
                     ("altas", counts["high"], SEVERITY["high"][0], SEVERITY["high"][1]),
                     ("abiertas o en curso", active, INK, SOFT), ("remediadas", fixed, SUCCESS, SUCCESS_BG),
                     ("excepciones aprobadas", excepted, BRAND, BRAND_BG)]),
              Spacer(1, 6),
              Paragraph(_t(f"{_n(len(findings), 'hallazgo', 'hallazgos')} en el alcance de este informe: {_n(counts['critical'], 'crítico', 'críticos')}, "
                           f"{_n(counts['high'], 'alto', 'altos')}, {_n(counts['medium'], 'medio', 'medios')} y "
                           f"{_n(counts['low'] + counts['info'], 'bajo o informativo', 'bajos o informativos')}. "
                           f"Abiertos o en curso: {active}; remediados: {fixed}; con excepción aprobada: {excepted}."
                           + (f" {_n(kev, 'corresponde', 'corresponden')} a vulnerabilidades con explotación activa conocida (CISA KEV)." if kev else "")
                           + (f" Se agrupan en {_n(len(groups), 'acción', 'acciones')}: los avisos de una misma dependencia se cierran con una sola actualización."
                              if len(groups) < len(findings) else ""), 900), STYLE["body"])]
    if controls:
        story += _controls(framework_label, controls, deadlines=bool(((record.get("summary") or {}).get("sla") or {}).get("days")))
    # Método y cobertura: qué se ejecutó y qué no, sin el volcado técnico.
    engines = [step for step in record.get("steps") or [] if (step.get("tool") or {}).get("version")]
    method = [f"Análisis estático del {analysed}, sin ejecutar el código ni enviarlo a servicios externos."]
    if engines:
        method.append("Motores: " + ", ".join(f"{step['name']}" for step in engines) + ".")
    if source.get("sha256"):
        method.append(f"Instantánea analizada: SHA-256 {source['sha256'][:16]}…")
    gaps = coverage_gaps(record.get("steps") or [])
    if record.get("type") == "asset_state":
        method = [f"Estado acumulado del repositorio a {analysed}: reúne los análisis completos y las revisiones de pull requests, "
                  "con la fecha en que cada hallazgo se detectó y, si aplica, se remedió."]
    if gaps:
        method.append("No se completó del todo: " + ", ".join(gaps) + ". Esas áreas no equivalen a «sin hallazgos».")
    elif engines and all(step.get("status") == "completed" for step in engines):
        method.append("Todos los motores del análisis se completaron.")
    story += [h2("Método y cobertura"), *[Paragraph("•&nbsp;&nbsp;" + _t(item, 500), STYLE["body"]) for item in method]]
    sources = attribution(findings)
    if sources:
        story += [Paragraph("Fuentes de los avisos", STYLE["h3"]), *bullets([_t(line, 300) for line in sources], "note")]
    # Hallazgos: una fila por acción (una dependencia con todos sus avisos, o un hallazgo de código).
    story += [CondPageBreak(55 * mm), h2(f"Hallazgos ({len(findings)})")]  # sin título huérfano al pie de página
    if findings:
        rows = [[Paragraph(label, STYLE["head"]) for label in ("Severidad", "Hallazgo", "Ubicación", "Estado", "Detectado", "Acción recomendada")]]
        for entry in groups:
            text, where = _group_cells(entry, record.get("created_at"))
            text += (MALICIOUS_MARK if entry.get("malicious") else "") + (KEV_MARK if entry["kev"] else "")
            rows.append([_chip(entry["severity"]), Paragraph(text, STYLE["cell"]), Paragraph(where, STYLE["cellmuted"]),
                         Paragraph(_t(_status_text(entry["items"]), 60), STYLE["cell"]),
                         Paragraph(_first_seen(entry["items"], record.get("created_at")), STYLE["cellmuted"]),
                         Paragraph(_t(action(entry, short=True), 180), STYLE["cell"])])
        story.append(_grid(rows, [19 * mm, 52 * mm, 34 * mm, 19 * mm, 17 * mm, WIDTH - 141 * mm], zebra=True))
    else:
        story.append(Paragraph("Ningún hallazgo en el alcance elegido.", STYLE["body"]))
    story += _deadlines(groups, (record.get("summary") or {}).get("sla"))
    # Excepciones: lo primero que pregunta un auditor. Van una a una: cada decisión tiene su motivo.
    exceptions = [item for item in findings if status_of(item) in ("accepted", "false_positive")]
    if options["include_exceptions"]:
        story.append(h2(f"Excepciones y decisiones ({len(exceptions)})"))
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
    # Detalle: solo lo pedido (por defecto, críticos y altos), también agrupado.
    detailed = [] if options["detail"] == "none" else groups if options["detail"] == "all" else \
               [entry for entry in groups if entry["severity"] in ("critical", "high")]
    if detailed:
        story.append(h2("Detalle" + (" de críticos y altos" if options["detail"] == "high" else "")))
        for entry in detailed[:DETAIL_LIMIT]:
            story += _detail_block(entry)
        if len(detailed) > DETAIL_LIMIT:
            story.append(Paragraph(f"Se detallan las {DETAIL_LIMIT} primeras de {len(detailed)} acciones (explotación activa y severidad primero); "
                                   "todas están en la tabla de hallazgos y el detalle completo en el informe técnico.", STYLE["note"]))
    story += signoff(options["prepared_by"]) + [Spacer(1, 6), Paragraph(DISCLAIMER, STYLE["note"])]
    title = options["title"] or f"Evidencia de gestión de vulnerabilidades · {system}"
    return build(story, title=title, footer=f"{title[:90]}  ·  {options['organization'][:40] or 'Tamandua'}", version=version,
                 author=options["prepared_by"] or "Tamandua", subject=framework_label)


# --- informe consolidado (organización o varios repositorios) -----------------------------

def render_portfolio_pdf(items: list[dict], options: dict, *, version: str, scope_label: str, coverage: dict) -> bytes:
    """Una organización (o una selección de repositorios) en un solo documento.

    `items`: [{"name", "findings", "last_complete", "last_status"}] con los hallazgos del registro de cada
    repositorio. `coverage`: {"total": repositorios en GitHub o None, "missing": nombres sin análisis completo}.
    Lo que pregunta un auditor a este nivel: ¿se analiza todo?, ¿dónde está el riesgo?, ¿qué sigue abierto?"""
    framework_label, controls = FRAMEWORKS[options["framework"]]
    issued = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    period = (f"{options['period_from'] or '—'} a {options['period_to'] or issued}" if options["period_from"] or options["period_to"]
              else f"Estado al {issued}")
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
        # Lo que hay que atender primero, agrupado por corrección dentro de cada repositorio.
        open_items += [(item["name"], entry) for entry in fix_groups([finding for finding in pending if finding.get("severity") in ("critical", "high")])]
        exceptions += [(item["name"], finding) for finding, state in zip(findings, states) if state in ("accepted", "false_positive")]
        totals["critical"] += counts["critical"]; totals["high"] += counts["high"]; totals["open"] += len(pending)
        totals["fixed"] += fixed; totals["excepted"] += excepted
    rows.sort(key=lambda row: (-row[1]["critical"], -row[1]["high"], -row[2], row[0]))
    open_items.sort(key=lambda pair: (not pair[1]["kev"], ORDER.get(pair[1]["severity"], 9), -len(pair[1]["items"]), pair[0]))
    analysed = sum(1 for row in rows if row[5])
    known_total = coverage.get("total")

    story = header("Evidencia de gestión de vulnerabilidades · consolidado" + (f"  ·  {framework_label}" if controls else ""),
                   options["title"] or "Evidencia de gestión de vulnerabilidades", options["scope"] or scope_label)
    story.append(meta([("Organización", options["organization"] or "—"), ("Alcance", options["scope"] or scope_label), ("Periodo", period),
                       ("Preparado por", options["prepared_by"] or "—"), ("Preparado para", options["prepared_for"] or "—"), ("Emitido", issued)]))
    story += [Spacer(1, 10), h2("Resumen"),
              _kpis([("repositorios con análisis completo", f"{analysed} de {known_total}" if known_total else analysed, INK, SOFT),
                     ("críticas abiertas", totals["critical"], SEVERITY["critical"][1], DANGER_BG),
                     ("altas abiertas", totals["high"], SEVERITY["high"][0], SEVERITY["high"][1]),
                     ("abiertas o en curso", totals["open"], INK, SOFT), ("remediadas", totals["fixed"], SUCCESS, SUCCESS_BG),
                     ("excepciones aprobadas", totals["excepted"], BRAND, BRAND_BG)]),
              Spacer(1, 6),
              Paragraph(_t(f"{_n(len(rows), 'repositorio', 'repositorios')} en el informe; {_n(totals['open'], 'hallazgo pendiente', 'hallazgos pendientes')}, "
                           f"de los que {_n(totals['critical'], 'es crítico', 'son críticos')} y {totals['high']} altos. "
                           f"{_n(totals['fixed'], 'hallazgo remediado', 'hallazgos remediados')} y {_n(totals['excepted'], 'excepción aprobada', 'excepciones aprobadas')}.", 700), STYLE["body"])]
    # Cobertura: ¿se analiza todo? Es lo primero que se pregunta a nivel de organización.
    story.append(h2("Cobertura"))
    incomplete = [row[0] for row in rows if not row[5] and row[6]]
    lines = []
    if known_total:
        lines.append(f"{analysed} de {known_total} repositorios de la organización tienen al menos un análisis completo"
                     f" ({round(100 * analysed / known_total)} %).")
    else:
        lines.append(f"{analysed} de {len(rows)} repositorios del informe tienen al menos un análisis completo.")
    if incomplete:
        lines.append(f"Con análisis, pero ninguno completo (un motor no se ejecutó): {listing(incomplete, 30)}.")
    missing = coverage.get("missing") or []
    if missing:
        lines.append(f"Sin ningún análisis ({len(missing)}): {listing(missing, 40)}.")
    story += [Paragraph("•&nbsp;&nbsp;" + _t(line, 1200), STYLE["body"]) for line in lines]
    if controls:
        story += _controls(framework_label, controls, deadlines=False)
    sources = attribution([finding for item in items for finding in item["findings"]])
    story += [h2("Método"),
              Paragraph("•&nbsp;&nbsp;Análisis estático de cada repositorio (código, dependencias, secretos, infraestructura y pipelines), "
                        "sin ejecutar el código ni enviarlo a servicios externos.", STYLE["body"]),
              Paragraph("•&nbsp;&nbsp;El estado de cada repositorio reúne sus análisis completos y las revisiones de pull requests: un hallazgo "
                        "queda remediado cuando deja de aparecer en un análisis completo, nunca por uno incompleto.", STYLE["body"])]
    if sources:
        story += [Paragraph("Fuentes de los avisos", STYLE["h3"]), *bullets([_t(line, 300) for line in sources], "note")]
    # Por repositorio
    story.append(h2(f"Por repositorio ({len(rows)})"))
    table = [[Paragraph(label, STYLE["head"]) for label in ("Repositorio", "Crít.", "Altas", "Medias", "Bajas", "Abiertos", "Remed.", "Excep.", "Último completo")]]
    for name, counts, pending, fixed, excepted, last, _ in rows[:1000]:
        table.append([Paragraph(_t(name, 80), STYLE["cell"]),
                      *[Paragraph(f'<font color="{hexval(SEVERITY[level][1 if level == "critical" else 0])}"><b>{counts[level]}</b></font>' if counts[level] else "0",
                                  STYLE["cell"]) for level in ("critical", "high", "medium", "low")],
                      Paragraph(str(pending), STYLE["cell"]), Paragraph(str(fixed), STYLE["cellmuted"]), Paragraph(str(excepted), STYLE["cellmuted"]),
                      Paragraph(_day(last) if last else '<font color="#b71824">Sin análisis completo</font>', STYLE["cellmuted"])])
    story.append(_grid(table, [WIDTH - 125 * mm, 11 * mm, 12 * mm, 14 * mm, 12 * mm, 15 * mm, 14 * mm, 13 * mm, 26 * mm], zebra=True))
    # Críticos y altos abiertos, con el repositorio y agrupados por corrección: lo que hay que atender primero.
    pending_count = sum(len(entry["items"]) for _, entry in open_items)
    story.append(h2(f"Críticos y altos abiertos ({pending_count})"))
    if open_items:
        table = [[Paragraph(label, STYLE["head"]) for label in ("Severidad", "Repositorio", "Hallazgo", "Detectado", "Acción recomendada")]]
        for name, entry in open_items[:400]:
            text, _ = _group_cells(entry, None)
            text += (MALICIOUS_MARK if entry.get("malicious") else "") + (KEV_MARK if entry["kev"] else "")
            table.append([_chip(entry["severity"]), Paragraph(_t(name, 60), STYLE["cellmuted"]), Paragraph(text, STYLE["cell"]),
                          Paragraph(_first_seen(entry["items"], None), STYLE["cellmuted"]), Paragraph(_t(action(entry, short=True), 160), STYLE["cell"])])
        story.append(_grid(table, [19 * mm, 36 * mm, 57 * mm, 17 * mm, WIDTH - 129 * mm], zebra=True))
        if len(open_items) > 400:
            story.append(Paragraph(f"Se muestran 400 de {len(open_items)} acciones; el detalle completo está en el informe de cada repositorio.", STYLE["note"]))
    else:
        story.append(Paragraph("No hay hallazgos críticos ni altos abiertos.", STYLE["body"]))
    if options["include_exceptions"]:
        story.append(h2(f"Excepciones y decisiones ({len(exceptions)})"))
        if exceptions:
            table = [[Paragraph(label, STYLE["head"]) for label in ("Repositorio", "Hallazgo", "Decisión", "Motivo", "Decidido por", "Vence")]]
            for name, finding in exceptions[:500]:
                decision = finding.get("triage") or {}
                table.append([Paragraph(_t(name, 60), STYLE["cellmuted"]), Paragraph(_t(finding.get("title"), 100), STYLE["cell"]),
                              Paragraph(STATUS_LABEL[status_of(finding)], STYLE["cell"]), Paragraph(_t(decision.get("reason") or "—", 200), STYLE["cell"]),
                              Paragraph(_t(decision.get("by") or "—", 40), STYLE["cellmuted"]), Paragraph(_day(decision.get("expires_at")), STYLE["cellmuted"])])
            story.append(_grid(table, [32 * mm, 42 * mm, 20 * mm, WIDTH - 132 * mm, 21 * mm, 17 * mm]))
        else:
            story.append(Paragraph("No hay riesgos aceptados ni falsos positivos declarados.", STYLE["body"]))
    story += signoff(options["prepared_by"]) + [Spacer(1, 6), Paragraph(DISCLAIMER, STYLE["note"])]
    title = options["title"] or "Evidencia de gestión de vulnerabilidades"
    return build(story, title=title, footer=f"{title[:70]}  ·  {scope_label[:50]}", version=version,
                 author=options["prepared_by"] or "Tamandua", subject=framework_label)
