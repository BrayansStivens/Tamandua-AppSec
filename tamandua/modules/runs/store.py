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



def _check_id(run_id: str) -> str:
    if not isinstance(run_id, str) or len(run_id) != 32 or any(ch not in "0123456789abcdef" for ch in run_id):
        raise ValueError("ID de ejecución inválido")
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
            raise FileExistsError(f"La ejecución {record['id']} ya existe")
    return record


def save_record(data_dir: Path, record: dict) -> None:
    """Guarda el registro de una ejecución (progreso, estado, resultado) sin tocar su informe ni su SARIF."""
    values = _values(record)
    statement = insert(runs).values(tenant_id=TENANT, id=_check_id(record["id"]), **values)
    with db.transaction(data_dir) as connection:
        connection.execute(statement.on_conflict_do_update(index_elements=[runs.c.tenant_id, runs.c.id], set_={**values, "updated_at": func.now()}))


def _row(record: dict) -> dict:
    item = {key: record.get(key) for key in ("id", "type", "status", "created_at", "fixture", "summary")}
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
        text = func.lower(func.concat_ws(" ", runs.c.row["source"]["name"].astext, runs.c.row["fixture"].astext, runs.c.id, runs.c.row["variant"].astext))
        conditions.append(text.like(needle, escape="\\"))
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
    from tamandua.modules.runs.kinds import FINDING_RUNS
    if record.get("type") in FINDING_RUNS:
        record = apply_to_record(data_dir, record, asset_key(record))
    saved = _persist(data_dir, record, render_repository_report(record), render_repository_sarif(record),
                     replace=run_id is not None)
    # Toda ejecución terminada, venga de donde venga (trabajador o CLI), actualiza el registro de hallazgos.
    from tamandua.modules.findings.registry import apply
    changes = apply(data_dir, saved)
    # Lo nuevo que importa, a los canales configurados (Slack, Teams, webhook). En segundo plano: no retrasa nada.
    if changes.get("new"):
        from tamandua.modules.integrations import notifications
        from tamandua.modules.findings import triage
        opened = set(changes["new"])
        active = [item for item in triage.annotate(data_dir, saved).get("findings", []) if item["fingerprint"] in opened and triage.is_active(item)]
        notifications.on_run(saved, active, data_dir=data_dir)
    return saved


ACTION_LABEL = {"act": "Actuar ya", "attend": "Atender", "track": "Seguimiento"}
ACTION_ORDER = {"act": 0, "attend": 1, "track": 2}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _ordered_findings(record: dict) -> list[dict]:
    return sorted(record.get("findings", []), key=lambda item: (
        ACTION_ORDER.get((item.get("priority") or {}).get("action"), 3),
        SEVERITY_ORDER.get(item.get("severity"), 5), item.get("title", "")))


def _finding_block(finding: dict) -> list[str]:
    package = finding.get("package") or {}
    advisory = finding.get("advisory") or {}
    action = (finding.get("priority") or {}).get("action", "track")
    lines = [f"### {finding['title']}", "",
             f"**{finding['severity'].upper()}** · {ACTION_LABEL.get(action, action)} · `{finding['scanner']}` · `{finding['rule_id']}`"]
    identifiers = [*finding.get("cve", []), *[item for item in finding.get("ghsa", []) if item != finding["rule_id"]]]
    if identifiers:
        lines.append("Identificadores: " + ", ".join(f"`{item}`" for item in identifiers))
    if package.get("name"):
        fixed = package.get("fixed_version")
        lines.append(f"Paquete: `{package['name']}` {package.get('version')} ({package.get('ecosystem')}) · "
                     + (f"**corregido en {fixed}**" if fixed else "**sin versión corregida**") + f" · declarado en `{finding['path']}`")
    else:
        lines.append(f"Ubicación: `{finding['path']}:{finding['line']}`")
    source = finding.get("source") or {}
    if source.get("name"):
        name = source["name"].replace("[", "(").replace("]", ")")
        label = f"[{name}]({source['url']})" if str(source.get("url") or "").startswith("https://") else name
        lines.append(f"Fuente del aviso: {label} · {source.get('license') or 'licencia sin revisar'}")
    if advisory.get("cvss_score") is not None:
        lines.append(f"CVSS {advisory['cvss_score']} · `{advisory.get('cvss_vector')}`")
    if finding.get("kev"):
        kev = finding["kev"]
        lines.append(f"**CISA KEV** desde {kev.get('date_added')}" + (" · usado por ransomware" if kev.get("ransomware") else ""))
    if finding.get("epss"):
        lines.append(f"EPSS {finding['epss']['score']:.1%} (percentil {finding['epss']['percentile']:.0%})")
    if finding.get("cwe"):
        lines.append("CWE: " + ", ".join(f"CWE-{item}" for item in finding["cwe"]))
    triage = finding.get("triage") or {}
    if triage.get("status", "open") != "open" or triage.get("expired"):
        detail = f"Triage: **{TRIAGE_LABELS.get(triage['status'], triage['status'])}**"
        if triage.get("by"):
            detail += f" por {triage['by']} ({(triage.get('at') or '')[:10]})"
        if triage.get("expires_at"):
            detail += f" · caduca {triage['expires_at']}"
        if triage.get("expired"):
            detail += " · la aceptación anterior caducó"
        if triage.get("reason"):
            detail += f" · motivo: {triage['reason']}"
        lines.append(detail)
    lines += ["", "**Por qué esta prioridad:** " + "; ".join((finding.get("priority") or {}).get("factors", [])) or "—",
              "", f"**Remediación:** {finding['remediation']}"]
    from tamandua.modules.findings.fix_guide import guide
    fix = finding.get("fix") or guide(finding)
    if fix and (fix["commands"] or fix["example"] or len(fix["steps"]) > 1):
        # Mismo orden que el panel: pasos, la edición (ejemplo) y el comando al final.
        lines += ["", "**Cómo corregirlo:**", "", *[f"{index}. {step}" for index, step in enumerate([item for item in fix["steps"] if item], 1)]]
        example = fix["example"]
        if example and example.get("before"):
            lines += ["", "Antes:", "", f"```{example['language']}", example["before"], "```", "", "Después:"]
        if example:
            lines += ["", f"```{example['language']}", example["after"], "```"] + ([example["note"]] if example.get("note") else [])
        for command in fix["commands"]:
            lines += ["", f"{command['label']}:", "", "```", command["code"], "```"]
    if advisory.get("details"):
        lines += ["", advisory["details"][:800].replace("\n\n", "\n")]
    if advisory.get("references"):
        lines += ["", "Referencias: " + " · ".join(advisory["references"][:4])]
    return lines + [""]


def render_repository_report(record: dict) -> str:
    source = record["source"]
    summary = record["summary"]
    severities = summary.get("severities") or {}
    priorities = summary.get("priorities") or {}
    findings = _ordered_findings(record)
    image = source.get("image") or {}
    identity = (f"imagen `{image.get('reference')}`" + (f" · digest `{image['resolved_digest']}`" if image.get("resolved_digest") else "")
                if image else f"snapshot SHA-256 `{source.get('sha256')}`")
    lines = [f"# {'Análisis de imagen' if image else 'Análisis de código'} · {source['name']}", "",
             f"Run `{record['id']}` · {record['created_at']} · fuente `{source['provider']}` · {identity}",
             f"Estado: **{record['status']}** · {summary['files']} archivos · {summary['dependencies']} dependencias examinadas.", "",
             "## Resumen ejecutivo", "",
             "| Prioridad | Cantidad | | Severidad | Cantidad |", "|---|---|---|---|---|"]
    rows = [("Actuar ya", priorities.get("act", 0), "Crítica", severities.get("critical", 0)),
            ("Atender", priorities.get("attend", 0), "Alta", severities.get("high", 0)),
            ("Seguimiento", priorities.get("track", 0), "Media", severities.get("medium", 0)),
            ("", "", "Baja", severities.get("low", 0))]
    lines += [f"| {a} | {b} | | {c} | {d} |" for a, b, c, d in rows]
    lines += ["", f"- {summary.get('kev', 0)} hallazgos en el catálogo CISA KEV (explotación activa conocida).",
              f"- {summary.get('fixable', 0)} dependencias con versión corregida publicada.",
              f"- {len(findings)} hallazgos en total; cada uno lleva una huella estable para no duplicar tickets entre ejecuciones.", ""]
    if record.get("context"):
        lines += ["## Contexto declarado", "", record["context"], "",
                  "Descripción aportada por el equipo, no una verificación del sistema.", ""]
    active = [item for item in findings if (item.get("triage") or {}).get("status", "open") not in SUPPRESSED]
    suppressed = [item for item in findings if item not in active]
    lines += _findings_sections([dict(item) for item in active])
    if suppressed:
        # Cada decisión con quién la tomó y por qué: es lo primero que pregunta quien revisa.
        lines += ["## Descartados en triage", "",
                  f"{len(suppressed)} hallazgos marcados como falso positivo o riesgo aceptado, con quién lo decidió y por qué.", "",
                  "| Hallazgo | Decisión | Motivo | Por | Vence |", "|---|---|---|---|---|"]
        for finding in suppressed:
            triage = finding.get("triage") or {}
            lines.append(f"| {_md(finding['title'], 100)} | {_md(triage.get('status'), 20)} | {_md(triage.get('reason') or '—', 200)} | "
                         f"{_md(triage.get('by') or '—', 40)} | {_md(str(triage.get('expires_at') or '—')[:10], 12)} |")
        lines.append("")
    lines += ["## Cobertura de esta ejecución", ""]
    for index, step in enumerate(record["steps"], 1):
        lines += [f"{index}. **{step['name']}** · `{step['status']}`. {step['detail']}"]
    lines += ["", "### OWASP Web Top 10:2025", ""]
    for item in record["owasp_coverage"]:
        lines.append(f"- {item['id']} · {item['title']}: `{item['status']}` · {item['reason']}")
    lines += ["", "### Límites", "", *[f"- {item}" for item in record["limitations"]], ""]
    return "\n".join(lines + _sources_section(record.get("findings") or []))


def _md(value, limit: int = 160) -> str:
    """Celda de tabla Markdown: una línea, sin romper la tabla y acotada."""
    text = " ".join(str(value if value is not None else "").split()).replace("|", "\\|")
    return text if len(text) <= limit else text[:limit].rsplit(" ", 1)[0] + "…"


SEVERITY_TEXT = {"critical": "Crítica", "high": "Alta", "medium": "Media", "low": "Baja", "info": "Info"}
MD_DETAIL_LIMIT, MD_TABLE_LIMIT, MD_ANNEX_LIMIT = 150, 500, 600


def _findings_sections(active: list[dict]) -> list[str]:
    """Hallazgos como en el informe técnico en PDF: qué hacer primero, dependencias agrupadas por paquete con su
    comando, código con detalle solo de críticos y altos, y un índice compacto. El detalle completo de cada
    hallazgo sigue en el panel, el JSON, el SARIF y los tickets."""
    from tamandua.modules.findings.fix_guide import attach
    from tamandua.modules.findings.remediation import action, counts_text, fix_groups
    lines = ["## Hallazgos", ""]
    if not active:
        return lines + ["No se generaron hallazgos con las reglas y dependencias examinadas. La cobertura se detalla más abajo.", ""]
    attach(active)
    groups = fix_groups(active)
    lines += [f"{len(active)} hallazgos pendientes que se cierran con {len(groups)} acciones.", "", "### Qué hacer primero", "",
              "| Severidad | Qué | Dónde | Acción |", "|---|---|---|---|"]
    for entry in groups[:15]:
        item = entry["items"][0]
        what = (f"{entry['name']} {entry['version']} · {len(entry['items'])} avisos" if entry["kind"] == "package" else item.get("title"))
        where = entry["path"] if entry["kind"] == "package" else f"{item.get('path')}:{item.get('line')}"
        lines.append(f"| {SEVERITY_TEXT.get(entry['severity'], entry['severity'])}{' · KEV' if entry['kev'] else ''} | {_md(what, 100)} | "
                     f"`{_md(where, 90)}` | {_md(action(entry, short=True), 160)} |")
    packages = [entry for entry in groups if entry["kind"] == "package"]
    if packages:
        lines += ["", f"### Dependencias ({len(packages)} paquetes · {sum(len(entry['items']) for entry in packages)} avisos)", "",
                  "| Severidad | Paquete | Manifiesto | Avisos | Actualizar a | Comando |", "|---|---|---|---|---|---|"]
        for entry in packages:
            commands = [command["code"] for command in (entry["items"][0].get("fix") or {}).get("commands") or [] if command.get("label") == "Actualiza"]
            lines.append(f"| {SEVERITY_TEXT.get(entry['severity'], entry['severity'])}{' · KEV' if entry['kev'] else ''} | "
                         f"{_md(entry['name'], 60)} {_md(entry['version'], 30)} | `{_md(entry['path'], 80)}` | {_md(counts_text(entry['counts']), 80)} | "
                         f"{_md(entry['target'] or 'sin corrección', 40)} | {('`' + _md(commands[0], 120) + '`') if commands and '`' not in commands[0] else '—'} |")
    code = [item for item in active if not (item.get("scanner") == "sca" and (item.get("package") or {}).get("name"))]
    if code:
        serious = [item for item in code if item.get("severity") in ("critical", "high")]
        rest = [item for item in code if item.get("severity") not in ("critical", "high")]
        lines += ["", f"### Código, secretos e infraestructura ({len(code)})", ""]
        for finding in serious[:MD_DETAIL_LIMIT]:
            lines += _finding_block(finding)
        if len(serious) > MD_DETAIL_LIMIT:
            lines += [f"Se detallan {MD_DETAIL_LIMIT} de {len(serious)} críticos y altos; el resto está en el panel, el JSON y el SARIF.", ""]
        if rest:
            lines += [f"#### Medios y bajos ({len(rest)})", "", "| Severidad | Hallazgo | Ubicación | Corrección |", "|---|---|---|---|"]
            for item in rest[:MD_TABLE_LIMIT]:
                where = f"{item.get('path')}:{item.get('line')}"
                lines.append(f"| {SEVERITY_TEXT.get(item.get('severity'), item.get('severity'))} | {_md(item.get('title'), 100)} | "
                             f"`{_md(where, 90)}` | {_md(item.get('remediation'), 160)} |")
            if len(rest) > MD_TABLE_LIMIT:
                lines.append(f"| | … y {len(rest) - MD_TABLE_LIMIT} más en el panel | | |")
            lines.append("")
    advisories = [item for item in active if item.get("scanner") == "sca"]
    if advisories:
        lines += ["", f"### Anexo · Índice de vulnerabilidades ({len(advisories)})", "",
                  "| Identificador | Paquete | Severidad | CVSS | EPSS | KEV | Corregida en | Fuente |", "|---|---|---|---|---|---|---|---|"]
        for item in sorted(advisories, key=lambda entry: (list(SEVERITY_TEXT).index(entry.get("severity")) if entry.get("severity") in SEVERITY_TEXT else 9,
                                                           str((entry.get("package") or {}).get("name"))))[:MD_ANNEX_LIMIT]:
            package, advisory = item.get("package") or {}, item.get("advisory") or {}
            epss = (item.get("epss") or {}).get("score")
            identifier = ((item.get("cve") or [])[:1] or (item.get("ghsa") or [])[:1] or [item.get("rule_id")])[0]
            lines.append(f"| {_md(identifier, 40)} | {_md(package.get('name'), 60)} {_md(package.get('version'), 30)} | "
                         f"{SEVERITY_TEXT.get(item.get('severity'), '—')} | {advisory['cvss_score'] if isinstance(advisory.get('cvss_score'), (int, float)) else '—'} | "
                         f"{f'{epss * 100:.1f} %' if isinstance(epss, (int, float)) else '—'} | {'sí' if item.get('kev') else '—'} | "
                         f"{_md(package.get('fixed_version') or '—', 40)} | {_md((item.get('source') or {}).get('short') or '—', 20)} |")
        if len(advisories) > MD_ANNEX_LIMIT:
            lines.append(f"| … y {len(advisories) - MD_ANNEX_LIMIT} más en el JSON y el SARIF | | | | | | | |")
    return lines + [""]


def _sources_section(findings: list[dict]) -> list[str]:
    """Atribución de las bases de avisos usadas (licencias en THIRD_PARTY_NOTICES.md)."""
    from tamandua.modules.intel.data_sources import attribution
    lines = attribution(findings)
    return ["## Fuentes de los avisos", "", *[f"- {line}" for line in lines], ""] if lines else []


def render_asset_report(record: dict) -> str:
    """Exporta el registro acumulado sin presentarlo como un escaneo puntual."""
    findings = _ordered_findings(record)
    lifecycle = record.get("summary", {}).get("lifecycle") or {}
    lines = [f"# Estado actual de hallazgos · {record['source']['name']}", "",
             f"Activo: `{record['source']['id']}` · corte UTC: `{record.get('created_at') or 'sin fecha'}`",
             "", "## Alcance", "",
             "Vista acumulada del registro de hallazgos de este activo. Combina escaneos completos y revisiones de PR; "
             "no representa una prueba independiente ni demuestra cobertura continua.", "",
             "## Resumen", "",
             f"- {len(findings)} hallazgos incluidos en esta vista.",
             f"- {lifecycle.get('open', 0)} abiertos; {lifecycle.get('fixed', 0)} remediados; "
             f"{lifecycle.get('suppressed', 0)} descartados en triage; {lifecycle.get('excluded', 0)} excluidos.", "",
             "## Hallazgos", ""]
    if not findings:
        lines += ["La vista seleccionada no contiene hallazgos.", ""]
    for finding in findings:
        lines += _finding_block(finding)
        state = finding.get("lifecycle") or {}
        lines += [f"Ciclo de vida: **{state.get('status') or 'desconocido'}** · "
                  f"primera observación `{state.get('first_seen') or '—'}` · "
                  f"última observación `{state.get('last_seen') or '—'}`.", ""]
    lines += ["## Límites", "", "- El registro refleja solo las herramientas, rutas y repositorios analizados.",
              "- Consulta cada ejecución original para sus pasos, versiones y cobertura específica.", ""]
    return "\n".join(lines + _sources_section(findings))


def render_tickets(record: dict) -> list[dict]:
    """Un ticket por hallazgo, con huella estable: la forma que necesitará el conector de Jira."""
    jira_priority = {"act": "Highest", "attend": "High", "track": "Medium"}
    tickets = []
    for finding in _ordered_findings(record):
        # Lo descartado en triage o ya remediado no genera trabajo.
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
            "description": "\n".join(_finding_block(finding)),
            "references": (finding.get("advisory") or {}).get("references", []),
            "run_id": record["id"], "source": record["source"]["name"], "detected_at": record["created_at"],
        })
    return tickets


def _sarif_suppression(finding: dict) -> dict:
    """SARIF 2.1.0 §3.35: los descartes de triage viajan como supresiones externas aceptadas."""
    triage = finding.get("triage") or {}
    if triage.get("status") not in SUPPRESSED:
        return {}
    justification = f"{TRIAGE_LABELS[triage['status']]}: {triage.get('reason') or ''}".strip()
    return {"suppressions": [{"kind": "external", "status": "accepted", "justification": justification[:500]}]}


# SARIF 2.1.0: nivel del resultado y `security-severity` (0-10), que GitHub code scanning usa para ordenar y filtrar.
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0"}


def render_repository_sarif(record: dict) -> dict:
    from tamandua.version import VERSION
    findings = record["findings"]
    rules = {item["rule_id"]: {"id": item["rule_id"], "shortDescription": {"text": item["title"]},
                               "properties": {"security-severity": SECURITY_SEVERITY.get(item["severity"], "5.5"),
                                              "tags": ["security", item["scanner"]]}}
             for item in findings}
    results = [{"ruleId": item["rule_id"], "level": SARIF_LEVEL.get(item["severity"], "warning"), "message": {"text": item["reason"] or item["title"]},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": item["path"]},
                                                    "region": {"startLine": item["line"]}}}],
                "partialFingerprints": {"tamandua/v1": item["fingerprint"]},
                **_sarif_suppression(item),
                "properties": {"verdict": "candidate", "scanner": item["scanner"], "cwe": item["cwe"],
                               "owasp": item["owasp"]}} for item in findings]
    return {"$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
            "version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Tamandua", "version": VERSION,
                                                     "informationUri": "https://github.com/BrayansStivens/appsec-agent",
                                                     "rules": list(rules.values())}}, "results": results}]}


def render_profile_report(record: dict, profile: str, title: str = "") -> str:
    """Dossier técnico; no emite una opinión de auditoría ni certificación."""
    labels = {
        "soc2": "SOC 2 Tipo II",
        "iso27001": "ISO/IEC 27001:2022",
        "custom": "Personalizado",
    }
    if profile not in labels or record.get("type") not in ("repository_scan", "image_scan", "pr_review", "asset_state"):
        raise ValueError("Perfil o ejecución no compatible")
    if title and (len(title) > 100 or not all(ch.isprintable() and ch not in "#`[]<>" for ch in title)):
        raise ValueError("Título inválido")
    heading = title.strip() if title else f"Evidencia técnica para {labels[profile]}"
    is_state = record["type"] == "asset_state"
    technical_report = render_asset_report(record) if is_state else render_repository_report(record)
    scope = (f"`{record['source']['name']}`, registro acumulado de hallazgos; consultar ejecuciones originales para cobertura."
             if is_state else
             f"`{record['source']['name']}`, " + (f"imagen `{record['source']['image'].get('reference')}` leída del registro"
             if record["source"].get("image") else f"snapshot SHA-256 `{record['source'].get('sha256')}`") + "; análisis estático puntual.")
    profile_rows = {
        "soc2": [
            ("Diseño del control", "Objetivo, responsables y frecuencia", "Descripción aprobada del control y dueño"),
            ("Operación", "Fecha, fuente, pasos y hallazgos de esta ejecución", "Muestras distribuidas a lo largo del periodo de evaluación"),
            ("Excepciones", "Hallazgos y decisiones de triage", "Tickets, aprobaciones y prueba de remediación"),
        ],
        "iso27001": [
            ("Alcance del SGSI", "Activo y fuente analizada", "Alcance aprobado y relación con el inventario de activos"),
            ("Tratamiento de riesgos", "Hallazgos, severidad y triage", "Evaluación de riesgos y plan de tratamiento aprobados"),
            ("Mejora y seguimiento", "Pasos y límites del análisis puntual", "Declaración de aplicabilidad y evidencias de seguimiento"),
        ],
        "custom": [
            ("Alcance", "Activo, fecha y cobertura técnica", "Definir criterio y periodo de revisión"),
            ("Resultado", "Hallazgos y decisiones de triage", "Agregar validación y aprobación del responsable"),
        ],
    }[profile]
    lines = [f"# {heading}", "", f"Perfil: **{labels[profile]}** · {'Registro' if is_state else 'Run'}: `{record['id']}` · UTC: `{record['created_at']}`", "",
             "> Documento de apoyo para el equipo de seguridad. No es una auditoría SOC 2, una certificación ISO 27001 ni una opinión de cumplimiento.", "",
             "## Contexto para revisión", "",
             "- Organización y propietario del control: completar por el equipo responsable.",
             f"- Sistema y alcance: {scope}",
             "- Evidencia: " + ("estado acumulado, huellas de hallazgos y decisiones de triage; consultar cada ejecución para hash y pasos de prueba."
                              if is_state else "identificador de run, hash del código, pasos de prueba, observaciones y estado de cobertura."),
             "- Frecuencia y periodo de observación: " + ("registro acumulado; sus entradas no demuestran por sí solas operación continua del control."
                                                     if is_state else "una ejecución puntual; no demuestra operación continua del control."),
             "- Evaluación de aplicabilidad y controles: requiere revisión humana y documentación adicional.", "",
             "## Matriz de preparación de evidencia", "",
             "| Aspecto | Evidencia técnica en este dossier | Documentación aún necesaria |",
             "|---|---|---|",
             *[f"| {aspect} | {available} | {missing} |" for aspect, available, missing in profile_rows], "",
             "La matriz es una guía de preparación; no evalúa la eficacia de controles ni sustituye el criterio del auditor.", "",
             "## Registro técnico adjunto", "", technical_report]
    return "\n".join(lines)


def load_run(data_dir: Path, run_id: str) -> dict:
    with db.transaction(data_dir) as connection:
        record = connection.execute(select(runs.c.record).where(runs.c.tenant_id == TENANT, runs.c.id == _check_id(run_id))).scalar_one_or_none()
    if record is None:
        raise FileNotFoundError(f"Ejecución {run_id} no encontrada")
    return record


def list_runs(data_dir: Path) -> list[dict]:
    """Las filas de listado, de la más reciente a la más antigua."""
    with db.transaction(data_dir) as connection:
        return list(connection.execute(select(runs.c.row).where(runs.c.tenant_id == TENANT)
                                       .order_by(runs.c.created_at.desc(), runs.c.id.desc())).scalars())
