"""Persistencia local de ejecuciones, sin aceptar nombres de archivo del usuario."""

from __future__ import annotations
from .triage import LABELS as TRIAGE_LABELS, SUPPRESSED

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .engine import PROBES


def _run_dir(data_dir: Path, run_id: str) -> Path:
    if len(run_id) != 32 or any(ch not in "0123456789abcdef" for ch in run_id):
        raise ValueError("ID de ejecución inválido")
    return data_dir / "runs" / run_id


def _write_atomic(path: Path, content: str) -> None:
    temp_path = path.with_name(path.name + ".tmp")
    with temp_path.open("x", encoding="utf-8") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    temp_path.replace(path)


def _persist(data_dir: Path, record: dict, report: str, sarif: dict | None = None, *, replace: bool = False) -> dict:
    run_dir = _run_dir(data_dir, record["id"])
    run_dir.mkdir(parents=True, exist_ok=replace)
    _write_atomic(run_dir / "report.md", report)
    if sarif is not None:
        _write_atomic(run_dir / "findings.sarif", json.dumps(sarif, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    _write_atomic(run_dir / "run.json", json.dumps(record, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    update_index(data_dir, record)
    return record


def _row(record: dict) -> dict:
    item = {key: record.get(key) for key in ("id", "type", "status", "created_at", "fixture", "summary")}
    for key in ("variant", "source", "context", "started_at", "finished_at", "pull_request", "trigger"):
        if key in record and record[key] is not None:
            item[key] = record[key]
    # La lista no lleva hallazgos: solo lo necesario para una fila.
    if isinstance(item.get("summary"), dict):
        item["summary"] = {key: value for key, value in item["summary"].items() if key != "tools"} | {"tools": item["summary"].get("tools", [])}
    return item


def _index_path(data_dir: Path) -> Path:
    return data_dir / "runs" / "index.json"


def update_index(data_dir: Path, record: dict) -> None:
    """Una fila por ejecución. Con mil escaneos, listar no puede leer mil archivos con todos sus hallazgos."""
    path = _index_path(data_dir)
    try:
        index = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    except (ValueError, OSError):
        index = {}
    index[record["id"]] = _row(record)
    path.parent.mkdir(parents=True, exist_ok=True)
    _write_atomic(path, json.dumps(index, ensure_ascii=False, sort_keys=True) + "\n")


def rebuild_index(data_dir: Path) -> dict:
    root = data_dir / "runs"
    index = {}
    if root.is_dir():
        for entry in root.iterdir():
            if not entry.is_dir() or entry.is_symlink():
                continue
            try:
                index[entry.name] = _row(load_run(data_dir, entry.name))
            except (ValueError, OSError, json.JSONDecodeError):
                continue
    _write_atomic(_index_path(data_dir), json.dumps(index, ensure_ascii=False, sort_keys=True) + "\n") if root.is_dir() else None
    return index


def page_runs(data_dir: Path, *, limit: int = 25, offset: int = 0, status: str | None = None,
              kind: str | None = None, query: str | None = None, asset: str | None = None) -> dict:
    rows = list_runs(data_dir)
    if asset:
        from .assets import asset_key
        rows = [row for row in rows if asset_key(row) == asset]
    if status:
        rows = [row for row in rows if row["status"] == status]
    if kind:
        kinds = set(kind.split(","))
        rows = [row for row in rows if row["type"] in kinds]
    if query:
        needle = query.strip().lower()
        rows = [row for row in rows if needle in f"{(row.get('source') or {}).get('name', '')} {row.get('fixture', '')} {row['id']} {row.get('variant', '')}".lower()]
    limit = max(1, min(limit, 200))
    offset = max(0, offset)
    return {"items": rows[offset:offset + limit], "total": len(rows), "limit": limit, "offset": offset}


def save_run(data_dir: Path, evaluation: dict) -> dict:
    run_id = uuid.uuid4().hex
    record = {
        "schema_version": "0.1.0",
        "id": run_id,
        "type": "fixture_evaluation",
        "status": "completed" if all(case["passed"] for case in evaluation["cases"]) else "failed",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "fixture": evaluation["fixture"],
        "fixture_version": evaluation["fixture_version"],
        "source_sha256": evaluation["source_sha256"],
        "summary": {
            "total": len(evaluation["cases"]),
            "passed": sum(case["passed"] for case in evaluation["cases"]),
            "failed": sum(not case["passed"] for case in evaluation["cases"]),
            "vulnerable_variants": sum(case["variant"] == "vulnerable" for case in evaluation["cases"]),
            "fixed_controls": sum(case["variant"] == "fixed" for case in evaluation["cases"]),
        },
        "cases": evaluation["cases"],
        "limitations": ["Ground truth conocido; no representa detección autónoma ni pentest de un cliente."],
    }
    return _persist(data_dir, record, render_report(record))


def save_scan(data_dir: Path, scan: dict) -> dict:
    record = {"schema_version": "0.2.0", "id": uuid.uuid4().hex,
              "created_at": datetime.now(timezone.utc).isoformat(), **scan}
    return _persist(data_dir, record, render_scan_report(record), render_sarif(record))


def save_repository_scan(data_dir: Path, scan: dict, *, run_id: str | None = None, created_at: str | None = None) -> dict:
    # Un escaneo en segundo plano ya tiene su identificador y su carpeta desde que se encoló.
    record = {"schema_version": "0.3.0", "id": run_id or uuid.uuid4().hex,
              "created_at": created_at or datetime.now(timezone.utc).isoformat(), **scan}
    # Rutas excluidas por un administrador: salen del informe, del SARIF y del panel, contadas en los límites.
    from .assets import asset_key
    from .exclusions import apply_to_record
    from .kinds import FINDING_RUNS
    if record.get("type") in FINDING_RUNS:
        record = apply_to_record(data_dir, record, asset_key(record))
    saved = _persist(data_dir, record, render_repository_report(record), render_repository_sarif(record),
                     replace=run_id is not None)
    # Toda ejecución terminada, venga de donde venga (trabajador o CLI), actualiza el registro de hallazgos.
    from .findings_registry import apply
    apply(data_dir, saved)
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
    lines += ["", f"**Por qué esta prioridad:** " + "; ".join((finding.get("priority") or {}).get("factors", [])) or "—",
              "", f"**Remediación:** {finding['remediation']}"]
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
    lines += ["## Hallazgos", ""]
    if not findings:
        lines += ["No se generaron hallazgos con las reglas y dependencias examinadas. La cobertura se detalla más abajo.", ""]
    for finding in active:
        lines += _finding_block(finding)
    if suppressed:
        lines += ["## Descartados en triage", "",
                  f"{len(suppressed)} hallazgos marcados como falso positivo o riesgo aceptado, con quién lo decidió y por qué.", ""]
        for finding in suppressed:
            lines += _finding_block(finding)
    lines += ["## Cobertura de esta ejecución", ""]
    for index, step in enumerate(record["steps"], 1):
        lines += [f"{index}. **{step['name']}** · `{step['status']}`. {step['detail']}"]
    lines += ["", "### OWASP Web Top 10:2025", ""]
    for item in record["owasp_coverage"]:
        lines.append(f"- {item['id']} · {item['title']}: `{item['status']}` · {item['reason']}")
    lines += ["", "### Límites", "", *[f"- {item}" for item in record["limitations"]], ""]
    return "\n".join(lines + _sources_section(record.get("findings") or []))


def _sources_section(findings: list[dict]) -> list[str]:
    """Atribución de las bases de avisos usadas (licencias en THIRD_PARTY_NOTICES.md)."""
    from .data_sources import attribution
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
    from .api.core import VERSION
    findings = record["findings"]
    rules = {item["rule_id"]: {"id": item["rule_id"], "shortDescription": {"text": item["title"]},
                               "properties": {"security-severity": SECURITY_SEVERITY.get(item["severity"], "5.5"),
                                              "tags": ["security", item["scanner"]]}}
             for item in findings}
    results = [{"ruleId": item["rule_id"], "level": SARIF_LEVEL.get(item["severity"], "warning"), "message": {"text": item["reason"] or item["title"]},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": item["path"]},
                                                    "region": {"startLine": item["line"]}}}],
                "partialFingerprints": {"appsecAgent/v1": item["fingerprint"]},
                **_sarif_suppression(item),
                "properties": {"verdict": "candidate", "scanner": item["scanner"], "cwe": item["cwe"],
                               "owasp": item["owasp"]}} for item in findings]
    return {"$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
            "version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Tamandua", "version": VERSION,
                                                     "informationUri": "https://github.com/BrayansStivens/appsec-agent",
                                                     "rules": list(rules.values())}}, "results": results}]}


def render_report(record: dict) -> str:
    summary = record["summary"]
    lines = ["# Evaluación del fixture", "", f"Run: `{record['id']}`", f"Fecha UTC: {record['created_at']}",
             f"Estado: **{record['status']}**", "", "## Alcance", "",
             f"Fixture sintético `{record['fixture']}` v{record['fixture_version']}.",
             "Se ejecutaron expectativas conocidas; no se descubrieron hallazgos nuevos.", "",
             f"Casos superados: **{summary['passed']}/{summary['total']}**.", "", "## Paso a paso", ""]
    for case in record["cases"]:
        request = case["request"]
        lines += [f"### {case['id']} · {case['category']} · {case['variant']}", "",
                  f"1. Crear instancia aislada de la variante `{case['variant']}`.",
                  f"2. Enviar `{request['method']} {request['path']}` con el usuario sintético `{request['token']}`.",
                  "3. Comparar observaciones con el ground truth:", ""]
        for check in case["checks"]:
            lines.append(f"   - `{check['assertion']}`: esperado `{check['expected']}`, observado `{check['observed']}`; {'OK' if check['passed'] else 'FALLÓ'}.")
        lines += ["", f"Resultado: **{'OK' if case['passed'] else 'FALLÓ'}**.", ""]
    lines += ["## Límites", "", *[f"- {item}" for item in record["limitations"]], ""]
    return "\n".join(lines)


def render_scan_report(record: dict) -> str:
    summary = record["summary"]
    lines = ["# Informe de pruebas dinámicas del laboratorio", "",
             f"Run: `{record['id']}` · UTC: {record['created_at']}",
             f"Objetivo: `tenant-api-lab` · variante `{record['variant']}` · SHA-256 de app.py: `{record['source_sha256']}`.",
             f"Estado: **{record['status']}**. Cobertura: {summary['executed']}/{summary['planned']} pruebas; "
             f"{summary['confirmed']} hallazgos reproducidos; {summary['needs_follow_up']} pendientes.",
             "", "## Método", "",
             "Cada prueba usa cuentas y datos sintéticos. Un candidato solo se reporta cuando "
             "la misma condición se reproduce en un segundo proceso fresco. El motor no lee `cases.json`.", "",
             "## Hallazgos reproducidos", ""]
    if not record["findings"]:
        message = ("No hay hallazgos reproducidos; existen pruebas pendientes de completar."
                   if summary["needs_follow_up"] else
                   "No se observó la condición vulnerable en los cinco escenarios probados.")
        lines += [message, ""]
    for finding in record["findings"]:
        lines += [f"### {finding['finding_id']} · {finding['title']}", "",
                  f"Severidad: **{finding['severity']}** · CWE-{finding['cwe'][0]} · {finding['owasp'][0]}.",
                  f"Impacto observado: {finding['impact']}", "", "Pasos de reproducción:", ""]
        for index, step in enumerate(finding["reproduction_steps"], 1):
            lines.append(f"{index}. Con `{step['token']}`, solicitar `{step['method']} {step['path']}`"
                         + (f" con cuerpo `{json.dumps(step['json'], sort_keys=True)}`." if "json" in step else "."))
        lines += ["", "Observaciones de descubrimiento y verificación:", ""]
        for attempt in finding["evidence"]:
            lines.append(f"- **{attempt['phase']}**: " + json.dumps(attempt["observations"], ensure_ascii=False, sort_keys=True))
        lines += [""]
    lines += ["## Cobertura y resultados negativos", ""]
    for item in record["coverage"]:
        lines.append(f"- `{item['probe_id']}` · `{item['endpoint']}` · **{item['status']}**"
                     + (f" · {item['reason']}" if item.get("reason") else ""))
    lines += ["", "## OWASP Web Top 10:2025", "",
              "Cada categoría se registra, incluso cuando no se ha probado. `partial` no implica cobertura completa.", ""]
    for item in record.get("owasp_coverage", []):
        lines.append(f"- **{item['id']} · {item['title']}**: `{item['status']}` · {item['reason']}"
                     + (f" · Pruebas: {', '.join(item['probe_ids'])}" if item["probe_ids"] else ""))
    lines += ["", "## Límites", "", *[f"- {item}" for item in record["limitations"]], ""]
    return "\n".join(lines)


def render_profile_report(record: dict, profile: str, title: str = "") -> str:
    """Dossier técnico; no emite una opinión de auditoría ni certificación."""
    labels = {
        "soc2": "SOC 2 Tipo II",
        "iso27001": "ISO/IEC 27001:2022",
        "custom": "Personalizado",
    }
    if profile not in labels or record.get("type") not in ("lab_scan", "repository_scan", "image_scan", "pr_review", "asset_state"):
        raise ValueError("Perfil o ejecución no compatible")
    if title and (len(title) > 100 or not all(ch.isprintable() and ch not in "#`[]<>" for ch in title)):
        raise ValueError("Título inválido")
    heading = title.strip() if title else f"Evidencia técnica para {labels[profile]}"
    is_state = record["type"] == "asset_state"
    is_repository = record["type"] in ("repository_scan", "image_scan", "pr_review", "asset_state")
    technical_report = (render_asset_report(record) if record["type"] == "asset_state" else
                        render_repository_report(record) if is_repository else render_scan_report(record))
    scope = (f"`{record['source']['name']}`, registro acumulado de hallazgos; consultar ejecuciones originales para cobertura."
             if record["type"] == "asset_state" else
             f"`{record['source']['name']}`, " + (f"imagen `{record['source']['image'].get('reference')}` leída del registro"
             if record["source"].get("image") else f"snapshot SHA-256 `{record['source'].get('sha256')}`") + "; análisis estático puntual."
             if is_repository else "`tenant-api-lab`, variante sintética indicada abajo; no incluye producción ni terceros.")
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


def render_sarif(record: dict) -> dict:
    rules = [{"id": probe.id, "name": probe.id,
              "shortDescription": {"text": probe.title},
              "properties": {"tags": [probe.owasp, f"CWE-{probe.cwe}"]}} for probe in PROBES]
    results = []
    for finding in sorted(record["findings"], key=lambda item: item["fingerprint"]):
        results.append({
            "ruleId": finding["rule_id"],
            "level": "error" if finding["severity"] in ("critical", "high") else "warning",
            "message": {"text": finding["impact"]},
            "locations": [{"logicalLocations": [{"name": finding["endpoint"]}]}],
            "partialFingerprints": {"appsecAgent/v1": finding["fingerprint"]},
            "properties": {"verdict": finding["verdict"], "confidence": finding["confidence"],
                           "cwe": finding["cwe"], "owasp": finding["owasp"],
                           "labVariant": record["variant"]},
        })
    return {"$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "Tamandua Lab", "version": record["engine_version"],
                                           "rules": rules}}, "results": results}]}


def load_run(data_dir: Path, run_id: str) -> dict:
    path = _run_dir(data_dir, run_id) / "run.json"
    return json.loads(path.read_text(encoding="utf-8"))


def list_runs(data_dir: Path) -> list[dict]:
    root = data_dir / "runs"
    if not root.is_dir():
        return []
    path = _index_path(data_dir)
    try:
        index = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None
    except (ValueError, OSError):
        index = None
    # Si el índice no existe o no cuadra con las carpetas, se reconstruye desde los archivos.
    folders = {entry.name for entry in root.iterdir() if entry.is_dir() and not entry.is_symlink()}
    if not isinstance(index, dict) or set(index) != folders:
        index = rebuild_index(data_dir)
    return sorted(index.values(), key=lambda item: (item.get("created_at") or "", item["id"]), reverse=True)
