"""Ejecuciones del laboratorio sintético (tenant-api-lab): guardarlas y su informe/SARIF.

Vivían en el almacén de ejecuciones; el producto no las usa, así que están aquí y el almacén no depende del laboratorio.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from tamandua.modules.lab.engine import PROBES
from tamandua.modules.runs.store import _persist
from tamandua.modules.findings.triage import LABELS as TRIAGE_LABELS, SUPPRESSED  # noqa: F401 — usados por los informes


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
