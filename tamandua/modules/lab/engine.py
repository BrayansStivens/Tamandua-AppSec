"""Cinco pruebas dinámicas específicas del laboratorio Tenant API.

Las pruebas no leen el catálogo de respuestas. Cada candidato se reproduce
en un segundo proceso nuevo antes de convertirse en hallazgo del laboratorio.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from tamandua.shared import paths
from tamandua.modules.scanning.owasp import WEB_TOP_10_2025
from tamandua.modules.lab.fixture import TRUSTED_HASHES, validate_fixture_code


@dataclass(frozen=True)
class Probe:
    id: str
    title: str
    category: str
    cwe: int
    owasp: str
    severity: str
    endpoint: str
    rationale: str
    steps: tuple[dict, ...]
    detects: Callable[[list[dict]], bool]


def _is_bola(obs: list[dict]) -> bool:
    return (obs[0]["status"] == 200 and obs[0]["tenant"] == "tenant-b"
            and obs[1]["status"] == 200 and obs[1]["tenant"] == "tenant-b")


def _is_bfla(obs: list[dict]) -> bool:
    return obs[0]["status"] == 200 and obs[1]["status"] == 200


def _is_exposure(obs: list[dict]) -> bool:
    return obs[0]["status"] == 200 and "support_pin" in obs[0]["json_keys"]


def _is_mass_assignment(obs: list[dict]) -> bool:
    return (obs[0]["status"] == 200 and obs[0]["role"] == "admin"
            and obs[1]["status"] == 200 and obs[1]["role"] == "admin")


def _is_sqli(obs: list[dict]) -> bool:
    return (obs[0]["status"] == 200 and "tenant-b" in obs[0]["document_tenants"]
            and obs[1]["status"] == 200 and obs[1]["document_tenants"] == ["tenant-a"])


PROBES = (
    Probe("BOLA", "Acceso a documento de otra organización", "BOLA", 639, "API1:2023", "high",
          "GET /api/documents/{id}", "El miembro de tenant-a leyó un documento de tenant-b.",
          ({"method": "GET", "path": "/api/documents/2", "token": "token-alice"},
           {"method": "GET", "path": "/api/documents/2", "token": "token-bob"}), _is_bola),
    Probe("BFLA", "Acceso de miembro a función administrativa", "BFLA", 862, "API5:2023", "high",
          "POST /api/admin/reports", "Un miembro obtuvo el mismo acceso a la función que un administrador.",
          ({"method": "POST", "path": "/api/admin/reports", "token": "token-alice"},
           {"method": "POST", "path": "/api/admin/reports", "token": "token-admin"}), _is_bfla),
    Probe("EXPOSURE", "Campo de soporte expuesto en el perfil", "sensitive_data_exposure", 200,
          "API3:2023", "medium", "GET /api/me", "La respuesta del perfil incluyó un campo sensible de soporte.",
          ({"method": "GET", "path": "/api/me", "token": "token-alice"},), _is_exposure),
    Probe("MASS", "Escalada de rol mediante actualización del perfil", "mass_assignment", 915,
          "API3:2023", "high", "PATCH /api/me", "Un miembro cambió su rol a admin y el cambio persistió.",
          ({"method": "PATCH", "path": "/api/me", "token": "token-alice", "json": {"role": "admin"}},
           {"method": "GET", "path": "/api/me", "token": "token-alice"}), _is_mass_assignment),
    Probe("SQLI", "Consulta manipulada cruza la frontera entre organizaciones", "sql_injection", 89,
          "A05:2025", "high", "GET /api/search", "Una búsqueda manipulada devolvió documentos de tenant-b; la búsqueda de control permaneció en tenant-a.",
          ({"method": "GET", "path": "/api/search?q=%25%27%20OR%201%3D1%20--", "token": "token-alice"},
           {"method": "GET", "path": "/api/search?q=Roadmap", "token": "token-alice"}), _is_sqli),
)



def _owasp_coverage(probe_coverage: list[dict]) -> list[dict]:
    by_id = {item["probe_id"]: item for item in probe_coverage}
    result = []
    for category, title, probe_ids in WEB_TOP_10_2025:
        if not probe_ids:
            status, reason = "not_tested", "No hay prueba implementada para esta categoría"
        elif any(by_id[probe_id]["status"] == "needs_follow_up" for probe_id in probe_ids):
            status, reason = "inconclusive", "Una o más pruebas específicas quedaron incompletas"
        else:
            status, reason = "partial", "Solo escenarios específicos del fixture; no cubre la categoría completa"
        result.append({"id": category, "title": title, "status": status,
                       "probe_ids": list(probe_ids), "reason": reason})
    return result


class ProbeError(RuntimeError):
    pass


def _run_probe(fixture_dir: Path, variant: str, steps: tuple[dict, ...]) -> list[dict]:
    task = {"fixture": str(fixture_dir), "variant": variant, "steps": steps}
    try:
        process = subprocess.run(
            [sys.executable, "-m", "tamandua.modules.lab.worker"],
            input=json.dumps(task), capture_output=True, text=True, timeout=8,
            cwd=paths.ROOT, check=False,
            env={"PYTHONIOENCODING": "utf-8"},
        )
    except subprocess.TimeoutExpired as exc:
        raise ProbeError("La prueba excedió ocho segundos") from exc
    if process.returncode != 0:
        raise ProbeError("El proceso de prueba terminó con error")
    try:
        observations = json.loads(process.stdout)["observations"]
    except (ValueError, KeyError, TypeError) as exc:
        raise ProbeError("Respuesta del proceso de prueba inválida") from exc
    if not isinstance(observations, list) or len(observations) != len(steps):
        raise ProbeError("Cantidad de observaciones inesperada")
    return observations


def _fingerprint(probe: Probe) -> str:
    identity = f"tenant-api-lab|{probe.id}|{probe.endpoint}|CWE-{probe.cwe}"
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def scan_fixture(fixture_dir: Path, variant: str) -> dict:
    if variant not in ("vulnerable", "fixed"):
        raise ValueError("Variante de laboratorio inválida")
    fixture_dir = validate_fixture_code(fixture_dir)
    coverage = []
    findings = []
    for probe in PROBES:
        entry = {"probe_id": probe.id, "endpoint": probe.endpoint, "category": probe.category,
                 "steps": list(probe.steps), "status": "needs_follow_up", "attempts": []}
        try:
            discovery = _run_probe(fixture_dir, variant, probe.steps)
            entry["attempts"].append({"phase": "discovery", "observations": discovery})
            if probe.detects(discovery):
                replay = _run_probe(fixture_dir, variant, probe.steps)
                entry["attempts"].append({"phase": "verification", "observations": replay})
                if probe.detects(replay):
                    entry["status"] = "reported"
                    fingerprint = _fingerprint(probe)
                    findings.append({
                        "finding_id": fingerprint[:16], "fingerprint": fingerprint,
                        "rule_id": probe.id, "title": probe.title, "category": probe.category,
                        "cwe": [probe.cwe], "owasp": [probe.owasp], "severity": probe.severity,
                        "confidence": 9, "verdict": "confirmed", "state": "open",
                        "endpoint": probe.endpoint, "impact": probe.rationale,
                        "evidence": entry["attempts"], "reproduction_steps": list(probe.steps),
                    })
                else:
                    entry["status"] = "needs_follow_up"
                    entry["reason"] = "El segundo proceso no reprodujo el candidato"
            else:
                entry["status"] = "no_issue_observed"
        except ProbeError as exc:
            entry["reason"] = str(exc)
        coverage.append(entry)
    incomplete = any(item["status"] == "needs_follow_up" for item in coverage)
    return {
        "type": "lab_scan", "fixture": "tenant-api-lab", "variant": variant,
        "source_sha256": TRUSTED_HASHES["app.py"], "engine_version": "lab-probes-0.1.0",
        "status": "incomplete" if incomplete else "completed",
        "summary": {
            "planned": len(PROBES), "executed": len(PROBES) - sum(item["status"] == "needs_follow_up" for item in coverage),
            "confirmed": len(findings),
            "no_issue_observed": sum(item["status"] == "no_issue_observed" for item in coverage),
            "needs_follow_up": sum(item["status"] == "needs_follow_up" for item in coverage),
            "llm_cost_usd": 0,
        },
        "coverage": coverage, "owasp_coverage": _owasp_coverage(coverage), "findings": findings,
        "limitations": [
            "Pruebas diseñadas exclusivamente para tenant-api-lab; no prueban capacidad de descubrimiento general.",
            "El proceso separado aísla estado entre reproducciones, pero no es una sandbox para código de clientes.",
            "Una prueba sin hallazgo solo cubre el escenario y los parámetros indicados.",
        ],
    }
