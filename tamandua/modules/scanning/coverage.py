"""Cobertura OWASP Web Top 10:2025 calculada de lo que de verdad corrió.

Cada categoría se marca según los motores y reglas que se ejecutaron y los
hallazgos que produjeron, no con una frase genérica. Las reglas propias declaran
su categoría en `metadata.owasp`; aquí se cuentan por categoría leyendo los
archivos de reglas (formato propio, así que basta una expresión regular).
"""

from __future__ import annotations

import re
from functools import lru_cache

from tamandua.shared import paths
from tamandua.modules.scanning.owasp import WEB_TOP_10_2025

RULES_DIR = paths.RULES_DIR
RULE_LINE = re.compile(r"^  - id: (?P<id>\S+)|^\s+metadata: \{.*?owasp: \"(?P<owasp>A\d\d):2025\"", re.M)
UNTESTABLE = {
    "A06": "Diseño inseguro: requiere modelado de amenazas y revisión de arquitectura, no lo detecta un análisis estático.",
    "A09": "Registro y alertas: sin reglas estáticas todavía; se evalúa en revisión de diseño y en pruebas dinámicas.",
    "A10": "Manejo de condiciones excepcionales: sin reglas estáticas todavía; requiere pruebas dinámicas o revisión manual.",
}


@lru_cache(maxsize=1)
def rules_by_category() -> dict[str, int]:
    """Cuántas reglas propias apuntan a cada categoría OWASP."""
    counts: dict[str, int] = {}
    for path in sorted(RULES_DIR.glob("*.yml")):
        current = None
        for match in RULE_LINE.finditer(path.read_text(encoding="utf-8")):
            if match.group("id"):
                current = match.group("id")
            elif current and match.group("owasp"):
                counts[match.group("owasp")] = counts.get(match.group("owasp"), 0) + 1
                current = None
    return counts


def _names(tools: tuple[str, ...]) -> str:
    return " y ".join(tools) if len(tools) <= 2 else ", ".join(tools[:-1]) + f" y {tools[-1]}"


def owasp_coverage(findings: list[dict], *, sast_ran: bool, sca_status: str, iac_ran: bool,
                   iac_files: int, secrets_ran: bool, engines: bool, iac_tools: tuple[str, ...] = ("Trivy",),
                   cicd_tools: tuple[str, ...] = (), pipeline_files: int = 0) -> list[dict]:
    rules = rules_by_category() if sast_ran else {}
    per_category: dict[str, int] = {}
    for finding in findings:
        for category in finding.get("owasp", []):
            per_category[category[:3]] = per_category.get(category[:3], 0) + 1
    result = []
    for identifier, title in WEB_TOP_10_2025:
        found = per_category.get(identifier, 0)
        parts, status = [], "not_tested"
        if identifier == "A03":
            if sca_status in ("partial", "completed"):
                status = "partial"
                parts.append("dependencias resueltas por Trivy con versión corregida, CVSS, CISA KEV y EPSS" if engines
                             else "dependencias consultadas en OSV")
            elif sca_status == "inconclusive":
                status = "inconclusive"
                parts.append("la consulta de dependencias no concluyó")
            else:
                parts.append("sin manifiestos de dependencias analizables o sin autorización para consultarlos")
            if cicd_tools and pipeline_files:
                status = "partial" if status == "not_tested" else status
                parts.append(f"pipelines de CI/CD revisados por {_names(cicd_tools)} en {pipeline_files} archivo(s)")
        if identifier == "A02":
            if iac_ran and iac_files:
                status = "partial"
                parts.append(f"configuración de infraestructura revisada por {_names(iac_tools)} en {iac_files} archivo(s)")
            elif iac_ran:
                parts.append(f"{_names(iac_tools)} no encontraron archivos de infraestructura (Dockerfile, Kubernetes, Terraform, CloudFormation) en el snapshot"
                             if len(iac_tools) > 1 else f"{_names(iac_tools)} no encontró archivos de infraestructura (Dockerfile, Kubernetes, Terraform) en el snapshot")
            if rules.get("A02"):
                status = "partial"
                parts.append(f"{rules['A02']} reglas propias de configuración")
        if identifier == "A04":
            if secrets_ran:
                status = "partial"
                parts.append("secretos con Gitleaks y Trivy" if engines else "secretos por patrones internos")
            if rules.get("A04"):
                status = "partial"
                parts.append(f"{rules['A04']} reglas propias de criptografía y secretos")
        if identifier in ("A01", "A05", "A07", "A08") and rules.get(identifier):
            status = "partial"
            parts.append(f"{rules[identifier]} reglas propias en Opengrep")
        if identifier == "A05" and not sast_ran and not engines:
            status = "partial"
            parts.append("reglas AST internas de Python (SQL dinámico, shell, eval)")
        if identifier in UNTESTABLE and status == "not_tested":
            parts.append(UNTESTABLE[identifier])
        if status == "not_tested" and not parts:
            parts.append("ningún motor ejecutado cubre esta categoría en este repositorio")
        reason = "; ".join(parts)
        if status == "partial":
            reason += f". {found} hallazgo(s)." if found else ". Sin hallazgos."
        result.append({"id": identifier, "title": title, "status": status,
                       "rules": rules.get(identifier, 0), "findings": found, "reason": reason})
    return result
