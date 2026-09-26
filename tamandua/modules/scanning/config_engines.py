"""Configuración como código y pipelines: Checkov y zizmor, sin repetir lo que ya ve Trivy.

- **Checkov** (Apache-2.0): Terraform, CloudFormation, Kubernetes, Helm, Kustomize, ARM, Bicep,
  Serverless, OpenAPI, Ansible, Dockerfile y pipelines (GitHub Actions, GitLab CI, Bitbucket,
  Azure Pipelines, CircleCI, Argo). Corre sin red y con `--skip-download`: no descarga módulos
  externos ni consulta la plataforma de Prisma. Por eso la edición libre no trae severidad y
  se asigna aquí con reglas visibles (`checkov_severity`).
- **zizmor** (MIT): auditoría a fondo de GitHub Actions (inyección en plantillas, disparadores
  peligrosos, permisos, acciones sin fijar por SHA, credenciales persistidas). Sin conexión.

En imágenes de contenedor, Checkov revisa un Dockerfile **reconstruido del historial** de la
imagen (`dockerfile_from_history`): su modo de imágenes necesita una clave de Prisma Cloud.

**Sin duplicados.** Cuando dos motores ven lo mismo en el mismo sitio queda un solo hallazgo:
el del motor principal (Trivy en infraestructura, zizmor en GitHub Actions, las reglas propias
en imágenes) con `also_detected_by` y `related_rules`. La equivalencia entre reglas sale de una
tabla medida sobre TerraGoat, CfnGoat, KubernetesGoat y CI/CD-Goat, más una comparación de
títulos cuando la tabla no conoce la pareja.

Ningún fragmento de código de los informes (`code_block` de Checkov, `feature` de zizmor) se
lee ni se guarda: puede contener secretos. Solo regla, archivo y líneas.
"""

from __future__ import annotations

import json
import re
import subprocess
import tempfile
import time
from pathlib import Path

from tamandua.modules.scanning.engines import _base, _relative, _result, _run, _stable, docker_available, with_cause
from tamandua.shared.i18n import msg, text

CHECKOV_FRAMEWORKS = ("terraform", "terraform_json", "cloudformation", "kubernetes", "helm", "kustomize", "dockerfile",
                      "arm", "bicep", "serverless", "openapi", "ansible", "github_actions", "gitlab_ci",
                      "bitbucket_pipelines", "azure_pipelines", "circleci_pipelines", "argo_workflows")
PIPELINE_FRAMEWORKS = {"github_actions", "gitlab_ci", "bitbucket_pipelines", "azure_pipelines", "circleci_pipelines",
                       "argo_workflows"}
FRAMEWORK_LABEL = {"terraform": "Terraform", "terraform_json": "Terraform", "cloudformation": "CloudFormation",
                   "kubernetes": "Kubernetes", "helm": "Helm", "kustomize": "Kustomize", "dockerfile": "Dockerfile",
                   "arm": "ARM", "bicep": "Bicep", "serverless": "Serverless", "openapi": "OpenAPI", "ansible": "Ansible",
                   "github_actions": "GitHub Actions", "gitlab_ci": "GitLab CI", "bitbucket_pipelines": "Bitbucket Pipelines",
                   "azure_pipelines": "Azure Pipelines", "circleci_pipelines": "CircleCI", "argo_workflows": "Argo Workflows"}
POLICY_INDEX = "https://www.checkov.io/5.Policy%20Index/all.html"

# --- equivalencias entre motores -------------------------------------------------------------

# Trivy (ID normalizado, sin «AVD-») → reglas de Checkov que comprueban lo mismo.
# Medida sobre TerraGoat, CfnGoat, KubernetesGoat y CI/CD-Goat, revisada a mano pareja por pareja.
TRIVY_CHECKOV: dict[str, tuple[str, ...]] = {
    # AWS (Terraform y CloudFormation comparten identificadores en los dos motores)
    "AWS-0017": ("CKV_AWS_158",), "AWS-0026": ("CKV_AWS_3", "CKV2_AWS_2"), "AWS-0027": ("CKV_AWS_189",),
    "AWS-0028": ("CKV_AWS_79",), "AWS-0029": ("CKV_AWS_46",), "AWS-0030": ("CKV_AWS_163",), "AWS-0031": ("CKV_AWS_51",),
    "AWS-0033": ("CKV_AWS_136",), "AWS-0038": ("CKV_AWS_37",), "AWS-0039": ("CKV_AWS_58",), "AWS-0040": ("CKV_AWS_39",),
    "AWS-0041": ("CKV_AWS_38",), "AWS-0042": ("CKV_AWS_84",), "AWS-0043": ("CKV_AWS_6",), "AWS-0046": ("CKV_AWS_83",),
    "AWS-0048": ("CKV_AWS_5",), "AWS-0065": ("CKV_AWS_7",), "AWS-0066": ("CKV_AWS_50",), "AWS-0075": ("CKV_AWS_101",),
    "AWS-0076": ("CKV_AWS_44",), "AWS-0077": ("CKV_AWS_133",), "AWS-0079": ("CKV_AWS_96",), "AWS-0080": ("CKV_AWS_16",),
    "AWS-0086": ("CKV_AWS_53",), "AWS-0087": ("CKV_AWS_54",), "AWS-0088": ("CKV_AWS_19",), "AWS-0089": ("CKV_AWS_18",),
    "AWS-0090": ("CKV_AWS_21",), "AWS-0091": ("CKV_AWS_55",), "AWS-0092": ("CKV_AWS_20",), "AWS-0093": ("CKV_AWS_56",),
    "AWS-0094": ("CKV2_AWS_6",), "AWS-0099": ("CKV_AWS_23",), "AWS-0104": ("CKV_AWS_382",),
    "AWS-0107": ("CKV_AWS_24", "CKV_AWS_25", "CKV_AWS_260", "CKV_AWS_277"), "AWS-0124": ("CKV_AWS_23",),
    "AWS-0126": ("CKV_AWS_228",), "AWS-0128": ("CKV_AWS_347",), "AWS-0131": ("CKV_AWS_8",), "AWS-0132": ("CKV_AWS_145",),
    "AWS-0133": ("CKV_AWS_353",), "AWS-0143": ("CKV_AWS_40",), "AWS-0164": ("CKV_AWS_130",), "AWS-0176": ("CKV_AWS_161",),
    "AWS-0177": ("CKV_AWS_293",), "AWS-0178": ("CKV2_AWS_11",), "AWS-0180": ("CKV_AWS_17",), "AWS-0343": ("CKV_AWS_139",),
    # Azure
    "AZU-0001": ("CKV_AZURE_17",), "AZU-0002": ("CKV_AZURE_16",), "AZU-0003": ("CKV_AZURE_13",), "AZU-0005": ("CKV_AZURE_18",),
    "AZU-0006": ("CKV_AZURE_15",), "AZU-0010": ("CKV_AZURE_36",), "AZU-0011": ("CKV_AZURE_44",), "AZU-0012": ("CKV_AZURE_35",),
    "AZU-0013": ("CKV_AZURE_109",), "AZU-0014": ("CKV_AZURE_40",), "AZU-0015": ("CKV_AZURE_114",), "AZU-0016": ("CKV_AZURE_110",),
    "AZU-0017": ("CKV_AZURE_41",), "AZU-0018": ("CKV_AZURE_26",), "AZU-0019": ("CKV_AZURE_31",),
    "AZU-0020": ("CKV_AZURE_28", "CKV_AZURE_29"), "AZU-0021": ("CKV_AZURE_32",),
    "AZU-0022": ("CKV_AZURE_113", "CKV_AZURE_68", "CKV_AZURE_53"), "AZU-0023": ("CKV_AZURE_27",), "AZU-0024": ("CKV_AZURE_30",),
    "AZU-0026": ("CKV_AZURE_52",), "AZU-0027": ("CKV_AZURE_23",), "AZU-0028": ("CKV_AZURE_25",), "AZU-0031": ("CKV_AZURE_37",),
    "AZU-0033": ("CKV_AZURE_38",), "AZU-0038": ("CKV_AZURE_2",), "AZU-0039": ("CKV_AZURE_149", "CKV_AZURE_1"),
    "AZU-0040": ("CKV_AZURE_4",), "AZU-0041": ("CKV_AZURE_6",), "AZU-0042": ("CKV_AZURE_5",), "AZU-0043": ("CKV_AZURE_7",),
    "AZU-0044": ("CKV_AZURE_21", "CKV_AZURE_22"), "AZU-0045": ("CKV_AZURE_19",), "AZU-0046": ("CKV_AZURE_20",), "AZU-0048": ("CKV_AZURE_9",),
    "AZU-0049": ("CKV_AZURE_12",), "AZU-0050": ("CKV_AZURE_10",), "AZU-0052": ("CKV_AZURE_39",), "AZU-0058": ("CKV_AZURE_206",),
    "AZU-0065": ("CKV_AZURE_115",), "AZU-0066": ("CKV_AZURE_116",), "AZU-0067": ("CKV_AZURE_117",), "AZU-0071": ("CKV_AZURE_78",),
    "AZU-0072": ("CKV_AZURE_14",),
    # Google Cloud
    "GCP-0001": ("CKV_GCP_28",), "GCP-0002": ("CKV_GCP_29",), "GCP-0015": ("CKV_GCP_6",), "GCP-0016": ("CKV_GCP_52",),
    "GCP-0017": ("CKV_GCP_60", "CKV_GCP_11"), "GCP-0020": ("CKV_GCP_54",), "GCP-0022": ("CKV_GCP_53",), "GCP-0024": ("CKV_GCP_14",),
    "GCP-0025": ("CKV_GCP_51",), "GCP-0029": ("CKV_GCP_26",), "GCP-0030": ("CKV_GCP_32",), "GCP-0031": ("CKV_GCP_40",),
    "GCP-0032": ("CKV_GCP_35",), "GCP-0033": ("CKV_GCP_38",), "GCP-0034": ("CKV_GCP_37",), "GCP-0036": ("CKV_GCP_34",),
    "GCP-0041": ("CKV_GCP_39",), "GCP-0043": ("CKV_GCP_36",), "GCP-0045": ("CKV_GCP_39",), "GCP-0046": ("CKV_GCP_15",),
    "GCP-0049": ("CKV_GCP_23",), "GCP-0051": ("CKV_GCP_21",), "GCP-0052": ("CKV_GCP_8",), "GCP-0053": ("CKV_GCP_18",),
    "GCP-0054": ("CKV_GCP_22",), "GCP-0056": ("CKV_GCP_12",), "GCP-0058": ("CKV_GCP_10",), "GCP-0059": ("CKV_GCP_25", "CKV_GCP_64"),
    "GCP-0060": ("CKV_GCP_1",), "GCP-0062": ("CKV_GCP_7",), "GCP-0063": ("CKV_GCP_9",), "GCP-0067": ("CKV_GCP_39",),
    "GCP-0070": ("CKV_GCP_3",), "GCP-0071": ("CKV_GCP_2",), "GCP-0075": ("CKV_GCP_74",), "GCP-0077": ("CKV_GCP_62",),
    "GCP-0078": ("CKV_GCP_78",),
    # Dockerfile
    "DS-0001": ("CKV_DOCKER_7",), "DS-0002": ("CKV_DOCKER_3", "CKV_DOCKER_8"), "DS-0004": ("CKV_DOCKER_1",),
    "DS-0005": ("CKV_DOCKER_4",), "DS-0017": ("CKV_DOCKER_5",), "DS-0026": ("CKV_DOCKER_2",),
    # Kubernetes (también lo que Checkov ve al renderizar Helm)
    "KSV-0001": ("CKV_K8S_20",), "KSV-0003": ("CKV_K8S_37",), "KSV-0004": ("CKV_K8S_37",), "KSV-0006": ("CKV_K8S_27",),
    "KSV-0008": ("CKV_K8S_18",), "KSV-0009": ("CKV_K8S_19",), "KSV-0010": ("CKV_K8S_17",), "KSV-0011": ("CKV_K8S_11",),
    "KSV-0012": ("CKV_K8S_23",), "KSV-0013": ("CKV_K8S_14",), "KSV-0014": ("CKV_K8S_22",), "KSV-0015": ("CKV_K8S_10",),
    "KSV-0016": ("CKV_K8S_12",), "KSV-0017": ("CKV_K8S_16",), "KSV-0018": ("CKV_K8S_13",), "KSV-0020": ("CKV_K8S_40",),
    "KSV-0022": ("CKV_K8S_25",), "KSV-0024": ("CKV_K8S_26",), "KSV-0030": ("CKV_K8S_31",), "KSV-0036": ("CKV_K8S_38",),
    "KSV-0044": ("CKV_K8S_49",), "KSV-0104": ("CKV_K8S_31",), "KSV-0105": ("CKV_K8S_23",), "KSV-0110": ("CKV_K8S_21",),
    "KSV-0118": ("CKV_K8S_29", "CKV_K8S_30"),
}
# Severidad de las reglas de Checkov que tienen pareja en Trivy: la de Trivy (sus metadatos sí la traen).
# Generada desde la tabla de arriba y el paquete de reglas de Trivy 0.74; el resto usa `checkov_severity`.
CHECKOV_SEVERITY: dict[str, str] = {rule: level for level, rules in {
    "critical": """CKV_AWS_38 CKV_AWS_382 CKV_AWS_39 CKV_AWS_46 CKV_AWS_83 CKV_AZURE_10 CKV_AZURE_109 CKV_AZURE_35
        CKV_AZURE_44 CKV_AZURE_6 CKV_AZURE_9 CKV_GCP_15 CKV_K8S_49""",
    "high": """CKV2_AWS_2 CKV_AWS_130 CKV_AWS_145 CKV_AWS_16 CKV_AWS_163 CKV_AWS_17 CKV_AWS_19 CKV_AWS_20
        CKV_AWS_228 CKV_AWS_24 CKV_AWS_25 CKV_AWS_260 CKV_AWS_277 CKV_AWS_3 CKV_AWS_347 CKV_AWS_44 CKV_AWS_5
        CKV_AWS_51 CKV_AWS_53 CKV_AWS_54 CKV_AWS_55 CKV_AWS_56 CKV_AWS_58 CKV_AWS_6 CKV_AWS_79 CKV_AWS_8
        CKV_AWS_96 CKV_AZURE_1 CKV_AZURE_149 CKV_AZURE_15 CKV_AZURE_2 CKV_AZURE_36 CKV_AZURE_5 CKV_AZURE_7
        CKV_DOCKER_3 CKV_DOCKER_5 CKV_DOCKER_8 CKV_GCP_11 CKV_GCP_18 CKV_GCP_28 CKV_GCP_3 CKV_GCP_36
        CKV_GCP_40 CKV_GCP_6 CKV_GCP_60 CKV_GCP_7 CKV_K8S_16 CKV_K8S_17 CKV_K8S_18 CKV_K8S_19 CKV_K8S_22
        CKV_K8S_26 CKV_K8S_27 CKV_K8S_29 CKV_K8S_30""",
    "medium": """CKV2_AWS_11 CKV_AWS_101 CKV_AWS_133 CKV_AWS_139 CKV_AWS_161 CKV_AWS_21 CKV_AWS_293 CKV_AWS_37
        CKV_AWS_7 CKV_AWS_84 CKV_AZURE_110 CKV_AZURE_113 CKV_AZURE_115 CKV_AZURE_13 CKV_AZURE_14
        CKV_AZURE_21 CKV_AZURE_22 CKV_AZURE_23 CKV_AZURE_25 CKV_AZURE_26 CKV_AZURE_28 CKV_AZURE_29
        CKV_AZURE_30 CKV_AZURE_31 CKV_AZURE_32 CKV_AZURE_37 CKV_AZURE_38 CKV_AZURE_39 CKV_AZURE_4
        CKV_AZURE_40 CKV_AZURE_52 CKV_AZURE_53 CKV_AZURE_68 CKV_AZURE_78 CKV_DOCKER_1 CKV_DOCKER_7
        CKV_GCP_12 CKV_GCP_14 CKV_GCP_2 CKV_GCP_25 CKV_GCP_29 CKV_GCP_32 CKV_GCP_34 CKV_GCP_35 CKV_GCP_39
        CKV_GCP_51 CKV_GCP_52 CKV_GCP_53 CKV_GCP_54 CKV_GCP_62 CKV_GCP_64 CKV_GCP_78 CKV_K8S_14 CKV_K8S_20
        CKV_K8S_23 CKV_K8S_25 CKV_K8S_31 CKV_K8S_38""",
    "low": """CKV2_AWS_6 CKV_AWS_136 CKV_AWS_158 CKV_AWS_18 CKV_AWS_189 CKV_AWS_23 CKV_AWS_353 CKV_AWS_40
        CKV_AWS_50 CKV_AZURE_114 CKV_AZURE_116 CKV_AZURE_117 CKV_AZURE_12 CKV_AZURE_16 CKV_AZURE_17
        CKV_AZURE_18 CKV_AZURE_19 CKV_AZURE_20 CKV_AZURE_206 CKV_AZURE_27 CKV_AZURE_41 CKV_DOCKER_2
        CKV_DOCKER_4 CKV_GCP_1 CKV_GCP_10 CKV_GCP_21 CKV_GCP_22 CKV_GCP_23 CKV_GCP_26 CKV_GCP_37 CKV_GCP_38
        CKV_GCP_74 CKV_GCP_8 CKV_GCP_9 CKV_K8S_10 CKV_K8S_11 CKV_K8S_12 CKV_K8S_13 CKV_K8S_21 CKV_K8S_37
        CKV_K8S_40""",
}.items() for rule in rules.split()}
# zizmor → Checkov en GitHub Actions. Checkov marca el workflow entero; zizmor, la línea exacta.
ZIZMOR_CHECKOV: dict[str, tuple[str, ...]] = {
    "template-injection": ("CKV_GHA_2",), "insecure-commands": ("CKV_GHA_1",), "excessive-permissions": ("CKV2_GHA_1",),
}
# Reglas propias de imagen → Trivy y Checkov sobre el Dockerfile reconstruido.
IMAGE_EQUIVALENT: dict[str, tuple[str, ...]] = {
    "IMG-ROOT": ("CKV_DOCKER_3", "CKV_DOCKER_8", "DS-0002"), "IMG-NO-HEALTHCHECK": ("CKV_DOCKER_2", "DS-0026"),
    "IMG-SSH": ("CKV_DOCKER_1", "DS-0004"), "IMG-ADD-URL": ("CKV_DOCKER_4", "DS-0005"),
}
# De la imagen entera (no de un paso del historial): se unen aunque cada motor la ubique distinto.
IMAGE_WIDE = {"IMG-ROOT", "IMG-NO-HEALTHCHECK", "IMG-SSH"}
# El Dockerfile reconstruido empieza con un FROM ficticio: estas reglas hablarían de él, no de la imagen.
IMAGE_SKIP = {"CKV_DOCKER_7", "CKV_DOCKER_11"}


def trivy_id(rule: str) -> str:
    """«AVD-AWS-0086», «AWS-0086» y «KSV001» son la misma regla de Trivy según la versión."""
    text = re.sub(r"^AVD-", "", str(rule or "").upper())
    match = re.fullmatch(r"([A-Z]+)-?(\d+)", text)
    return f"{match[1]}-{int(match[2]):04d}" if match else text


_STOP = set("ensure that the a an is are be should not no to of for in on with and or by all any enabled enable disabled "
            "disable set used use using has have must only at from as it its this default resource resources".split())
_SYNONYMS = {"encrypted": "encrypt", "encryption": "encrypt", "unencrypted": "encrypt", "logs": "log", "logging": "log",
             "publicly": "public", "privileged": "privilege", "privileges": "privilege", "versioning": "version",
             "ssl": "tls", "https": "tls", "capabilities": "capability", "containers": "container", "keys": "key",
             "rotation": "rotate", "rotated": "rotate", "retention": "retain", "limits": "limit", "requests": "request"}


def _words(text: str) -> set[str]:
    return {_SYNONYMS.get(word, word) for word in re.findall(r"[a-z0-9]+", text.lower()) if word not in _STOP}


def similar(a, b) -> float:
    left, right = _words(text(a, "en")), _words(text(b, "en"))
    return len(left & right) / max(1, len(left | right))


def _span(finding: dict) -> tuple[int, int]:
    start = int(finding.get("line") or 1)
    return start, max(start, int(finding.get("end_line") or start))


def _overlap(a: dict, b: dict) -> bool:
    (a1, a2), (b1, b2) = _span(a), _span(b)
    return a1 <= b2 and b1 <= a2


def merge_equivalent(primary: list[dict], secondary: list[dict], table: dict[str, tuple[str, ...]], *,
                     normalize=lambda rule: rule, file_level: set[str] | None = None, anywhere: set[str] | None = None,
                     by_title: float | None = None) -> tuple[list[dict], int]:
    """Une lo que dos motores ven a la vez. Devuelve los principales (anotados) más los secundarios nuevos.

    Un secundario es el mismo hallazgo que un principal si su regla es equivalente según `table`
    (o, con `by_title`, si los títulos se parecen al menos eso), están en el mismo archivo y sus
    líneas se solapan. `file_level`: reglas secundarias que señalan el archivo entero. `anywhere`:
    reglas principales que valen para todo el activo, sin importar dónde las ubique cada motor.
    """
    file_level, anywhere = file_level or set(), anywhere or set()
    by_path: dict[str, list[dict]] = {}
    for finding in primary:
        by_path.setdefault(finding["path"], []).append(finding)
    extra, absorbed = [], 0
    for finding in secondary:
        rule = normalize(finding["rule_id"])
        twins = []
        for candidate in primary if anywhere else by_path.get(finding["path"], []):
            equivalent = rule in table.get(normalize(candidate["rule_id"]), ())
            if not equivalent and by_title is not None and candidate["path"] == finding["path"]:
                equivalent = similar(candidate["title"], finding["title"]) >= by_title
            if not equivalent:
                continue
            if normalize(candidate["rule_id"]) in anywhere or (candidate["path"] == finding["path"]
                                                               and (rule in file_level or _overlap(candidate, finding))):
                twins.append(candidate)
        if not twins:
            extra.append(finding)
            continue
        absorbed += 1
        for twin in twins:
            if finding["tool"] != twin["tool"] and finding["tool"] not in twin.setdefault("also_detected_by", []):
                twin["also_detected_by"].append(finding["tool"])
                twin["confidence"] = min(10, twin["confidence"] + 1)
            if finding["rule_id"] not in twin.setdefault("related_rules", []):
                twin["related_rules"].append(finding["rule_id"])
    return primary + extra, absorbed


# --- Checkov -----------------------------------------------------------------------------------

_HIGH = re.compile(r"public|0\.0\.0\.0|anonymous|unauthenticated|privilege|admin|wildcard|\*|secret|password|credential|"
                   r"hard-?coded|injection|docker (daemon )?socket|host (network|pid|ipc)|root|write-all|unsecure commands|"
                   r"curl with secrets|netcat|certificate|tls|ssl|https|strict-ssl|sslverify|no-check-certificate|"
                   r"allow-untrusted|allow-unauthenticated|nogpgcheck|nosignature|force-yes|chpasswd|"
                   r"encrypt(?!.*(customer|cmk|kms|csek))", re.I)
_LOW = re.compile(r"\btags?\b|label|description|monitoring|x-?ray|tracing|performance insights|backup|versioning|multi-az|"
                  r"deletion protection|retention|replication|readiness|liveness|probe|digest|customer.managed|\bcmk\b|"
                  r"\bkms\b|csek|healthcheck|cosign|sbom|requests should|limits should|\bapt\b|workdir|maintainer|"
                  r"expiration|content.type|event notification|lifecycle|auto(matic)? (node )?(repair|upgrade)|release channel|default namespace", re.I)


def checkov_severity(check_id: str, name: str) -> str:
    """La edición libre de Checkov no trae severidad: se deduce del nombre de la regla, a la baja si hay duda."""
    if check_id in CHECKOV_SEVERITY:
        return CHECKOV_SEVERITY[check_id]
    if _LOW.search(name):
        return "low"
    if _HIGH.search(name):
        return "high"
    return "medium"


def parse_checkov(payload, *, image: dict | None = None, step_of: dict[int, int] | None = None) -> list[dict]:
    """Hallazgos de Checkov. Con `image`, las líneas del Dockerfile reconstruido se traducen a pasos del historial."""
    reports = payload if isinstance(payload, list) else [payload] if isinstance(payload, dict) else []
    findings, seen = [], set()
    for report in reports:
        framework = str(report.get("check_type") or "")
        for entry in ((report.get("results") or {}).get("failed_checks") or []):
            if not isinstance(entry, dict):
                continue
            rule, name = str(entry.get("check_id") or "checkov"), str(entry.get("check_name") or "")
            if image is not None and rule in IMAGE_SKIP:
                continue
            start, end = (list(entry.get("file_line_range") or [1, 1]) + [1, 1])[:2]
            start, end = max(1, int(start or 1)), max(1, int(end or 1))
            resource = str(entry.get("resource") or "")
            label = FRAMEWORK_LABEL.get(framework, framework or "IaC")
            severity = checkov_severity(rule, name)
            if image is not None:
                step = (step_of or {}).get(start) if start == end else None
                path = f"image-history/step-{step + 1}" if step is not None else "image-config"
                digest = _stable("image-config", rule, image["asset"], str(step) if step is not None else "image")
                finding = _base("iac", rule, name or rule, path, 1, severity, tool="checkov",
                                reason=msg("scanning.checkov.image_reason_step", rule=rule, step=step + 1) if step is not None
                                else msg("scanning.checkov.image_reason", rule=rule),
                                remediation=msg("scanning.checkov.image_remediation", check=name or rule, index=POLICY_INDEX),
                                cwe=[1188], owasp="A02:2025", confidence=6, digest=digest)
            else:
                path = _relative(str(entry.get("repo_file_path") or entry.get("file_path") or "")).lstrip("/")
                pipeline = framework in PIPELINE_FRAMEWORKS
                digest = _stable("cicd" if pipeline else "iac", rule, path, resource or f"{start}-{end}")
                finding = _base("cicd" if pipeline else "iac", rule, name or rule, path, start, severity, tool="checkov",
                                reason=msg("scanning.checkov.reason", framework=label, resource=resource or path, rule=rule,
                                           start=start, end=end),
                                remediation=msg("scanning.checkov.remediation", resource=resource, check=name or rule, index=POLICY_INDEX)
                                if resource else msg("scanning.checkov.remediation_generic", check=name or rule, index=POLICY_INDEX),
                                cwe=[829 if pipeline else 1188], owasp="A03:2025" if pipeline else "A02:2025",
                                confidence=7, digest=digest)
                finding["end_line"] = end
            finding["framework"] = label
            if finding["fingerprint"] not in seen:
                seen.add(finding["fingerprint"])
                findings.append(finding)
    return findings


def _checkov(arguments: list[str], mount: Path, timeout: int) -> subprocess.CompletedProcess:
    return _run("checkov", [*arguments, "--output", "json", "--quiet", "--compact", "--soft-fail", "--skip-download",
                            "--download-external-modules", "false"], mount, timeout=timeout)


def run_checkov(snapshot: Path) -> dict:
    started = time.time()
    if not docker_available():
        return _result("checkov", "not_tested", msg("scanning.checkov.no_docker"))
    try:
        completed = _checkov(["--directory", "/src", "--framework", *CHECKOV_FRAMEWORKS], snapshot, 900)
        text = completed.stdout.strip()
        payload = json.loads(text) if text.startswith(("[", "{")) else []
    except subprocess.TimeoutExpired:
        return _result("checkov", "inconclusive", msg("scanning.checkov.timeout"), started=started)
    except (OSError, ValueError):
        return _result("checkov", "inconclusive", msg("scanning.engines.unreadable", engine="Checkov"), started=started)
    if completed.returncode not in (0, 1) and not payload:
        return _result("checkov", "inconclusive", with_cause(msg("scanning.engines.failed_early", engine="Checkov"), completed), started=started)
    findings = parse_checkov(payload)
    frameworks = sorted({item["framework"] for item in findings})
    detail = (msg("scanning.checkov.detail", failures=len(findings), frameworks=", ".join(frameworks))
              if findings else msg("scanning.checkov.clean"))
    return _result("checkov", "completed", detail, findings, started)


RUN_PREFIX = re.compile(r"^(?:\|\d+(?:\s+\S+=\S*)*\s+)?/bin/(?:ba)?sh -c\s+")
INSTRUCTION = re.compile(r"^(RUN|ENV|COPY|ADD|USER|EXPOSE|WORKDIR|ARG|LABEL|HEALTHCHECK|ENTRYPOINT|CMD|VOLUME|STOPSIGNAL|SHELL|ONBUILD)\b\s*(.*)$", re.S)


def dockerfile_from_history(history: list[str], config: dict | None = None) -> tuple[str, dict[int, int]]:
    """Dockerfile equivalente al historial de la imagen y, para cada línea, el paso del que sale.

    Admite el formato del constructor clásico (`/bin/sh -c #(nop) …`) y el de BuildKit (`RUN … # buildkit`).
    El `ADD file:…` de la capa base es el sistema de ficheros de la imagen de partida, no un ADD del autor.
    """
    lines, step_of = ["FROM scratch"], {}
    for index, raw in enumerate(history):
        step = " ".join(str(raw or "").split())
        step = re.sub(r"\s*# buildkit$", "", step)
        nop = re.match(r"^/bin/(?:ba)?sh -c #\(nop\)\s*(.*)$", step)
        if nop:
            step = nop[1]
        elif RUN_PREFIX.match(step):
            step = "RUN " + RUN_PREFIX.sub("", step)
        match = INSTRUCTION.match(step)
        if not match:
            continue
        instruction, rest = match[1], match[2].strip()
        if instruction == "RUN":
            rest = RUN_PREFIX.sub("", rest)
        elif instruction == "ADD" and re.match(r"^(file|multi|dir):", rest):
            instruction, rest = "COPY", "rootfs /"
        elif instruction == "EXPOSE":
            rest = " ".join(re.findall(r"\d+(?:/(?:tcp|udp))?", rest)) or rest
        elif instruction == "HEALTHCHECK":
            rest = "NONE" if "NONE" in rest.upper()[:12] else "CMD true"
        lines.append(f"{instruction} {rest}".strip())
        step_of[len(lines)] = index
    config = config or {}
    if config.get("User") and not any(line.startswith("USER ") for line in lines):
        lines.append(f"USER {config['User']}")
    if config.get("Healthcheck") and not any(line.startswith("HEALTHCHECK ") for line in lines):
        lines.append("HEALTHCHECK CMD true")
    return "\n".join(lines) + "\n", step_of


def run_checkov_image(metadata: dict, image: dict, work_dir: Path) -> dict:
    """Checkov sobre el Dockerfile reconstruido. El historial puede llevar secretos: el fichero vive en una
    carpeta temporal que se borra al terminar y el contenedor no tiene red."""
    started = time.time()
    if not docker_available():
        return _result("checkov", "not_tested", msg("scanning.checkov.image_no_docker"))
    config_block = metadata.get("ImageConfig") or {}
    history = [str(item.get("created_by") or "") for item in config_block.get("history") or []]
    if not history:
        return _result("checkov", "not_tested", msg("scanning.checkov.image_no_history"), started=started)
    dockerfile, step_of = dockerfile_from_history(history, config_block.get("config") or {})
    work_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="checkov-image-", dir=work_dir) as folder:
        (Path(folder) / "Dockerfile").write_text(dockerfile, encoding="utf-8")
        try:
            completed = _checkov(["--file", "/src/Dockerfile", "--framework", "dockerfile"], Path(folder), 300)
            text = completed.stdout.strip()
            payload = json.loads(text) if text.startswith(("[", "{")) else []
        except subprocess.TimeoutExpired:
            return _result("checkov", "inconclusive", msg("scanning.checkov.image_timeout"), started=started)
        except (OSError, ValueError):
            return _result("checkov", "inconclusive", msg("scanning.engines.unreadable", engine="Checkov"), started=started)
    findings = parse_checkov(payload, image=image, step_of=step_of)
    return _result("checkov", "completed", msg("scanning.checkov.image_detail", failures=len(findings), steps=len(step_of)),
                   findings, started)


# --- zizmor ------------------------------------------------------------------------------------

# zizmor audit → (our title, CWE). Audits not listed use zizmor's own description.
ZIZMOR_AUDITS = {
    "template-injection": (msg("scanning.zizmor.audits.template_injection"), 94),
    "dangerous-triggers": (msg("scanning.zizmor.audits.dangerous_triggers"), 863),
    "excessive-permissions": (msg("scanning.zizmor.audits.excessive_permissions"), 250),
    "unpinned-uses": (msg("scanning.zizmor.audits.unpinned_uses"), 829),
    "artipacked": (msg("scanning.zizmor.audits.artipacked"), 522),
    "cache-poisoning": (msg("scanning.zizmor.audits.cache_poisoning"), 349),
    "archived-uses": (msg("scanning.zizmor.audits.archived_uses"), 1104),
    "insecure-commands": (msg("scanning.zizmor.audits.insecure_commands"), 77),
    "github-env": (msg("scanning.zizmor.audits.github_env"), 94),
    "hardcoded-container-credentials": (msg("scanning.zizmor.audits.hardcoded_container_credentials"), 798),
    "self-hosted-runner": (msg("scanning.zizmor.audits.self_hosted_runner"), 250),
    "secrets-inherit": (msg("scanning.zizmor.audits.secrets_inherit"), 250),
    "overprovisioned-secrets": (msg("scanning.zizmor.audits.overprovisioned_secrets"), 250),
    "unredacted-secrets": (msg("scanning.zizmor.audits.unredacted_secrets"), 532),
    "bot-conditions": (msg("scanning.zizmor.audits.bot_conditions"), 290),
    "unsound-condition": (msg("scanning.zizmor.audits.unsound_condition"), 670),
    "unsound-contains": (msg("scanning.zizmor.audits.unsound_contains"), 697),
    "unpinned-images": (msg("scanning.zizmor.audits.unpinned_images"), 829),
    "use-trusted-publishing": (msg("scanning.zizmor.audits.use_trusted_publishing"), 522),
    "obfuscation": (msg("scanning.zizmor.audits.obfuscation"), 506),
    "forbidden-uses": (msg("scanning.zizmor.audits.forbidden_uses"), 829),
    "ref-version-mismatch": (msg("scanning.zizmor.audits.ref_version_mismatch"), 1104),
    "anonymous-definition": (msg("scanning.zizmor.audits.anonymous_definition"), 1104),
    "dependabot-cooldown": (msg("scanning.zizmor.audits.dependabot_cooldown"), 1104),
    "dependabot-execution": (msg("scanning.zizmor.audits.dependabot_execution"), 829),
    "concurrency-limits": (msg("scanning.zizmor.audits.concurrency_limits"), 400),
    "undocumented-permissions": (msg("scanning.zizmor.audits.undocumented_permissions"), 1104),
}
ZIZMOR_SEVERITY = {"high": "high", "medium": "medium", "low": "low", "informational": "info", "unknown": "low"}
ZIZMOR_CONFIDENCE = {"high": 8, "medium": 6, "low": 4, "unknown": 4}
# Riesgo real, pero para explotarlo hace falta comprometer antes la acción de terceros: se rebaja un nivel.
ZIZMOR_DOWNGRADE = {"unpinned-uses": "medium", "unpinned-images": "low", "anonymous-definition": "info"}


def parse_zizmor(payload: list) -> list[dict]:
    findings, seen = [], set()
    for entry in payload or []:
        if not isinstance(entry, dict):
            continue
        ident = str(entry.get("ident") or "zizmor")
        determinations = entry.get("determinations") or {}
        locations = [item for item in entry.get("locations") or [] if isinstance(item, dict)]
        primary = next((item for item in locations if (item.get("symbolic") or {}).get("kind") == "Primary"), locations[0] if locations else {})
        key = ((primary.get("symbolic") or {}).get("key") or {})
        path = _relative(str((key.get("Local") or {}).get("verbatim_path") or next(iter(key.values()), {}).get("verbatim_path", "")
                             if isinstance(key, dict) and key else "")).lstrip("/")
        location = (primary.get("concrete") or {}).get("location") or {}
        line = int((location.get("start_point") or {}).get("row") or 0) + 1
        end = int((location.get("end_point") or {}).get("row") or line - 1) + 1
        title, cwe = ZIZMOR_AUDITS.get(ident, (str(entry.get("desc") or ident), 1104))
        severity = ZIZMOR_DOWNGRADE.get(ident) or ZIZMOR_SEVERITY.get(str(determinations.get("severity") or "").lower(), "medium")
        annotation = str((primary.get("symbolic") or {}).get("annotation") or "").strip()
        digest = _stable("cicd", ident, path, str(line))
        finding = _base("cicd", ident, title, path, line, severity, tool="zizmor",
                        reason=msg("scanning.zizmor.reason_annotated" if annotation else "scanning.zizmor.reason",
                                   description=str(entry.get("desc") or "").rstrip(".") or title, annotation=annotation, path=path, line=line),
                        remediation=msg("scanning.zizmor.remediation", url=entry.get("url") or "https://docs.zizmor.sh/audits/"),
                        cwe=[cwe], owasp="A03:2025", confidence=ZIZMOR_CONFIDENCE.get(str(determinations.get("confidence") or "").lower(), 6),
                        digest=digest)
        finding["end_line"] = max(line, end)
        finding["framework"] = "GitHub Actions"
        if digest not in seen:
            seen.add(digest)
            findings.append(finding)
    return findings


def github_actions_files(snapshot: Path) -> list[Path]:
    """Workflows y acciones compuestas que zizmor audita."""
    workflows = snapshot / ".github" / "workflows"
    found = sorted(path for path in workflows.iterdir() if path.suffix in (".yml", ".yaml")) if workflows.is_dir() else []
    return found + sorted(path for path in snapshot.rglob("action.y*ml") if path.name in ("action.yml", "action.yaml"))


def run_zizmor(snapshot: Path) -> dict:
    started = time.time()
    if not docker_available():
        return _result("zizmor", "not_tested", msg("scanning.zizmor.no_docker"))
    audited = github_actions_files(snapshot)
    if not audited:
        return _result("zizmor", "completed", msg("scanning.zizmor.nothing_to_audit"), started=started)
    try:
        completed = _run("zizmor", ["--offline", "--no-exit-codes", "--no-progress", "--format", "json", "/src"], snapshot, timeout=300)
        payload = json.loads(completed.stdout or "[]")
    except subprocess.TimeoutExpired:
        return _result("zizmor", "inconclusive", msg("scanning.engines.timeout", engine="zizmor"), started=started)
    except (OSError, ValueError):
        return _result("zizmor", "inconclusive", msg("scanning.engines.unreadable", engine="zizmor"), started=started)
    if completed.returncode != 0 and not payload:
        return _result("zizmor", "inconclusive", with_cause(msg("scanning.engines.failed_early", engine="zizmor"), completed), started=started)
    findings = parse_zizmor(payload)
    affected = len({item["path"] for item in findings})
    detail = (msg("scanning.zizmor.detail", audited=len(audited), problems=len(findings), affected=affected)
              if findings else msg("scanning.zizmor.clean", audited=len(audited)))
    return _result("zizmor", "completed", detail, findings, started)


# --- unión -------------------------------------------------------------------------------------

def merge_repository(trivy_iac: list[dict], checkov: list[dict], zizmor: list[dict]) -> tuple[list[dict], dict]:
    """Infraestructura: Trivy manda y Checkov suma lo que Trivy no ve. GitHub Actions: zizmor manda."""
    checkov_iac = [item for item in checkov if item["scanner"] == "iac"]
    checkov_cicd = [item for item in checkov if item["scanner"] == "cicd"]
    iac, iac_joined = merge_equivalent(trivy_iac, checkov_iac, TRIVY_CHECKOV, normalize=trivy_id, by_title=0.75)
    cicd, cicd_joined = merge_equivalent(zizmor, checkov_cicd, ZIZMOR_CHECKOV,
                                         file_level={rule for rules in ZIZMOR_CHECKOV.values() for rule in rules})
    return iac + cicd, {"checkov": len(checkov), "zizmor": len(zizmor), "joined": iac_joined + cicd_joined,
                        "checkov_new": len(checkov) - iac_joined - cicd_joined}


def merge_image(own: list[dict], trivy_config: list[dict], checkov: list[dict]) -> tuple[list[dict], int]:
    """Imágenes: las reglas propias mandan; Trivy y Checkov solo añaden lo que ellas no cubren."""
    merged, joined = merge_equivalent(own, trivy_config, IMAGE_EQUIVALENT, anywhere=IMAGE_WIDE, normalize=trivy_id)
    merged, joined_checkov = merge_equivalent(merged, checkov, IMAGE_EQUIVALENT, anywhere=IMAGE_WIDE, normalize=trivy_id)
    return merged, joined + joined_checkov
