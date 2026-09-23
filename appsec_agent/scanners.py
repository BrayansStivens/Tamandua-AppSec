"""Escáneres externos en contenedores pinneados por digest, un frente cada uno.

- Trivy: dependencias de cualquier ecosistema, configuración de infraestructura
  (Dockerfile, Kubernetes, Terraform) y secretos. Necesita red solo para bajar su
  base de vulnerabilidades, que se cachea; no envía nada del repositorio.
- Gitleaks: secretos con alta precisión. Sin red.
- Opengrep: SAST multi-lenguaje con nuestras propias reglas (`rules/`). Sin red.

Cada contenedor corre sin capacidades, sin escalada de privilegios y con el
snapshot montado en solo lectura. Si Docker o una imagen no están, el paso se
declara `not_tested` con el motivo: nunca se finge una ejecución.

Los valores de secretos no se guardan jamás: solo regla, archivo y línea.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from .advisories import compare_versions, cvss3_base_score, prioritize, severity_from_score
from .advisories import fingerprint as sca_fingerprint

RULES_DIR = Path(__file__).resolve().parents[1] / "rules"
IMAGES = {
    "trivy": {"name": "Trivy", "version": "0.74.0",
              "image": "aquasec/trivy@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969"},
    "gitleaks": {"name": "Gitleaks", "version": "8.30.1",
                 "image": "ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"},
    "opengrep": {"name": "Opengrep", "version": "1.30.0", "image": "appsec-agent/opengrep:1.30.0"},
}
# Lenguajes con reglas propias y las extensiones por las que se reconocen en el snapshot.
RULE_LANGUAGES = {
    "JavaScript": {".js", ".jsx", ".mjs", ".cjs"}, "TypeScript": {".ts", ".tsx"}, "Python": {".py"},
    "Java": {".java"}, "Go": {".go"}, "PHP": {".php"}, "Ruby": {".rb"}, "C#": {".cs"},
}
OTHER_LANGUAGES = {"Kotlin": {".kt", ".kts"}, "Rust": {".rs"}, "Swift": {".swift"}, "Scala": {".scala"},
                   "Dart": {".dart"}, "C/C++": {".c", ".h", ".cpp", ".cc", ".hpp"}, "Vue": {".vue"}, "Svelte": {".svelte"}}
SEVERITY_LABEL = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "UNKNOWN": "medium",
                  "ERROR": "high", "WARNING": "medium", "INFO": "low"}
CONFIDENCE = {"HIGH": 8, "MEDIUM": 6, "LOW": 4}
_docker_state: dict[str, bool] = {}


def host_path(path: Path) -> str:
    """Ruta tal como la ve el demonio de Docker.

    Cuando la app corre en un contenedor, los volúmenes que pide para los
    contenedores hermanos se resuelven en el host, no dentro de la app. Con
    APPSEC_AGENT_DATA_DIR (ruta interna) y APPSEC_AGENT_HOST_DATA_DIR (la misma
    carpeta vista desde el host) se traduce el prefijo; igual con las reglas.
    """
    resolved = path.resolve()
    for inside, outside in ((os.environ.get("APPSEC_AGENT_DATA_DIR"), os.environ.get("APPSEC_AGENT_HOST_DATA_DIR")),
                            (str(RULES_DIR), os.environ.get("APPSEC_AGENT_HOST_RULES_DIR"))):
        if inside and outside:
            try:
                return str(Path(outside) / resolved.relative_to(Path(inside).resolve()))
            except ValueError:
                continue
    return str(resolved)


def docker_available() -> bool:
    if "ok" not in _docker_state:
        binary = shutil.which("docker")
        try:
            _docker_state["ok"] = bool(binary) and subprocess.run(
                [binary, "info", "--format", "{{.ServerVersion}}"], capture_output=True, text=True, timeout=8).returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            _docker_state["ok"] = False
    return _docker_state["ok"]


def image_available(key: str) -> bool:
    binary = shutil.which("docker")
    try:
        return bool(binary) and subprocess.run([binary, "image", "inspect", IMAGES[key]["image"]],
                                               capture_output=True, timeout=15).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _result(key: str, status: str, detail: str, findings: list | None = None, started: float | None = None) -> dict:
    meta = IMAGES[key]
    return {"tool": key, "name": meta["name"], "version": meta["version"], "image": meta["image"],
            "status": status, "detail": detail, "findings": findings or [],
            "duration_s": round(time.time() - started, 1) if started else None}


def _run(key: str, arguments: list[str], snapshot: Path, *, network: bool = False,
         mounts: list[str] | None = None, timeout: int = 900) -> subprocess.CompletedProcess:
    command = [shutil.which("docker"), "run", "--rm", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
               "--pids-limit", "512", "--memory", "3g", "--cpus", "2",
               "--network", "bridge" if network else "none",
               "-v", f"{host_path(snapshot)}:/src:ro", *(mounts or []), IMAGES[key]["image"], *arguments]
    return subprocess.run(command, capture_output=True, text=True, timeout=timeout)


def _relative(path: str) -> str:
    return re.sub(r"^/src/", "", path or "")


def _stable(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


def _base(scanner: str, rule: str, title: str, path: str, line: int, severity: str, *, reason: str,
          remediation: str, cwe: list[int], owasp: str, confidence: int, digest: str, tool: str) -> dict:
    action = "act" if severity == "critical" else "attend" if severity == "high" else "track"
    return {"finding_id": digest[:16], "fingerprint": digest, "scanner": scanner, "tool": tool, "rule_id": rule,
            "title": title[:200], "path": path, "line": line, "severity": severity, "confidence": confidence,
            "verdict": "candidate", "cwe": cwe, "owasp": [owasp], "cve": [], "ghsa": [],
            "package": None, "advisory": None, "kev": None, "epss": None,
            "priority": {"action": action, "factors": [f"Hallazgo estático de severidad {severity}",
                                                       "Requiere confirmar alcanzabilidad en el contexto de la aplicación"]},
            "reason": reason, "remediation": remediation}


# --- Opengrep ---------------------------------------------------------------------

def snapshot_languages(snapshot: Path) -> dict:
    """Qué lenguajes hay en el repositorio y cuáles tienen reglas propias."""
    present: dict[str, int] = {}
    for path in snapshot.rglob("*"):
        if not path.is_file():
            continue
        for table in (RULE_LANGUAGES, OTHER_LANGUAGES):
            for language, extensions in table.items():
                if path.suffix.lower() in extensions:
                    present[language] = present.get(language, 0) + 1
    return {"covered": {name: count for name, count in present.items() if name in RULE_LANGUAGES},
            "uncovered": {name: count for name, count in present.items() if name not in RULE_LANGUAGES}}


def parse_opengrep(payload: dict) -> list[dict]:
    findings = []
    for result in payload.get("results", []):
        extra = result.get("extra") or {}
        metadata = extra.get("metadata") or {}
        rule = str(result.get("check_id", "")).removeprefix("rules.")
        path = _relative(result.get("path", ""))
        line = int((result.get("start") or {}).get("line") or 1)
        snippet = " ".join(str(extra.get("lines", "")).split())[:200]
        severity = "critical" if str(metadata.get("severity", "")).upper() == "CRITICAL" \
            else SEVERITY_LABEL.get(str(extra.get("severity", "")).upper(), "medium")
        cwe = [int(item) for item in metadata.get("cwe", []) if str(item).isdigit()]
        message = str(extra.get("message", "")).strip()
        title = f"{metadata.get('category', 'sast').capitalize()}: {rule.rsplit('.', 1)[-1].replace('-', ' ')}"
        findings.append(_base(
            "sast", rule, title, path, line, severity, tool="opengrep",
            reason=f"`{snippet}` en {path}:{line}.", remediation=message,
            cwe=cwe, owasp=str(metadata.get("owasp", "A05:2025")),
            confidence=CONFIDENCE.get(str(metadata.get("confidence", "MEDIUM")).upper(), 6),
            # La huella usa el fragmento, no la línea: mover código no debe reabrir tickets.
            digest=_stable("sast", rule, path, snippet)))
    return findings


def run_opengrep(snapshot: Path) -> dict:
    started = time.time()
    if not docker_available():
        return _result("opengrep", "not_tested", "Docker no disponible: el SAST multi-lenguaje no se ejecutó.")
    if not image_available("opengrep"):
        return _result("opengrep", "not_tested", "Imagen de Opengrep no construida: docker build -t appsec-agent/opengrep:1.30.0 containers/opengrep.")
    languages = snapshot_languages(snapshot)
    try:
        completed = _run("opengrep", ["scan", "--config", "/rules", "--json", "--quiet", "/src"], snapshot,
                         mounts=["-v", f"{host_path(RULES_DIR)}:/rules:ro"])
        payload = json.loads(completed.stdout or "{}")
    except subprocess.TimeoutExpired:
        return _result("opengrep", "inconclusive", "Opengrep superó el tiempo máximo; el SAST no concluyó.", started=started)
    except (OSError, ValueError):
        return _result("opengrep", "inconclusive", "Opengrep no devolvió una salida legible.", started=started)
    findings = parse_opengrep(payload)
    errors = [item for item in payload.get("errors", []) if isinstance(item, dict)]
    covered = ", ".join(f"{name} ({count})" for name, count in sorted(languages["covered"].items())) or "ninguno con reglas"
    uncovered = ", ".join(sorted(languages["uncovered"]))
    detail = (f"{sum(1 for _ in RULES_DIR.glob('*.yml'))} conjuntos de reglas propias sobre {covered}; "
              f"{len(findings)} candidatos.")
    if uncovered:
        detail += f" Sin reglas todavía para: {uncovered}."
    if errors:
        detail += f" {len(errors)} archivos no se pudieron analizar (sintaxis o tamaño)."
    status = "partial" if (errors or uncovered) else "completed"
    return _result("opengrep", status, detail, findings, started)


# --- Trivy ----------------------------------------------------------------------------

def _pick_fixed(fixed: str | None, installed: str) -> str | None:
    candidates = [item.strip() for item in str(fixed or "").split(",") if item.strip()]
    later = [item for item in candidates if compare_versions(item, installed) > 0]
    return min(later, key=lambda item: (len(item.split(".")), item)) if later else (candidates[0] if candidates else None)


def _trivy_vulnerability(entry: dict, target: str, ecosystem: str, feeds: dict) -> dict:
    identifier = str(entry.get("VulnerabilityID", ""))
    name, installed = str(entry.get("PkgName", "")), str(entry.get("InstalledVersion", ""))
    fixed = _pick_fixed(entry.get("FixedVersion"), installed)
    scores = entry.get("CVSS") or {}
    vector = score = None
    for source in ("nvd", "ghsa", "redhat"):
        block = scores.get(source) or {}
        if block.get("V3Vector"):
            vector, score = block["V3Vector"], cvss3_base_score(block["V3Vector"]) or block.get("V3Score")
            break
    severity = severity_from_score(score, entry.get("Severity"))
    cves = [identifier] if identifier.startswith("CVE-") else [item for item in entry.get("VendorIDs", []) or [] if str(item).startswith("CVE-")]
    ghsas = [identifier] if identifier.startswith("GHSA-") else []
    kev = next((feeds.get("kev", {}).get(cve) for cve in cves if feeds.get("kev", {}).get(cve)), None)
    epss = next((feeds.get("epss", {}).get(cve) for cve in cves if feeds.get("epss", {}).get(cve)), None)
    priority = prioritize(severity, score, kev, epss, fixed)
    summary = str(entry.get("Title") or "").strip() or identifier
    cwe = [int(match.group(1)) for item in entry.get("CweIDs", []) or [] if (match := re.fullmatch(r"CWE-(\d+)", str(item)))]
    references = [url for url in entry.get("References", []) or [] if isinstance(url, str) and url.startswith("https://")][:8]
    remediation = (f"Actualiza {name} de {installed} a {fixed} o superior en {target} y regenera el lockfile."
                   if fixed else f"No hay versión corregida publicada para {name}. Evalúa alcanzabilidad, mitiga o sustituye la dependencia.")
    digest = sca_fingerprint("sca", identifier, ecosystem, name, installed)
    return {"finding_id": digest[:16], "fingerprint": digest, "scanner": "sca", "tool": "trivy", "rule_id": identifier,
            "title": f"{name} {installed}: {summary}"[:200], "path": target, "line": 1, "severity": severity,
            "confidence": 8 if score is not None else 6, "verdict": "candidate", "cwe": cwe, "owasp": ["A03:2025"],
            "cve": cves, "ghsa": ghsas,
            "package": {"ecosystem": ecosystem, "name": name, "version": installed, "fixed_version": fixed, "introduced": None},
            "advisory": {"id": identifier, "aliases": cves + ghsas, "summary": summary,
                         "details": str(entry.get("Description") or "")[:2000], "cvss_vector": vector,
                         "cvss_score": score, "published": entry.get("PublishedDate"),
                         "modified": entry.get("LastModifiedDate"), "references": references},
            "kev": kev, "epss": {"score": epss[0], "percentile": epss[1]} if epss else None,
            "priority": priority, "reason": summary, "remediation": remediation}


def _trivy_misconfiguration(entry: dict, target: str) -> dict:
    cause = entry.get("CauseMetadata") or {}
    line = int(cause.get("StartLine") or 1)
    rule = str(entry.get("AVDID") or entry.get("ID") or "misconfig")
    severity = SEVERITY_LABEL.get(str(entry.get("Severity", "")).upper(), "medium")
    resource = str(cause.get("Resource") or cause.get("Provider") or "")
    return _base("iac", rule, f"{entry.get('Title', rule)}", target, line, severity, tool="trivy",
                 reason=str(entry.get("Message") or entry.get("Description") or "").strip(),
                 remediation=str(entry.get("Resolution") or "Revisa la configuración según la referencia del aviso.").strip(),
                 cwe=[], owasp="A02:2025", confidence=8,
                 digest=_stable("iac", rule, target, resource or str(line)))


def _trivy_secret(entry: dict, target: str) -> dict:
    line = int(entry.get("StartLine") or 1)
    rule = str(entry.get("RuleID") or "secret")
    severity = SEVERITY_LABEL.get(str(entry.get("Severity", "")).upper(), "high")
    # Nunca se guarda el valor: Trivy ya lo redacta, y aquí ni siquiera se lee.
    return _base("secrets", rule, (SECRET_TITLES.get(rule) or f"Secreto expuesto: {entry.get('Title', rule)}"), target, line, severity, tool="trivy",
                 reason=f"Patrón {entry.get('Category', 'secreto')} en {target}:{line}; valor redactado.",
                 remediation="Rota la credencial ahora y muévela a un gestor de secretos. Si el repositorio es público, considera reescribir el historial.",
                 cwe=[798], owasp="A04:2025", confidence=8, digest=_stable("secrets", rule, target, str(line)))


def parse_trivy(payload: dict, feeds: dict) -> list[dict]:
    findings = []
    for result in payload.get("Results", []) or []:
        target = _relative(str(result.get("Target", "")))
        ecosystem = str(result.get("Type") or "").lower() or "unknown"
        for entry in result.get("Vulnerabilities") or []:
            findings.append(_trivy_vulnerability(entry, target, ecosystem, feeds))
        for entry in result.get("Misconfigurations") or []:
            if str(entry.get("Status", "FAIL")).upper() == "FAIL":
                findings.append(_trivy_misconfiguration(entry, target))
        for entry in result.get("Secrets") or []:
            findings.append(_trivy_secret(entry, target))
    seen, unique = set(), []
    for finding in findings:
        if finding["fingerprint"] not in seen:
            seen.add(finding["fingerprint"])
            unique.append(finding)
    return unique


def run_trivy(snapshot: Path, cache_dir: Path, feeds: dict) -> dict:
    started = time.time()
    if not docker_available():
        return _result("trivy", "not_tested", "Docker no disponible: dependencias, IaC y secretos con Trivy no se ejecutaron.")
    cache_dir.mkdir(parents=True, exist_ok=True)
    try:
        completed = _run("trivy", ["fs", "--scanners", "vuln,misconfig,secret", "--format", "json", "--quiet",
                                   "--timeout", "14m", "/src"], snapshot, network=True,
                         mounts=["-v", f"{host_path(cache_dir)}:/root/.cache/trivy"])
        if completed.returncode != 0 and not completed.stdout.strip():
            return _result("trivy", "inconclusive", "Trivy terminó con error antes de producir resultados"
                           + (" (sin acceso a su base de vulnerabilidades)." if "download" in completed.stderr.lower() else "."), started=started)
        payload = json.loads(completed.stdout or "{}")
    except subprocess.TimeoutExpired:
        return _result("trivy", "inconclusive", "Trivy superó el tiempo máximo; dependencias e IaC no concluyeron.", started=started)
    except (OSError, ValueError):
        return _result("trivy", "inconclusive", "Trivy no devolvió una salida legible.", started=started)
    findings = parse_trivy(payload, feeds)
    kinds = {"sca": 0, "iac": 0, "secrets": 0}
    for finding in findings:
        kinds[finding["scanner"]] = kinds.get(finding["scanner"], 0) + 1
    targets = [result.get("Target", "") for result in payload.get("Results", []) or []]
    manifests = [target for result, target in zip(payload.get("Results", []) or [], targets) if result.get("Class") == "lang-pkgs"]
    configs = [target for result, target in zip(payload.get("Results", []) or [], targets) if result.get("Class") == "config"]
    detail = (f"{len(manifests)} manifiestos de dependencias y {len(configs)} archivos de infraestructura examinados: "
              f"{kinds['sca']} avisos de dependencias, {kinds['iac']} fallos de configuración, {kinds['secrets']} secretos.")
    if not feeds.get("kev") or not feeds.get("epss"):
        detail += " KEV/EPSS no disponibles; la prioridad usa solo CVSS."
    return _result("trivy", "completed", detail, findings, started)


# --- Gitleaks -------------------------------------------------------------------------

# Nombre en español de las reglas de Gitleaks más comunes; el resto usa su identificador.
SECRET_TITLES = {
    "jwt": "JSON Web Token expuesto", "generic-api-key": "Clave de API expuesta", "private-key": "Clave privada expuesta",
    "aws-access-token": "Clave de acceso de AWS expuesta", "aws-secret-access-key": "Clave secreta de AWS expuesta",
    "github-pat": "Token personal de GitHub expuesto", "github-fine-grained-pat": "Token de GitHub expuesto",
    "github-app-token": "Token de GitHub App expuesto", "github-oauth": "Token OAuth de GitHub expuesto",
    "gitlab-pat": "Token de GitLab expuesto", "slack-bot-token": "Token de Slack expuesto", "slack-webhook-url": "Webhook de Slack expuesto",
    "stripe-access-token": "Clave de Stripe expuesta", "gcp-api-key": "Clave de API de Google expuesta",
    "openai-api-key": "Clave de API de OpenAI expuesta", "anthropic-api-key": "Clave de API de Anthropic expuesta",
    "twilio-api-key": "Clave de API de Twilio expuesta", "sendgrid-api-token": "Token de SendGrid expuesto",
    "npm-access-token": "Token de npm expuesto", "pypi-upload-token": "Token de PyPI expuesto",
    "azure-ad-client-secret": "Secreto de cliente de Azure AD expuesto", "heroku-api-key": "Clave de API de Heroku expuesta",
}


def secret_title(rule: str) -> str:
    return SECRET_TITLES.get(rule) or f"Secreto expuesto ({rule})"


def parse_gitleaks(payload: list) -> list[dict]:
    findings = []
    for entry in payload or []:
        if not isinstance(entry, dict):
            continue
        rule = str(entry.get("RuleID") or "secret")
        path = _relative(str(entry.get("File", "")))
        line = int(entry.get("StartLine") or 1)
        entropy = float(entry.get("Entropy") or 0)
        severity = "medium" if rule.startswith("generic") else "high"
        # El valor nunca se lee: gitleaks corre con --redact y aquí solo se toman regla, archivo y línea.
        findings.append(_base("secrets", rule, secret_title(rule), path, line, severity, tool="gitleaks",
                              reason=f"Regla {rule} en {path}:{line} (entropía {entropy:.1f}); valor redactado.",
                              remediation="Rota la credencial ahora y muévela a un gestor de secretos. Si el repositorio es público, considera reescribir el historial.",
                              cwe=[798], owasp="A04:2025", confidence=8 if entropy >= 3.5 else 6,
                              digest=_stable("secrets", rule, path, str(line))))
    return findings


def run_gitleaks(snapshot: Path) -> dict:
    started = time.time()
    if not docker_available():
        return _result("gitleaks", "not_tested", "Docker no disponible: la detección de secretos con Gitleaks no se ejecutó.")
    # El reporte se escribe junto al snapshot: es la única carpeta que ambos contenedores ven.
    with tempfile.TemporaryDirectory(prefix="gitleaks-", dir=snapshot.parent) as output:
        try:
            completed = _run("gitleaks", ["dir", "/src", "--report-format", "json", "--report-path", "/out/report.json",
                                          "--no-banner", "--exit-code", "0", "--redact"], snapshot,
                             mounts=["-v", f"{host_path(Path(output))}:/out"], timeout=600)
            report = Path(output) / "report.json"
            payload = json.loads(report.read_text(encoding="utf-8") or "[]") if report.is_file() else []
        except subprocess.TimeoutExpired:
            return _result("gitleaks", "inconclusive", "Gitleaks superó el tiempo máximo.", started=started)
        except (OSError, ValueError):
            return _result("gitleaks", "inconclusive", "Gitleaks no devolvió un reporte legible.", started=started)
    if completed.returncode not in (0, 1):
        return _result("gitleaks", "inconclusive", "Gitleaks terminó con error.", started=started)
    findings = parse_gitleaks(payload)
    return _result("gitleaks", "completed", f"Reglas de Gitleaks sobre el snapshot: {len(findings)} secretos; valores redactados.", findings, started)


def merge_secrets(*groups: list[dict]) -> list[dict]:
    """Un mismo secreto lo ven dos motores: se conserva uno y se anota el otro."""
    by_location: dict[tuple[str, int], dict] = {}
    for group in groups:
        for finding in group:
            key = (finding["path"], finding["line"])
            if key in by_location:
                by_location[key].setdefault("also_detected_by", []).append(finding["tool"])
            else:
                by_location[key] = finding
    return list(by_location.values())
