"""Análisis pasivo de snapshot: SAST acotado, secretos redactados y SCA OSV."""

from __future__ import annotations

import ast
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from tamandua.modules.scanning.inventory import collect as collect_inventory
from tamandua.modules.scanning.unused_deps import analyze as unused_dependencies
from tamandua.modules.intel.advisories import MAX_DETAILS, dependency_finding, fetch_advisory, load_feeds
from tamandua.modules.scanning.coverage import owasp_coverage
from tamandua.modules.scanning.config_engines import merge_repository, run_checkov, run_zizmor
from tamandua.modules.scanning.dependency_merge import merge_dependencies
from tamandua.modules.scanning.engines import IMAGES, docker_available, host_mount_problem, run_osv_scanner, socket_problem, merge_secrets, run_gitleaks, run_opengrep, run_trivy


SECRET_RULES = (
    ("GitHub token", re.compile(r"\b(?:ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9]{36,}\b")),
    ("OpenAI API key", re.compile(r"\bsk-[A-Za-z0-9_-]{30,}\b")),
    ("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    # Firma incluida: un JWT completo en el código o la documentación es una credencial reutilizable.
    ("JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("clave privada", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----")),
    ("Stripe secret key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b")),
    ("Slack token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
)
CODE_EXTENSIONS = {".py", ".js", ".ts", ".tsx", ".jsx", ".json", ".yaml", ".yml", ".env", ".md", ".txt", ".html", ".xml",
                   ".rst", ".ipynb", ".pem", ".key", ".toml", ".ini", ".cfg", ".conf", ".properties", ".sh", ".tf"}


def _finding(scanner: str, rule: str, title: str, path: str, line: int, severity: str,
             reason: str, cwe: int, owasp: str, *, cve: list[str] | None = None,
             ghsa: list[str] | None = None) -> dict:
    fingerprint = hashlib.sha256(f"{scanner}|{rule}|{path}|{line}".encode()).hexdigest()
    action = "attend" if severity in ("critical", "high") else "track"
    return {"finding_id": fingerprint[:16], "fingerprint": fingerprint, "scanner": scanner, "rule_id": rule,
            "title": title, "path": path, "line": line, "severity": severity,
            "confidence": 6, "verdict": "candidate", "cwe": [cwe] if cwe else [], "owasp": [owasp],
            "cve": cve or [], "ghsa": ghsa or [], "reason": reason, "package": None, "advisory": None,
            "kev": None, "epss": None,
            "priority": {"action": action, "factors": [f"Patrón estático de severidad {severity}; requiere confirmar alcanzabilidad"]},
            "remediation": "Revisar el flujo y la versión afectada; validar la alcanzabilidad antes de priorizar."}


def _python_sast(path: Path, relative: str) -> list[dict]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
    except (SyntaxError, UnicodeError, OSError):
        return []
    results = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else ""
        if name in ("execute", "executemany") and node.args and isinstance(node.args[0], (ast.JoinedStr, ast.BinOp)):
            results.append(_finding("sast", "PY-SQL-STRING", "SQL construido dinámicamente", relative, node.lineno,
                                    "high", "Consulta formada con interpolación o concatenación; revisar si incorpora entrada no confiable.", 89, "A05:2025"))
        if name in ("run", "Popen", "call", "check_output") and any(
                keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True
                for keyword in node.keywords):
            results.append(_finding("sast", "PY-SHELL-TRUE", "Comando con shell=True", relative, node.lineno,
                                    "high", "La ejecución usa intérprete de shell; revisar el origen de sus argumentos.", 78, "A05:2025"))
        if name in ("eval", "exec") and isinstance(func, ast.Name):
            results.append(_finding("sast", "PY-DYNAMIC-CODE", "Ejecución dinámica de código", relative, node.lineno,
                                    "medium", "eval/exec requiere revisión del origen y validación del contenido.", 95, "A05:2025"))
    return results


def _secret_candidates(path: Path, relative: str) -> list[dict]:
    try:
        content = path.read_text(encoding="utf-8")
    except (UnicodeError, OSError):
        return []
    result = []
    for number, line in enumerate(content.splitlines(), 1):
        for name, pattern in SECRET_RULES:
            if pattern.search(line):
                result.append(_finding("secrets", name.upper().replace(" ", "-"),
                                       f"Posible {name}", relative, number, "high",
                                       "Patrón de credencial detectado. El valor se omitió del reporte y no se envió al navegador.",
                                       798, "A04:2025"))
    return result


def _dependencies(root: Path) -> tuple[list[dict], list[str]]:
    result = []
    manifests = []
    for lock in root.rglob("package-lock.json"):
        if any(part in {"node_modules", ".git", ".venv"} for part in lock.relative_to(root).parts):
            continue
        if len(result) >= 250:
            break
        try:
            data = json.loads(lock.read_text(encoding="utf-8"))
            packages = data.get("packages", {})
            if not isinstance(packages, dict):
                continue
            manifests.append(str(lock.relative_to(root)))
            for package_path, metadata in packages.items():
                if not isinstance(metadata, dict) or "node_modules/" not in package_path:
                    continue
                name = package_path.rsplit("node_modules/", 1)[1]
                version = metadata.get("version")
                if isinstance(version, str) and re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", version):
                    result.append({"name": name, "version": version, "ecosystem": "npm", "path": str(lock.relative_to(root))})
                if len(result) >= 250:
                    break
        except (OSError, ValueError, UnicodeError):
            continue
    for manifest in root.rglob("requirements.txt"):
        if any(part in {"node_modules", ".git", ".venv"} for part in manifest.relative_to(root).parts):
            continue
        try:
            lines = manifest.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError):
            continue
        manifests.append(str(manifest.relative_to(root)))
        for line in lines:
            match = re.fullmatch(r"\s*([A-Za-z0-9_.-]+)==(\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?)\s*", line)
            if match and len(result) < 250:
                result.append({"name": match[1], "version": match[2], "ecosystem": "PyPI", "path": str(manifest.relative_to(root))})
    unique = {(item["ecosystem"], item["name"], item["version"]): item for item in result}
    return list(unique.values()), manifests


def _query_osv(dependencies: list[dict]) -> list[dict]:
    request = Request("https://api.osv.dev/v1/querybatch",
                      data=json.dumps({"queries": [{"package": {"ecosystem": item["ecosystem"], "name": item["name"]},
                                                      "version": item["version"]} for item in dependencies]}).encode(),
                      headers={"Content-Type": "application/json", "User-Agent": "AppSecAgent/0.3"}, method="POST")
    with urlopen(request, timeout=15) as response:
        body = response.read(2_000_001)
    if len(body) > 2_000_000:
        raise ValueError("Respuesta OSV demasiado grande")
    data = json.loads(body)
    if not isinstance(data.get("results"), list) or len(data["results"]) != len(dependencies):
        raise ValueError("Respuesta OSV inválida")
    return data["results"]


def scan_repository(root: Path, source: dict, *, allow_osv_upload: bool = False,
                    context: str = "", data_dir: Path | None = None, progress=None) -> dict:
    def report(level: str, message: str) -> None:
        if progress is not None:
            progress(level, message)

    files = sorted(path for path in root.rglob("*") if path.is_file() and not path.is_symlink())
    findings = []
    snapshot = source.get("snapshot") or {}
    skipped = (snapshot.get("skipped", 0) + snapshot.get("skipped_not_analyzable", 0)
               + snapshot.get("skipped_too_large", 0) + snapshot.get("skipped_over_budget", 0))
    detail = f"{len(files)} archivos copiados en solo lectura, sin instalar dependencias ni ejecutar scripts."
    if skipped:
        detail += (f" Se dejaron fuera {skipped}: "
                   f"{snapshot.get('skipped_not_analyzable', 0)} no analizables (binarios, imágenes, bundles), "
                   f"{snapshot.get('skipped_too_large', 0)} por tamaño de archivo")
        if snapshot.get("skipped_over_budget"):
            detail += f" y {snapshot['skipped_over_budget']} al agotarse el presupuesto del snapshot"
        detail += "."
    steps = [{"id": "snapshot", "name": "Snapshot de código",
              "status": "partial" if snapshot.get("truncated") else "completed", "detail": detail}]
    digest = hashlib.sha256()
    for path in files:
        relative = path.relative_to(root).as_posix()
        digest.update(relative.encode() + b"\0" + hashlib.sha256(path.read_bytes()).digest())
    engines = docker_available()
    feeds = load_feeds(data_dir or Path("data")) if (engines or allow_osv_upload) else {"kev": {}, "epss": {}}
    tools: list[dict] = []
    misconfigured = None if engines else socket_problem()
    if misconfigured:
        # Docker está, pero este contenedor no puede usarlo: no es un análisis sin motores a propósito.
        report("warn", misconfigured)
    if engines:
        # Cada motor corre en su contenedor pinneado por digest; el paso guarda versión, imagen y duración.
        mount_problem = host_mount_problem()
        if mount_problem:
            report("warn", mount_problem)
        report("info", "Opengrep 1.30.0: SAST multi-lenguaje con reglas propias…")
        sast = run_opengrep(root)
        report("ok" if sast["status"] != "inconclusive" else "warn", f"Opengrep: {sast['detail']}")
        report("info", "Gitleaks 8.30.1: buscando secretos…")
        secrets_gitleaks = run_gitleaks(root)
        report("ok" if secrets_gitleaks["status"] != "inconclusive" else "warn", f"Gitleaks: {secrets_gitleaks['detail']}")
        report("info", "Trivy 0.74.0: dependencias, infraestructura y secretos…")
        trivy = run_trivy(root, (data_dir or Path("data")) / "trivy-cache", feeds)
        report("ok" if trivy["status"] != "inconclusive" else "warn", f"Trivy: {trivy['detail']}")
        report("info", f"OSV-Scanner {IMAGES['osv-scanner']['version']}: dependencias con la base OSV (la primera vez descarga las bases de avisos)…")
        osv = run_osv_scanner(root, (data_dir or Path("data")) / "osv-cache", feeds, resolve=allow_osv_upload)
        report("info", f"Checkov {IMAGES['checkov']['version']}: infraestructura como código y pipelines…")
        checkov = run_checkov(root)
        report("info", f"zizmor {IMAGES['zizmor']['version']}: seguridad de GitHub Actions…")
        zizmor = run_zizmor(root)
        tools = [sast, secrets_gitleaks, trivy, osv, checkov, zizmor]
        # Un motor que no corrió no es «cero hallazgos»: se dice en claro y la ejecución queda incompleta.
        failed = [tool["name"] for tool in (sast, secrets_gitleaks, trivy, osv) if tool["status"] == "inconclusive"]
        if failed:
            report("warn", f"No se pudieron ejecutar: {', '.join(failed)}. El resultado no equivale a «sin hallazgos»; "
                           "revisa en el servidor que las imágenes estén construidas (docker compose build).")
        findings.extend(sast["findings"])
        trivy_secrets = [item for item in trivy["findings"] if item["scanner"] == "secrets"]
        findings.extend(merge_secrets(secrets_gitleaks["findings"], trivy_secrets))
        # Trivy manda (sus huellas sostienen el triage ya hecho); OSV-Scanner suma lo que Trivy no ve y
        # confirma lo que coincide, sin repetir el aviso aunque lo nombre con otro identificador.
        dependencies_found, dependency_merge = merge_dependencies([item for item in trivy["findings"] if item["scanner"] == "sca"],
                                                                  ("osv-scanner", osv["findings"]))
        findings.extend(dependencies_found)
        if osv["status"] == "completed" and osv["findings"]:
            osv["detail"] += (f" {dependency_merge['joined']} coinciden con Trivy y se unieron al mismo hallazgo; "
                              f"{dependency_merge['new']} son nuevos.")
        report("ok" if osv["status"] != "inconclusive" else "warn", f"OSV-Scanner: {osv['detail']}")
        # Lo que Trivy y Checkov (o zizmor y Checkov) ven a la vez queda como un solo hallazgo con los dos motores.
        configuration, joined = merge_repository([item for item in trivy["findings"] if item["scanner"] == "iac"],
                                                 checkov["findings"], zizmor["findings"])
        findings.extend(configuration)
        if checkov["status"] == "completed" and checkov["findings"]:
            checkov["detail"] += (f" {joined['joined']} coinciden con Trivy o zizmor y se unieron al mismo hallazgo; "
                                  f"{joined['checkov_new']} son nuevos.")
        report("ok" if checkov["status"] != "inconclusive" else "warn", f"Checkov: {checkov['detail']}")
        report("ok" if zizmor["status"] != "inconclusive" else "warn", f"zizmor: {zizmor['detail']}")
        for tool in tools:
            steps.append({"id": tool["tool"], "name": f"{tool['name']} {tool['version']}", "status": tool["status"],
                          "detail": tool["detail"], "tool": {"name": tool["tool"], "version": tool["version"],
                                                            "image": tool["image"], "duration_s": tool["duration_s"]}})
    else:
        report("warn", "Docker no disponible: se usan las reglas internas (solo Python) y patrones de secretos.")
        for path in files:
            relative = path.relative_to(root).as_posix()
            if path.suffix == ".py":
                findings.extend(_python_sast(path, relative))
            if path.suffix in CODE_EXTENSIONS or path.name.startswith(".env"):
                findings.extend(_secret_candidates(path, relative))
        steps.extend([
            {"id": "sast", "name": "SAST interno (Python)", "status": "partial",
             "detail": f"{sum(item['scanner'] == 'sast' for item in findings)} candidatos con reglas AST internas. "
                       "Docker no disponible: sin Opengrep, solo Python queda cubierto."},
            {"id": "secrets", "name": "Secretos (patrones internos)", "status": "partial",
             "detail": f"{sum(item['scanner'] == 'secrets' for item in findings)} candidatos; valores redactados. Docker no disponible: sin Gitleaks ni Trivy."},
        ])
    # Invariante del registro: una huella, un hallazgo. Ningún motor ni fusión puede colar un duplicado.
    unique, seen = [], set()
    for item in findings:
        if item["fingerprint"] not in seen:
            seen.add(item["fingerprint"])
            unique.append(item)
    findings = unique
    sast_count = sum(item["scanner"] == "sast" for item in findings)
    secret_count = sum(item["scanner"] == "secrets" for item in findings)
    engine_sca = [tool["name"] for tool in tools if tool["tool"] in ("trivy", "osv-scanner") and tool["status"] == "completed"]
    trivy_sca = engines and bool(engine_sca)
    dependencies, manifests = _dependencies(root)
    dependency_scope = f"primeras {len(dependencies)} versiones fijadas" if len(dependencies) >= 250 else f"{len(dependencies)} versiones fijadas"
    if trivy_sca:
        report("info", "Cruzando avisos con CISA KEV y EPSS para priorizar…")
        sca_count = sum(item["scanner"] == "sca" for item in findings)
        sca_status = "partial"
        joined = sum(1 for item in findings if item["scanner"] == "sca" and item.get("also_detected_by"))
        sca_detail = (f"Dependencias de todos los ecosistemas del snapshot con {' y '.join(engine_sca)}: {sca_count} avisos "
                      f"únicos con versión corregida, CVSS, KEV y EPSS"
                      + (f"; {joined} confirmados por los dos motores" if joined else "") + ".")
    elif not manifests:
        sca_status, sca_detail = "not_tested", "No se encontró package-lock.json ni requirements.txt con versiones fijadas."
    elif not dependencies:
        sca_status, sca_detail = "inconclusive", "Hay manifiestos, pero no se extrajeron versiones fijadas compatibles."
    elif not allow_osv_upload:
        sca_status, sca_detail = ("not_tested", f"{dependency_scope} detectadas. Consulta OSV no autorizada; "
                                  "se requiere consentimiento para transmitir nombres y versiones de paquetes a api.osv.dev.")
    else:
        try:
            responses = _query_osv(dependencies)
            # querybatch solo devuelve identificadores: el detalle de cada aviso es lo que da valor.
            identifiers = []
            for item in responses:
                for vulnerability in item.get("vulns", []):
                    identifier = vulnerability.get("id", "")
                    if re.fullmatch(r"[A-Za-z0-9-]{5,80}", identifier) and identifier not in identifiers:
                        identifiers.append(identifier)
            details = {identifier: fetch_advisory(identifier) for identifier in identifiers[:MAX_DETAILS]}
            seen = set()
            for dependency, item in zip(dependencies, responses):
                for vulnerability in item.get("vulns", []):
                    identifier = vulnerability.get("id", "")
                    advisory = details.get(identifier)
                    if advisory:
                        finding = dependency_finding(dependency, advisory, feeds)
                    elif re.fullmatch(r"[A-Za-z0-9-]{5,80}", identifier):
                        finding = _finding("sca", identifier, f"{dependency['name']} {dependency['version']}: {identifier}",
                                           dependency["path"], 1, "medium",
                                           f"OSV asocia {identifier} a esta versión; no se pudo obtener el detalle del aviso.",
                                           1104, "A03:2025", cve=[identifier] if identifier.startswith("CVE-") else [],
                                           ghsa=[identifier] if identifier.startswith("GHSA-") else [])
                        finding["package"] = {"ecosystem": dependency["ecosystem"], "name": dependency["name"],
                                              "version": dependency["version"], "fixed_version": None, "introduced": None}
                    else:
                        continue
                    if finding["fingerprint"] in seen:
                        continue
                    seen.add(finding["fingerprint"])
                    findings.append(finding)
            sca_findings = [item for item in findings if item["scanner"] == "sca"]
            packages = {(item["package"] or {}).get("name") for item in sca_findings}
            fixed = sum(1 for item in sca_findings if (item.get("package") or {}).get("fixed_version"))
            in_kev = sum(1 for item in sca_findings if item.get("kev"))
            sca_detail = (f"{dependency_scope} consultadas en OSV; {len(sca_findings)} avisos en {len(packages)} paquetes, "
                          f"{fixed} con versión corregida publicada, {in_kev} en CISA KEV.")
            if not feeds.get("kev") or not feeds.get("epss"):
                sca_detail += " KEV/EPSS no disponibles en esta ejecución; la prioridad se calculó solo con CVSS."
            if len(identifiers) > MAX_DETAILS:
                sca_detail += f" Se detalló el aviso de {MAX_DETAILS} de {len(identifiers)} identificadores."
            sca_status = "partial"
        except (HTTPError, URLError, TimeoutError, OSError, ValueError, KeyError, TypeError):
            sca_status, sca_detail = "inconclusive", "No se pudo completar la consulta a OSV. No equivale a cero vulnerabilidades."
    steps.append({"id": "sca", "name": f"Dependencias · {' + '.join(engine_sca)}" if trivy_sca else "Dependencias · OSV", "status": sca_status, "detail": sca_detail})
    steps.append({"id": "review", "name": "Triage humano", "status": "pending", "detail": "Los resultados estáticos son candidatos; revisar flujo, alcanzabilidad y aplicabilidad."})
    iac_tools = tuple(tool["name"] for tool in tools if tool["tool"] in ("trivy", "checkov") and tool["status"] == "completed")
    iac_ran = engines and bool(iac_tools)
    cicd_tools = tuple(tool["name"] for tool in tools if tool["tool"] in ("checkov", "zizmor") and tool["status"] == "completed")
    sast_ran = engines and any(tool["tool"] == "opengrep" and tool["status"] in ("completed", "partial") for tool in tools)
    iac_files = sum(1 for path in files if path.name.lower() in ("dockerfile", "containerfile") or path.suffix.lower() in (".tf", ".tfvars", ".bicep")
                    or (path.suffix.lower() in (".yml", ".yaml", ".json") and any(marker in path.read_text(encoding="utf-8", errors="ignore")[:4000]
                                                                                 for marker in ("apiVersion:", "AWSTemplateFormatVersion", "services:",
                                                                                                "deploymentTemplate.json"))))
    pipelines = sum(1 for path in files if ".github/workflows/" in path.relative_to(root).as_posix()
                    or path.name in ("action.yml", "action.yaml", ".gitlab-ci.yml", "bitbucket-pipelines.yml", "azure-pipelines.yml")
                    or path.relative_to(root).as_posix() == ".circleci/config.yml")
    coverage = owasp_coverage(findings, sast_ran=bool(sast_ran), sca_status=sca_status, iac_ran=bool(iac_ran),
                              iac_files=iac_files, secrets_ran=True, engines=bool(engines), iac_tools=iac_tools,
                              cicd_tools=cicd_tools if engines else (), pipeline_files=pipelines)
    source = {**source, "sha256": digest.hexdigest()}
    declared = " ".join(str(context).split())[:400]
    severities = {level: sum(1 for item in findings if item["severity"] == level)
                  for level in ("critical", "high", "medium", "low", "info")}
    priorities = {action: sum(1 for item in findings if (item.get("priority") or {}).get("action") == action)
                  for action in ("act", "attend", "track")}
    truncated = bool(snapshot.get("truncated"))
    return {"type": "repository_scan",
            # Sin Docker no corrió ningún motor: las reglas internas no bastan para dar el repositorio por revisado.
            "status": "incomplete" if not engines or sca_status == "inconclusive" or truncated or misconfigured or any(
                tool["tool"] in ("opengrep", "gitleaks", "trivy", "osv-scanner") and tool["status"] == "inconclusive" for tool in tools) else "completed",
            "source": source, "fixture": source["name"], "variant": "code", "context": declared,
            "steps": steps, "findings": findings,
            "owasp_coverage": coverage, "inventory": collect_inventory(root), "unused_dependencies": unused_dependencies(root),
            # Paquetes con versión (de Trivy): la vigilancia diaria de avisos los contrasta sin reanalizar.
            "dependencies": next((tool.get("packages") or [] for tool in tools if tool["tool"] == "trivy"), []),
            "summary": {"files": len(files), "dependencies": len(dependencies),
                                                    "candidates": len(findings), "sast": sast_count,
                                                    "secrets": secret_count, "sca": sum(item["scanner"] == "sca" for item in findings),
                                                    "severities": severities, "priorities": priorities,
                                                    "kev": sum(1 for item in findings if item.get("kev")),
                                                    "fixable": sum(1 for item in findings if (item.get("package") or {}).get("fixed_version")),
                                                    "iac": sum(item["scanner"] == "iac" for item in findings),
                                                    "cicd": sum(item["scanner"] == "cicd" for item in findings),
                                                    "tools": [{"name": tool["tool"], "version": tool["version"], "status": tool["status"]} for tool in tools],
                                                    "planned": 3, "executed": 2 + (sca_status == "partial"),
                                                    "confirmed": 0},
            "limitations": ([f"El snapshot se truncó: {snapshot.get('skipped_over_budget', 0)} archivos "
                             "no se analizaron por límite de tamaño total. La cobertura de este repositorio es parcial."]
                            if snapshot.get("truncated") else [])
                           + ["No se ejecutó código del repositorio",
                              ("SAST con reglas propias: cobertura limitada a los lenguajes con reglas y sin análisis entre archivos"
                               if engines else "Sin Docker: SAST solo Python con reglas internas y secretos por patrones"),
                            "SCA limita la consulta a 250 versiones por ejecución",
                            "Los avisos de OSV no prueban explotación", "IA y DAST no participaron en esta ejecución"],
            "scanned_at": datetime.now(timezone.utc).isoformat()}
