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
from tamandua.modules.scanning import secret_rules
from tamandua.modules.scanning.engines import SECRET_SEVERITY, EngineStep, ScanContext, report_done, run_engines, SEVERITY_NAME, and_list, engines_available, joined as join_messages, host_mount_problem, run_osv_scanner, runner, socket_problem, merge_secrets, run_gitleaks, run_opengrep, run_trivy, masked_lead, secret_context, with_secret_identities
from tamandua.shared.i18n import msg
from tamandua.shared.model import RunRecord
from tamandua.version import USER_AGENT


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
# Titles of the internal secret patterns (the name above is part of the rule id and must not change).
SECRET_TITLES = {
    "GitHub token": msg("scanning.internal.secret_titles.github_token"),
    "OpenAI API key": msg("scanning.internal.secret_titles.openai_api_key"),
    "AWS access key ID": msg("scanning.internal.secret_titles.aws_access_key_id"),
    "JSON Web Token": msg("scanning.internal.secret_titles.jwt"),
    "clave privada": msg("scanning.internal.secret_titles.private_key"),
    "Stripe secret key": msg("scanning.internal.secret_titles.stripe_secret_key"),
    "Slack token": msg("scanning.internal.secret_titles.slack_token"),
    "Google API key": msg("scanning.internal.secret_titles.google_api_key"),
}
CODE_EXTENSIONS = {".py", ".js", ".ts", ".tsx", ".jsx", ".json", ".yaml", ".yml", ".env", ".md", ".txt", ".html", ".xml",
                   ".rst", ".ipynb", ".pem", ".key", ".toml", ".ini", ".cfg", ".conf", ".properties", ".sh", ".tf"}


def _finding(scanner: str, rule: str, title, path: str, line: int, severity: str,
             reason, cwe: int, owasp: str, *, cve: list[str] | None = None,
             ghsa: list[str] | None = None) -> dict:
    fingerprint = hashlib.sha256(f"{scanner}|{rule}|{path}|{line}".encode()).hexdigest()
    if scanner == "secrets":
        severity = SECRET_SEVERITY
    action = "attend" if severity in ("critical", "high") else "track"
    return {"finding_id": fingerprint[:16], "fingerprint": fingerprint, "scanner": scanner, "rule_id": rule,
            "title": title, "path": path, "line": line, "severity": severity,
            "confidence": 6, "verdict": "candidate", "cwe": [cwe] if cwe else [], "owasp": [owasp],
            "cve": cve or [], "ghsa": ghsa or [], "reason": reason, "package": None, "advisory": None,
            "kev": None, "epss": None,
            "priority": {"action": action, "factors": [msg("scanning.priority.internal_pattern", severity=SEVERITY_NAME.get(severity, severity))]},
            "remediation": msg("scanning.internal.remediation")}


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
            results.append(_finding("sast", "PY-SQL-STRING", msg("scanning.internal.sql.title"), relative, node.lineno,
                                    "high", msg("scanning.internal.sql.reason"), 89, "A05:2025"))
        if name in ("run", "Popen", "call", "check_output") and any(
                keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True
                for keyword in node.keywords):
            results.append(_finding("sast", "PY-SHELL-TRUE", msg("scanning.internal.shell.title"), relative, node.lineno,
                                    "high", msg("scanning.internal.shell.reason"), 78, "A05:2025"))
        if name in ("eval", "exec") and isinstance(func, ast.Name):
            results.append(_finding("sast", "PY-DYNAMIC-CODE", msg("scanning.internal.dynamic_code.title"), relative, node.lineno,
                                    "medium", msg("scanning.internal.dynamic_code.reason"), 95, "A05:2025"))
    return results


def _secret_candidates(path: Path, relative: str) -> list[dict]:
    try:
        content = path.read_text(encoding="utf-8")
    except (UnicodeError, OSError):
        return []
    items = []
    for number, line in enumerate(content.splitlines(), 1):
        spans = [found.span() for _, pattern in SECRET_RULES for found in pattern.finditer(line)]
        for name, pattern in SECRET_RULES:
            if found := pattern.search(line):
                items.append((_finding("secrets", name.upper().replace(" ", "-"), SECRET_TITLES[name], relative, number,
                                       SECRET_SEVERITY, msg("scanning.internal.secret_reason"), 798, "A04:2025"),
                              secret_context(masked_lead(line, found.start(), spans)), (number, found.start())))
    return with_secret_identities(items)


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
                      headers={"Content-Type": "application/json", "User-Agent": USER_AGENT}, method="POST")
    with urlopen(request, timeout=15) as response:
        body = response.read(2_000_001)
    if len(body) > 2_000_000:
        raise ValueError("OSV response too large")
    data = json.loads(body)
    if not isinstance(data.get("results"), list) or len(data["results"]) != len(dependencies):
        raise ValueError("Invalid OSV response")
    return data["results"]


# The engines of a code scan, in the order they run. Each is looked up here when it runs (so a test can replace one).
# `required`: without its result the run is incomplete. `merged`: its progress line waits for the merge below.
# Adding an engine: its image in engines.IMAGES, its run_* function, a line here and, if it overlaps others, its merge.
CODE_ENGINES: tuple[EngineStep, ...] = (
    EngineStep("opengrep", lambda context: run_opengrep(context.root), "scanning.progress.opengrep"),
    EngineStep("gitleaks", lambda context: run_gitleaks(context.root, context.secret_settings), "scanning.progress.gitleaks"),
    EngineStep("trivy", lambda context: run_trivy(context.root, context.data_dir / "trivy-cache", context.feeds, context.secret_settings),
               "scanning.progress.trivy"),
    EngineStep("osv-scanner", lambda context: run_osv_scanner(context.root, context.data_dir / "osv-cache", context.feeds,
                                                              resolve=context.allow_osv_upload),
               "scanning.progress.osv", merged=True),
    EngineStep("checkov", lambda context: run_checkov(context.root), "scanning.progress.checkov", required=False, merged=True),
    EngineStep("zizmor", lambda context: run_zizmor(context.root), "scanning.progress.zizmor", required=False, merged=True),
)
REQUIRED_ENGINES = frozenset(engine.key for engine in CODE_ENGINES if engine.required)


def scan_repository(root: Path, source: dict, *, allow_osv_upload: bool = False,
                    context: str = "", data_dir: Path | None = None, progress=None) -> RunRecord:
    def report(level: str, message) -> None:
        if progress is not None:
            progress(level, message)

    files = sorted(path for path in root.rglob("*") if path.is_file() and not path.is_symlink())
    findings, withheld = [], []
    snapshot = source.get("snapshot") or {}
    skipped = (snapshot.get("skipped", 0) + snapshot.get("skipped_not_analyzable", 0)
               + snapshot.get("skipped_too_large", 0) + snapshot.get("skipped_over_budget", 0))
    detail = msg("scanning.repository.snapshot.copied", files=len(files))
    if skipped:
        counts = {"skipped": skipped, "not_analyzable": snapshot.get("skipped_not_analyzable", 0),
                  "too_large": snapshot.get("skipped_too_large", 0)}
        detail = (msg("scanning.repository.snapshot.skipped_budget", detail=detail, over_budget=snapshot["skipped_over_budget"], **counts)
                  if snapshot.get("skipped_over_budget") else msg("scanning.repository.snapshot.skipped", detail=detail, **counts))
    steps = [{"id": "snapshot", "name": msg("scanning.repository.steps.snapshot"),
              "status": "partial" if snapshot.get("truncated") else "completed", "detail": detail}]
    digest = hashlib.sha256()
    for path in files:
        relative = path.relative_to(root).as_posix()
        digest.update(relative.encode() + b"\0" + hashlib.sha256(path.read_bytes()).digest())
    engines = engines_available()
    docker = runner() == "docker"
    feeds = load_feeds(data_dir or Path("data")) if (engines or allow_osv_upload) else {"kev": {}, "epss": {}}
    tools: list[dict] = []
    misconfigured = None if engines or not docker else socket_problem()
    if misconfigured:
        # Docker está, pero este contenedor no puede usarlo: no es un análisis sin motores a propósito.
        report("warn", misconfigured)
    if engines:
        # Each engine runs in its container pinned by digest; the step keeps version, image and duration.
        mount_problem = host_mount_problem() if docker else None
        if mount_problem:
            report("warn", mount_problem)
        # The defaults plus this repository's own entries apply to both secret engines.
        secret_settings = secret_rules.for_scan(data_dir, source.get("uid") or source.get("id") or source.get("name"))
        results = run_engines(CODE_ENGINES, ScanContext(root, data_dir or Path("data"), feeds, secret_settings, allow_osv_upload), report)
        sast, secrets_gitleaks, trivy = results["opengrep"], results["gitleaks"], results["trivy"]
        osv, checkov, zizmor = results["osv-scanner"], results["checkov"], results["zizmor"]
        tools = list(results.values())
        # An engine that didn't run isn't "zero findings": it's said plainly and the run is incomplete.
        failed = [results[engine.key]["name"] for engine in CODE_ENGINES if engine.required and results[engine.key]["status"] == "inconclusive"]
        if failed:
            report("warn", msg("scanning.progress.engines_failed", engines=", ".join(failed)))
        findings.extend(sast["findings"])
        trivy_secrets = [item for item in trivy["findings"] if item["scanner"] == "secrets"]
        findings.extend(merge_secrets(secrets_gitleaks["findings"], trivy_secrets))
        withheld = merge_secrets(secrets_gitleaks.get("withheld") or [], trivy.get("withheld") or [])
        # Trivy manda (sus huellas sostienen el triage ya hecho); OSV-Scanner suma lo que Trivy no ve y
        # confirma lo que coincide, sin repetir el aviso aunque lo nombre con otro identificador.
        dependencies_found, dependency_merge = merge_dependencies([item for item in trivy["findings"] if item["scanner"] == "sca"],
                                                                  ("osv-scanner", osv["findings"]))
        findings.extend(dependencies_found)
        if osv["status"] == "completed" and osv["findings"]:
            osv["detail"] = msg("scanning.repository.osv_merged", detail=osv["detail"], joined=dependency_merge["joined"],
                                new=dependency_merge["new"])
        report_done(report, osv)
        # Lo que Trivy y Checkov (o zizmor y Checkov) ven a la vez queda como un solo hallazgo con los dos motores.
        configuration, joined = merge_repository([item for item in trivy["findings"] if item["scanner"] == "iac"],
                                                 checkov["findings"], zizmor["findings"])
        findings.extend(configuration)
        if checkov["status"] == "completed" and checkov["findings"]:
            checkov["detail"] = msg("scanning.repository.checkov_merged", detail=checkov["detail"], joined=joined["joined"],
                                    new=joined["checkov_new"])
        report_done(report, checkov)
        report_done(report, zizmor)
        for tool in tools:
            steps.append({"id": tool["tool"], "name": f"{tool['name']} {tool['version']}", "status": tool["status"],
                          "detail": tool["detail"], "tool": {"name": tool["tool"], "version": tool["version"],
                                                            "image": tool["image"], "duration_s": tool["duration_s"]}})
    else:
        report("warn", msg("scanning.progress.no_docker"))
        for path in files:
            relative = path.relative_to(root).as_posix()
            if path.suffix == ".py":
                findings.extend(_python_sast(path, relative))
            if path.suffix in CODE_EXTENSIONS or path.name.startswith(".env"):
                findings.extend(_secret_candidates(path, relative))
        steps.extend([
            {"id": "sast", "name": msg("scanning.repository.steps.internal_sast.name"), "status": "partial",
             "detail": msg("scanning.repository.steps.internal_sast.detail", candidates=sum(item["scanner"] == "sast" for item in findings))},
            {"id": "secrets", "name": msg("scanning.repository.steps.internal_secrets.name"), "status": "partial",
             "detail": msg("scanning.repository.steps.internal_secrets.detail",
                           candidates=sum(item["scanner"] == "secrets" for item in findings))},
        ])
    # Invariante del registro: una huella, un hallazgo. Ningún motor ni fusión puede colar un duplicado.
    unique, seen = [], set()
    for item in findings:
        if item["fingerprint"] not in seen:
            seen.add(item["fingerprint"])
            unique.append(item)
    findings = unique
    withheld = [item for item in withheld if item["fingerprint"] not in seen]
    sast_count = sum(item["scanner"] == "sast" for item in findings)
    secret_count = sum(item["scanner"] == "secrets" for item in findings)
    engine_sca = [tool["name"] for tool in tools if tool["tool"] in ("trivy", "osv-scanner") and tool["status"] == "completed"]
    trivy_sca = engines and bool(engine_sca)
    dependencies, manifests = _dependencies(root)
    dependency_scope = (msg("scanning.repository.sca.scope_first", versions=len(dependencies)) if len(dependencies) >= 250
                        else msg("scanning.repository.sca.scope", versions=len(dependencies)))
    if trivy_sca:
        report("info", msg("scanning.progress.feeds"))
        sca_count = sum(item["scanner"] == "sca" for item in findings)
        sca_status = "partial"
        joined = sum(1 for item in findings if item["scanner"] == "sca" and item.get("also_detected_by"))
        sca_detail = (msg("scanning.repository.sca.engines_confirmed", engines=and_list(engine_sca), advisories=sca_count, confirmed=joined)
                      if joined else msg("scanning.repository.sca.engines", engines=and_list(engine_sca), advisories=sca_count))
    elif not manifests:
        sca_status, sca_detail = "not_tested", msg("scanning.repository.sca.no_manifests")
    elif not dependencies:
        sca_status, sca_detail = "inconclusive", msg("scanning.repository.sca.no_versions")
    elif not allow_osv_upload:
        sca_status, sca_detail = "not_tested", msg("scanning.repository.sca.osv_not_allowed", scope=dependency_scope)
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
                                           msg("scanning.repository.sca.osv_without_detail", advisory=identifier),
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
            parts = [msg("scanning.repository.sca.osv_detail", scope=dependency_scope, advisories=len(sca_findings),
                         packages=len(packages), fixed=fixed, kev=in_kev)]
            if not feeds.get("kev") or not feeds.get("epss"):
                parts.append(msg("scanning.repository.sca.no_feeds"))
            if len(identifiers) > MAX_DETAILS:
                parts.append(msg("scanning.repository.sca.detailed_subset", detailed=MAX_DETAILS, total=len(identifiers)))
            sca_detail = join_messages(parts, "scanning.join.sentences")
            sca_status = "partial"
        except (HTTPError, URLError, TimeoutError, OSError, ValueError, KeyError, TypeError):
            sca_status, sca_detail = "inconclusive", msg("scanning.repository.sca.osv_failed")
    steps.append({"id": "sca", "name": msg("scanning.repository.steps.sca", engines=" + ".join(engine_sca) if trivy_sca else "OSV"),
                  "status": sca_status, "detail": sca_detail})
    steps.append({"id": "review", "name": msg("scanning.steps.review"), "status": "pending",
                  "detail": msg("scanning.repository.steps.review")})
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
                tool["tool"] in REQUIRED_ENGINES and tool["status"] == "inconclusive" for tool in tools)
                # Allowlisted secrets not identified: one that stopped appearing may only be silenced.
                or any("withheld" in tool and tool["withheld"] is None for tool in tools) else "completed",
            "source": source, "target": source["name"], "variant": "code", "context": declared,
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
            "limitations": ([msg("scanning.repository.limitations.truncated", files=snapshot.get("skipped_over_budget", 0))]
                            if snapshot.get("truncated") else [])
                           + [msg("scanning.repository.limitations.no_execution"),
                              msg("scanning.repository.limitations.sast_rules") if engines
                              else msg("scanning.repository.limitations.no_docker"),
                              msg("scanning.repository.limitations.sca_cap"), msg("scanning.repository.limitations.osv_not_exploit"),
                              msg("scanning.repository.limitations.no_ai_dast")]
                           + ([msg("scanning.secret_rules.withheld.limitation", count=len(withheld))] if withheld else []),
            **({"excluded_findings": withheld} if withheld else {}),
            "scanned_at": datetime.now(timezone.utc).isoformat()}
