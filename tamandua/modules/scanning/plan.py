"""Qué va a hacer un escaneo de este repositorio, calculado antes de lanzarlo.

El paso «Revisar y lanzar» del asistente se construye aquí con datos reales, no
con texto fijo: qué motores están disponibles y en qué versión, qué lenguajes
tiene el repositorio (leídos del árbol de git, sin descargarlo) y cuáles cubren
las reglas SAST propias, qué manifiestos puede resolver el análisis de
dependencias y si hay infraestructura como código. Lo que no se va a cubrir se
dice con nombre propio.
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import PurePosixPath

from tamandua.modules.sources.repositories import is_manifest
from tamandua.modules.scanning.engines import IMAGES, RULES_DIR, engine_ready, joined
from tamandua.shared.i18n import msg

EXTENSIONS = {
    ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".vue": "JavaScript", ".svelte": "JavaScript",
    ".java": "Java", ".kt": "Kotlin", ".kts": "Kotlin", ".go": "Go", ".php": "PHP", ".rb": "Ruby", ".cs": "C#",
    ".rs": "Rust", ".swift": "Swift", ".scala": "Scala", ".dart": "Dart", ".c": "C", ".h": "C",
    ".cpp": "C++", ".cc": "C++", ".hpp": "C++", ".ex": "Elixir", ".exs": "Elixir", ".lua": "Lua", ".sh": "Shell",
}
# Nombre del lenguaje en las reglas → nombre mostrado.
RULE_LANGUAGES = {"python": "Python", "javascript": "JavaScript", "typescript": "TypeScript", "java": "Java",
                  "go": "Go", "php": "PHP", "ruby": "Ruby", "csharp": "C#"}
SKIP = {"node_modules", ".git", "vendor", "dist", "build", ".next", "venv", ".venv", "__pycache__", "target"}


def _language(item: dict, *, rules: bool = True) -> dict:
    """«Python (14 rules, 2 files)» or, without rules, «Rust (1 file)»."""
    if rules:
        return msg("scanning.plan.language_rules", name=item["name"], rules=msg("scanning.plan.rules", count=item["rules"]),
                   files=msg("scanning.plan.files", count=item["files"]))
    return msg("scanning.plan.language", name=item["name"], files=msg("scanning.plan.files", count=item["files"]))


def _sample(paths: list[str]) -> str:
    return ", ".join(paths[:4]) + ("…" if len(paths) > 4 else "")


def rule_counts() -> Counter:
    """Reglas propias por lenguaje, leídas de los ficheros de reglas (una línea `languages:` por regla)."""
    counts: Counter = Counter()
    for path in RULES_DIR.glob("*.yml"):
        for line in path.read_text(encoding="utf-8").splitlines():
            match = re.match(r"\s*languages:\s*\[([^\]]+)\]", line)
            if match:
                for language in {item.strip() for item in match[1].split(",")}:
                    if language in RULE_LANGUAGES:
                        counts[RULE_LANGUAGES[language]] += 1
    return counts


def files_of(source_id: str, *, installation_id: int | None) -> list[str] | None:
    """Rutas del repositorio sin descargarlo. None si el proveedor no permite listarlas."""
    if source_id.startswith("github:") and installation_id is not None:
        from tamandua.modules.integrations.github import installation_repository, repository_tree
        entry = installation_repository(installation_id, source_id)
        if entry is None:
            return None
        return [item["path"] for item in repository_tree(installation_id, source_id.removeprefix("github:"), entry.get("branch") or "main")
                if item.get("type") == "blob" and isinstance(item.get("path"), str)]
    return None


def plan(source_id: str, *, installation_id: int | None) -> dict:
    paths = files_of(source_id, installation_id=installation_id)
    paths = [path for path in (paths or []) if not SKIP.intersection(path.split("/"))] if paths is not None else None
    engines = {key: {"key": key, "name": value["name"], "version": value["version"],
                     "available": engine_ready(key)} for key, value in IMAGES.items()}
    rules = rule_counts()
    languages = Counter()
    manifests, iac, pipelines = [], [], []
    for path in paths or []:
        name = path.rsplit("/", 1)[-1]
        suffix = ("." + name.rsplit(".", 1)[-1].lower()) if "." in name else ""
        if suffix in EXTENSIONS:
            languages[EXTENSIONS[suffix]] += 1
        # La misma definición que decide qué entra al snapshot: el plan no promete lo que no se descarga.
        if is_manifest(PurePosixPath(path)):
            manifests.append(path)
        if name == "Dockerfile" or name.endswith((".tf", ".tfvars", ".bicep")) or name in ("Chart.yaml", "kustomization.yaml", "serverless.yml") \
                or re.fullmatch(r"(docker-)?compose[\w.-]*\.ya?ml", name):
            iac.append(path)
        if re.fullmatch(r"\.github/workflows/[^/]+\.ya?ml", path) or name in ("action.yml", "action.yaml", ".gitlab-ci.yml",
                                                                             "bitbucket-pipelines.yml", "azure-pipelines.yml") \
                or path == ".circleci/config.yml":
            pipelines.append(path)
    detected = [{"name": name, "files": count, "rules": rules.get(name, 0)} for name, count in languages.most_common()]
    runs, skips = [msg("scanning.plan.runs.snapshot")], [msg("scanning.plan.skips.no_execution")]
    opengrep, gitleaks, trivy, osv = engines["opengrep"], engines["gitleaks"], engines["trivy"], engines["osv-scanner"]
    covered = [item for item in detected if item["rules"]]
    uncovered = [item for item in detected if not item["rules"]]
    if opengrep["available"]:
        if covered:
            runs.append(msg("scanning.plan.runs.sast", engine=opengrep["name"], version=opengrep["version"],
                            languages=joined(_language(item) for item in covered)))
        elif paths is not None:
            skips.append(msg("scanning.plan.skips.sast_no_files"))
    else:
        runs.append(msg("scanning.plan.runs.internal_sast"))
        uncovered = [item for item in detected if item["name"] != "Python"]
    if uncovered:
        skips.append(msg("scanning.plan.skips.no_rules", languages=joined(_language(item, rules=False) for item in uncovered)))
    runs.append(msg("scanning.plan.runs.secrets", engine=gitleaks["name"], version=gitleaks["version"])
                if gitleaks["available"] else msg("scanning.plan.runs.internal_secrets"))
    if trivy["available"]:
        if manifests:
            common = {"engine": trivy["name"], "version": trivy["version"], "sample": _sample(manifests),
                      "manifests": msg("scanning.plan.manifests", count=len(manifests))}
            runs.append(msg("scanning.plan.runs.dependencies_osv", osv=osv["name"], osv_version=osv["version"], **common)
                        if osv["available"] else msg("scanning.plan.runs.dependencies", **common))
        elif paths is not None:
            skips.append(msg("scanning.plan.skips.no_manifests"))
        if iac:
            runs.append(msg("scanning.plan.runs.iac", engine=trivy["name"], sample=_sample(iac)))
    else:
        runs.append(msg("scanning.plan.runs.osv_only"))
        if iac:
            skips.append(msg("scanning.plan.skips.iac_without_trivy", files=msg("scanning.plan.files", count=len(iac))))
    checkov, zizmor = engines["checkov"], engines["zizmor"]
    if iac or pipelines or paths is None:
        if checkov["available"]:
            runs.append(msg("scanning.plan.runs.checkov", engine=checkov["name"], version=checkov["version"]))
        else:
            skips.append(msg("scanning.plan.skips.no_checkov"))
    if pipelines or paths is None:
        if zizmor["available"]:
            runs.append(msg("scanning.plan.runs.zizmor_workflows", engine=zizmor["name"], version=zizmor["version"],
                            workflows=msg("scanning.plan.workflows", count=len(pipelines)))
                        if pipelines else msg("scanning.plan.runs.zizmor", engine=zizmor["name"], version=zizmor["version"]))
        elif pipelines:
            skips.append(msg("scanning.plan.skips.no_zizmor"))
    skips += [msg("scanning.plan.skips.no_dast"), msg("scanning.plan.skips.no_ai")]
    if paths is None:
        runs.insert(1, msg("scanning.plan.runs.languages_later"))
    return {"source_id": source_id, "languages": detected, "engines": list(engines.values()), "manifests": manifests[:50],
            "iac": iac[:50], "pipelines": pipelines[:50], "runs": runs, "skips": skips, "osv_needed": not trivy["available"],
            "files": len(paths) if paths is not None else None}
