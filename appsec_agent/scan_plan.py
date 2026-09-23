"""Qué va a hacer un escaneo de este repositorio, calculado antes de lanzarlo.

El paso «Revisar y lanzar» del asistente se construye aquí con datos reales, no
con texto fijo: qué motores están disponibles y en qué versión, qué lenguajes
tiene el repositorio (leídos del árbol de git, sin descargarlo) y cuáles cubren
las reglas SAST propias, qué manifiestos puede resolver el análisis de
dependencias y si hay infraestructura como código. Lo que no se va a cubrir se
dice con nombre propio.
"""

from __future__ import annotations

import os
import re
from collections import Counter
from pathlib import Path

from .scanners import IMAGES, RULES_DIR, docker_available, image_available

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
LOCKFILES = re.compile(r"(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|requirements[\w.-]*\.txt|"
                       r"poetry\.lock|Pipfile\.lock|uv\.lock|go\.mod|Cargo\.lock|composer\.lock|Gemfile\.lock|pom\.xml|"
                       r"gradle\.lockfile|packages\.lock\.json|mix\.lock|pubspec\.lock)")
SKIP = {"node_modules", ".git", "vendor", "dist", "build", ".next", "venv", ".venv", "__pycache__", "target"}


def _n(count: int, one: str, many: str) -> str:
    return f"{count} {one if count == 1 else many}"


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
    if source_id == "local:appsec-agent":
        from .repository_sources import IGNORED, WORKSPACE
        paths = []
        for directory, folders, names in os.walk(WORKSPACE):
            folders[:] = [item for item in folders if item not in IGNORED and not item.startswith(".")]
            paths.extend(str((Path(directory) / name).relative_to(WORKSPACE)) for name in names)
            if len(paths) > 200_000:
                break
        return paths
    if source_id.startswith("github:") and installation_id is not None:
        from .github_app import installation_repositories, repository_tree
        entry = next((item for item in installation_repositories(installation_id) if item["id"] == source_id), None)
        if entry is None:
            return None
        return [item["path"] for item in repository_tree(installation_id, source_id.removeprefix("github:"), entry.get("branch") or "main")
                if item.get("type") == "blob" and isinstance(item.get("path"), str)]
    return None


def plan(source_id: str, *, installation_id: int | None) -> dict:
    paths = files_of(source_id, installation_id=installation_id)
    paths = [path for path in (paths or []) if not SKIP.intersection(path.split("/"))] if paths is not None else None
    docker = docker_available()
    engines = {key: {"key": key, "name": value["name"], "version": value["version"],
                     "available": docker and image_available(key)} for key, value in IMAGES.items()}
    rules = rule_counts()
    languages = Counter()
    manifests, iac, pipelines = [], [], []
    for path in paths or []:
        name = path.rsplit("/", 1)[-1]
        suffix = ("." + name.rsplit(".", 1)[-1].lower()) if "." in name else ""
        if suffix in EXTENSIONS:
            languages[EXTENSIONS[suffix]] += 1
        if LOCKFILES.fullmatch(name):
            manifests.append(path)
        if name == "Dockerfile" or name.endswith((".tf", ".tfvars", ".bicep")) or name in ("Chart.yaml", "kustomization.yaml", "serverless.yml") \
                or re.fullmatch(r"(docker-)?compose[\w.-]*\.ya?ml", name):
            iac.append(path)
        if re.fullmatch(r"\.github/workflows/[^/]+\.ya?ml", path) or name in ("action.yml", "action.yaml", ".gitlab-ci.yml",
                                                                             "bitbucket-pipelines.yml", "azure-pipelines.yml") \
                or path == ".circleci/config.yml":
            pipelines.append(path)
    detected = [{"name": name, "files": count, "rules": rules.get(name, 0)} for name, count in languages.most_common()]
    runs, skips = ["Snapshot de solo lectura del repositorio y hash SHA-256 del contenido"], [
        "No se instala ni se ejecuta el código del repositorio: el análisis es estático"]
    opengrep, gitleaks, trivy = engines["opengrep"], engines["gitleaks"], engines["trivy"]
    covered = [item for item in detected if item["rules"]]
    uncovered = [item for item in detected if not item["rules"]]
    if opengrep["available"]:
        if covered:
            runs.append(f"SAST con {opengrep['name']} {opengrep['version']}: "
                        + ", ".join(f"{item['name']} ({_n(item['rules'], 'regla', 'reglas')}, {_n(item['files'], 'fichero', 'ficheros')})" for item in covered))
        elif paths is not None:
            skips.append("SAST: no hay ficheros en los lenguajes que cubren las reglas propias")
    else:
        runs.append("SAST interno solo para Python (Opengrep no está disponible en este servidor)")
        uncovered = [item for item in detected if item["name"] != "Python"]
    if uncovered:
        skips.append("Sin reglas SAST propias para " + ", ".join(f"{item['name']} ({_n(item['files'], 'fichero', 'ficheros')})" for item in uncovered)
                     + ": solo se revisan sus secretos y dependencias")
    runs.append(f"Secretos con {gitleaks['name']} {gitleaks['version']} en todo el snapshot; el valor nunca se guarda"
                if gitleaks["available"] else "Secretos con patrones internos (Gitleaks no está disponible)")
    if trivy["available"]:
        if manifests:
            runs.append(f"Dependencias con {trivy['name']} {trivy['version']} y su base de avisos local: "
                        f"{_n(len(manifests), 'manifiesto', 'manifiestos')} ({', '.join(manifests[:4])}{'…' if len(manifests) > 4 else ''}), cruzados con CISA KEV y EPSS")
        elif paths is not None:
            skips.append("Dependencias: no hay lockfiles ni manifiestos con versiones que resolver")
        if iac:
            runs.append(f"Infraestructura como código con {trivy['name']}: {', '.join(iac[:4])}{'…' if len(iac) > 4 else ''}")
    else:
        runs.append("Dependencias con OSV solo si lo autorizas (Trivy no está disponible)")
        if iac:
            skips.append(f"Infraestructura como código: hay {_n(len(iac), 'fichero', 'ficheros')}, pero Trivy no está disponible")
    checkov, zizmor = engines["checkov"], engines["zizmor"]
    if iac or pipelines or paths is None:
        if checkov["available"]:
            runs.append(f"Infraestructura y pipelines con {checkov['name']} {checkov['version']} (Terraform, CloudFormation, Kubernetes, "
                        "Helm, Dockerfile, GitHub Actions, GitLab CI…), sin red; lo que ya ve Trivy se une al mismo hallazgo")
        else:
            skips.append("Checkov no está disponible: la infraestructura se revisa solo con Trivy")
    if pipelines or paths is None:
        if zizmor["available"]:
            runs.append(f"GitHub Actions con {zizmor['name']} {zizmor['version']}: inyección en plantillas, disparadores peligrosos, "
                        "permisos y acciones sin fijar" + (f" ({_n(len(pipelines), 'workflow', 'workflows')})" if pipelines else ""))
        elif pipelines:
            skips.append("zizmor no está disponible: los workflows de GitHub Actions solo los revisa Checkov")
    skips += ["Sin pruebas dinámicas: no se envía tráfico a ninguna aplicación",
              "Sin IA: no se envía código fuente a OpenAI ni a Anthropic"]
    if paths is None:
        runs.insert(1, "Los lenguajes se conocerán al descargar el snapshot (este proveedor no permite listarlos antes)")
    return {"source_id": source_id, "languages": detected, "engines": list(engines.values()), "manifests": manifests[:50],
            "iac": iac[:50], "pipelines": pipelines[:50], "runs": runs, "skips": skips, "osv_needed": not trivy["available"],
            "files": len(paths) if paths is not None else None}
