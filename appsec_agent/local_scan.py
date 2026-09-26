"""Análisis de una carpeta local: `appsec-agent scan`. Para la terminal, pre-commit y CI.

Sin `--base` se analiza todo. Con `--base main` se analiza también el punto de partida
(el merge-base con esa rama) y se informa solo de lo que el cambio introduce: lo que ya
estaba antes no bloquea. Cuenta lo que aún no se ha subido (cambios sin commit y archivos
nuevos no ignorados), así sirve antes del push y en el pipeline.

Un análisis incompleto nunca pasa por limpio: si un motor no pudo ejecutarse, el comando
lo dice y sale con su propio código.
"""

from __future__ import annotations

import io
import json
import re
import subprocess
import tarfile
from pathlib import Path
from tempfile import TemporaryDirectory

from .pr_review import SEVERITY_ORDER, changed_lines, classify, verdict
from .repository_scan import scan_repository
from .repository_sources import snapshot_directory

# Códigos de salida (documentados en docs/cli.md).
EXIT_OK, EXIT_BLOCKED, EXIT_ERROR, EXIT_INCOMPLETE = 0, 1, 2, 3
FAIL_ON = ("critical", "high", "medium", "low", "never")
# Rama, etiqueta, SHA o expresión de git (HEAD~1, origin/main…). Nunca empieza por «-»: no puede
# colarse como opción de git.
REF = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._/@^~{}+-]{0,199}")
CORE_ENGINES = ("opengrep", "gitleaks", "trivy", "osv-scanner")


class LocalScanError(ValueError):
    pass


def _git(path: Path, *args: str, binary: bool = False, timeout: int = 120):
    try:
        # safe.directory: dentro del contenedor la carpeta montada es de otro usuario. core.fsmonitor=false:
        # la configuración local de un repositorio no puede lanzar programas mientras se calcula el diff.
        completed = subprocess.run(["git", "-c", f"safe.directory={path}", "-c", "core.fsmonitor=false", "-C", str(path), *args],
                                   capture_output=True, text=not binary, timeout=timeout)
    except FileNotFoundError as exc:
        raise LocalScanError("Para comparar con --base hace falta git instalado") from exc
    except subprocess.TimeoutExpired as exc:
        raise LocalScanError(f"git {args[0]} tardó demasiado") from exc
    if completed.returncode != 0:
        detail = completed.stderr.decode(errors="replace") if binary else completed.stderr
        raise LocalScanError(f"git {args[0]}: {' '.join(detail.split())[:200] or 'falló'}")
    return completed.stdout


def merge_base(path: Path, base: str) -> str:
    """El commit desde el que parte el cambio: el merge-base entre la base y HEAD."""
    if not REF.fullmatch(base or ""):
        raise LocalScanError(f"Referencia de git inválida: {base!r}")
    commit = _git(path, "rev-parse", "--verify", "--quiet", "--end-of-options", f"{base}^{{commit}}").strip()
    if not re.fullmatch(r"[0-9a-f]{40,64}", commit):
        raise LocalScanError(f"No existe la referencia {base!r} en este repositorio (¿falta `git fetch`?)")
    return _git(path, "merge-base", commit, "HEAD").strip()


def parse_diff(text: str) -> list[dict]:
    """`git diff --unified=0` → la misma forma que los ficheros de un PR de GitHub (filename, status, patch)."""
    files, current, patch = [], None, []
    def close():
        if current is not None:
            current["patch"] = None if current.pop("binary", False) else "\n".join(patch)
            files.append(current)
    for line in text.splitlines():
        if line.startswith("diff --git "):
            close()
            current, patch = {"filename": None, "status": "modified"}, []
        elif current is None:
            continue
        elif line.startswith("+++ "):
            target = line[4:]
            if target == "/dev/null":
                current["status"] = "removed"
            else:
                current["filename"] = target[2:] if target.startswith("b/") else target
        elif line.startswith("--- "):
            source = line[4:]
            if source == "/dev/null":
                current["status"] = "added"
            elif not current["filename"]:
                current["filename"] = source[2:] if source.startswith("a/") else source
        elif line.startswith("rename to "):
            current["filename"] = line[len("rename to "):]
        elif line.startswith("Binary files "):
            current["binary"] = True
            match = re.search(r" and (?:b/)?(.+) differ$", line)
            if match and match.group(1) != "/dev/null":
                current["filename"] = match.group(1)
        elif line.startswith(("@@", "+", "-", " ", "\\")):
            patch.append(line)
    close()
    return [item for item in files if item["filename"]]


def diff_files(path: Path, commit: str) -> list[dict]:
    """Lo que cambió desde `commit` hasta el árbol de trabajo, más los archivos nuevos no ignorados."""
    text = _git(path, "diff", "--unified=0", "--no-color", "--no-ext-diff", "--relative", "-M", commit, "--")
    files = parse_diff(text)
    untracked = _git(path, "ls-files", "--others", "--exclude-standard", "--", ".").splitlines()
    return files + [{"filename": name, "status": "added", "patch": None} for name in untracked if name]


def snapshot_commit(path: Path, commit: str, destination: Path) -> dict:
    """La carpeta tal como estaba en `commit`, con los mismos filtros que el análisis actual."""
    prefix = _git(path, "rev-parse", "--show-prefix").strip()
    archive = _git(path, "archive", "--format=tar", f"{commit}:{prefix}" if prefix else commit, binary=True, timeout=600)
    raw = destination.parent / f"{destination.name}-raw"
    raw.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(archive)) as bundle:
        # Filtro «data» (PEP 706): sin rutas absolutas, sin salir de la carpeta, sin dispositivos ni enlaces fuera.
        bundle.extractall(raw, filter="data")
    return snapshot_directory(raw, destination)


def _engines(scan: dict) -> tuple[list[str], list[str]]:
    ran, failed = [], []
    for step in scan.get("steps") or []:
        tool = (step.get("tool") or {}).get("name")
        if tool in CORE_ENGINES:
            (ran if step["status"] in ("completed", "partial") else failed).append(step["name"])
    return ran, failed


def run(path: Path, *, data_dir: Path, base: str | None = None, baseline: bool = True, fail_on: str = "high",
        allow_osv_upload: bool = False, progress=None, name: str | None = None, exclude: list[str] | None = None) -> dict:
    """Analiza `path` y aplica el umbral. Devuelve el resultado listo para mostrar y el código de salida.

    `exclude`: patrones glob relativos a la raíz (`fixtures/**`, `**/testdata/**`) cuyos hallazgos no cuentan.
    Se dicen en la salida («N en rutas excluidas»): nada se oculta sin decirlo."""
    from .exclusions import ExclusionError, excluded, normalize
    from .scanners import docker_available, docker_problem
    try:
        patterns = normalize(list(exclude or []))
    except ExclusionError as exc:
        raise LocalScanError(f"--exclude: {exc}") from exc
    path = path.expanduser().resolve()
    if not path.is_dir():
        raise LocalScanError(f"No es una carpeta: {path}")
    if fail_on not in FAIL_ON:
        raise LocalScanError(f"--fail-on debe ser uno de: {', '.join(FAIL_ON)}")
    report = progress or (lambda level, message: None)
    work = data_dir / "work"
    work.mkdir(parents=True, exist_ok=True)
    name = (name or path.name).strip()[:100] or path.name
    source = {"id": f"local:{name}", "name": name, "provider": "local"}
    comparison = None
    with TemporaryDirectory(prefix="scan-", dir=work) as temporary:
        head = Path(temporary) / "head"
        stats = snapshot_directory(path, head)
        report("info", f"Copia de solo lectura: {stats['files']} archivos analizables.")
        scan = scan_repository(head, {**source, "files": stats["files"], "snapshot": stats},
                               allow_osv_upload=allow_osv_upload, data_dir=data_dir, progress=report)
        findings = [item for item in scan["findings"] if not excluded(item.get("path", ""), patterns)]
        skipped = len(scan["findings"]) - len(findings)
        if base:
            commit = merge_base(path, base)
            changed = changed_lines(diff_files(path, commit))
            report("info", f"Comparando con {base} (merge-base {commit[:8]}): {len(changed)} archivos cambiados.")
            prints, base_status = None, None
            if baseline and changed:
                base_dir = Path(temporary) / "base"
                base_stats = snapshot_commit(path, commit, base_dir)
                report("info", f"Analizando el punto de partida para no contar lo que ya estaba ({base_stats['files']} archivos)…")
                base_scan = scan_repository(base_dir, {**source, "files": base_stats["files"], "snapshot": base_stats},
                                            allow_osv_upload=allow_osv_upload, data_dir=data_dir)
                prints, base_status = {item["fingerprint"] for item in base_scan["findings"]}, base_scan["status"]
            outcome = classify(findings, changed, prints)
            findings = outcome["introduced"]
            comparison = {"base": base, "merge_base": commit, "changed_files": len(changed),
                          "baseline": prints is not None, "baseline_status": base_status,
                          "preexisting_in_changed_code": len(outcome["preexisting"])}
    ran, failed = _engines(scan)
    missing = [] if docker_available() else [docker_problem() or "Docker no disponible: los motores no se ejecutaron."]
    incomplete = scan["status"] == "incomplete" or bool(failed) or bool(missing)
    order = {level: index for index, level in enumerate(SEVERITY_ORDER)}
    findings = sorted(findings, key=lambda item: (order.get(item["severity"], 9), item["path"], item["line"]))
    gate = verdict(findings, fail_on)
    code = EXIT_BLOCKED if gate["blocking"] else EXIT_OK
    if incomplete and code == EXIT_OK:
        code = EXIT_INCOMPLETE
    return {"target": str(path), "name": name, "comparison": comparison, "fail_on": fail_on,
            "excluded": {"patterns": patterns, "findings": skipped},
            "status": "incomplete" if incomplete else "completed", "engines": {"ran": ran, "failed": failed},
            "not_analyzed": missing + [f"{step['name']}: {step['detail']}" for step in scan.get("steps") or []
                                       if (step.get("tool") or {}).get("name") in CORE_ENGINES and step["status"] not in ("completed", "partial")],
            "findings": findings, "gate": gate, "exit_code": code, "scan": scan}


# --- salida ----------------------------------------------------------------------------

SEVERITY_TEXT = {"critical": "CRÍTICA", "high": "ALTA", "medium": "MEDIA", "low": "BAJA", "info": "INFO"}
FAIL_ON_TEXT = {"critical": "crítica", "high": "alta o superior", "medium": "media o superior", "low": "baja o superior",
                "never": "nunca (solo informa)"}


def _grouped(findings: list[dict]) -> list[tuple[str, str, str]]:
    """Una línea por corrección: los avisos de un mismo paquete se cierran con una sola actualización.

    La versión propuesta es la más alta entre las que corrigen cada aviso (la que los cierra todos)."""
    from .advisories import compare_versions
    order = {level: index for index, level in enumerate(SEVERITY_ORDER)}
    rows, packages = [], {}
    for item in findings:
        package = item.get("package") or {}
        if item.get("scanner") == "sca" and package.get("name"):
            packages.setdefault((item["path"], package["name"], package.get("version") or ""), []).append(item)
        else:
            rows.append((item["severity"], f"{item['path']}:{item['line']}", item["title"]))
    for (path, name, version), items in packages.items():
        worst = min((item["severity"] for item in items), key=lambda level: order.get(level, 9))
        fixes = [item["package"]["fixed_version"] for item in items if item["package"].get("fixed_version")]
        target = None
        for fix in fixes:
            target = fix if target is None or compare_versions(fix, target) > 0 else target
        counts = ", ".join(f"{sum(1 for item in items if item['severity'] == level)} {SEVERITY_TEXT[level].lower()}"
                           for level in SEVERITY_ORDER if any(item["severity"] == level for item in items))
        advice = f"actualiza a {target}" if target and len(fixes) == len(items) else \
                 f"actualiza a {target} (hay avisos sin versión corregida)" if target else "sin versión corregida publicada"
        rows.append((worst, path, f"{name} {version}: {len(items)} {'aviso' if len(items) == 1 else 'avisos'} ({counts}) → {advice}"))
    return sorted(rows, key=lambda row: (order.get(row[0], 9), row[1]))


_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def _safe(value) -> str:
    """Rutas y títulos vienen del repositorio analizado: sin caracteres de control, un nombre de archivo
    no puede mover el cursor, borrar líneas ni falsear el veredicto en la terminal o el log de CI (CWE-150)."""
    return _CONTROL.sub("?", str(value))


def render_text(result: dict, *, limit: int = 50) -> str:
    comparison = result["comparison"]
    scope = (f"cambios respecto a {comparison['base']} (merge-base {comparison['merge_base'][:8]}, "
             f"{comparison['changed_files']} archivos)" if comparison else "toda la carpeta")
    lines = [f"Tamandua · {_safe(result['name'])} · {scope}", ""]
    if comparison and not comparison["baseline"] and comparison["changed_files"]:
        lines += ["Sin analizar el punto de partida (--no-baseline): cuenta todo lo que cae en líneas cambiadas.", ""]
    findings = result["findings"]
    if findings:
        rows = _grouped(findings)
        for severity, where, text in rows[:limit]:
            lines.append(f"{SEVERITY_TEXT.get(severity, severity).ljust(8)} {_safe(where)}  {_safe(text)}")
        if len(rows) > limit:
            lines.append(f"… y {len(rows) - limit} más (usa --format json o sarif para verlos todos)")
    else:
        lines.append("Sin hallazgos nuevos." if comparison else "Sin hallazgos.")
    if comparison and comparison["preexisting_in_changed_code"]:
        lines += ["", f"{comparison['preexisting_in_changed_code']} ya existían en el código que tocas: no bloquean."]
    skipped = (result.get("excluded") or {}).get("findings") or 0
    if skipped:
        lines += ["", f"{skipped} en rutas excluidas ({', '.join(_safe(item) for item in result['excluded']['patterns'])}): no cuentan."]
    lines += ["", f"Motores: {', '.join(result['engines']['ran']) or 'ninguno'}"
              + (f" · no se ejecutaron: {', '.join(result['engines']['failed'])}" if result["engines"]["failed"] else "")]
    for item in result["not_analyzed"]:
        lines.append(f"Sin analizar: {_safe(item)}")
    gate = result["gate"]
    verdict_line = {EXIT_OK: "PASA", EXIT_BLOCKED: "BLOQUEA", EXIT_INCOMPLETE: "INCOMPLETO"}[result["exit_code"]]
    detail = gate["description"] if result["exit_code"] != EXIT_INCOMPLETE else "el análisis no terminó: no equivale a «sin hallazgos»"
    lines += ["", f"{verdict_line} · umbral: {FAIL_ON_TEXT[result['fail_on']]} · {detail}"]
    return "\n".join(lines) + "\n"


def render_json(result: dict) -> str:
    fields = ("fingerprint", "severity", "scanner", "tool", "also_detected_by", "rule_id", "title", "path", "line",
              "cwe", "cve", "ghsa", "package", "remediation", "priority", "kev", "epss")
    payload = {key: result.get(key) for key in ("target", "status", "comparison", "fail_on", "excluded", "engines", "not_analyzed", "exit_code")}
    payload["gate"] = result["gate"]
    payload["findings"] = [{key: item.get(key) for key in fields if item.get(key) is not None} for item in result["findings"]]
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def render_sarif(result: dict) -> str:
    from .store import render_repository_sarif
    return json.dumps(render_repository_sarif({"findings": result["findings"]}), ensure_ascii=False, indent=2) + "\n"
