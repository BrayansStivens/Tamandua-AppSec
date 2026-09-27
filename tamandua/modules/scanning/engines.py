"""Escáneres externos en contenedores pinneados por digest, un frente cada uno.

- Trivy: dependencias de cualquier ecosistema, configuración de infraestructura
  (Dockerfile, Kubernetes, Terraform) y secretos. Necesita red solo para bajar su
  base de vulnerabilidades, que se cachea; no envía nada del repositorio.
- OSV-Scanner: dependencias con la base OSV (que incluye la GitHub Advisory Database de
  Dependabot) y más formatos de manifiesto (.NET, Gradle, uv…). Baja las bases de avisos
  y compara en local; lo que coincide con Trivy se une en un solo hallazgo.
- Gitleaks: secretos con alta precisión. Sin red.
- Opengrep: SAST multi-lenguaje con nuestras propias reglas (`rules/`). Sin red.
- Checkov y zizmor: infraestructura como código y pipelines de CI/CD (`config_scanners`). Sin red.

Cada contenedor corre sin capacidades, sin escalada de privilegios, con el
snapshot montado en solo lectura y **con el mismo UID y GID que la app**: en Linux,
root sin capacidades no puede entrar en las carpetas 0700 de la app y los motores
devolverían cero hallazgos sin avisar (en macOS Docker Desktop lo oculta). Si Docker o una imagen no están, el paso se
declara `not_tested` con el motivo: nunca se finge una ejecución.

Los valores de secretos no se guardan jamás: solo regla, archivo y línea.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

from tamandua.shared import paths, settings
from tamandua.shared.i18n import msg
from tamandua.modules.intel import data_sources
from tamandua.modules.intel.advisories import compare_versions, cvss3_base_score, prioritize, severity_from_score
from tamandua.modules.intel.advisories import fingerprint as sca_fingerprint
from tamandua.modules.scanning import secret_rules

RULES_DIR = paths.RULES_DIR
IMAGES = {
    "trivy": {"name": "Trivy", "version": "0.74.0",
              "image": "aquasec/trivy@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969"},
    # Dependencias con la base OSV (incluye la GitHub Advisory Database de Dependabot) y más formatos de manifiesto.
    "osv-scanner": {"name": "OSV-Scanner", "version": "2.6.0",
                    "image": "ghcr.io/google/osv-scanner@sha256:afd838850ac1a0fcc15ff4a041dc9ba11123c3f0d2666217a5f0fcf9222b55fa"},
    "gitleaks": {"name": "Gitleaks", "version": "8.30.1",
                 "image": "ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"},
    "opengrep": {"name": "Opengrep", "version": "1.30.0", "image": "localhost/tamandua/opengrep:1.30.0"},
    # Segunda opinión en imágenes de contenedor: discrepa con Trivy sobre todo en paquetes del sistema.
    "grype": {"name": "Grype", "version": "0.119.0",
              "image": "anchore/grype@sha256:8c2c9234a345577a6d321a4753aa3ee1276d8975c8452d2344a56b57733ecad3"},
    # Infraestructura como código y pipelines: casi el doble de reglas que Trivy en Terraform y CloudFormation.
    "checkov": {"name": "Checkov", "version": "3.3.19",
                "image": "bridgecrew/checkov@sha256:d3e96adafdb315ca82e792ca8708c01adae85292800fb064c8b309b3d0cb7b80"},
    # GitHub Actions a fondo: inyección en plantillas, disparadores peligrosos, permisos y acciones sin fijar.
    "zizmor": {"name": "zizmor", "version": "1.30.1",
               "image": "ghcr.io/zizmorcore/zizmor@sha256:a2eb396d886c053073405c7a980f2139ba2248ec172243cfa3841e57196e8101"},
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


_own_mounts: dict[str, object] = {"at": None, "mounts": {}}


def in_container() -> bool:
    return Path("/.dockerenv").exists()


def own_mounts() -> dict[str, str]:
    """Montajes de este contenedor tal como los ve el demonio: {ruta interna: ruta en el host}.

    Se pregunta a Docker en vez de fiarse de `${PWD}` en compose, que en PowerShell o cmd
    (Windows) llega vacío. Así vale igual en macOS (Apple Silicon e Intel), Linux, Windows y WSL.
    Fuera de un contenedor, o si Docker no responde, devuelve {} (y se reintenta al minuto)."""
    at = _own_mounts["at"]
    if at is not None and (_own_mounts["mounts"] or time.monotonic() - at < 60):
        return dict(_own_mounts["mounts"])
    mounts: dict[str, str] = {}
    binary, identity = shutil.which("docker"), os.environ.get("HOSTNAME", "")
    if binary and re.fullmatch(r"[0-9a-f]{12,64}", identity) and in_container():
        try:
            completed = subprocess.run([binary, "inspect", identity, "--format", "{{json .Mounts}}"],
                                       capture_output=True, text=True, timeout=8)
            rows = json.loads(completed.stdout or "[]") if completed.returncode == 0 else []
        except (OSError, subprocess.TimeoutExpired, ValueError):
            rows = []
        for row in rows if isinstance(rows, list) else []:
            if isinstance(row, dict) and row.get("Type") == "bind" and isinstance(row.get("Source"), str) \
                    and isinstance(row.get("Destination"), str):
                mounts[row["Destination"].rstrip("/")] = row["Source"]
    _own_mounts.update(at=time.monotonic(), mounts=mounts)
    return dict(mounts)


def _host_pairs() -> list[tuple[str, str]]:
    detected = own_mounts()
    pairs = []
    for inside, configured in ((settings.text("TAMANDUA_DATA_DIR"), settings.text("TAMANDUA_HOST_DATA_DIR")),
                               (str(RULES_DIR), settings.text("TAMANDUA_HOST_RULES_DIR"))):
        if not inside:
            continue
        outside = detected.get(str(Path(inside)).rstrip("/")) or (configured if _usable(inside, configured) else None)
        if outside:
            pairs.append((inside, outside))
    return pairs


def _usable(inside: str, outside: str | None) -> bool:
    # `${PWD}/data` con PWD vacío queda en `/data`: igual a la ruta interna, no apunta al host.
    return bool(outside and outside.strip() and outside.rstrip("/") not in (inside.rstrip("/"), "/data", "/rules"))


def host_path(path: Path) -> str:
    """Ruta tal como la ve el demonio de Docker.

    Cuando la app corre en un contenedor, los volúmenes que pide para los
    contenedores hermanos se resuelven en el host, no dentro de la app. La ruta del
    host se detecta preguntando a Docker por los montajes de este contenedor; si no
    se puede, se usan TAMANDUA_HOST_DATA_DIR y TAMANDUA_HOST_RULES_DIR.
    """
    resolved = path.resolve()
    if runner() == "local":
        return str(resolved)
    for inside, outside in _host_pairs():
        try:
            return str(Path(outside) / resolved.relative_to(Path(inside).resolve()))
        except ValueError:
            continue
    return str(resolved)


_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_TOKENS = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,})")


def cause(completed: subprocess.CompletedProcess | None) -> str:
    """La última línea útil del stderr del motor o de Docker, para decir *por qué* falló.

    Se recorta, se quitan colores y cualquier token, y la carpeta de datos del host se
    abrevia: lo que se ve en el panel ayuda a diagnosticar sin exponer credenciales."""
    if completed is None:
        return ""
    lines = [line.strip() for line in _ANSI.sub("", completed.stderr or "").splitlines() if line.strip()]
    return _clean_cause(lines[-1]) if lines else ""


def _clean_cause(line: str) -> str:
    text = _TOKENS.sub("[token]", line)
    host = settings.text("TAMANDUA_HOST_DATA_DIR")
    if len(host) > 1:
        text = text.replace(host, "<datos>")
    return " ".join(text.split())[:240]


def config_cause(completed: subprocess.CompletedProcess) -> str:
    """Why an engine rejected its configuration: the first error line (a Go panic ends with its stack, not its cause)."""
    lines = [line.strip() for line in _ANSI.sub("", completed.stderr or "").splitlines() if line.strip()]
    first = next((line for line in lines if re.search(r"panic:|FTL|FATAL|error", line, re.IGNORECASE)), None)
    return _clean_cause(first) if first else cause(completed)


def with_cause(message, completed: subprocess.CompletedProcess | None):
    reason = cause(completed)
    if not reason:
        return message
    return msg("scanning.engines.with_cause", message=message.rstrip(".") if isinstance(message, str) else message, cause=reason)


def joined(items, key: str = "scanning.join.comma"):
    """Folds strings or messages into one message, two at a time, with `key` ({{first}} and {{second}})."""
    items = [item for item in items if item]
    if all(isinstance(item, str) for item in items) and key == "scanning.join.comma":
        return ", ".join(items)
    result = items[0] if items else ""
    for item in items[1:]:
        result = msg(key, first=result, second=item)
    return result


def and_list(items):
    """«A», «A and B», «A, B and C», in the reader's language."""
    items = list(items)
    if len(items) <= 1:
        return items[0] if items else ""
    return msg("scanning.join.and", rest=joined(items[:-1]), last=items[-1])


def host_mount_problem() -> dict | None:
    """Dentro del contenedor, los motores montan la carpeta de datos *del host*. Si no se pudo
    averiguar (ni preguntando a Docker ni por el entorno), los motores fallarían sin explicación."""
    inside = settings.text("TAMANDUA_DATA_DIR")
    if not inside or not in_container():
        return None
    if any(pair[0] == inside for pair in _host_pairs()):
        return None
    return msg("scanning.engines.host_mount_problem")


_last_image_error: dict[str, str] = {}


DOCKER_SOCKET = Path("/var/run/docker.sock")


def socket_problem() -> dict | None:
    """El caso típico en Linux y WSL: el socket es del grupo `docker`, no de root, y el contenedor no está en él."""
    try:
        if not DOCKER_SOCKET.exists() or os.access(DOCKER_SOCKET, os.R_OK | os.W_OK):
            return None
        gid = DOCKER_SOCKET.stat().st_gid
    except OSError:
        return None
    return msg("scanning.engines.socket_problem", gid=gid)


def docker_available() -> bool:
    if "ok" not in _docker_state:
        binary = shutil.which("docker")
        try:
            completed = subprocess.run([binary, "info", "--format", "{{.ServerVersion}}"], capture_output=True, text=True,
                                       timeout=8) if binary else None
        except (OSError, subprocess.TimeoutExpired):
            completed = None
        # Sin permiso sobre el socket, `docker info` puede salir con 0 y sin versión de servidor: eso no es Docker disponible.
        _docker_state["ok"] = bool(completed) and completed.returncode == 0 and bool(completed.stdout.strip())
        _docker_state["why"] = socket_problem() or cause(completed) if not _docker_state["ok"] else ""
    return _docker_state["ok"]


def docker_problem():
    """Por qué Docker no está disponible, en una frase; vacío si lo está."""
    return "" if docker_available() else (_docker_state.get("why") or msg("scanning.engines.docker_unresponsive"))


def image_available(key: str) -> bool:
    binary = shutil.which("docker")
    try:
        completed = subprocess.run([binary, "image", "inspect", IMAGES[key]["image"]], capture_output=True, text=True,
                                   timeout=15) if binary else None
    except (OSError, subprocess.TimeoutExpired):
        return False
    _last_image_error[key] = cause(completed)
    return bool(completed) and completed.returncode == 0


# The local runner runs the same pinned engines installed in the worker image (the `worker-standalone` target), for
# platforms without a Docker socket. Each engine's arguments are the ones its image's entrypoint takes.
BINARIES = {"trivy": "trivy", "osv-scanner": "osv-scanner", "gitleaks": "gitleaks", "opengrep": "opengrep",
            "grype": "grype", "checkov": "checkov", "zizmor": "zizmor"}
_runner_state: dict[str, str] = {}


def runner() -> str:
    """"docker" (a sibling container per engine) or "local" (the engines installed next to the worker).
    TAMANDUA_ENGINE_RUNNER decides; `auto` prefers Docker and falls back to installed engines."""
    choice = settings.text("TAMANDUA_ENGINE_RUNNER")
    if choice in ("docker", "local"):
        return choice
    if "auto" not in _runner_state:
        installed = any(shutil.which(binary) for binary in BINARIES.values())
        _runner_state["auto"] = "local" if installed and not docker_available() else "docker"
    return _runner_state["auto"]


def engine_ready(key: str) -> bool:
    if runner() == "local":
        return shutil.which(BINARIES[key]) is not None
    return docker_available() and image_available(key)


def engines_available() -> bool:
    """Whether this process can run engines at all (Docker answers, or at least one engine is installed)."""
    if runner() == "local":
        return any(shutil.which(binary) for binary in BINARIES.values())
    return docker_available()


def engines_problem():
    """Why no engine can run, in one sentence; empty if some can."""
    if engines_available():
        return ""
    return msg("scanning.engines.none_installed") if runner() == "local" else docker_problem()


def unavailable(key: str, without_docker):
    """None if engine `key` can run; else the reason, in the terms of the runner in use."""
    if runner() == "local":
        return None if engine_ready(key) else msg("scanning.engines.not_installed", engine=IMAGES[key]["name"], binary=BINARIES[key])
    return None if docker_available() else without_docker


def engine_status() -> list[dict]:
    """Which engines are ready (images in the host's Docker, or installed binaries). For `make doctor` and `engines`."""
    local = runner() == "local"
    return [{"tool": key, "name": meta["name"], "version": meta["version"], "image": shutil.which(BINARIES[key]) or BINARIES[key] if local else meta["image"],
             "ready": engine_ready(key), "built_locally": local or "@sha256:" not in meta["image"]} for key, meta in IMAGES.items()]


def pull_engines(report=None) -> list[dict]:
    """Descarga por digest las imágenes publicadas que falten; la de Opengrep se construye con `make build`.

    `make engines` descarga desde el host (con progreso); esto queda para quien no use make."""
    if runner() == "local":  # installed with the image: nothing to download
        return [{**row, "action": msg("scanning.engines.action.none") if row["ready"] else msg("scanning.engines.action.not_installed")}
                for row in engine_status()]
    binary = shutil.which("docker")
    results = []
    for row in engine_status():
        if report and not (row["ready"] or row["built_locally"] or not binary):
            report(msg("scanning.engines.pulling", name=row["name"], version=row["version"]))
        if row["ready"] or row["built_locally"] or not binary:
            results.append({**row, "action": msg("scanning.engines.action.none") if row["ready"]
                            else msg("scanning.engines.action.build") if row["built_locally"] else msg("scanning.engines.action.no_docker")})
            continue
        try:
            completed = subprocess.run([binary, "pull", "--quiet", row["image"]], capture_output=True, text=True, timeout=3600)
        except (OSError, subprocess.TimeoutExpired):
            completed = None
        done = bool(completed) and completed.returncode == 0
        results.append({**row, "ready": done, "action": msg("scanning.engines.action.pulled") if done
                        else with_cause(msg("scanning.engines.action.pull_failed"), completed)})
    return results


def _result(key: str, status: str, detail, findings: list | None = None, started: float | None = None) -> dict:
    meta = IMAGES[key]
    return {"tool": key, "name": meta["name"], "version": meta["version"], "image": meta["image"],
            "status": status, "detail": detail, "findings": findings or [],
            "duration_s": round(time.time() - started, 1) if started else None}


def engine_user() -> list[str]:
    """`--user` con el UID y GID de este proceso, y un HOME escribible para motores que guardan estado."""
    if not hasattr(os, "getuid"):
        return []
    return ["--user", f"{os.getuid()}:{os.getgid()}", "-e", "HOME=/tmp"]


def writable_cache(preferred: Path) -> Path:
    """La caché del motor si este usuario puede escribirla; si no (p. ej. la crearon motores que corrían
    como root en una versión anterior), una nueva junto a ella. La vieja se puede borrar a mano."""
    preferred.mkdir(parents=True, exist_ok=True)
    blocked = not os.access(preferred, os.W_OK | os.X_OK) or any(
        not os.access(entry, os.W_OK) for entry in list(preferred.iterdir())[:50])
    if not blocked:
        return preferred
    fallback = preferred.with_name(f"{preferred.name}-{os.getuid() if hasattr(os, 'getuid') else 'user'}")
    fallback.mkdir(parents=True, exist_ok=True)
    return fallback


def _run(key: str, arguments: list[str], snapshot: Path | None, *, network: bool = False,
         mounts: list[str] | None = None, timeout: int = 900, env: dict[str, str] | None = None,
         secret_env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    """Contenedor efímero del motor. `secret_env` viaja por el entorno del cliente de Docker
    (`-e NOMBRE` sin valor), nunca en la línea de comandos, para que no se vea en `ps` ni en los logs."""
    if runner() == "local":
        return _run_local(key, arguments, snapshot, mounts=mounts, timeout=timeout, env=env, secret_env=secret_env)
    environment = [part for name, value in (env or {}).items() for part in ("-e", f"{name}={value}")]
    environment += [part for name in (secret_env or {}) for part in ("-e", name)]
    source = ["-v", f"{host_path(snapshot)}:/src:ro"] if snapshot is not None else []
    docker = shutil.which("docker")
    name = f"tamandua-{key}-{uuid.uuid4().hex[:12]}"
    command = [docker, "run", "--rm", "--name", name, "--label", "tamandua.engine=1",
               "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
               *engine_user(), "--pids-limit", "512", "--memory", "3g", "--cpus", "2",
               "--network", "bridge" if network else "none",
               # An image built here has no digest: never let Docker fetch that name from a registry instead.
               *([] if "@sha256:" in IMAGES[key]["image"] else ["--pull", "never"]),
               *source, *environment, *(mounts or []), IMAGES[key]["image"], *arguments]
    process_env = {**os.environ, **(secret_env or {})} if secret_env else None
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=timeout, env=process_env)
    except subprocess.TimeoutExpired:
        # The timeout only kills the docker client: the engine container would keep its CPU and memory.
        try:
            subprocess.run([docker, "rm", "--force", name], capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired):
            pass
        raise


def _limits() -> None:
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))  # a crashing engine never dumps repository contents to disk


def _run_local(key: str, arguments: list[str], snapshot: Path | None, *, mounts: list[str] | None, timeout: int,
               env: dict[str, str] | None, secret_env: dict[str, str] | None) -> subprocess.CompletedProcess:
    """The engine installed next to the worker, with the same arguments as its container. Container paths (/src,
    /cache, /rules…) become the real folders, and back in its output, so parsers see what they always saw.

    It gets a fresh HOME and only PATH from this process: never the database URL, the master key or any other
    setting. There is no network isolation here (that needs the Docker runner); engines run with their offline flags.
    """
    binary = shutil.which(BINARIES[key])
    if binary is None:
        raise OSError(f"{BINARIES[key]} is not installed")
    paths = {"/src": str(Path(snapshot).resolve())} if snapshot is not None else {}
    parts = list(mounts or [])
    for flag, spec in zip(parts[::2], parts[1::2]):
        if flag == "-v":
            source, destination = spec.split(":")[:2]
            paths[destination] = source
    order = sorted(paths, key=len, reverse=True)

    def local(value: str) -> str:
        for inside in order:
            if value == inside or value.startswith(inside + "/"):
                return paths[inside] + value[len(inside):]
        return value

    def back(text: str) -> str:
        for inside in order:
            text = text.replace(paths[inside], inside)
        return text

    with tempfile.TemporaryDirectory(prefix=f"engine-{key}-") as home:
        environment = {"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"), "HOME": home, "TMPDIR": home,
                       "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PYTHONUTF8": "1", **{name: local(value) for name, value in (env or {}).items()},
                       **(secret_env or {})}
        process = subprocess.Popen([binary, *(local(argument) for argument in arguments)], stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, env=environment, cwd=home, start_new_session=True,
                                   preexec_fn=_limits)
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)  # the engine and anything it started
            process.communicate()
            raise
    # Report files an engine writes (Gitleaks' /out) also name the real folders.
    if "/out" in paths:
        for report in Path(paths["/out"]).glob("*.json"):
            if report.stat().st_size < 50_000_000:
                report.write_text(back(report.read_text(encoding="utf-8", errors="replace")), encoding="utf-8")
    return subprocess.CompletedProcess([BINARIES[key], *arguments], process.returncode, back(stdout), back(stderr))


def _relative(path: str) -> str:
    return re.sub(r"^/src/", "", path or "")


def _stable(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


SEVERITY_NAME = {"critical": msg("scanning.severity.critical"), "high": msg("scanning.severity.high"),
                 "medium": msg("scanning.severity.medium"), "low": msg("scanning.severity.low"), "info": msg("scanning.severity.info")}


SECRET_SEVERITY = "critical"  # an exposed secret is always critical, whatever the engine or the rule says


def _base(scanner: str, rule: str, title, path: str, line: int, severity: str, *, reason,
          remediation, cwe: list[int], owasp: str, confidence: int, digest: str, tool: str) -> dict:
    if scanner == "secrets":
        severity = SECRET_SEVERITY
    action = "act" if severity == "critical" else "attend" if severity == "high" else "track"
    return {"finding_id": digest[:16], "fingerprint": digest, "scanner": scanner, "tool": tool, "rule_id": rule,
            "title": title[:200] if isinstance(title, str) else title, "path": path, "line": line, "severity": severity,
            "confidence": confidence, "verdict": "candidate", "cwe": cwe, "owasp": [owasp], "cve": [], "ghsa": [],
            "package": None, "advisory": None, "kev": None, "epss": None,
            "priority": {"action": action, "factors": [
                msg("scanning.priority.static_severity", severity=SEVERITY_NAME.get(severity, severity)),
                msg("scanning.priority.confirm_reachability")]},
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


def _rule_texts(value, limit: int = 2000) -> dict | str:
    """A Tamandua rule text in its own languages (`metadata.title` / `metadata.fix` as {en, es}), or "" if absent."""
    from tamandua.shared.i18n import inline
    if not isinstance(value, dict):
        return ""
    return inline({locale: text[:limit] for locale, text in value.items() if isinstance(text, str)})


def _rule_id(check_id: str) -> str:
    """Opengrep prefixes each rule id with the dotted path of the rules folder ("rules." in a container, the whole real
    path when the engine runs locally). Our ids start at "appsec.", so the fingerprint is the same either way."""
    start = check_id.find("appsec.")
    return check_id[start:] if start >= 0 else check_id.removeprefix("rules.")


def parse_opengrep(payload: dict) -> list[dict]:
    findings, seen = [], set()
    for result in payload.get("results", []):
        extra = result.get("extra") or {}
        metadata = extra.get("metadata") or {}
        rule = _rule_id(str(result.get("check_id", "")))
        path = _relative(result.get("path", ""))
        line = int((result.get("start") or {}).get("line") or 1)
        snippet = " ".join(str(extra.get("lines", "")).split())[:200]
        severity = "critical" if str(metadata.get("severity", "")).upper() == "CRITICAL" \
            else SEVERITY_LABEL.get(str(extra.get("severity", "")).upper(), "medium")
        cwe = [int(item) for item in metadata.get("cwe", []) if str(item).isdigit()]
        message = str(extra.get("message", "")).strip()
        title = _rule_texts(metadata.get("title"), 200) \
            or f"{metadata.get('category', 'sast').capitalize()}: {rule.rsplit('.', 1)[-1].replace('-', ' ')}"
        remediation = _rule_texts(metadata.get("fix")) or _rule_texts({"en": message})
        finding = _base(
            "sast", rule, title, path, line, severity, tool="opengrep",
            reason=msg("scanning.opengrep.reason", snippet=snippet, path=path, line=line), remediation=remediation,
            cwe=cwe, owasp=str(metadata.get("owasp", "A05:2025")),
            confidence=CONFIDENCE.get(str(metadata.get("confidence", "MEDIUM")).upper(), 6),
            # La huella usa el fragmento, no la línea: mover código no debe reabrir tickets.
            digest=_stable("sast", rule, path, snippet))
        # Dos coincidencias de la misma regla en la misma línea son un solo hallazgo (misma huella).
        if finding["fingerprint"] not in seen:
            seen.add(finding["fingerprint"])
            findings.append(finding)
    return findings


MINIFIED_SUFFIXES = {".js", ".mjs", ".cjs", ".css"}


def minified_files(snapshot: Path, limit: int = 200) -> list[str]:
    """JavaScript y CSS compilados o minificados: líneas kilométricas que el SAST no puede leer con sentido.

    Siguen en la instantánea (un bundle puede llevar una clave incrustada y Gitleaks debe verla);
    solo se excluyen de Opengrep.
    """
    found = []
    for path in sorted(snapshot.rglob("*")):
        if len(found) >= limit:
            break
        if path.suffix.lower() not in MINIFIED_SUFFIXES or not path.is_file() or path.is_symlink():
            continue
        try:
            with path.open("rb") as handle:
                head = handle.read(512_000)
        except OSError:
            continue
        lines = head.split(b"\n")
        if max((len(line) for line in lines), default=0) > 3000 or len(head) / max(1, len(lines)) > 500:
            found.append(path.relative_to(snapshot).as_posix())
    return found


def _rules_for(snapshot: Path) -> Path:
    """Las reglas tal como puede montarlas el motor. Con compose vienen montadas del host; lanzada la app
    con `docker run` (CI) están solo dentro de su imagen, y el motor —un contenedor hermano— no las vería.
    En ese caso se copian junto al snapshot, que sí está en la carpeta de datos montada."""
    if not in_container() or any(Path(inside).resolve() == RULES_DIR.resolve() for inside, _ in _host_pairs()):
        return RULES_DIR
    target = snapshot.parent / "opengrep-rules"
    if not target.exists():
        shutil.copytree(RULES_DIR, target)
    return target


def run_opengrep(snapshot: Path) -> dict:
    started = time.time()
    if runner() == "local":
        if not engine_ready("opengrep"):
            return _result("opengrep", "not_tested", unavailable("opengrep", None))
    elif not docker_available():
        return _result("opengrep", "not_tested", msg("scanning.opengrep.no_docker", problem=docker_problem()))
    elif not image_available("opengrep"):
        reason = _last_image_error.get("opengrep", "")
        # «No such image» es que falta construirla; cualquier otra cosa es un problema con Docker.
        if not reason or "no such image" in reason.lower():
            return _result("opengrep", "not_tested", msg("scanning.opengrep.image_missing"))
        return _result("opengrep", "not_tested", msg("scanning.opengrep.image_error", cause=reason))
    languages = snapshot_languages(snapshot)
    compiled = minified_files(snapshot)
    excludes = [part for path in compiled for part in ("--exclude", path)]
    try:
        completed = _run("opengrep", ["scan", "--config", "/rules", "--json", "--quiet", *excludes, "/src"], snapshot,
                         mounts=["-v", f"{host_path(_rules_for(snapshot))}:/rules:ro"])
        # 0: sin hallazgos · 1: con hallazgos. Otro código (2 fatal, 7 configuración inválida…) es que no analizó:
        # contarlo como «0 candidatos» sería un falso limpio.
        if completed.returncode not in (0, 1):
            return _result("opengrep", "inconclusive", with_cause(msg("scanning.opengrep.exit_code", code=completed.returncode), completed), started=started)
        payload = json.loads(completed.stdout or "{}")
    except subprocess.TimeoutExpired:
        return _result("opengrep", "inconclusive", msg("scanning.opengrep.timeout"), started=started)
    except (OSError, ValueError):
        return _result("opengrep", "inconclusive", msg("scanning.engines.unreadable", engine="Opengrep"), started=started)
    findings = parse_opengrep(payload)
    errors = [item for item in payload.get("errors", []) if isinstance(item, dict)]
    covered = ", ".join(f"{name} ({count})" for name, count in sorted(languages["covered"].items())) \
        or msg("scanning.opengrep.no_covered_language")
    uncovered = ", ".join(sorted(languages["uncovered"]))
    parts = [msg("scanning.opengrep.detail", rulesets=sum(1 for _ in RULES_DIR.glob("*.yml")), languages=covered,
                 candidates=len(findings))]
    if uncovered:
        parts.append(msg("scanning.opengrep.uncovered", languages=uncovered))
    if compiled:
        parts.append(msg("scanning.opengrep.minified", count=len(compiled)))
    if errors:
        parts.append(msg("scanning.opengrep.errors", count=len(errors)))
    detail = joined(parts, "scanning.join.sentences")
    status = "partial" if (errors or uncovered) else "completed"
    return _result("opengrep", status, detail, findings, started)


# --- Trivy ----------------------------------------------------------------------------

def _pick_fixed(fixed: str | None, installed: str) -> str | None:
    candidates = [item.strip() for item in str(fixed or "").split(",") if item.strip()]
    later = [item for item in candidates if compare_versions(item, installed) > 0]
    return min(later, key=lambda item: (len(item.split(".")), item)) if later else (candidates[0] if candidates else None)


def _trivy_vulnerability(entry: dict, target: str, ecosystem: str, feeds: dict, packages: dict | None = None) -> dict:
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
    remediation = (msg("scanning.sca.upgrade", package=name, installed=installed, fixed=fixed, target=target)
                   if fixed else msg("scanning.sca.no_fix", package=name))
    meta = (packages or {}).get(entry.get("PkgID")) or {}
    dev = bool(meta.get("Dev"))
    if dev:
        # De desarrollo: no llega a producción, pero corre en los equipos y en la CI (cadena de suministro).
        priority["factors"].append(msg("scanning.priority.dev_dependency"))
        if not kev and priority["action"] == "act":
            priority["action"] = "attend"
        elif not kev:
            priority["action"] = "track"
        remediation = msg("scanning.sca.dev_remediation", remediation=remediation)
    relationship = meta.get("Relationship")
    digest = sca_fingerprint("sca", identifier, ecosystem, name, installed)
    return {"finding_id": digest[:16], "fingerprint": digest, "scanner": "sca", "tool": "trivy", "rule_id": identifier,
            "title": f"{name} {installed}: {summary}"[:200], "path": target, "line": 1, "severity": severity,
            "confidence": 8 if score is not None else 6, "verdict": "candidate", "cwe": cwe, "owasp": ["A03:2025"],
            "cve": cves, "ghsa": ghsas,
            "package": {"ecosystem": ecosystem, "name": name, "version": installed, "fixed_version": fixed, "introduced": None,
                        "dev": dev, "direct": relationship == "direct" if relationship else None},
            "advisory": {"id": identifier, "aliases": cves + ghsas, "summary": summary,
                         "details": str(entry.get("Description") or "")[:2000], "cvss_vector": vector,
                         "cvss_score": score, "published": entry.get("PublishedDate"),
                         "modified": entry.get("LastModifiedDate"), "references": references},
            "kev": kev, "epss": {"score": epss[0], "percentile": epss[1]} if epss else None,
            "source": data_sources.from_trivy(entry),
            "priority": priority, "reason": summary, "remediation": remediation}


def _trivy_misconfiguration(entry: dict, target: str) -> dict:
    cause = entry.get("CauseMetadata") or {}
    line = int(cause.get("StartLine") or 1)
    rule = str(entry.get("AVDID") or entry.get("ID") or "misconfig")
    severity = SEVERITY_LABEL.get(str(entry.get("Severity", "")).upper(), "medium")
    resource = str(cause.get("Resource") or cause.get("Provider") or "")
    finding = _base("iac", rule, f"{entry.get('Title', rule)}", target, line, severity, tool="trivy",
                    reason=str(entry.get("Message") or entry.get("Description") or "").strip(),
                    remediation=str(entry.get("Resolution") or "").strip() or msg("scanning.iac.review_reference"),
                    cwe=[], owasp="A02:2025", confidence=8,
                    digest=_stable("iac", rule, target, resource or str(line)))
    # Rango de líneas: con él se reconoce el mismo fallo cuando Checkov lo señala en el bloque del recurso.
    finding["end_line"] = max(line, int(cause.get("EndLine") or line))
    return finding


def _trivy_secret(entry: dict, target: str, custom: dict | None = None) -> dict:
    line = int(entry.get("StartLine") or 1)
    rule = str(entry.get("RuleID") or "secret")
    if rule in (custom or {}):
        return _custom_secret(custom[rule], rule, target, line, tool="trivy", confidence=8)
    # Nunca se guarda el valor: Trivy ya lo redacta, y aquí ni siquiera se lee.
    category = entry.get("Category")
    return _base("secrets", rule, (SECRET_TITLES.get(rule) or msg("scanning.secrets.exposed_titled", title=str(entry.get("Title") or rule))),
                 target, line, SECRET_SEVERITY, tool="trivy",
                 reason=msg("scanning.secrets.trivy_reason", category=str(category), path=target, line=line) if category
                 else msg("scanning.secrets.trivy_reason_generic", path=target, line=line),
                 remediation=msg("scanning.secrets.rotate"),
                 cwe=[798], owasp="A04:2025", confidence=8, digest=_stable("secrets", rule, target, str(line)))


MAX_PACKAGES = 20_000


def trivy_packages(payload: dict, *, system: bool = False) -> list[dict]:
    """Paquetes con su versión (no solo los vulnerables), de Trivy.

    Por defecto, los de aplicación: con ellos se comprueban a diario los avisos que se publiquen después, sin
    volver a analizar (ver advisory_watch). Con `system`, los del sistema operativo de una imagen, que solo van
    al SBOM (sus avisos dependen de la versión de la distribución y llegan al reanalizar).
    Además del nombre y la versión se guarda lo que pide un SBOM: purl, licencias y si es dependencia directa."""
    packages, seen = [], set()
    wanted = "os-pkgs" if system else "lang-pkgs"
    for result in payload.get("Results", []) or []:
        if result.get("Class") != wanted:
            continue
        ecosystem = str(result.get("Type") or "").lower()
        target = _relative(str(result.get("Target", "")))
        for item in result.get("Packages") or []:
            name, version = str(item.get("Name") or ""), str(item.get("Version") or "")
            key = (ecosystem, name, version, target)
            if not name or not version or key in seen:
                continue
            seen.add(key)
            package = {"ecosystem": ecosystem, "name": name, "version": version, "path": target}
            purl = str((item.get("Identifier") or {}).get("PURL") or "")
            if purl.startswith("pkg:"):
                package["purl"] = purl[:500]
            licenses = [str(entry)[:100] for entry in item.get("Licenses") or [] if entry][:5]
            if licenses:
                package["licenses"] = licenses
            if item.get("Relationship") in ("direct", "indirect"):
                package["direct"] = item["Relationship"] == "direct"
            packages.append(package)
            if len(packages) >= MAX_PACKAGES:
                return packages
    return packages


def parse_trivy(payload: dict, feeds: dict, custom: dict | None = None) -> list[dict]:
    findings = []
    for result in payload.get("Results", []) or []:
        target = _relative(str(result.get("Target", "")))
        ecosystem = str(result.get("Type") or "").lower() or "unknown"
        packages = {item.get("ID"): item for item in result.get("Packages") or [] if item.get("ID")}
        for entry in result.get("Vulnerabilities") or []:
            findings.append(_trivy_vulnerability(entry, target, ecosystem, feeds, packages))
        for entry in result.get("Misconfigurations") or []:
            if str(entry.get("Status", "FAIL")).upper() == "FAIL":
                findings.append(_trivy_misconfiguration(entry, target))
        for entry in result.get("Secrets") or []:
            findings.append(_trivy_secret(entry, target, custom))
    seen, unique = set(), []
    for finding in findings:
        if finding["fingerprint"] not in seen:
            seen.add(finding["fingerprint"])
            unique.append(finding)
    return unique


def _trivy_fs(snapshot: Path, cache_dir: Path, scanners: str, config_dir: Path | None, *,
              network: bool = True) -> subprocess.CompletedProcess:
    # Con las dependencias de desarrollo (marcadas como tales) y la lista de paquetes para saber cuáles son.
    secret_config = ["--secret-config", "/cfg/trivy-secret.yaml"] if config_dir else []
    return _run("trivy", ["fs", "--scanners", scanners, *secret_config, "--include-dev-deps", "--list-all-pkgs",
                          "--cache-dir", "/cache", "--format", "json", "--quiet",
                          "--timeout", "14m", "/src"], snapshot, network=network,
                mounts=["-v", f"{host_path(cache_dir)}:/cache",
                        *(["-v", f"{host_path(config_dir)}:/cfg:ro"] if config_dir else [])])


def run_trivy(snapshot: Path, cache_dir: Path, feeds: dict, secret_settings: dict | None = None) -> dict:
    """`secret_settings`: the organization's secret detection settings (secret_rules), applied through
    `--secret-config`. If Trivy rejects them, it runs again without secret detection so dependencies and IaC are
    still analyzed, and the step says secrets were not covered by Trivy."""
    started = time.time()
    if problem := unavailable("trivy", msg("scanning.trivy.no_docker")):
        return _result("trivy", "not_tested", problem)
    cache_dir = writable_cache(cache_dir)
    rejected = None
    try:
        with tempfile.TemporaryDirectory(prefix="trivy-config-", dir=snapshot.parent) as folder:
            config_dir = None
            if secret_settings:
                config_dir = Path(folder)
                (config_dir / "trivy-secret.yaml").write_text(secret_rules.trivy_secret_config(secret_settings), encoding="utf-8")
            completed = _trivy_fs(snapshot, cache_dir, "vuln,misconfig,secret", config_dir)
        if config_dir and completed.returncode != 0 and not completed.stdout.strip() and "secret config" in completed.stderr.lower():
            reason = config_cause(completed)
            rejected = msg("scanning.trivy.secret_config_rejected_cause", cause=reason) if reason \
                else msg("scanning.trivy.secret_config_rejected")
            completed = _trivy_fs(snapshot, cache_dir, "vuln,misconfig", None)
        if completed.returncode != 0 and not completed.stdout.strip():
            failure = msg("scanning.trivy.failed_download") if "download" in completed.stderr.lower() \
                else msg("scanning.engines.failed_early", engine="Trivy")
            return _result("trivy", "inconclusive", with_cause(failure, completed), started=started)
        payload = json.loads(completed.stdout or "{}")
    except subprocess.TimeoutExpired:
        return _result("trivy", "inconclusive", msg("scanning.trivy.timeout"), started=started)
    except (OSError, ValueError):
        return _result("trivy", "inconclusive", msg("scanning.engines.unreadable", engine="Trivy"), started=started)
    findings = parse_trivy(payload, feeds, secret_rules.custom_rules(secret_settings))
    kinds = {"sca": 0, "iac": 0, "secrets": 0}
    for finding in findings:
        kinds[finding["scanner"]] = kinds.get(finding["scanner"], 0) + 1
    targets = [result.get("Target", "") for result in payload.get("Results", []) or []]
    manifests = [target for result, target in zip(payload.get("Results", []) or [], targets) if result.get("Class") == "lang-pkgs"]
    configs = [target for result, target in zip(payload.get("Results", []) or [], targets) if result.get("Class") == "config"]
    dev = sum(1 for finding in findings if (finding.get("package") or {}).get("dev"))
    counts = {"manifests": len(manifests), "configs": len(configs), "sca": kinds["sca"], "iac": kinds["iac"], "secrets": kinds["secrets"]}
    detail = msg("scanning.trivy.detail_dev", dev=dev, **counts) if dev else msg("scanning.trivy.detail", **counts)
    if not feeds.get("kev") or not feeds.get("epss"):
        detail = joined([detail, msg("scanning.trivy.no_feeds")], "scanning.join.sentences")
    if rejected:
        detail = joined([detail, rejected], "scanning.join.sentences")
    result = {**_result("trivy", "partial" if rejected else "completed", detail, findings, started), "packages": trivy_packages(payload)}
    return _withhold(result, secret_settings, lambda reference: _trivy_secrets(snapshot, cache_dir, reference))


def _trivy_secrets(snapshot: Path, cache_dir: Path, settings: dict | None) -> list[dict] | None:
    """Secret detection alone, for the unfiltered run. Without network: it needs no vulnerability database."""
    try:
        with tempfile.TemporaryDirectory(prefix="trivy-config-", dir=snapshot.parent) as folder:
            config_dir = None
            if settings:
                config_dir = Path(folder)
                (config_dir / "trivy-secret.yaml").write_text(secret_rules.trivy_secret_config(settings), encoding="utf-8")
            completed = _trivy_fs(snapshot, cache_dir, "secret", config_dir, network=False)
        if completed.returncode != 0 and not completed.stdout.strip():
            return None
        payload = json.loads(completed.stdout or "{}")
    except (subprocess.TimeoutExpired, OSError, ValueError):
        return None
    return parse_trivy(payload, {}, secret_rules.custom_rules(settings)) if isinstance(payload, dict) else None


def _withhold(result: dict, settings: dict | None, reference) -> dict:
    """With settings that filter, adds `withheld`: the secrets only an unfiltered run (`reference`) sees
    (secret_rules.withheld). If that run fails, `withheld` is None and the step partial: the scan is then incomplete,
    so a secret that stopped appearing is never taken as fixed."""
    if result["status"] != "completed" or not secret_rules.filters(settings):
        return result
    unfiltered = reference(secret_rules.unfiltered(settings))
    if unfiltered is None:
        return {**result, "status": "partial", "withheld": None,
                "detail": joined([result["detail"], msg("scanning.secret_rules.withheld.unknown")], "scanning.join.sentences")}
    kept = {finding["fingerprint"] for finding in result["findings"]}
    return {**result, "withheld": [secret_rules.withheld(finding, settings) for finding in unfiltered
                                   if finding["scanner"] == "secrets" and finding["fingerprint"] not in kept]}


# --- OSV-Scanner ---------------------------------------------------------------------

def parse_osv_scanner(payload: dict, feeds: dict) -> list[dict]:
    """Un hallazgo por aviso y paquete. OSV agrupa en `groups` los identificadores del mismo aviso
    (GHSA, PYSEC, CVE…); de cada grupo se toma uno como principal y el resto quedan como alias."""
    from tamandua.modules.intel.advisories import dependency_finding
    from tamandua.modules.scanning.dependency_merge import stable_fingerprint
    findings, seen = [], set()
    for result in payload.get("results") or []:
        path = _relative(str((result.get("source") or {}).get("path") or ""))
        for entry in result.get("packages") or []:
            package = entry.get("package") or {}
            name, version, ecosystem = str(package.get("name") or ""), str(package.get("version") or ""), str(package.get("ecosystem") or "")
            if not name or not version:
                continue
            vulnerabilities = {item.get("id"): item for item in entry.get("vulnerabilities") or [] if isinstance(item, dict) and item.get("id")}
            groups = entry.get("groups") or [{"ids": [identifier]} for identifier in vulnerabilities]
            for group in groups:
                ids = [item for item in group.get("ids") or [] if item in vulnerabilities]
                if not ids:
                    continue
                main = next((item for item in ids if item.startswith("GHSA-")), ids[0])
                aliases = set(group.get("aliases") or []) | set(ids)
                for item in ids:
                    aliases |= set(vulnerabilities[item].get("aliases") or [])
                advisory = {**vulnerabilities[main], "aliases": sorted(aliases - {main})}
                finding = dependency_finding({"ecosystem": ecosystem, "name": name, "version": version, "path": path}, advisory, feeds)
                digest = stable_fingerprint(main, aliases, ecosystem, name, version)
                if digest in seen:
                    continue
                seen.add(digest)
                finding.update(fingerprint=digest, finding_id=digest[:16], tool="osv-scanner")
                findings.append(finding)
    return findings


def run_osv_scanner(snapshot: Path, cache_dir: Path, feeds: dict, *, resolve: bool = False) -> dict:
    """OSV-Scanner con las bases de avisos descargadas en local: la lista de dependencias no sale de aquí.

    Solo con `resolve` (el usuario autorizó consultas externas) resuelve dependencias transitivas de
    manifiestos sin lockfile, lo que consulta deps.dev. El análisis de llamadas queda apagado: en Rust
    ejecutaría scripts de compilación del repositorio."""
    started = time.time()
    if problem := unavailable("osv-scanner", msg("scanning.osv.no_docker")):
        return _result("osv-scanner", "not_tested", problem)
    cache_dir = writable_cache(cache_dir)
    arguments = ["scan", "source", "-r", "--format", "json", "--offline-vulnerabilities", "--download-offline-databases",
                 "--allow-no-lockfiles", "--no-call-analysis=go", "--no-call-analysis=rust", *([] if resolve else ["--no-resolve"]), "/src"]
    try:
        completed = _run("osv-scanner", arguments, snapshot, network=True, timeout=1800,
                         env={"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": "/cache"}, mounts=["-v", f"{host_path(cache_dir)}:/cache"])
        # 0: sin avisos · 1: con avisos. Cualquier otro código es un error del motor.
        if completed.returncode not in (0, 1) or not completed.stdout.strip():
            if completed.returncode == 0:
                return _result("osv-scanner", "completed", msg("scanning.osv.no_manifests"), started=started)
            return _result("osv-scanner", "inconclusive", with_cause(msg("scanning.engines.failed_early", engine="OSV-Scanner"), completed), started=started)
        payload = json.loads(completed.stdout)
    except subprocess.TimeoutExpired:
        return _result("osv-scanner", "inconclusive", msg("scanning.osv.timeout"), started=started)
    except (OSError, ValueError):
        return _result("osv-scanner", "inconclusive", msg("scanning.engines.unreadable", engine="OSV-Scanner"), started=started)
    findings = parse_osv_scanner(payload, feeds)
    manifests = {str((result.get("source") or {}).get("path") or "") for result in payload.get("results") or []}
    packages = sum(len(result.get("packages") or []) for result in payload.get("results") or [])
    detail = msg("scanning.osv.detail_resolved" if resolve else "scanning.osv.detail",
                 manifests=len(manifests), packages=packages, advisories=len(findings))
    return _result("osv-scanner", "completed", detail, findings, started)


# --- Gitleaks -------------------------------------------------------------------------

# Names of the most common Gitleaks rules; the rest use their identifier.
SECRET_TITLES = {
    "jwt": msg("scanning.secrets.titles.jwt"), "generic-api-key": msg("scanning.secrets.titles.generic_api_key"),
    "private-key": msg("scanning.secrets.titles.private_key"), "aws-access-token": msg("scanning.secrets.titles.aws_access_token"),
    "aws-secret-access-key": msg("scanning.secrets.titles.aws_secret_access_key"), "github-pat": msg("scanning.secrets.titles.github_pat"),
    "github-fine-grained-pat": msg("scanning.secrets.titles.github_fine_grained_pat"),
    "github-app-token": msg("scanning.secrets.titles.github_app_token"), "github-oauth": msg("scanning.secrets.titles.github_oauth"),
    "gitlab-pat": msg("scanning.secrets.titles.gitlab_pat"), "slack-bot-token": msg("scanning.secrets.titles.slack_bot_token"),
    "slack-webhook-url": msg("scanning.secrets.titles.slack_webhook_url"),
    "stripe-access-token": msg("scanning.secrets.titles.stripe_access_token"), "gcp-api-key": msg("scanning.secrets.titles.gcp_api_key"),
    "openai-api-key": msg("scanning.secrets.titles.openai_api_key"), "anthropic-api-key": msg("scanning.secrets.titles.anthropic_api_key"),
    "twilio-api-key": msg("scanning.secrets.titles.twilio_api_key"), "sendgrid-api-token": msg("scanning.secrets.titles.sendgrid_api_token"),
    "npm-access-token": msg("scanning.secrets.titles.npm_access_token"), "pypi-upload-token": msg("scanning.secrets.titles.pypi_upload_token"),
    "azure-ad-client-secret": msg("scanning.secrets.titles.azure_ad_client_secret"),
    "heroku-api-key": msg("scanning.secrets.titles.heroku_api_key"),
}


def secret_title(rule: str) -> dict:
    return SECRET_TITLES.get(rule) or msg("scanning.secrets.exposed_rule", rule=rule)


def _custom_secret(rule: dict, rule_id: str, path: str, line: int, *, tool: str, confidence: int) -> dict:
    """A finding from a custom rule: its description (as written, one language) as the title."""
    return _base("secrets", rule_id, rule["description"], path, line, SECRET_SEVERITY, tool=tool,
                 reason=msg("scanning.secrets.custom_reason", rule=rule["id"], path=path, line=line),
                 remediation=msg("scanning.secrets.rotate"), cwe=[798], owasp="A04:2025", confidence=confidence,
                 digest=_stable("secrets", rule_id, path, str(line)))


def parse_gitleaks(payload: list, custom: dict | None = None) -> list[dict]:
    findings = []
    for entry in payload or []:
        if not isinstance(entry, dict):
            continue
        rule = str(entry.get("RuleID") or "secret")
        path = _relative(str(entry.get("File", "")))
        line = int(entry.get("StartLine") or 1)
        entropy = float(entry.get("Entropy") or 0)
        if rule in (custom or {}):
            findings.append(_custom_secret(custom[rule], rule, path, line, tool="gitleaks", confidence=8 if entropy >= 3.5 else 6))
            continue
        # El valor nunca se lee: gitleaks corre con --redact y aquí solo se toman regla, archivo y línea.
        findings.append(_base("secrets", rule, secret_title(rule), path, line, SECRET_SEVERITY, tool="gitleaks",
                              reason=msg("scanning.secrets.gitleaks_reason", rule=rule, path=path, line=line, entropy=f"{entropy:.1f}"),
                              remediation=msg("scanning.secrets.rotate"),
                              cwe=[798], owasp="A04:2025", confidence=8 if entropy >= 3.5 else 6,
                              digest=_stable("secrets", rule, path, str(line))))
    return findings


def _gitleaks_report(snapshot: Path, settings: dict | None, started: float, *, strict: bool = False) -> tuple[list | None, dict | None]:
    """(report, None), or (None, the step's result) when Gitleaks couldn't produce it. `strict`: a missing report is
    a failure even without settings."""
    # El reporte se escribe junto al snapshot: es la única carpeta que ambos contenedores ven.
    # The settings go in a separate folder, mounted read-only.
    with tempfile.TemporaryDirectory(prefix="gitleaks-", dir=snapshot.parent) as output, \
            tempfile.TemporaryDirectory(prefix="gitleaks-config-", dir=snapshot.parent) as config:
        arguments = ["dir", "/src", "--report-format", "json", "--report-path", "/out/report.json",
                     "--no-banner", "--exit-code", "0", "--redact"]
        mounts = ["-v", f"{host_path(Path(output))}:/out"]
        if settings:
            (Path(config) / "gitleaks.toml").write_text(secret_rules.gitleaks_toml(settings), encoding="utf-8")
            arguments[2:2] = ["--config", "/cfg/gitleaks.toml"]
            mounts += ["-v", f"{host_path(Path(config))}:/cfg:ro"]
        try:
            completed = _run("gitleaks", arguments, snapshot, mounts=mounts, timeout=600)
            report = Path(output) / "report.json"
            # Without settings, a missing report keeps its old meaning; with them it may be the settings' fault.
            if (settings or strict) and (completed.returncode != 0 or not report.is_file()):
                if "config" not in (completed.stderr or "").lower():
                    return None, _result("gitleaks", "inconclusive", with_cause(msg("scanning.engines.failed", engine="Gitleaks"), completed),
                                         started=started)
                reason = config_cause(completed)
                failure = msg("scanning.gitleaks.config_failed_cause", cause=reason) if reason else msg("scanning.gitleaks.config_failed")
                return None, _result("gitleaks", "inconclusive", failure, started=started)
            payload = json.loads(report.read_text(encoding="utf-8") or "[]") if report.is_file() else []
        except subprocess.TimeoutExpired:
            return None, _result("gitleaks", "inconclusive", msg("scanning.engines.timeout", engine="Gitleaks"), started=started)
        except (OSError, ValueError):
            return None, _result("gitleaks", "inconclusive", msg("scanning.gitleaks.unreadable"), started=started)
    if completed.returncode not in (0, 1):
        return None, _result("gitleaks", "inconclusive", with_cause(msg("scanning.engines.failed", engine="Gitleaks"), completed), started=started)
    return (payload if isinstance(payload, list) else []), None


def run_gitleaks(snapshot: Path, settings: dict | None = None) -> dict:
    """`settings`: the organization's secret detection settings (secret_rules). With them, Gitleaks gets a generated
    `--config` mounted read-only; if it rejects it, the step is inconclusive, never clean."""
    started = time.time()
    if problem := unavailable("gitleaks", msg("scanning.gitleaks.no_docker")):
        return _result("gitleaks", "not_tested", problem)
    payload, failure = _gitleaks_report(snapshot, settings, started)
    if failure:
        return failure
    findings = parse_gitleaks(payload, secret_rules.custom_rules(settings))
    detail = msg("scanning.gitleaks.detail_configured", secrets=len(findings), **secret_rules.counts(settings)) if settings \
        else msg("scanning.gitleaks.detail", secrets=len(findings))

    def reference(unfiltered: dict | None) -> list[dict] | None:
        report, failed = _gitleaks_report(snapshot, unfiltered, started, strict=True)
        return None if failed else parse_gitleaks(report, secret_rules.custom_rules(unfiltered))
    return _withhold(_result("gitleaks", "completed", detail, findings, started), settings, reference)


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
