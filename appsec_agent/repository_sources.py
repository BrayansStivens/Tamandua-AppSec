"""Fuentes de código autorizadas: workspace fijo y repositorios listados por API."""

from __future__ import annotations

import io
import json
import os
import re
import tarfile
from pathlib import Path, PurePosixPath
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


WORKSPACE = Path(__file__).resolve().parents[1]
# Los topes no son una política de producto: son defensa contra descompresión
# maliciosa y contra una ejecución desbocada. Lo que acota el trabajo real es la
# lista de lo que los analizadores saben leer, no un presupuesto de bytes.
MAX_ARCHIVE = 1_000_000_000      # descarga comprimida, en disco por streaming
MAX_EXPANSION = 5_000_000_000    # bytes leídos del archivo antes de sospechar bomba
MAX_FILES = 200_000              # freno de ejecución desbocada
MAX_FILE = 2_000_000             # por archivo: por encima es generado o datos
MAX_TOTAL = 2_000_000_000        # fuente acumulada; no debería alcanzarse nunca
IGNORED = {".git", "node_modules", ".venv", "venv", "data", "dist", "build", "__pycache__", ".next",
           "coverage", "htmlcov", "site-packages", "vendor", "bower_components", "target", "out",
           ".angular", ".nuxt", ".svelte-kit", ".turbo", ".gradle", "storybook-static"}
# Nada de esto lo mira un analizador de código, así que no debe gastar presupuesto
# ni desplazar a un fichero fuente que sí importa.
# Lista de admitidos, no de descartados: un repositorio de 600 MB suele tener
# unos pocos MB de código y el resto son activos que nadie va a analizar.
SOURCE_SUFFIXES = {
    ".py", ".pyi", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue", ".svelte",
    ".java", ".kt", ".kts", ".go", ".rb", ".php", ".cs", ".rs", ".swift", ".scala", ".dart",
    ".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".m", ".mm", ".lua", ".pl", ".pm",
    ".ex", ".exs", ".erl", ".clj", ".groovy", ".sh", ".bash", ".zsh", ".ps1",
    ".sql", ".graphql", ".proto", ".tf", ".tfvars",
    ".erb", ".jinja", ".jinja2", ".j2", ".twig", ".blade", ".hbs", ".ejs", ".pug",
    ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf", ".properties", ".env",
}
# Manifiestos y ficheros sin extensión que hacen falta para SCA, secretos e IaC.
SOURCE_NAMES = {
    "dockerfile", "containerfile", "makefile", "rakefile", "gemfile", "procfile",
    "requirements.txt", "pipfile", "poetry.lock", "pyproject.toml", "setup.py", "setup.cfg",
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json",
    "go.mod", "go.sum", "pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle",
    "gemfile.lock", "composer.json", "composer.lock", "cargo.toml", "cargo.lock",
}
# Salida de compilación y bundles: texto, pero generado, y ahoga la señal.
# Los secretos aparecen en cualquier texto, no solo en el código: la documentación, los
# ejemplos de configuración y las notas son de los sitios más habituales. Estos ficheros
# no los mira el SAST, pero Gitleaks sí, y dejarlos fuera producía falsos negativos.
TEXT_SUFFIXES = {
    ".md", ".markdown", ".mdx", ".txt", ".rst", ".adoc", ".html", ".htm", ".xml", ".csv", ".tsv", ".ipynb",
    ".log", ".pem", ".key", ".crt", ".cer", ".pub", ".asc", ".tpl", ".template", ".example", ".sample", ".dist",
    ".plist", ".xcconfig", ".http", ".rest", ".postman_collection", ".har", ".cnf", ".config",
}
SECRET_NAMES = {".npmrc", ".pypirc", ".netrc", ".dockercfg", ".git-credentials", ".htpasswd", "id_rsa", "id_dsa",
                "id_ecdsa", "id_ed25519", "credentials", "authorized_keys", "known_hosts", ".s3cfg", ".boto"}
SKIP_NAME_PARTS = (".min.js", ".min.css", ".bundle.js", "-bundle.js", ".chunk.js", ".d.ts")
# Lo que empieza por punto se descarta salvo los pipelines de CI/CD (Checkov, zizmor). Los ficheros de
# credenciales (.env, .npmrc…) siguen fuera de la instantánea a propósito.
DOT_FOLDERS = {".github", ".gitlab", ".circleci", ".buildkite", ".tekton", ".devcontainer"}
DOT_FILES = {".gitlab-ci.yml", ".gitlab-ci.yaml", ".pre-commit-config.yaml", ".pre-commit-hooks.yaml"}


class SourceError(ValueError):
    pass


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def _request(url: str, token: str, provider: str, *, redirect_host: str | None = None) -> bytes:
    headers = {"Accept": "application/json", "User-Agent": "AppSecAgent/0.3"}
    if provider == "github":
        headers["Authorization"] = f"Bearer {token}"
        headers["X-GitHub-Api-Version"] = "2022-11-28"
    else:
        headers["PRIVATE-TOKEN"] = token
    opener = build_opener(_NoRedirect)
    try:
        try:
            response = opener.open(Request(url, headers=headers), timeout=12)
        except HTTPError as exc:
            if exc.code != 302 or not redirect_host:
                raise
            target = exc.headers.get("Location", "")
            parsed = urlsplit(target)
            if parsed.scheme != "https" or parsed.hostname != redirect_host or parsed.username or parsed.password:
                raise SourceError("Redirección de archivo no permitida")
            # La URL temporal se consulta sin la credencial original.
            response = opener.open(Request(target, headers={"User-Agent": "AppSecAgent/0.3"}), timeout=20)
        with response:
            body = response.read(MAX_ARCHIVE + 1)
            if len(body) > MAX_ARCHIVE:
                raise SourceError("El repositorio supera el límite de descarga")
            return body
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise SourceError("No se pudo consultar el proveedor de código") from exc


def _download_archive(url: str, token: str, provider: str, destination: Path,
                      *, redirect_host: str | None = None) -> int:
    """Baja el tarball a disco por trozos. Un repositorio de cientos de MB no cabe en memoria."""
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "AppSecAgent/0.4"}
    if provider == "github":
        headers["Authorization"] = f"Bearer {token}"
        headers["X-GitHub-Api-Version"] = "2022-11-28"
    else:
        headers["PRIVATE-TOKEN"] = token
    opener = build_opener(_NoRedirect)
    try:
        try:
            response = opener.open(Request(url, headers=headers), timeout=30)
        except HTTPError as exc:
            if exc.code != 302 or not redirect_host:
                raise
            target = exc.headers.get("Location", "")
            parsed = urlsplit(target)
            if parsed.scheme != "https" or parsed.hostname != redirect_host or parsed.username or parsed.password:
                raise SourceError("Redirección de archivo no permitida")
            # La URL temporal se consulta sin la credencial original.
            response = opener.open(Request(target, headers={"User-Agent": "AppSecAgent/0.4"}), timeout=180)
        written = 0
        with response, open(destination, "wb") as handle:
            while True:
                chunk = response.read(1_048_576)
                if not chunk:
                    break
                written += len(chunk)
                if written > MAX_ARCHIVE:
                    raise SourceError("El archivo del repositorio supera 1 GB comprimido")
                handle.write(chunk)
        return written
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise SourceError("No se pudo descargar el repositorio") from exc


def list_repositories(provider: str, token: str | None = None) -> list[dict]:
    if provider not in ("github", "gitlab"):
        raise SourceError("Proveedor de código inválido")
    token = token or os.environ.get("GITHUB_TOKEN" if provider == "github" else "GITLAB_TOKEN")
    if not token:
        return []
    url = ("https://api.github.com/user/repos?per_page=50&sort=updated"
           if provider == "github" else
           "https://gitlab.com/api/v4/projects?membership=true&per_page=50&order_by=last_activity_at")
    try:
        rows = json.loads(_request(url, token, provider))
    except (ValueError, UnicodeDecodeError) as exc:
        raise SourceError("El proveedor respondió con datos inválidos") from exc
    if not isinstance(rows, list):
        raise SourceError("Lista de repositorios inválida")
    result = []
    for item in rows[:50]:
        if not isinstance(item, dict):
            continue
        name = item.get("full_name") if provider == "github" else item.get("path_with_namespace")
        identifier = name if provider == "github" else item.get("id")
        if not isinstance(name, str) or not name or not identifier:
            continue
        result.append({"id": f"{provider}:{identifier}", "name": name,
                       "provider": provider, "private": item.get("private", False) if provider == "github" else item.get("visibility") != "public",
                       "branch": item.get("default_branch")})
    return result


def available_sources(tokens: dict[str, str] | None = None, installation_id: int | None = None, *,
                      include_workspace: bool | None = None) -> dict:
    """Repositorios analizables. El código de la propia herramienta solo aparece en la CLI (desarrollo y
    dogfooding) o si se pide con APPSEC_AGENT_SHOW_WORKSPACE=1: a un usuario del panel no le sirve."""
    tokens = tokens or {}
    if include_workspace is None:
        include_workspace = os.environ.get("APPSEC_AGENT_SHOW_WORKSPACE", "").strip() == "1"
    sources = ([{"id": "local:appsec-agent", "name": "appsec-agent · código propio", "provider": "local",
                 "private": True, "branch": "workspace"}] if include_workspace else [])
    statuses = {}
    if installation_id is not None:
        # La App solo ve los repositorios que el usuario marcó al instalarla.
        from .github_app import GitHubAppError, installation_repositories
        try:
            sources.extend(installation_repositories(installation_id))
            statuses["github"] = {"configured": True, "origin": "github_app"}
        except GitHubAppError as exc:
            statuses["github"] = {"configured": True, "origin": "github_app", "error": str(exc)}
    for provider, env in (("github", "GITHUB_TOKEN"), ("gitlab", "GITLAB_TOKEN")):
        if provider in statuses:
            continue
        origin = "session" if tokens.get(provider) else "environment" if os.environ.get(env) else None
        statuses[provider] = {"configured": bool(origin), "origin": origin}
        if statuses[provider]["configured"]:
            try:
                sources.extend(list_repositories(provider, tokens.get(provider)))
            except SourceError:
                statuses[provider]["error"] = "No se pudo listar repositorios; revisa el token y sus permisos"
    return {"sources": sources, "providers": statuses}


def _safe_name(name: str) -> Path | None:
    if name.startswith("/") or "\\" in name:
        return None
    parts = PurePosixPath(name).parts
    if len(parts) < 2:
        return None
    relative = parts[1:]
    if any(part in ("", ".", "..") or part in IGNORED for part in relative):
        return None
    if any(part.startswith(".") and not _dot_allowed(part, last=index == len(relative) - 1, secrets=False)
           for index, part in enumerate(relative)):
        return None
    return Path(*relative)


def _dot_allowed(part: str, *, last: bool, secrets: bool = False) -> bool:
    """Carpetas de CI/CD y, como último tramo, sus ficheros; con `secrets`, también los de credenciales."""
    name = part.lower()
    if not last:
        return name in DOT_FOLDERS
    return name in DOT_FILES or (secrets and (name in SECRET_NAMES or name.startswith(".env")))


def _analyzable(relative: Path) -> bool:
    name = relative.name.lower()
    if name in SOURCE_NAMES or name in SECRET_NAMES or name.startswith(".env"):
        return True
    if any(part in name for part in SKIP_NAME_PARTS):
        return False
    return relative.suffix.lower() in SOURCE_SUFFIXES or relative.suffix.lower() in TEXT_SUFFIXES


def _extract_limited(blob: bytes | Path, root: Path) -> dict:
    """Copia lo que cabe y devuelve cuentas de lo que quedó fuera.

    Pasarse de los límites no es un error: un repositorio grande se analiza en
    parte y la ejecución declara exactamente qué no se miró. Fallar dejaría al
    usuario sin nada, y analizar en silencio el 10 % sería peor todavía.
    """
    stats = {"files": 0, "bytes": 0, "skipped_not_analyzable": 0, "skipped_too_large": 0,
             "skipped_over_budget": 0, "truncated": False}
    total = 0
    count = 0
    expanded = 0
    try:
        archive = (tarfile.open(name=str(blob), mode="r:gz") if isinstance(blob, Path)
                   else tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz"))
        with archive:
            for member in archive:
                if not member.isfile():
                    continue
                # Defensa contra descompresión maliciosa: un tarball pequeño puede
                # declarar teras. Se mira el tamaño anunciado antes de leer nada.
                expanded += member.size
                if expanded > MAX_EXPANSION:
                    raise SourceError("El archivo se expande de forma desproporcionada; "
                                      "se descarta por posible bomba de descompresión")
                relative = _safe_name(member.name)
                if relative is None:
                    continue
                if not _analyzable(relative):
                    stats["skipped_not_analyzable"] += 1
                    continue
                if member.size > MAX_FILE:
                    stats["skipped_too_large"] += 1
                    continue
                if count >= MAX_FILES or total + member.size > MAX_TOTAL:
                    stats["skipped_over_budget"] += 1
                    stats["truncated"] = True
                    continue
                source = archive.extractfile(member)
                if source is None:
                    continue
                content = source.read(MAX_FILE + 1)
                if len(content) != member.size:
                    raise SourceError("Archivo de repositorio inválido")
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
                total += len(content)
                count += 1
    except (tarfile.TarError, OSError) as exc:
        raise SourceError("Archivo comprimido inválido") from exc
    stats["files"] = count
    stats["bytes"] = total
    stats["archive_bytes"] = expanded
    return stats


def snapshot_source(source_id: str, destination: Path, tokens: dict[str, str] | None = None,
                    installation_id: int | None = None, ref: str | None = None) -> tuple[Path, dict]:
    """Snapshot de solo lectura. `ref` fija un commit concreto (revisión de un PR); solo GitHub."""
    if ref is not None and (not re.fullmatch(r"[0-9a-f]{40}", ref) or not source_id.startswith("github:")):
        raise SourceError("Commit inválido")
    if source_id == "local:appsec-agent":
        source = WORKSPACE
        total = count = skipped = 0
        truncated = False
        for directory, folders, filenames in os.walk(source, followlinks=False):
            folders[:] = [folder for folder in folders if folder not in IGNORED
                          and (not folder.startswith(".") or _dot_allowed(folder, last=False))
                          and not (Path(directory) / folder).is_symlink()]
            for filename in filenames:
                path = Path(directory) / filename
                if path.is_symlink() or not path.is_file() or (filename.startswith(".") and filename != ".env.example"
                                                                        and not _dot_allowed(filename, last=True)):
                    continue
                relative = path.relative_to(source)
                size = path.stat().st_size
                if not _analyzable(relative) or size > MAX_FILE:
                    skipped += 1
                    continue
                if count >= MAX_FILES or total + size > MAX_TOTAL:
                    skipped += 1
                    truncated = True
                    continue
                target = destination / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                content = path.read_bytes()
                target.write_bytes(content)
                total += len(content)
                count += 1
        return destination, {"id": source_id, "name": "appsec-agent · código propio", "provider": "local",
                             "files": count, "snapshot": {"files": count, "bytes": total, "skipped": skipped,
                                                          "truncated": truncated}}
    if not re.fullmatch(r"(?:github:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+|gitlab:[0-9]+)", source_id):
        raise SourceError("Repositorio inválido")
    provider = source_id.partition(":")[0]
    if provider == "github" and installation_id is not None:
        from .github_app import GitHubAppError, installation_repositories, installation_token
        try:
            entries = installation_repositories(installation_id)
            token = installation_token(installation_id)
        except GitHubAppError as exc:
            raise SourceError(str(exc)) from exc
    else:
        token = (tokens or {}).get(provider) or os.environ.get("GITHUB_TOKEN" if provider == "github" else "GITLAB_TOKEN")
        entries = list_repositories(provider, token)
    selected = next((entry for entry in entries if entry["id"] == source_id), None)
    if selected is None:
        raise SourceError("Repositorio no disponible para la credencial configurada")
    if not token:
        raise SourceError("Conecta el proveedor de código antes de analizar")
    archive_path = destination.parent / "repository.tar.gz"
    if provider == "github":
        name = source_id.removeprefix("github:")
        url = f"https://api.github.com/repos/{name}/tarball" + (f"/{ref}" if ref else "")
        _download_archive(url, token, provider, archive_path, redirect_host="codeload.github.com")
    else:
        identifier = source_id.removeprefix("gitlab:")
        url = f"https://gitlab.com/api/v4/projects/{quote(identifier)}/repository/archive.tar.gz?include_lfs_blobs=false"
        _download_archive(url, token, provider, archive_path)
    try:
        stats = _extract_limited(archive_path, destination)
    finally:
        archive_path.unlink(missing_ok=True)
    selected["files"] = stats["files"]
    selected["snapshot"] = stats
    return destination, selected
