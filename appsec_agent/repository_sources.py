"""Fuentes de código autorizadas: workspace fijo y repositorios listados por API."""

from __future__ import annotations

import io
import json
import os
import re
import tarfile
import time
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
MAX_MANIFEST = 64_000_000        # manifiestos y lockfiles: se reconocen por nombre; un lockfile grande es normal
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
# Manifiestos y lockfiles de dependencias de cada ecosistema. Se reconocen por su nombre o
# extensión, nunca por su tamaño: sin ellos el análisis de dependencias no ve nada.
MANIFEST_NAMES = {
    # JavaScript / TypeScript
    "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock",
    "deno.json", "deno.lock",
    # Python
    "requirements.txt", "pipfile", "pipfile.lock", "poetry.lock", "pyproject.toml", "setup.py", "setup.cfg",
    "uv.lock", "pdm.lock", "pylock.toml",
    # .NET
    "packages.config", "packages.lock.json", "directory.packages.props", "directory.build.props",
    "paket.dependencies", "paket.lock",
    # Java, Kotlin, Scala
    "pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts", "gradle.lockfile",
    "libs.versions.toml", "verification-metadata.xml",
    # Go, Rust, PHP, Ruby
    "go.mod", "go.sum", "go.work", "go.work.sum", "cargo.toml", "cargo.lock", "composer.json", "composer.lock",
    "gemfile", "gemfile.lock", "gems.rb", "gems.locked",
    # Dart, Elixir, Erlang, Swift, Objective-C, C/C++, R, Haskell
    "pubspec.yaml", "pubspec.lock", "mix.exs", "mix.lock", "rebar.config", "rebar.lock", "package.swift",
    "package.resolved", "podfile", "podfile.lock", "cartfile", "cartfile.resolved", "conanfile.txt", "conanfile.py",
    "conan.lock", "vcpkg.json", "renv.lock", "stack.yaml.lock", "cabal.project.freeze",
}
MANIFEST_SUFFIXES = {".csproj", ".fsproj", ".vbproj", ".nuspec", ".sbt", ".gradle", ".lock", ".lockfile"}


def is_manifest(relative: Path) -> bool:
    name = relative.name.lower()
    return name in MANIFEST_NAMES or relative.suffix.lower() in MANIFEST_SUFFIXES or name.startswith("requirements")


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


def _download_timeout() -> int:
    try:
        return max(60, int(os.environ.get("APPSEC_AGENT_DOWNLOAD_TIMEOUT", "900")))
    except ValueError:
        return 900


def _download_archive(url: str, token: str, provider: str, destination: Path,
                      *, redirect_host: str | None = None, progress=None) -> int:
    """Baja el tarball a disco por trozos. Un repositorio de cientos de MB no cabe en memoria.

    El `timeout` del socket solo corta si no llega nada; una conexión que gotea podría
    tardar horas sin decir nada. Por eso hay un plazo total y se informa de lo descargado."""
    deadline = time.monotonic() + _download_timeout()
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
        written, reported = 0, time.monotonic()
        with response, open(destination, "wb") as handle:
            while True:
                chunk = response.read1(1_048_576)
                if not chunk:
                    break
                written += len(chunk)
                if written > MAX_ARCHIVE:
                    raise SourceError("El archivo del repositorio supera 1 GB comprimido")
                handle.write(chunk)
                now = time.monotonic()
                if now > deadline:
                    raise SourceError(f"La descarga superó {_download_timeout() // 60} min "
                                      f"({written // 1_048_576} MB recibidos); revisa la conexión con {provider.capitalize()}")
                if progress and now - reported >= 10:
                    progress("info", f"Descargando… {written / 1_048_576:.0f} MB recibidos")
                    reported = now
        if progress:
            progress("info", f"Descarga completa ({written / 1_048_576:.1f} MB). Extrayendo archivos analizables…")
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


def _include_workspace(include_workspace: bool | None) -> bool:
    if include_workspace is None:
        return os.environ.get("APPSEC_AGENT_SHOW_WORKSPACE", "").strip() == "1"
    return include_workspace


WORKSPACE_SOURCE = {"id": "local:appsec-agent", "name": "appsec-agent · código propio", "provider": "local",
                    "private": True, "branch": "workspace"}


def available_sources(tokens: dict[str, str] | None = None, installation_id: int | list[int] | None = None, *,
                      include_workspace: bool | None = None) -> dict:
    """Todos los repositorios analizables (CLI). El panel usa `source_page`, que no lista organizaciones enteras.

    El código de la propia herramienta solo aparece en la CLI (desarrollo y dogfooding) o si se pide
    con APPSEC_AGENT_SHOW_WORKSPACE=1: a un usuario del panel no le sirve."""
    tokens = tokens or {}
    sources = [dict(WORKSPACE_SOURCE)] if _include_workspace(include_workspace) else []
    statuses = {}
    installations = [installation_id] if isinstance(installation_id, int) else installation_id or []
    if installations:
        # Cada instalación autoriza únicamente los repositorios elegidos en esa cuenta.
        from .github_app import GitHubAppError, installation_repositories
        errors = []
        seen = set()
        for current in installations:
            try:
                for entry in installation_repositories(current):
                    key = entry.get("uid") or entry["id"]
                    if key not in seen:
                        sources.append({**entry, "installation_id": current, "account": entry["name"].split("/", 1)[0]})
                        seen.add(key)
            except GitHubAppError as exc:
                errors.append(f"Instalación {current}: {exc}")
        statuses["github"] = {"configured": True, "origin": "github_app"}
        if errors:
            statuses["github"]["error"] = " · ".join(errors)
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


def _paged(first: list[dict], fetch, per_page: int, decorate):
    """Filas [offset, offset+limit) de un origen paginado por GitHub: como mucho dos páginas."""
    def rows(offset: int, limit: int) -> list[dict]:
        result = []
        for number in range(offset // per_page + 1, (offset + limit - 1) // per_page + 2):
            chunk = first if number == 1 else fetch(number)
            base = (number - 1) * per_page
            result.extend(chunk[max(0, offset - base):offset + limit - base])
        return decorate(result)
    return rows


def source_page(tokens: dict[str, str] | None = None, installations: list[int] | None = None, *, query: str = "",
                account: str | None = None, provider: str | None = None, page: int = 1, per_page: int = 25,
                include_workspace: bool | None = None) -> dict:
    """Una página de repositorios analizables, con el total y búsqueda por nombre.

    A GitHub solo se le pide la página visible (o su búsqueda): con miles de repositorios la
    respuesta tarda lo mismo que con diez. Las cuentas de la App van en orden y se concatenan.
    """
    tokens = tokens or {}
    needle = query.strip().casefold()
    segments: list[tuple[int, object]] = []
    statuses: dict[str, dict] = {}
    accounts: list[str] = []
    errors: list[str] = []
    partial = False

    def local(rows: list[dict]) -> None:
        rows = [row for row in rows if not needle or needle in row["name"].casefold()]
        segments.append((len(rows), lambda offset, limit: rows[offset:offset + limit]))

    if _include_workspace(include_workspace) and provider in (None, "local") and not account:
        local([dict(WORKSPACE_SOURCE)])
    if installations:
        from .github_app import GitHubAppError, installation_info, repositories_page, search_repositories
        statuses["github"] = {"configured": True, "origin": "github_app"}
        for current in installations:
            try:
                owner = installation_info(current).get("account")
                if isinstance(owner, str):
                    accounts.append(owner)
                if provider not in (None, "github") or (account and account != owner):
                    continue

                def decorate(rows: list[dict], current=current) -> list[dict]:
                    return [{**row, "installation_id": current, "account": row["name"].split("/", 1)[0]} for row in rows]

                if needle:
                    first, total, loading = search_repositories(current, query, 1, per_page)
                    partial = partial or loading
                    fetch = lambda number, current=current: search_repositories(current, query, number, per_page)[0]
                else:
                    first, total = repositories_page(current, 1, per_page)
                    fetch = lambda number, current=current: repositories_page(current, number, per_page)[0]
                segments.append((total, _paged(first, fetch, per_page, decorate)))
            except GitHubAppError as exc:
                errors.append(f"Instalación {current}: {exc}")
    for name, env in (("github", "GITHUB_TOKEN"), ("gitlab", "GITLAB_TOKEN")):
        if name in statuses:
            continue
        origin = "session" if tokens.get(name) else "environment" if os.environ.get(env) else None
        statuses[name] = {"configured": bool(origin), "origin": origin}
        if origin and provider in (None, name) and not account:
            try:
                local(list_repositories(name, tokens.get(name)))
            except SourceError:
                statuses[name]["error"] = "No se pudo listar repositorios; revisa el token y sus permisos"
    # Solo se piden a cada origen las filas que caen en la página pedida.
    total = sum(count for count, _ in segments)
    offset, remaining, sources = (page - 1) * per_page, per_page, []
    for count, rows in segments:
        if remaining <= 0:
            break
        if offset >= count:
            offset -= count
            continue
        take = min(remaining, count - offset)
        try:
            sources.extend(rows(offset, take))
        except Exception as exc:  # GitHubAppError: una página que falla no tumba el resto
            errors.append(str(exc))
        remaining -= take
        offset = 0
    if errors:
        statuses.setdefault("github", {"configured": True, "origin": "github_app"})["error"] = " · ".join(errors)
    return {"sources": sources, "providers": statuses, "total": total, "page": page, "per_page": per_page,
            "partial": partial, "accounts": sorted(set(accounts), key=str.casefold)}


def find_source(tokens: dict[str, str] | None, installations: list[int] | None, source_id: str, *,
                include_workspace: bool | None = None) -> dict | None:
    """Un repositorio concreto, validado contra su credencial sin listar el catálogo entero.

    Acepta el identificador por nombre (`github:owner/repo`) o la identidad estable (`github#123`)."""
    if not isinstance(source_id, str):
        return None
    if source_id == WORKSPACE_SOURCE["id"]:
        return dict(WORKSPACE_SOURCE) if _include_workspace(include_workspace) else None
    if installations and (source_id.startswith("github:") or source_id.startswith("github#")):
        from .github_app import GitHubAppError, installation_info, installation_repository, installation_repository_by_uid
        owner = source_id.removeprefix("github:").split("/", 1)[0].casefold() if source_id.startswith("github:") else None
        for current in installations:
            try:
                account = installation_info(current).get("account")
                if owner and isinstance(account, str) and account.casefold() != owner:
                    continue
                entry = (installation_repository(current, source_id) if owner is not None
                         else installation_repository_by_uid(current, source_id))
            except GitHubAppError:
                continue
            if entry:
                return {**entry, "installation_id": current, "account": entry["name"].split("/", 1)[0]}
        return None
    provider = source_id.partition(":")[0]
    if provider not in ("github", "gitlab"):
        return None
    try:
        return next((item for item in list_repositories(provider, (tokens or {}).get(provider)) if item["id"] == source_id), None)
    except SourceError:
        return None


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
    if name in SOURCE_NAMES or name in SECRET_NAMES or name.startswith(".env") or is_manifest(relative):
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
                # El código de más de 2 MB es casi siempre generado; un manifiesto, no: su límite es otro.
                limit = MAX_MANIFEST if is_manifest(relative) else MAX_FILE
                if member.size > limit:
                    stats["skipped_too_large"] += 1
                    continue
                if count >= MAX_FILES or total + member.size > MAX_TOTAL:
                    stats["skipped_over_budget"] += 1
                    stats["truncated"] = True
                    continue
                source = archive.extractfile(member)
                if source is None:
                    continue
                content = source.read(limit + 1)
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


def snapshot_directory(source: Path, destination: Path) -> dict:
    """Copia de solo lectura de una carpeta local con los mismos filtros que un repositorio remoto.

    Sin enlaces simbólicos (no se sale de la carpeta), sin lo que ignora el análisis y con los
    mismos límites: código hasta 2 MB por archivo, manifiestos y lockfiles hasta 64 MB."""
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
            if not _analyzable(relative) or size > (MAX_MANIFEST if is_manifest(relative) else MAX_FILE):
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
    return {"files": count, "bytes": total, "skipped": skipped, "truncated": truncated}


def snapshot_source(source_id: str, destination: Path, tokens: dict[str, str] | None = None,
                    installation_id: int | None = None, ref: str | None = None, progress=None) -> tuple[Path, dict]:
    """Snapshot de solo lectura. `ref` fija un commit concreto (revisión de un PR); solo GitHub."""
    if ref is not None and (not re.fullmatch(r"[0-9a-f]{40}", ref) or not source_id.startswith("github:")):
        raise SourceError("Commit inválido")
    if source_id == "local:appsec-agent":
        stats = snapshot_directory(WORKSPACE, destination)
        return destination, {"id": source_id, "name": "appsec-agent · código propio", "provider": "local",
                             "files": stats["files"], "snapshot": stats}
    if not re.fullmatch(r"(?:github:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+|gitlab:[0-9]+)", source_id):
        raise SourceError("Repositorio inválido")
    provider = source_id.partition(":")[0]
    if provider == "github" and installation_id is not None:
        from .github_app import GitHubAppError, installation_repository, installation_token
        try:
            selected = installation_repository(installation_id, source_id)
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
        _download_archive(url, token, provider, archive_path, redirect_host="codeload.github.com", progress=progress)
    else:
        identifier = source_id.removeprefix("gitlab:")
        url = f"https://gitlab.com/api/v4/projects/{quote(identifier)}/repository/archive.tar.gz?include_lfs_blobs=false"
        _download_archive(url, token, provider, archive_path, progress=progress)
    try:
        stats = _extract_limited(archive_path, destination)
    finally:
        archive_path.unlink(missing_ok=True)
    selected["files"] = stats["files"]
    selected["snapshot"] = stats
    return destination, selected
