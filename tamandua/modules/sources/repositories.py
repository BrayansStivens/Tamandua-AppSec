"""Authorised code sources: the fixed workspace and repositories listed through the API."""

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
from urllib.request import Request
from tamandua.shared import http, settings
from tamandua.shared.i18n import msg, text
from tamandua.version import USER_AGENT


# These caps are not product policy: they defend against malicious decompression
# and runaway runs. What bounds the real work is the list of what the analysers
# can read, not a byte budget.
MAX_ARCHIVE = 1_000_000_000      # compressed download, streamed to disk
MAX_EXPANSION = 5_000_000_000    # bytes read from the archive before suspecting a bomb
MAX_FILES = 200_000              # brake on runaway runs
MAX_FILE = 2_000_000             # per file: anything bigger is generated code or data
MAX_MANIFEST = 64_000_000        # manifests and lockfiles: recognised by name; a large lockfile is normal
MAX_TOTAL = 2_000_000_000        # accumulated source; should never be reached
IGNORED = {".git", "node_modules", ".venv", "venv", "data", "dist", "build", "__pycache__", ".next",
           "coverage", "htmlcov", "site-packages", "vendor", "bower_components", "target", "out",
           ".angular", ".nuxt", ".svelte-kit", ".turbo", ".gradle", "storybook-static"}
# No code analyser looks at any of this, so it must not spend budget or crowd
# out a source file that does matter.
# An allowlist, not a denylist: a 600 MB repository usually holds a few MB of
# code and the rest is assets nobody is going to analyse.
SOURCE_SUFFIXES = {
    ".py", ".pyi", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue", ".svelte",
    ".java", ".kt", ".kts", ".go", ".rb", ".php", ".cs", ".rs", ".swift", ".scala", ".dart",
    ".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".m", ".mm", ".lua", ".pl", ".pm",
    ".ex", ".exs", ".erl", ".clj", ".groovy", ".sh", ".bash", ".zsh", ".ps1",
    ".sql", ".graphql", ".proto", ".tf", ".tfvars",
    ".erb", ".jinja", ".jinja2", ".j2", ".twig", ".blade", ".hbs", ".ejs", ".pug",
    ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf", ".properties", ".env",
}
# Manifests and extensionless files needed for SCA, secrets and IaC.
SOURCE_NAMES = {
    "dockerfile", "containerfile", "makefile", "rakefile", "gemfile", "procfile",
    "requirements.txt", "pipfile", "poetry.lock", "pyproject.toml", "setup.py", "setup.cfg",
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json",
    "go.mod", "go.sum", "pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle",
    "gemfile.lock", "composer.json", "composer.lock", "cargo.toml", "cargo.lock",
}
# Dependency manifests and lockfiles for each ecosystem. Recognised by name or extension,
# never by size: without them dependency analysis sees nothing.
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


# Build output and bundles: text, but generated, and it drowns the signal.
# Secrets show up in any text, not just code: docs, sample configuration and notes are
# among the most common places. SAST ignores these files but Gitleaks reads them, and
# leaving them out caused false negatives.
TEXT_SUFFIXES = {
    ".md", ".markdown", ".mdx", ".txt", ".rst", ".adoc", ".html", ".htm", ".xml", ".csv", ".tsv", ".ipynb",
    ".log", ".pem", ".key", ".crt", ".cer", ".pub", ".asc", ".tpl", ".template", ".example", ".sample", ".dist",
    ".plist", ".xcconfig", ".http", ".rest", ".postman_collection", ".har", ".cnf", ".config",
}
SECRET_NAMES = {".npmrc", ".pypirc", ".netrc", ".dockercfg", ".git-credentials", ".htpasswd", "id_rsa", "id_dsa",
                "id_ecdsa", "id_ed25519", "credentials", "authorized_keys", "known_hosts", ".s3cfg", ".boto"}
SKIP_NAME_PARTS = (".min.js", ".min.css", ".bundle.js", "-bundle.js", ".chunk.js", ".d.ts")
# Dot-prefixed entries are dropped except CI/CD pipelines (Checkov, zizmor). Credential files
# (.env, .npmrc…) stay out of the snapshot on purpose.
DOT_FOLDERS = {".github", ".gitlab", ".circleci", ".buildkite", ".tekton", ".devcontainer"}
DOT_FILES = {".gitlab-ci.yml", ".gitlab-ci.yaml", ".pre-commit-config.yaml", ".pre-commit-hooks.yaml"}


class SourceError(ValueError):
    """`message` is what people read (rendered per reader); str() stays English, for logs."""

    def __init__(self, message):
        super().__init__(text(message, "en"))
        self.message = message


def _joined(problems: list) -> dict | str:
    """Several problems in one line; each keeps its own message."""
    if not problems:
        return ""
    result = problems[0]
    for item in problems[1:]:
        result = msg("sources.errors.joined", first=result, second=item)
    return result


def _request(url: str, token: str, provider: str, *, redirect_host: str | None = None) -> bytes:
    headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
    if provider == "github":
        headers["Authorization"] = f"Bearer {token}"
        headers["X-GitHub-Api-Version"] = "2022-11-28"
    else:
        headers["PRIVATE-TOKEN"] = token
    opener = http.opener()
    try:
        try:
            response = opener.open(Request(url, headers=headers), timeout=12)
        except HTTPError as exc:
            if exc.code != 302 or not redirect_host:
                raise
            target = exc.headers.get("Location", "")
            parsed = urlsplit(target)
            if parsed.scheme != "https" or parsed.hostname != redirect_host or parsed.username or parsed.password:
                raise SourceError(msg("sources.errors.redirect_not_allowed")) from None
            # The temporary URL is fetched without the original credential.
            response = opener.open(Request(target, headers={"User-Agent": USER_AGENT}), timeout=20)
        with response:
            body = response.read(MAX_ARCHIVE + 1)
            if len(body) > MAX_ARCHIVE:
                raise SourceError(msg("sources.errors.over_download_limit"))
            return body
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise SourceError(msg("sources.errors.provider_unreachable")) from exc


def _download_timeout() -> int:
    try:
        return settings.integer("TAMANDUA_DOWNLOAD_TIMEOUT")
    except ValueError:
        return 900


def _download_archive(url: str, token: str, provider: str, destination: Path,
                      *, redirect_host: str | None = None, progress=None) -> int:
    """Downloads the tarball to disk in chunks. A repository of hundreds of MB does not fit in memory.

    The socket `timeout` only fires when nothing arrives; a trickling connection could take
    hours without a word. Hence an overall deadline, and progress reports on what was downloaded."""
    deadline = time.monotonic() + _download_timeout()
    headers = {"Accept": "application/vnd.github+json", "User-Agent": USER_AGENT}
    if provider == "github":
        headers["Authorization"] = f"Bearer {token}"
        headers["X-GitHub-Api-Version"] = "2022-11-28"
    else:
        headers["PRIVATE-TOKEN"] = token
    opener = http.opener()
    try:
        try:
            response = opener.open(Request(url, headers=headers), timeout=30)
        except HTTPError as exc:
            if exc.code != 302 or not redirect_host:
                raise
            target = exc.headers.get("Location", "")
            parsed = urlsplit(target)
            if parsed.scheme != "https" or parsed.hostname != redirect_host or parsed.username or parsed.password:
                raise SourceError(msg("sources.errors.redirect_not_allowed")) from None
            # The temporary URL is fetched without the original credential.
            response = opener.open(Request(target, headers={"User-Agent": USER_AGENT}), timeout=180)
        written, reported = 0, time.monotonic()
        with response, open(destination, "wb") as handle:
            while True:
                chunk = response.read1(1_048_576)
                if not chunk:
                    break
                written += len(chunk)
                if written > MAX_ARCHIVE:
                    raise SourceError(msg("sources.errors.archive_too_big"))
                handle.write(chunk)
                now = time.monotonic()
                if now > deadline:
                    raise SourceError(msg("sources.errors.download_timeout", minutes=_download_timeout() // 60,
                                          mb=written // 1_048_576, provider=provider.capitalize()))
                if progress and now - reported >= 10:
                    progress("info", msg("sources.progress.downloading", mb=f"{written / 1_048_576:.0f}"))
                    reported = now
        if progress:
            progress("info", msg("sources.progress.downloaded", mb=f"{written / 1_048_576:.1f}"))
        return written
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise SourceError(msg("sources.errors.download_failed")) from exc


def list_repositories(provider: str, token: str | None = None) -> list[dict]:
    if provider not in ("github", "gitlab"):
        raise SourceError(msg("sources.errors.invalid_provider"))
    token = token or settings.text("GITHUB_TOKEN" if provider == "github" else "GITLAB_TOKEN")
    if not token:
        return []
    url = ("https://api.github.com/user/repos?per_page=50&sort=updated"
           if provider == "github" else
           "https://gitlab.com/api/v4/projects?membership=true&per_page=50&order_by=last_activity_at")
    try:
        rows = json.loads(_request(url, token, provider))
    except (ValueError, UnicodeDecodeError) as exc:
        raise SourceError(msg("sources.errors.invalid_data")) from exc
    if not isinstance(rows, list):
        raise SourceError(msg("sources.errors.invalid_list"))
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


def available_sources(tokens: dict[str, str] | None = None, installation_id: int | list[int] | None = None) -> dict:
    """Every analysable repository (CLI). The panel uses `source_page`, which does not list whole organisations."""
    tokens = tokens or {}
    sources = []
    statuses = {}
    installations = [installation_id] if isinstance(installation_id, int) else installation_id or []
    if installations:
        # Each installation authorises only the repositories chosen in that account.
        from tamandua.modules.integrations.github import GitHubAppError, installation_repositories
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
                errors.append(msg("sources.errors.installation", id=current, detail=exc.message))
        statuses["github"] = {"configured": True, "origin": "github_app"}
        if errors:
            statuses["github"]["error"] = _joined(errors)
    for provider, env in (("github", "GITHUB_TOKEN"), ("gitlab", "GITLAB_TOKEN")):
        if provider in statuses:
            continue
        origin = "session" if tokens.get(provider) else "environment" if settings.is_set(env) else None
        statuses[provider] = {"configured": bool(origin), "origin": origin}
        if statuses[provider]["configured"]:
            try:
                sources.extend(list_repositories(provider, tokens.get(provider)))
            except SourceError:
                statuses[provider]["error"] = msg("sources.errors.list_failed")
    return {"sources": sources, "providers": statuses}


def _paged(first: list[dict], fetch, per_page: int, decorate):
    """Rows [offset, offset+limit) of a source paginated by GitHub: two pages at most."""
    def rows(offset: int, limit: int) -> list[dict]:
        result = []
        for number in range(offset // per_page + 1, (offset + limit - 1) // per_page + 2):
            chunk = first if number == 1 else fetch(number)
            base = (number - 1) * per_page
            result.extend(chunk[max(0, offset - base):offset + limit - base])
        return decorate(result)
    return rows


def source_page(tokens: dict[str, str] | None = None, installations: list[int] | None = None, *, query: str = "",
                account: str | None = None, provider: str | None = None, page: int = 1, per_page: int = 25) -> dict:
    """One page of analysable repositories, with the total and search by name.

    GitHub is asked only for the visible page (or its search): with thousands of repositories the
    response takes as long as with ten. The App's accounts go in order, concatenated.
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

    if installations:
        from tamandua.modules.integrations.github import GitHubAppError, installation_info, repositories_page, search_repositories
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
                errors.append(msg("sources.errors.installation", id=current, detail=exc.message))
    for name, env in (("github", "GITHUB_TOKEN"), ("gitlab", "GITLAB_TOKEN")):
        if name in statuses:
            continue
        origin = "session" if tokens.get(name) else "environment" if settings.is_set(env) else None
        statuses[name] = {"configured": bool(origin), "origin": origin}
        if origin and provider in (None, name) and not account:
            try:
                local(list_repositories(name, tokens.get(name)))
            except SourceError:
                statuses[name]["error"] = msg("sources.errors.list_failed")
    # Each source is asked only for the rows that fall on the requested page.
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
        except Exception as exc:  # GitHubAppError: one failing page doesn't take down the rest
            errors.append(getattr(exc, "message", None) or str(exc))
        remaining -= take
        offset = 0
    if errors:
        statuses.setdefault("github", {"configured": True, "origin": "github_app"})["error"] = _joined(errors)
    return {"sources": sources, "providers": statuses, "total": total, "page": page, "per_page": per_page,
            "partial": partial, "accounts": sorted(set(accounts), key=str.casefold)}


def find_source(tokens: dict[str, str] | None, installations: list[int] | None, source_id: str) -> dict | None:
    """One specific repository, validated against its credential without listing the whole catalogue.

    Accepts the name-based identifier (`github:owner/repo`) or the stable identity (`github#123`)."""
    if not isinstance(source_id, str):
        return None
    if installations and (source_id.startswith("github:") or source_id.startswith("github#")):
        from tamandua.modules.integrations.github import GitHubAppError, installation_info, installation_repository, installation_repository_by_uid
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
    """CI/CD folders and, as the last path segment, their files; with `secrets`, credential files too."""
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
    """Copies what fits and returns counts of what was left out.

    Exceeding the limits is not an error: a large repository is partly analysed
    and the run states exactly what was not looked at. Failing would leave the
    user with nothing, and silently analysing 10 % would be worse still.
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
                # Defence against malicious decompression: a small tarball can declare
                # terabytes. The declared size is checked before reading anything.
                expanded += member.size
                if expanded > MAX_EXPANSION:
                    raise SourceError(msg("sources.errors.decompression_bomb"))
                relative = _safe_name(member.name)
                if relative is None:
                    continue
                if not _analyzable(relative):
                    stats["skipped_not_analyzable"] += 1
                    continue
                # Code over 2 MB is almost always generated; a manifest isn't, so it has its own limit.
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
                    raise SourceError(msg("sources.errors.invalid_archive_file"))
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
                total += len(content)
                count += 1
    except (tarfile.TarError, OSError) as exc:
        raise SourceError(msg("sources.errors.invalid_archive")) from exc
    stats["files"] = count
    stats["bytes"] = total
    stats["archive_bytes"] = expanded
    return stats


def snapshot_directory(source: Path, destination: Path) -> dict:
    """Read-only copy of a local folder with the same filters as a remote repository.

    No symlinks (nothing escapes the folder), nothing the analysis ignores, and the same
    limits: code up to 2 MB per file, manifests and lockfiles up to 64 MB."""
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
    """Read-only snapshot. `ref` pins a specific commit (PR review); GitHub only."""
    if ref is not None and (not re.fullmatch(r"[0-9a-f]{40}", ref) or not source_id.startswith("github:")):
        raise SourceError(msg("sources.errors.invalid_commit"))
    if not re.fullmatch(r"(?:github:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+|gitlab:[0-9]+)", source_id):
        raise SourceError(msg("sources.errors.invalid_repository"))
    provider = source_id.partition(":")[0]
    if provider == "github" and installation_id is not None:
        from tamandua.modules.integrations.github import GitHubAppError, installation_repository, installation_token
        try:
            selected = installation_repository(installation_id, source_id)
            token = installation_token(installation_id)
        except GitHubAppError as exc:
            raise SourceError(exc.message) from exc
    else:
        token = (tokens or {}).get(provider) or settings.text("GITHUB_TOKEN" if provider == "github" else "GITLAB_TOKEN")
        entries = list_repositories(provider, token)
        selected = next((entry for entry in entries if entry["id"] == source_id), None)
    if selected is None:
        raise SourceError(msg("sources.errors.not_available"))
    if not token:
        raise SourceError(msg("sources.errors.connect_first"))
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
