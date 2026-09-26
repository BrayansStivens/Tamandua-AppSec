"""Inventario de arquitectura de un snapshot: qué usa el código, no qué versión.

Alimenta la propuesta del modelo de amenazas. Solo se guardan **nombres**:
dependencias directas por ecosistema (no transitivas, que no dicen nada de la
arquitectura) e imágenes de servicios de docker-compose. No se lee ningún valor
de configuración ni de ``.env``.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

# Fixtures y tests declaran dependencias de ejemplo que no son la arquitectura del producto.
SKIP = {"node_modules", ".git", ".venv", "venv", "vendor", "dist", "build", "__pycache__", ".next", "fixtures", "test", "tests"}
MAX_NAMES = 600


def _walk(root: Path, pattern: str):
    for path in root.rglob(pattern):
        relative = path.relative_to(root)
        if path.is_file() and not path.is_symlink() and not SKIP.intersection(relative.parts) and len(relative.parts) <= 6:
            yield path


def _npm(path: Path) -> set[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError):
        return set()
    names = set()
    for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        section = data.get(key) if isinstance(data, dict) else None
        if isinstance(section, dict):
            names.update(name for name in section if isinstance(name, str) and len(name) <= 214)
    return names


def _python(path: Path) -> set[str]:
    names = set()
    try:
        if path.name == "pyproject.toml":
            data = tomllib.loads(path.read_text(encoding="utf-8"))
            items = list((data.get("project") or {}).get("dependencies") or [])
            poetry = ((data.get("tool") or {}).get("poetry") or {}).get("dependencies") or {}
            items += [name for name in poetry if name != "python"]
        else:
            items = path.read_text(encoding="utf-8").splitlines()
    except (OSError, ValueError, UnicodeError, tomllib.TOMLDecodeError):
        return names
    for line in items:
        match = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9_.\-]{0,99})", str(line))
        if match and not str(line).lstrip().startswith(("#", "-")):
            names.add(match[1].lower().replace("_", "-"))
    return names


def _go(path: Path) -> set[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return set()
    return set(re.findall(r"^\s*(?:require\s+)?([a-z0-9.\-]+\.[a-z]{2,}/[^\s]+)\s+v\d", text, re.MULTILINE))


def _cargo(path: Path) -> set[str]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError):
        return set()
    names = set()
    for section in (data.get("dependencies"), data.get("dev-dependencies"), (data.get("workspace") or {}).get("dependencies")):
        if isinstance(section, dict):
            names.update(name.lower() for name in section if isinstance(name, str) and len(name) <= 100)
    return names


def _compose(path: Path) -> set[str]:
    """Imágenes declaradas en compose: `postgres:16` → `postgres`. Sin parsear YAML completo."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return set()
    images = set()
    for image in re.findall(r"^\s*image:\s*['\"]?([^\s'\"#]+)", text, re.MULTILINE):
        name = image.split("@", 1)[0].rsplit("/", 1)[-1].split(":", 1)[0].lower()
        if re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", name):
            images.add(name)
    return images


def collect(root: Path) -> dict:
    """Además de los nombres, dónde se vio cada uno: la propuesta cita su origen para poder comprobarla."""
    packages: dict[str, set[str]] = {"npm": set(), "pypi": set(), "go": set(), "cargo": set()}
    found_in: dict[str, str] = {}
    manifests: list[str] = []

    def add(ecosystem: str, names: set[str], path: Path) -> None:
        relative = str(path.relative_to(root))
        manifests.append(relative)
        packages[ecosystem] |= names
        for name in names:
            found_in.setdefault(name, relative)

    for path in _walk(root, "package.json"):
        add("npm", _npm(path), path)
    for pattern in ("requirements*.txt", "pyproject.toml"):
        for path in _walk(root, pattern):
            add("pypi", _python(path), path)
    for path in _walk(root, "go.mod"):
        add("go", _go(path), path)
    for path in _walk(root, "Cargo.toml"):
        add("cargo", _cargo(path), path)
    services: set[str] = set()
    for pattern in ("docker-compose*.yml", "docker-compose*.yaml", "compose.yml", "compose.yaml"):
        for path in _walk(root, pattern):
            found = _compose(path)
            services |= found
            manifests.append(str(path.relative_to(root)))
            for name in found:
                found_in.setdefault(f"image:{name}", str(path.relative_to(root)))
    names = {name for values in packages.values() for name in values} | {f"image:{name}" for name in services}
    return {"packages": {ecosystem: sorted(values)[:MAX_NAMES] for ecosystem, values in packages.items() if values},
            "services": sorted(services)[:100],
            "dockerfile": any(True for _ in _walk(root, "Dockerfile")),
            "manifests": sorted(set(manifests))[:100],
            "found_in": {name: path for name, path in sorted(found_in.items()) if name in names}}


def live(source_id: str, *, installation_id: int | None) -> dict | None:
    """Inventario leído en el momento, sin escanear: de GitHub solo los manifiestos; del workspace, en disco."""
    import tempfile
    from tamandua.modules.sources.repositories import WORKSPACE
    if source_id == "local:appsec-agent":
        return collect(WORKSPACE)
    if not source_id.startswith("github:") or installation_id is None:
        return None
    from tamandua.modules.integrations.github import installation_repository, repository_manifests
    repository = source_id.removeprefix("github:")
    entry = installation_repository(installation_id, source_id)
    if entry is None:
        return None
    files = repository_manifests(installation_id, repository, entry.get("branch") or "main")
    with tempfile.TemporaryDirectory(prefix="inventory-") as directory:
        root = Path(directory).resolve()
        for relative, content in files:
            target = (root / relative).resolve()
            if root not in target.parents:
                continue  # ruta que intenta salir del directorio: se ignora
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        return collect(root)
