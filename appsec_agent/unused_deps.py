"""Dependencias declaradas que el código no usa. Informativo: nunca bloquea.

Una dependencia sin usar sigue entrando en el build y en el análisis de
vulnerabilidades: amplía la superficie sin aportar nada. Se revisan solo las
dependencias de ejecución (``dependencies`` de npm, las del proyecto en Python),
no las de desarrollo, que suelen ser herramientas que no se importan.

Para no dar falsos positivos, una dependencia cuenta como usada si se importa en
el código **o** si su nombre aparece en configuración, scripts, Dockerfile o
Procfile (plugins de PostCSS, `gunicorn` en el CMD, apps de Django…). Aun así es
una heurística y se presenta como tal.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

SKIP = {"node_modules", ".git", ".venv", "venv", "vendor", "dist", "build", ".next", "__pycache__", "coverage"}
JS_SUFFIXES = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue", ".svelte", ".astro", ".css", ".scss"}
PY_SUFFIXES = {".py", ".pyi"}
CONFIG_HINTS = re.compile(r"(\.config\.|^\.?babelrc|^tsconfig|^jsconfig|^dockerfile|^procfile|^makefile|\.ya?ml$|\.toml$|\.ini$|\.cfg$|\.json$|\.sh$|\.env)", re.I)
JS_IMPORT = re.compile(r"""(?:\bfrom\s+|\bimport\s*\(\s*|\brequire\s*\(\s*|\bimport\s+|@import\s+(?:url\()?)['"]([^'"\s]+)['"]""")
PY_IMPORT = re.compile(r"^\s*(?:from\s+([A-Za-z_][\w]*)|import\s+([A-Za-z_][\w]*))", re.M)
# Nombre de distribución → módulo que se importa, donde no coinciden.
PY_MODULES = {"python-dotenv": "dotenv", "pillow": "PIL", "beautifulsoup4": "bs4", "pyyaml": "yaml", "scikit-learn": "sklearn",
              "opencv-python": "cv2", "psycopg2-binary": "psycopg2", "psycopg-binary": "psycopg", "pyjwt": "jwt",
              "python-jose": "jose", "python-multipart": "multipart", "google-cloud-storage": "google", "protobuf": "google",
              "attrs": "attr", "email-validator": "email_validator", "typing-extensions": "typing_extensions",
              "pymysql": "pymysql", "mysqlclient": "MySQLdb", "discord.py": "discord", "msgpack-python": "msgpack"}
# Se usan sin importarse: los carga el framework o una herramienta.
IMPLICIT = {"npm": {"react-dom", "sharp", "typescript", "tailwindcss", "postcss", "autoprefixer", "@types/node", "tslib",
                    "core-js", "regenerator-runtime", "server-only", "client-only"},
            "pypi": {"uvicorn", "gunicorn", "psycopg2", "psycopg2-binary", "psycopg", "psycopg-binary", "asyncpg", "pymysql",
                     "mysqlclient", "python-multipart", "email-validator", "setuptools", "wheel", "pip", "alembic", "celery"}}
MAX_FILE = 400_000


def _files(root: Path):
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if path.is_file() and not path.is_symlink() and not SKIP.intersection(relative.parts):
            yield path, relative


def _read(path: Path) -> str:
    try:
        if path.stat().st_size > MAX_FILE:
            return ""
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _package(spec: str) -> str | None:
    if spec.startswith((".", "/", "~", "#", "http:", "https:", "data:", "node:")):
        return None
    parts = spec.split("/")
    return "/".join(parts[:2]) if spec.startswith("@") and len(parts) > 1 else parts[0]


def _npm_manifests(root: Path) -> list[tuple[Path, dict[str, int]]]:
    result = []
    for path, relative in _files(root):
        if path.name != "package.json":
            continue
        text = _read(path)
        try:
            data = json.loads(text)
        except ValueError:
            continue
        section = data.get("dependencies") if isinstance(data, dict) else None
        if not isinstance(section, dict) or not section:
            continue
        lines = {name: next((number for number, line in enumerate(text.splitlines(), 1) if f'"{name}"' in line), 1) for name in section}
        result.append((path, lines))
    return result


def _python_manifests(root: Path) -> list[tuple[Path, dict[str, int]]]:
    result = []
    for path, relative in _files(root):
        name = path.name
        if name == "pyproject.toml":
            text = _read(path)
            try:
                data = tomllib.loads(text)
            except tomllib.TOMLDecodeError:
                continue
            items = list((data.get("project") or {}).get("dependencies") or [])
            items += [key for key in (((data.get("tool") or {}).get("poetry") or {}).get("dependencies") or {}) if key != "python"]
        elif re.fullmatch(r"requirements(?!-dev|-test|_dev|_test)[\w.-]*\.txt", name):
            text = _read(path)
            items = text.splitlines()
        else:
            continue
        lines = {}
        for item in items:
            match = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9_.\-]*)", str(item))
            if match and not str(item).lstrip().startswith(("#", "-")):
                dist = match[1].lower().replace("_", "-")
                lines[dist] = next((number for number, line in enumerate(text.splitlines(), 1) if match[1] in line), 1)
        if lines:
            result.append((path, lines))
    return result


def analyze(root: Path) -> dict:
    """Dependencias de ejecución sin uso encontrado, por manifiesto."""
    root = root.resolve()
    js_used, py_used, mentions = set(), set(), []
    for path, relative in _files(root):
        suffix = path.suffix.lower()
        if suffix in JS_SUFFIXES:
            js_used.update(filter(None, (_package(spec) for spec in JS_IMPORT.findall(_read(path)))))
        elif suffix in PY_SUFFIXES:
            text = _read(path)
            py_used.update(item for pair in PY_IMPORT.findall(text) for item in pair if item)
            mentions.append(text)
        if CONFIG_HINTS.search(path.name) and path.name not in ("package.json", "package-lock.json") and not path.name.startswith("requirements"):
            mentions.append(_read(path))
    # Los scripts de package.json nombran binarios: `next dev`, `prisma migrate`.
    for path, _ in _npm_manifests(root):
        try:
            mentions.append(" ".join((json.loads(_read(path)).get("scripts") or {}).values()))
        except (ValueError, AttributeError):
            pass
    corpus = "\n".join(mentions)
    unused = []
    for path, declared in _npm_manifests(root):
        for name, line in declared.items():
            if name in js_used or name in IMPLICIT["npm"] or name.startswith("@types/"):
                continue
            if re.search(rf"(?<![\w@/-]){re.escape(name)}(?![\w-])", corpus):
                continue
            unused.append({"name": name, "ecosystem": "npm", "manifest": str(path.relative_to(root)), "line": line})
    for path, declared in _python_manifests(root):
        for dist, line in declared.items():
            module = PY_MODULES.get(dist, dist.replace("-", "_").removeprefix("python_"))
            if dist in IMPLICIT["pypi"] or module in py_used or module.lower() in {item.lower() for item in py_used}:
                continue
            if re.search(rf"\b{re.escape(module)}\b|\b{re.escape(dist)}\b", corpus):
                continue
            unused.append({"name": dist, "ecosystem": "pypi", "manifest": str(path.relative_to(root)), "line": line})
    ecosystems = sorted({item["ecosystem"] for item in unused} | ({"npm"} if _npm_manifests(root) else set())
                        | ({"pypi"} if _python_manifests(root) else set()))
    return {"ecosystems": ecosystems, "unused": sorted(unused, key=lambda item: (item["manifest"], item["name"]))}


def split_by_pr(unused: list[dict], changed: dict[str, set[int] | None]) -> tuple[list[dict], list[dict]]:
    """Las que añade el PR (su línea del manifiesto está en el diff) y las que ya estaban."""
    new, before = [], []
    for item in unused:
        lines = changed.get(item["manifest"], set())
        (new if lines is None or item["line"] in (lines or set()) else before).append(item)
    return new, before
