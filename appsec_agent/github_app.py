"""GitHub App propia de cada instalación: la creas en GitHub y la conectas aquí.

Tamandua es autoalojado: cada persona o equipo crea **su** GitHub App ("Any account"
si necesita varias organizaciones) siguiendo la guía del panel y pega aquí dos datos: el App ID
y la clave privada (.pem). El panel las verifica contra GitHub antes de guardarlas y
de ahí saca el nombre, la cuenta y los permisos; no hace falta client secret, OAuth
ni ningún token personal.

- **Clave privada de la App**: se guarda cifrada en el almacén (`vault`), nunca en
  claro ni en `data/`. El entorno (`GITHUB_APP_ID` + `GITHUB_APP_PRIVATE_KEY_FILE`)
  manda sobre el almacén para quien prefiera montarla como secreto.
- **Token de instalación** (1 h). Es el que lee código. Se acuña en memoria firmando
  un JWT con la clave privada; de la instalación solo se guarda su identificador,
  que además se comprueba contra GitHub antes de aceptarlo.
"""

from __future__ import annotations

import base64
import json
import os
import re
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, Request, build_opener

API = "https://api.github.com"
WEB = "https://github.com"
# Las credenciales de la App son nuestras y tienen que sobrevivir al reinicio.
# Viven fuera del repositorio, con permisos restringidos; al contenerizar se
# montan como secreto y el entorno tiene prioridad sobre este almacén.
CONFIG_DIR = Path(os.environ.get("APPSEC_AGENT_CONFIG_DIR") or Path.home() / ".config" / "appsec-agent")
# El JWT de la App admite como máximo 10 minutos; damos margen por desfase de reloj.
JWT_TTL = 540
CLOCK_SKEW = 30
# Se renueva antes de caducar para que un escaneo largo no se quede sin token a medias.
TOKEN_MARGIN = 300


class GitHubAppError(RuntimeError):
    pass


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


VAULT_NAME = "github_app"


def _stored() -> dict:
    """Credenciales guardadas al crear la App desde el panel. Ausencia no es error."""
    from .vault import VaultError, get
    try:
        data = get(VAULT_NAME)
    except VaultError:
        return {}
    return data if isinstance(data, dict) else {}


def _resolved() -> dict:
    """El entorno manda sobre el almacén, para que un despliegue monte sus secretos."""
    stored = _stored()
    key_file = os.environ.get("GITHUB_APP_PRIVATE_KEY_FILE", "").strip()
    from_env = bool(os.environ.get("GITHUB_APP_ID", "").strip())
    return {"app_id": os.environ.get("GITHUB_APP_ID", "").strip() or str(stored.get("app_id") or ""),
            "slug": os.environ.get("GITHUB_APP_SLUG", "").strip() or str(stored.get("slug") or ""),
            "key_file": key_file, "pem": "" if key_file else str(stored.get("pem") or ""),
            "owner": stored.get("owner"), "name": stored.get("name"), "html_url": stored.get("html_url"),
            "source": "entorno" if from_env else "almacén cifrado" if stored else None}


def config() -> dict:
    """Qué falta para poder conectar. Ningún secreto sale de aquí."""
    values = _resolved()
    missing = []
    if not values["app_id"]:
        missing.append("App ID")
    if values["key_file"] and not os.path.isfile(values["key_file"]):
        missing.append("GITHUB_APP_PRIVATE_KEY_FILE (la ruta no existe)")
    elif not values["key_file"] and not values["pem"]:
        missing.append("clave privada")
    if not values["slug"]:
        missing.append("GITHUB_APP_SLUG")
    return {"configured": not missing, "missing": missing, "slug": values["slug"], "app_id": values["app_id"],
            "owner": values["owner"], "name": values["name"], "html_url": values["html_url"], "source": values["source"]}


def _settings() -> dict:
    if not config()["configured"]:
        raise GitHubAppError("La GitHub App no está configurada en el servidor")
    return _resolved()


OWNER = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?")


APP_ID = re.compile(r"[1-9][0-9]{0,11}")
PEM_MAX = 16_000


def _load_key(material: bytes):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    try:
        key = serialization.load_pem_private_key(material, password=None)
    except (ValueError, TypeError) as exc:
        raise GitHubAppError("La clave privada no es un .pem válido de GitHub App") from exc
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
        raise GitHubAppError("La clave privada debe ser RSA de al menos 2048 bits (la que genera GitHub)")
    return key


def _jwt(app_id: str, key) -> str:
    """JWT RS256 firmado con la clave privada de la App (autenticación como App)."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    now = int(time.time())
    encode = lambda data: base64.urlsafe_b64encode(json.dumps(data, separators=(",", ":")).encode()).rstrip(b"=")
    signing_input = encode({"alg": "RS256", "typ": "JWT"}) + b"." + encode(
        {"iat": now - CLOCK_SKEW, "exp": now + JWT_TTL, "iss": str(app_id)})
    signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return (signing_input + b"." + base64.urlsafe_b64encode(signature).rstrip(b"=")).decode()


def verify_app(app_id, private_key) -> dict:
    """Comprueba contra GitHub que el App ID y la clave casan, y devuelve lo que GitHub dice de la App.

    Nada se guarda si falla. La clave solo viaja del navegador a este servidor; a GitHub
    solo va un JWT firmado con ella, nunca la clave.
    """
    app_id = str(app_id or "").strip()
    if not APP_ID.fullmatch(app_id):
        raise GitHubAppError("El App ID es un número: lo ves arriba en la página de tu GitHub App")
    if not isinstance(private_key, str) or not private_key.strip() or len(private_key) > PEM_MAX:
        raise GitHubAppError("Falta la clave privada (.pem)")
    pem = private_key.strip() + "\n"
    key = _load_key(pem.encode())
    try:
        app = _get(f"{API}/app", _jwt(app_id, key), jwt=True)
    except GitHubAppError as exc:
        raise GitHubAppError("GitHub no reconoce ese App ID con esa clave privada: revisa que la clave sea de esta App") from exc
    if not isinstance(app, dict) or str(app.get("id")) != app_id or not re.fullmatch(r"[a-z0-9-]{1,100}", str(app.get("slug") or "")):
        raise GitHubAppError("GitHub devolvió una App inesperada")
    return {"app_id": app_id, "pem": pem, "slug": app["slug"], "name": app.get("name"),
            "owner": (app.get("owner") or {}).get("login"), "owner_type": (app.get("owner") or {}).get("type"),
            "html_url": app.get("html_url"), "permissions": app.get("permissions") or {}, "events": app.get("events") or []}


def save_credentials(credentials: dict) -> None:
    """Guarda la App verificada, cifrada; la clave privada nunca toca el disco en claro."""
    from .vault import put
    put(VAULT_NAME, {key: credentials.get(key) for key in ("app_id", "pem", "slug", "name", "owner", "html_url")})
    _tokens.clear()


def forget_app() -> bool:
    """Olvida la App en este servidor. En GitHub sigue existiendo: se borra allí."""
    from .vault import delete
    _tokens.clear()
    return delete(VAULT_NAME)


def install_url() -> str:
    """Pantalla de GitHub donde eliges la cuenta y los repositorios concretos que se analizan."""
    settings = _settings()
    if not re.fullmatch(r"[a-z0-9-]{1,100}", settings["slug"]):
        raise GitHubAppError("GITHUB_APP_SLUG inválido")
    return f"{WEB}/apps/{settings['slug']}/installations/new"


def _get(url: str, token: str, *, jwt: bool = False, forbidden: str | None = None) -> dict | list:
    request = Request(url, headers={
        "Accept": "application/vnd.github+json", "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "AppSecAgent/0.4"})
    try:
        with build_opener(_NoRedirect).open(request, timeout=15) as response:
            return json.loads(response.read(2_000_000))
    except HTTPError as exc:
        if forbidden and exc.code in (403, 404):
            raise GitHubAppError(forbidden) from exc
        kind = "la App" if jwt else "el token"
        raise GitHubAppError(f"GitHub rechazó {kind} (HTTP {exc.code})") from exc
    except (URLError, TimeoutError, OSError, ValueError, UnicodeDecodeError) as exc:
        raise GitHubAppError("No se pudo contactar con GitHub") from exc


def _app_jwt() -> str:
    settings = _settings()
    try:
        if settings["key_file"]:
            with open(settings["key_file"], "rb") as handle:
                material = handle.read()
        else:
            material = settings["pem"].encode()
    except OSError as exc:
        raise GitHubAppError("No se pudo leer la clave privada de la GitHub App") from exc
    return _jwt(settings["app_id"], _load_key(material))


def app_installations() -> list[dict]:
    """Todas las cuentas donde está instalada la App, incluidas páginas adicionales."""
    token = _app_jwt()
    result = []
    for page in range(1, 101):
        rows = _get(f"{API}/app/installations?per_page=100&page={page}", token, jwt=True)
        if not isinstance(rows, list):
            raise GitHubAppError("GitHub devolvió una lista de instalaciones inválida")
        result.extend({"installation_id": item["id"], "account": (item.get("account") or {}).get("login"),
                       "account_type": (item.get("account") or {}).get("type"),
                       "repository_selection": item.get("repository_selection")}
                      for item in rows if isinstance(item, dict) and isinstance(item.get("id"), int))
        if len(rows) < 100:
            return result
    raise GitHubAppError("La App tiene más instalaciones de las que se pueden listar")


_tokens: dict[int, tuple[str, float]] = {}


def installation_token(installation_id: int) -> str:
    """Token de instalación de 1 h, cacheado en memoria y renovado antes de caducar."""
    if not isinstance(installation_id, int) or not 0 < installation_id < 2**63:
        raise GitHubAppError("Identificador de instalación inválido")
    cached = _tokens.get(installation_id)
    if cached and cached[1] - TOKEN_MARGIN > time.time():
        return cached[0]
    request = Request(f"{API}/app/installations/{installation_id}/access_tokens", data=b"", method="POST", headers={
        "Accept": "application/vnd.github+json", "Authorization": f"Bearer {_app_jwt()}",
        "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "AppSecAgent/0.4"})
    try:
        with build_opener(_NoRedirect).open(request, timeout=15) as response:
            payload = json.loads(response.read(200_000))
    except HTTPError as exc:
        if exc.code in (401, 404):
            _tokens.pop(installation_id, None)
            raise GitHubAppError("La instalación ya no es válida; vuelve a conectar GitHub") from exc
        raise GitHubAppError(f"GitHub no emitió el token de instalación (HTTP {exc.code})") from exc
    except (URLError, TimeoutError, OSError, ValueError, UnicodeDecodeError) as exc:
        raise GitHubAppError("No se pudo contactar con GitHub") from exc
    token = payload.get("token") if isinstance(payload, dict) else None
    if not isinstance(token, str) or not token:
        raise GitHubAppError("GitHub no emitió el token de instalación")
    expires = time.time() + 3600
    if isinstance(payload.get("expires_at"), str):
        try:
            from datetime import datetime
            expires = datetime.fromisoformat(payload["expires_at"]).timestamp()
        except ValueError:
            pass
    _tokens[installation_id] = (token, expires)
    return token


def forget(installation_id: int | None = None) -> None:
    _tokens.clear() if installation_id is None else _tokens.pop(installation_id, None)


def installation_details(installation_id: int) -> dict:
    """Cuenta y alcance de la instalación, para mostrar qué se concedió."""
    payload = _get(f"{API}/app/installations/{installation_id}", _app_jwt(), jwt=True)
    if not isinstance(payload, dict):
        raise GitHubAppError("GitHub devolvió una instalación inválida")
    account = payload.get("account") if isinstance(payload.get("account"), dict) else {}
    return {"account": account.get("login") if isinstance(account.get("login"), str) else None,
            "account_type": account.get("type") if isinstance(account.get("type"), str) else None,
            "repository_selection": payload.get("repository_selection")
            if payload.get("repository_selection") in ("all", "selected") else None,
            "permissions": {name: value for name, value in (payload.get("permissions") or {}).items()
                            if isinstance(name, str) and isinstance(value, str)}}


_repos_cache: dict[int, tuple[float, list[dict]]] = {}
REPOS_TTL = 60
MAX_REPO_PAGES = 100  # 10 000 repositorios


def installation_repositories(installation_id: int, *, fresh: bool = False) -> list[dict]:
    """Todos los repositorios que la cuenta concedió a la App, paginados (GitHub da 100 por página).

    `uid` es el identificador numérico de GitHub: no cambia al renombrar ni al transferir
    el repositorio, así que es la identidad con la que se agrupan hallazgos y decisiones.
    Lanza error si no se pudo leer la lista entera: una lista a medias no debe tomarse
    como «esos repositorios ya no existen».
    """
    cached = _repos_cache.get(installation_id)
    if cached and not fresh and cached[0] + REPOS_TTL > time.time():
        return cached[1]
    token = installation_token(installation_id)
    result, expected = [], None
    for page in range(1, MAX_REPO_PAGES + 1):
        payload = _get(f"{API}/installation/repositories?per_page=100&page={page}", token)
        rows = payload.get("repositories") if isinstance(payload, dict) else None
        if not isinstance(rows, list):
            raise GitHubAppError("GitHub devolvió una lista de repositorios inválida")
        expected = payload.get("total_count") if isinstance(payload.get("total_count"), int) else expected
        for item in rows:
            if not isinstance(item, dict) or not isinstance(item.get("full_name"), str) or not isinstance(item.get("id"), int):
                continue
            result.append({"id": f"github:{item['full_name']}", "uid": f"github#{item['id']}", "name": item["full_name"],
                           "provider": "github", "private": bool(item.get("private")), "branch": item.get("default_branch"),
                           "archived": bool(item.get("archived"))})
        if len(rows) < 100 or (expected is not None and len(result) >= expected):
            break
    else:
        raise GitHubAppError("La instalación tiene más repositorios de los que se pueden listar")
    _repos_cache[installation_id] = (time.time(), result)
    return result


# ------------------------------------------------------------ pull requests

REPO_PATTERN = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}")
COMMENT_MARKER = "<!-- appsec-agent:pr-review -->"
UNUSED_MARKER = "<!-- appsec-agent:unused-dependencies -->"
PULLS_FORBIDDEN = ("La GitHub App no puede leer los pull requests de este repositorio: su instalación necesita el "
                   "permiso «Pull requests». El operador lo añade en la configuración de la App y la cuenta acepta la actualización.")


def _send_json(method: str, url: str, token: str, body: dict) -> dict:
    request = Request(url, data=json.dumps(body).encode("utf-8"), method=method, headers={
        "Accept": "application/vnd.github+json", "Authorization": f"Bearer {token}", "Content-Type": "application/json",
        "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "AppSecAgent/0.7"})
    try:
        with build_opener(_NoRedirect).open(request, timeout=15) as response:
            payload = json.loads(response.read(2_000_000) or b"{}")
    except HTTPError as exc:
        if exc.code in (403, 404):
            raise GitHubAppError("La GitHub App no tiene permiso para escribir en este repositorio "
                                 "(hace falta Pull requests y Commit statuses en escritura)") from exc
        raise GitHubAppError(f"GitHub rechazó la petición (HTTP {exc.code})") from exc
    except (URLError, TimeoutError, OSError, ValueError, UnicodeDecodeError) as exc:
        raise GitHubAppError("No se pudo contactar con GitHub") from exc
    return payload if isinstance(payload, dict) else {}


def _repo(repository: str) -> str:
    if not isinstance(repository, str) or not REPO_PATTERN.fullmatch(repository) or ".." in repository:
        raise GitHubAppError("Repositorio inválido")
    return repository


def open_pull_requests(installation_id: int, repository: str) -> list[dict]:
    token = installation_token(installation_id)
    rows = _get(f"{API}/repos/{_repo(repository)}/pulls?state=open&per_page=50&sort=updated&direction=desc", token,
                forbidden=PULLS_FORBIDDEN)
    if not isinstance(rows, list):
        raise GitHubAppError("GitHub devolvió una lista de pull requests inválida")
    return [_pull(item) for item in rows if isinstance(item, dict)]


def pull_request(installation_id: int, repository: str, number: int) -> dict:
    if not isinstance(number, int) or not 0 < number < 10**9:
        raise GitHubAppError("Número de pull request inválido")
    payload = _get(f"{API}/repos/{_repo(repository)}/pulls/{number}", installation_token(installation_id), forbidden=PULLS_FORBIDDEN)
    if not isinstance(payload, dict):
        raise GitHubAppError("GitHub devolvió un pull request inválido")
    return _pull(payload)


def _pull(item: dict) -> dict:
    head, base, user = item.get("head") or {}, item.get("base") or {}, item.get("user") or {}
    sha = head.get("sha") if isinstance(head.get("sha"), str) and re.fullmatch(r"[0-9a-f]{40}", head.get("sha") or "") else None
    return {"number": item.get("number"), "title": str(item.get("title") or "")[:200], "url": item.get("html_url"),
            "author": user.get("login"), "draft": bool(item.get("draft")), "head_sha": sha,
            "head_ref": head.get("ref"), "base_ref": base.get("ref"), "updated_at": item.get("updated_at"),
            "state": item.get("state"), "merged": bool(item.get("merged_at")), "closed_at": item.get("closed_at")}


def pull_files(installation_id: int, repository: str, number: int) -> list[dict]:
    """Ficheros del PR con su parche. GitHub corta en 3000 ficheros y omite el parche de los grandes."""
    token = installation_token(installation_id)
    files: list[dict] = []
    for page in range(1, 31):
        rows = _get(f"{API}/repos/{_repo(repository)}/pulls/{number}/files?per_page=100&page={page}", token, forbidden=PULLS_FORBIDDEN)
        if not isinstance(rows, list):
            raise GitHubAppError("GitHub devolvió los ficheros del PR en un formato inválido")
        files.extend({"filename": item.get("filename"), "status": item.get("status"), "patch": item.get("patch")}
                     for item in rows if isinstance(item, dict) and isinstance(item.get("filename"), str))
        if len(rows) < 100:
            break
    return files


def upsert_pr_comment(installation_id: int, repository: str, number: int, body: str, marker: str = COMMENT_MARKER) -> str:
    """Un solo comentario por PR, que se reescribe en cada revisión en lugar de acumular ruido."""
    token = installation_token(installation_id)
    repository = _repo(repository)
    body = f"{marker}\n{body}"[:65_000]
    comments = _get(f"{API}/repos/{repository}/issues/{number}/comments?per_page=100", token)
    # Solo se reescribe un comentario creado por esta App: el marcador solo no basta, cualquiera puede pegarlo.
    app_id = str(_settings()["app_id"])
    mine = next((item for item in comments if isinstance(item, dict) and marker in str(item.get("body") or "")
                 and str((item.get("performed_via_github_app") or {}).get("id")) == app_id), None) if isinstance(comments, list) else None
    if mine:
        _send_json("PATCH", f"{API}/repos/{repository}/issues/comments/{int(mine['id'])}", token, {"body": body})
        return "updated"
    _send_json("POST", f"{API}/repos/{repository}/issues/{number}/comments", token, {"body": body})
    return "created"


def set_commit_status(installation_id: int, repository: str, sha: str, state: str, description: str) -> None:
    if state not in ("success", "failure", "error", "pending") or not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise GitHubAppError("Estado de commit inválido")
    _send_json("POST", f"{API}/repos/{_repo(repository)}/statuses/{sha}", installation_token(installation_id),
               {"state": state, "context": "appsec-agent", "description": description[:140]})


# ------------------------------------------------------------ mínimo privilegio

# Lo único que necesita el producto: leer código y dejar el resultado de la revisión en el PR.
REQUIRED_PERMISSIONS = {"contents": "read", "metadata": "read", "pull_requests": "write", "statuses": "write"}
_LEVEL = {"read": 1, "write": 2, "admin": 3}
_app_cache: dict = {}


def app_permissions(max_age: int = 60) -> dict:
    """Permisos que declara la App (no la instalación). Cacheado: es una llamada autenticada como App."""
    cached = _app_cache.get("value")
    if cached and _app_cache.get("at", 0) + max_age > time.time():
        return cached
    payload = _get(f"{API}/app", _app_jwt(), jwt=True)
    permissions = {name: value for name, value in ((payload or {}).get("permissions") or {}).items()
                   if isinstance(name, str) and isinstance(value, str)} if isinstance(payload, dict) else {}
    _app_cache.update(value=permissions, at=time.time())
    return permissions


def permission_review(declared: dict, granted: dict) -> dict:
    """Compara lo declarado y lo concedido con lo necesario: qué sobra y qué falta."""
    excess = sorted(name for name, level in declared.items()
                    if _LEVEL.get(level, 0) > _LEVEL.get(REQUIRED_PERMISSIONS.get(name, ""), 0))
    missing = sorted(name for name, level in REQUIRED_PERMISSIONS.items()
                     if _LEVEL.get(granted.get(name, ""), 0) < _LEVEL[level])
    pending = sorted(name for name, level in declared.items() if granted.get(name) != level)
    return {"required": REQUIRED_PERMISSIONS, "declared": declared, "granted": granted,
            "excess": excess, "missing": missing, "pending_acceptance": pending}


# ------------------------------------------------------------ manifiestos

MANIFEST_NAMES = re.compile(r"(package\.json|requirements[\w.-]*\.txt|pyproject\.toml|go\.mod|Cargo\.toml|Dockerfile|"
                            r"(docker-)?compose[\w.-]*\.ya?ml)")
MANIFEST_SKIP = {"node_modules", ".git", "vendor", "dist", "build", ".next", "venv", ".venv", "__pycache__", "fixtures", "test", "tests"}


def repository_tree(installation_id: int, repository: str, branch: str) -> list[dict]:
    """Ficheros del repositorio (ruta, sha, tamaño) sin descargarlos. GitHub corta en ~100 000 entradas."""
    token = installation_token(installation_id)
    repository = _repo(repository)
    if not isinstance(branch, str) or not re.fullmatch(r"[A-Za-z0-9._/-]{1,200}", branch) or ".." in branch:
        raise GitHubAppError("Rama inválida")
    tree = _get(f"{API}/repos/{repository}/git/trees/{quote(branch, safe='')}?recursive=1", token)
    entries = tree.get("tree") if isinstance(tree, dict) else None
    if not isinstance(entries, list):
        raise GitHubAppError("GitHub devolvió el árbol del repositorio en un formato inválido")
    return [entry for entry in entries if isinstance(entry, dict)]


def repository_manifests(installation_id: int, repository: str, branch: str, *, max_files: int = 40) -> list[tuple[str, bytes]]:
    """Solo los ficheros que describen la arquitectura, leídos con la API de git: sin bajar el repositorio."""
    token = installation_token(installation_id)
    repository = _repo(repository)
    entries = repository_tree(installation_id, repository, branch)
    wanted = []
    for entry in entries:
        path = entry.get("path") if isinstance(entry, dict) else None
        if (entry.get("type") != "blob" or not isinstance(path, str) or not isinstance(entry.get("sha"), str)
                or not re.fullmatch(r"[0-9a-f]{40}", entry["sha"]) or (entry.get("size") or 0) > 1_000_000):
            continue
        parts = path.split("/")
        if len(parts) > 6 or MANIFEST_SKIP.intersection(parts) or any(part in ("", ".", "..") for part in parts):
            continue
        if MANIFEST_NAMES.fullmatch(parts[-1]):
            wanted.append((len(parts), path, entry["sha"]))
    files = []
    for _, path, sha in sorted(wanted)[:max_files]:
        blob = _get(f"{API}/repos/{repository}/git/blobs/{sha}", token)
        if isinstance(blob, dict) and blob.get("encoding") == "base64" and isinstance(blob.get("content"), str):
            try:
                files.append((path, base64.b64decode(blob["content"])))
            except ValueError:
                continue
    return files
