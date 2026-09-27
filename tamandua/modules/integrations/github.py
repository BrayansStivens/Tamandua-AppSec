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
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import logging
import os
import re
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request
from tamandua.shared import http
from tamandua.shared.i18n import default_locale, msg, text
from tamandua.version import USER_AGENT

API = "https://api.github.com"
WEB = "https://github.com"
# Las credenciales de la App son nuestras y tienen que sobrevivir al reinicio.
# Viven fuera del repositorio, con permisos restringidos; al contenerizar se
# montan como secreto y el entorno tiene prioridad sobre este almacén.
# El JWT de la App admite como máximo 10 minutos; damos margen por desfase de reloj.
JWT_TTL = 540
CLOCK_SKEW = 30
# Se renueva antes de caducar para que un escaneo largo no se quede sin token a medias.
TOKEN_MARGIN = 300


class GitHubAppError(RuntimeError):
    """`message` is what people read (rendered per reader); str() stays English, for logs."""

    def __init__(self, message):
        super().__init__(text(message, "en"))
        self.message = message


VAULT_NAME = "github_app"


def _stored() -> dict:
    """Credenciales guardadas al crear la App desde el panel. Ausencia no es error."""
    from tamandua.shared.vault import VaultError, get
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
            "source": "environment" if from_env else "vault" if stored else None}


def config() -> dict:
    """Qué falta para poder conectar. Ningún secreto sale de aquí."""
    values = _resolved()
    missing = []
    if not values["app_id"]:
        missing.append("App ID")
    if values["key_file"] and not os.path.isfile(values["key_file"]):
        missing.append(msg("integrations.github.missing.key_file"))
    elif not values["key_file"] and not values["pem"]:
        missing.append(msg("integrations.github.missing.private_key"))
    if not values["slug"]:
        missing.append("GITHUB_APP_SLUG")
    return {"configured": not missing, "missing": missing, "slug": values["slug"], "app_id": values["app_id"],
            "owner": values["owner"], "name": values["name"], "html_url": values["html_url"], "source": values["source"]}


def _settings() -> dict:
    if not config()["configured"]:
        raise GitHubAppError(msg("integrations.github.not_configured"))
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
        raise GitHubAppError(msg("integrations.github.invalid_pem")) from exc
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
        raise GitHubAppError(msg("integrations.github.weak_key"))
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
        raise GitHubAppError(msg("integrations.github.app_id_number"))
    if not isinstance(private_key, str) or not private_key.strip() or len(private_key) > PEM_MAX:
        raise GitHubAppError(msg("integrations.github.missing_key"))
    pem = private_key.strip() + "\n"
    key = _load_key(pem.encode())
    try:
        app = _get(f"{API}/app", _jwt(app_id, key), jwt=True)
    except GitHubAppError as exc:
        raise GitHubAppError(msg("integrations.github.key_mismatch")) from exc
    if not isinstance(app, dict) or str(app.get("id")) != app_id or not re.fullmatch(r"[a-z0-9-]{1,100}", str(app.get("slug") or "")):
        raise GitHubAppError(msg("integrations.github.unexpected_app"))
    return {"app_id": app_id, "pem": pem, "slug": app["slug"], "name": app.get("name"),
            "owner": (app.get("owner") or {}).get("login"), "owner_type": (app.get("owner") or {}).get("type"),
            "html_url": app.get("html_url"), "permissions": app.get("permissions") or {}, "events": app.get("events") or []}


def save_credentials(credentials: dict) -> None:
    """Guarda la App verificada, cifrada; la clave privada nunca toca el disco en claro."""
    from tamandua.shared.vault import put
    put(VAULT_NAME, {key: credentials.get(key) for key in ("app_id", "pem", "slug", "name", "owner", "html_url")})
    _tokens.clear()


def forget_app() -> bool:
    """Olvida la App en este servidor. En GitHub sigue existiendo: se borra allí."""
    from tamandua.shared.vault import delete
    _tokens.clear()
    return delete(VAULT_NAME)


def install_url() -> str:
    """Pantalla de GitHub donde eliges la cuenta y los repositorios concretos que se analizan."""
    settings = _settings()
    if not re.fullmatch(r"[a-z0-9-]{1,100}", settings["slug"]):
        raise GitHubAppError(msg("integrations.github.invalid_slug"))
    return f"{WEB}/apps/{settings['slug']}/installations/new"


def _get(url: str, token: str, *, jwt: bool = False, forbidden: dict | None = None, missing: dict | None = None) -> dict | list:
    request = Request(url, headers={
        "Accept": "application/vnd.github+json", "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28", "User-Agent": USER_AGENT})
    try:
        with http.opener().open(request, timeout=15) as response:
            return json.loads(response.read(2_000_000))
    except HTTPError as exc:
        if missing and exc.code == 404:
            raise GitHubAppError(missing) from exc
        if forbidden and exc.code in (403, 404):
            raise GitHubAppError(forbidden) from exc
        raise GitHubAppError(msg("integrations.github.rejected_app", code=exc.code) if jwt
                             else msg("integrations.github.rejected_token", code=exc.code)) from exc
    except (URLError, TimeoutError, OSError, ValueError, UnicodeDecodeError) as exc:
        raise GitHubAppError(msg("integrations.github.unreachable")) from exc


def _app_jwt() -> str:
    settings = _settings()
    try:
        if settings["key_file"]:
            with open(settings["key_file"], "rb") as handle:
                material = handle.read()
        else:
            material = settings["pem"].encode()
    except OSError as exc:
        raise GitHubAppError(msg("integrations.github.key_unreadable")) from exc
    return _jwt(settings["app_id"], _load_key(material))


def app_installations() -> list[dict]:
    """Todas las cuentas donde está instalada la App, incluidas páginas adicionales."""
    token = _app_jwt()
    result = []
    for page in range(1, 101):
        rows = _get(f"{API}/app/installations?per_page=100&page={page}", token, jwt=True)
        if not isinstance(rows, list):
            raise GitHubAppError(msg("integrations.github.invalid_installations"))
        result.extend({"installation_id": item["id"], "account": (item.get("account") or {}).get("login"),
                       "account_type": (item.get("account") or {}).get("type"),
                       "repository_selection": item.get("repository_selection")}
                      for item in rows if isinstance(item, dict) and isinstance(item.get("id"), int))
        if len(rows) < 100:
            return result
    raise GitHubAppError(msg("integrations.github.too_many_installations"))


_tokens: dict[int, tuple[str, float]] = {}


def installation_token(installation_id: int) -> str:
    """Token de instalación de 1 h, cacheado en memoria y renovado antes de caducar."""
    if not isinstance(installation_id, int) or not 0 < installation_id < 2**63:
        raise GitHubAppError(msg("integrations.github.invalid_installation_id"))
    cached = _tokens.get(installation_id)
    if cached and cached[1] - TOKEN_MARGIN > time.time():
        return cached[0]
    request = Request(f"{API}/app/installations/{installation_id}/access_tokens", data=b"", method="POST", headers={
        "Accept": "application/vnd.github+json", "Authorization": f"Bearer {_app_jwt()}",
        "X-GitHub-Api-Version": "2022-11-28", "User-Agent": USER_AGENT})
    try:
        with http.opener().open(request, timeout=15) as response:
            payload = json.loads(response.read(200_000))
    except HTTPError as exc:
        if exc.code in (401, 404):
            _tokens.pop(installation_id, None)
            raise GitHubAppError(msg("integrations.github.installation_gone")) from exc
        raise GitHubAppError(msg("integrations.github.token_refused", code=exc.code)) from exc
    except (URLError, TimeoutError, OSError, ValueError, UnicodeDecodeError) as exc:
        raise GitHubAppError(msg("integrations.github.unreachable")) from exc
    token = payload.get("token") if isinstance(payload, dict) else None
    if not isinstance(token, str) or not token:
        raise GitHubAppError(msg("integrations.github.no_token"))
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
    forget_catalog(installation_id)


def forget_catalog(installation_id: int | None = None) -> None:
    """Descarta lo cacheado del catálogo («Actualizar lista» o al desconectar)."""
    with _repos_guard:
        targets = set(_repos_cache) | set(_repos_loading) | set(_info) if installation_id is None else [installation_id]
        for target in targets:
            _repos_cache.pop(target, None)
            _repos_errors.pop(target, None)
            _info.pop(target, None)
            _repos_generation[target] = _repos_generation.get(target, 0) + 1
        for store in (_pages, _known):
            for key in [key for key in store if installation_id is None or key[1 if store is _pages else 0] == installation_id]:
                del store[key]


def installation_details(installation_id: int) -> dict:
    """Cuenta y alcance de la instalación, para mostrar qué se concedió."""
    payload = _get(f"{API}/app/installations/{installation_id}", _app_jwt(), jwt=True)
    if not isinstance(payload, dict):
        raise GitHubAppError(msg("integrations.github.invalid_installation"))
    account = payload.get("account") if isinstance(payload.get("account"), dict) else {}
    return {"account": account.get("login") if isinstance(account.get("login"), str) else None,
            "account_type": account.get("type") if isinstance(account.get("type"), str) else None,
            "repository_selection": payload.get("repository_selection")
            if payload.get("repository_selection") in ("all", "selected") else None,
            "permissions": {name: value for name, value in (payload.get("permissions") or {}).items()
                            if isinstance(name, str) and isinstance(value, str)}}


_repos_cache: dict[int, tuple[float, list[dict]]] = {}
_repos_guard = threading.Lock()
_repos_fetch_locks: dict[int, threading.Lock] = {}
_repos_loading: dict[int, dict] = {}
_repos_errors: dict[int, tuple[float, dict]] = {}
_repos_generation: dict[int, int] = {}
REPOS_TTL = 300
MAX_REPO_PAGES = 100  # 10 000 repositorios
REPOS_RETRY_AFTER = 30


def _repo_rows(payload: dict | list) -> list[dict]:
    rows = payload.get("repositories") if isinstance(payload, dict) else None
    if not isinstance(rows, list) or len(rows) > 100:
        raise GitHubAppError(msg("integrations.github.invalid_repositories"))
    result = []
    for item in rows:
        if not isinstance(item, dict) or not isinstance(item.get("full_name"), str) or not isinstance(item.get("id"), int):
            continue
        result.append({"id": f"github:{item['full_name']}", "uid": f"github#{item['id']}", "name": item["full_name"],
                       "provider": "github", "private": bool(item.get("private")), "branch": item.get("default_branch"),
                       "archived": bool(item.get("archived"))})
    return result


def _fetch_repositories(installation_id: int, progress=None) -> list[dict]:
    token = installation_token(installation_id)

    def fetch(page: int) -> dict:
        payload = _get(f"{API}/installation/repositories?per_page=100&page={page}", token)
        if not isinstance(payload, dict):
            raise GitHubAppError(msg("integrations.github.invalid_repositories"))
        return payload

    first = fetch(1)
    result = _repo_rows(first)
    expected = first.get("total_count")
    if expected is not None and (not isinstance(expected, int) or isinstance(expected, bool) or expected < 0 or expected > MAX_REPO_PAGES * 100):
        raise GitHubAppError(msg("integrations.github.invalid_total"))
    if progress:
        progress(result, expected)
    if expected is not None:
        pages = max(1, (expected + 99) // 100)
        if expected != len(result) and len(result) < 100:
            raise GitHubAppError(msg("integrations.github.incomplete_page"))
        if pages > 1:
            pending: dict[int, list[dict]] = {}
            next_page = 2
            with ThreadPoolExecutor(max_workers=4, thread_name_prefix="github-repos") as pool:
                futures = {pool.submit(fetch, page): page for page in range(2, pages + 1)}
                for future in as_completed(futures):
                    pending[futures[future]] = _repo_rows(future.result())
                    while next_page in pending:
                        result.extend(pending.pop(next_page))
                        next_page += 1
                        if progress:
                            progress(result, expected)
        if len(result) != expected:
            raise GitHubAppError(msg("integrations.github.list_changed"))
        return result
    # Compatibilidad con respuestas sin total_count: aquí no se puede anticipar el número de páginas.
    for page in range(2, MAX_REPO_PAGES + 1):
        if len(result) < (page - 1) * 100:
            return result
        rows = _repo_rows(fetch(page))
        result.extend(rows)
        if progress:
            progress(result, None)
        if len(rows) < 100:
            return result
    raise GitHubAppError(msg("integrations.github.too_many_repositories"))


def installation_repositories(installation_id: int, *, fresh: bool = False, progress=None) -> list[dict]:
    """Todos los repositorios que la cuenta concedió a la App, paginados (GitHub da 100 por página).

    `uid` es el identificador numérico de GitHub: no cambia al renombrar ni al transferir
    el repositorio, así que es la identidad con la que se agrupan hallazgos y decisiones.
    Lanza error si no se pudo leer la lista entera: una lista a medias no debe tomarse
    como «esos repositorios ya no existen».
    """
    with _repos_guard:
        lock = _repos_fetch_locks.setdefault(installation_id, threading.Lock())
        generation = _repos_generation.get(installation_id, 0)
    with lock:
        with _repos_guard:
            cached = _repos_cache.get(installation_id)
            if cached and not fresh and cached[0] + REPOS_TTL > time.time():
                return cached[1]
        result = _fetch_repositories(installation_id, progress)
        with _repos_guard:
            if _repos_generation.get(installation_id, 0) == generation:
                _repos_cache[installation_id] = (time.time(), result)
                _repos_errors.pop(installation_id, None)
        return result


def installation_repositories_snapshot(installation_id: int, *, fresh: bool = False) -> tuple[list[dict], bool, int | None, dict | None]:
    """Devuelve lo disponible ya y sincroniza el resto fuera del hilo HTTP."""
    start = False
    with _repos_guard:
        cached = _repos_cache.get(installation_id)
        loading = _repos_loading.get(installation_id)
        if cached and not fresh and cached[0] + REPOS_TTL > time.time() and not loading:
            return cached[1], False, len(cached[1]), None
        if fresh:
            _repos_errors.pop(installation_id, None)
        failure = _repos_errors.get(installation_id)
        if failure and failure[0] + REPOS_RETRY_AFTER > time.time() and not loading:
            return cached[1] if cached else [], False, len(cached[1]) if cached else None, failure[1]
        if not loading:
            loading = {"repos": [], "total": None}
            _repos_loading[installation_id] = loading
            start = True
        rows = cached[1] if cached else loading["repos"]
        total = len(rows) if cached else loading["total"]
    if start:
        def update(rows: list[dict], total: int | None) -> None:
            with _repos_guard:
                loading["repos"] = rows.copy()
                loading["total"] = total

        def run() -> None:
            try:
                installation_repositories(installation_id, fresh=True, progress=update)
            except GitHubAppError as exc:
                with _repos_guard:
                    _repos_errors[installation_id] = (time.time(), exc.message)
            except Exception:
                logging.getLogger("tamandua.github").exception("repository_catalog_sync_failed")
                with _repos_guard:
                    _repos_errors[installation_id] = (time.time(), msg("integrations.github.catalog_sync_failed"))
            finally:
                with _repos_guard:
                    _repos_loading.pop(installation_id, None)

        threading.Thread(target=run, name=f"github-repos-{installation_id}", daemon=True).start()
    return rows, True, total, None


# ------------------------------------------------------------ catálogo por páginas
# Listar una organización grande entera cuesta decenas de llamadas. Las vistas piden solo la
# página que enseñan, la búsqueda la hace GitHub y comprobar un repositorio concreto no exige
# listar los demás. La lista completa queda para el vigilante de PRs, que la necesita para
# detectar repositorios retirados, y su caché se aprovecha aquí cuando está fresca.

PAGE_TTL = 60
SEARCH_LIMIT = 1000  # GitHub no devuelve más resultados por búsqueda
_pages: dict[tuple, tuple[float, object]] = {}
_known: dict[tuple[int, str], tuple[float, dict | None]] = {}
_info: dict[int, tuple[float, dict]] = {}
_MISSING = object()
UID = re.compile(r"github#([1-9][0-9]{0,15})")
NOT_FOUND = msg("integrations.github.not_in_installation")


def _cached(store: dict, key, ttl: int):
    with _repos_guard:
        entry = store.get(key)
    return entry[1] if entry and entry[0] + ttl > time.time() else _MISSING


def _store(store: dict, key, value) -> None:
    with _repos_guard:
        if len(store) > 20_000:
            store.clear()
        store[key] = (time.time(), value)


def _remember(installation_id: int, rows: list[dict]) -> None:
    """Lo que GitHub acaba de listar para la instalación sirve para validar esa selección sin otra llamada."""
    for row in rows:
        _store(_known, (installation_id, row["id"]), row)
        _store(_known, (installation_id, row["uid"]), row)


def _complete(installation_id: int) -> list[dict] | None:
    with _repos_guard:
        cached = _repos_cache.get(installation_id)
    return cached[1] if cached and cached[0] + REPOS_TTL > time.time() else None


def installation_info(installation_id: int) -> dict:
    """`installation_details` cacheado: cuenta y alcance cambian poco y se consultan en cada página."""
    cached = _cached(_info, installation_id, REPOS_TTL)
    if cached is _MISSING:
        cached = installation_details(installation_id)
        _store(_info, installation_id, cached)
    return cached


def _check_page(page: int, per_page: int) -> None:
    if not 1 <= per_page <= 100 or not 1 <= page or page * per_page > MAX_REPO_PAGES * 100:
        raise GitHubAppError(msg("integrations.github.invalid_page"))


def _total(payload: dict, fallback: int) -> int:
    total = payload.get("total_count")
    return total if isinstance(total, int) and not isinstance(total, bool) and total >= 0 else fallback


def repositories_page(installation_id: int, page: int, per_page: int) -> tuple[list[dict], int]:
    """Una página del catálogo con el total: una sola llamada a GitHub, sin recorrer las demás."""
    _check_page(page, per_page)
    start = (page - 1) * per_page
    full = _complete(installation_id)
    if full is not None:
        return full[start:start + per_page], len(full)
    key = ("page", installation_id, page, per_page)
    cached = _cached(_pages, key, PAGE_TTL)
    if cached is not _MISSING:
        return cached
    payload = _get(f"{API}/installation/repositories?per_page={per_page}&page={page}", installation_token(installation_id))
    rows = _repo_rows(payload)
    result = (rows, _total(payload, start + len(rows)))
    _remember(installation_id, rows)
    _store(_pages, key, result)
    return result


def search_repositories(installation_id: int, text: str, page: int, per_page: int) -> tuple[list[dict], int, bool]:
    """Busca por nombre. Devuelve (filas, total, parcial).

    Con acceso a todos los repositorios de la cuenta busca GitHub (`/search/repositories`
    acotado a esa cuenta). Con repositorios seleccionados la búsqueda de GitHub también
    devolvería públicos no concedidos, así que se filtra la lista de la instalación; si aún
    se está leyendo, el resultado es parcial.
    """
    _check_page(page, per_page)
    needle = text.strip().casefold()
    start = (page - 1) * per_page
    full = _complete(installation_id)
    if full is None:
        info = installation_info(installation_id)
        account = info.get("account")
        # Solo letras, números y separadores: el texto no puede añadir calificadores (`org:`, `user:`…).
        term = " ".join(re.sub(r"[^A-Za-z0-9._-]+", " ", text).split())[:100]
        if (term and info.get("repository_selection") == "all" and isinstance(account, str)
                and OWNER.fullmatch(account) and page * per_page <= SEARCH_LIMIT):
            key = ("search", installation_id, term.casefold(), page, per_page)
            cached = _cached(_pages, key, PAGE_TTL)
            if cached is not _MISSING:
                return cached
            qualifier = "org" if info.get("account_type") == "Organization" else "user"
            query = quote(f"{term} in:name {qualifier}:{account} fork:true")
            try:
                payload = _get(f"{API}/search/repositories?q={query}&per_page={per_page}&page={page}",
                               installation_token(installation_id))
                rows = _repo_rows({"repositories": payload.get("items") if isinstance(payload, dict) else None})
            except GitHubAppError:
                # La búsqueda tiene su propio límite (30/min); se sigue con la lista de la instalación.
                pass
            else:
                rows = [row for row in rows if row["name"].split("/", 1)[0].casefold() == account.casefold()]
                result = (rows, min(_total(payload, start + len(rows)), SEARCH_LIMIT), False)
                _remember(installation_id, rows)
                _store(_pages, key, result)
                return result
        rows, partial, _, error = installation_repositories_snapshot(installation_id)
        if error and not rows:
            raise GitHubAppError(error)
    else:
        rows, partial = full, False
    matches = [row for row in rows if needle in row["name"].casefold()]
    return matches[start:start + per_page], len(matches), partial


def _scoped_repository(installation_id: int, name: str) -> dict | None:
    """GitHub solo acuña un token para repositorios concedidos a la instalación: es la prueba de pertenencia.

    El token se pide con el mínimo (metadatos de lectura de ese repositorio) y se descarta.
    """
    body = json.dumps({"repositories": [name], "permissions": {"metadata": "read"}}).encode()
    request = Request(f"{API}/app/installations/{installation_id}/access_tokens", data=body, method="POST", headers={
        "Accept": "application/vnd.github+json", "Authorization": f"Bearer {_app_jwt()}", "Content-Type": "application/json",
        "X-GitHub-Api-Version": "2022-11-28", "User-Agent": USER_AGENT})
    try:
        with http.opener().open(request, timeout=15) as response:
            payload = json.loads(response.read(2_000_000))
    except HTTPError as exc:
        if exc.code in (404, 422):
            return None
        raise GitHubAppError(msg("integrations.github.check_failed", code=exc.code)) from exc
    except (URLError, TimeoutError, OSError, ValueError, UnicodeDecodeError) as exc:
        raise GitHubAppError(msg("integrations.github.unreachable")) from exc
    rows = _repo_rows({"repositories": payload.get("repositories") if isinstance(payload, dict) else None})
    return rows[0] if len(rows) == 1 else None


def installation_repository(installation_id: int, source_id: str) -> dict | None:
    """Un repositorio concreto de la instalación (`github:owner/repo`), sin listar el resto."""
    if not isinstance(source_id, str) or not source_id.startswith("github:"):
        return None
    cached = _cached(_known, (installation_id, source_id), REPOS_TTL)
    if cached is not _MISSING:
        return cached
    full = _complete(installation_id)
    if full is not None:
        return next((row for row in full if row["id"] == source_id), None)
    repository = source_id.removeprefix("github:")
    if not REPO_PATTERN.fullmatch(repository) or ".." in repository:
        return None
    owner, name = repository.split("/", 1)
    account = installation_info(installation_id).get("account")
    if isinstance(account, str) and owner.casefold() != account.casefold():
        return None
    found = _scoped_repository(installation_id, name)
    if found is not None and found["id"] != source_id:
        found = None
    _store(_known, (installation_id, source_id), found)
    if found is not None:
        _remember(installation_id, [found])
    return found


def installation_repository_by_uid(installation_id: int, uid: str) -> dict | None:
    """Igual que `installation_repository`, por identidad estable (`github#123`), que sobrevive a renombrados."""
    match = UID.fullmatch(uid) if isinstance(uid, str) else None
    if match is None:
        return None
    cached = _cached(_known, (installation_id, uid), REPOS_TTL)
    if cached is not _MISSING:
        return cached
    full = _complete(installation_id)
    if full is not None:
        return next((row for row in full if row["uid"] == uid), None)
    try:
        payload = _get(f"{API}/repositories/{match.group(1)}", installation_token(installation_id), forbidden=NOT_FOUND)
    except GitHubAppError as exc:
        if exc.message != NOT_FOUND:
            raise
        payload = None
    name = payload.get("full_name") if isinstance(payload, dict) else None
    # Un repositorio público se lee aunque no esté concedido: la pertenencia se confirma aparte.
    found = installation_repository(installation_id, f"github:{name}") if isinstance(name, str) else None
    if found is not None and found["uid"] != uid:
        found = None
    _store(_known, (installation_id, uid), found)
    return found


# ------------------------------------------------------------ pull requests

REPO_PATTERN = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}")
COMMENT_MARKER = "<!-- tamandua:pr-review -->"
UNUSED_MARKER = "<!-- tamandua:unused-dependencies -->"
PULLS_FORBIDDEN = msg("integrations.github.pulls_forbidden")


def _send_json(method: str, url: str, token: str, body: dict) -> dict:
    request = Request(url, data=json.dumps(body).encode("utf-8"), method=method, headers={
        "Accept": "application/vnd.github+json", "Authorization": f"Bearer {token}", "Content-Type": "application/json",
        "X-GitHub-Api-Version": "2022-11-28", "User-Agent": USER_AGENT})
    try:
        with http.opener().open(request, timeout=15) as response:
            payload = json.loads(response.read(2_000_000) or b"{}")
    except HTTPError as exc:
        if exc.code in (403, 404):
            raise GitHubAppError(msg("integrations.github.write_forbidden")) from exc
        raise GitHubAppError(msg("integrations.github.request_rejected", code=exc.code)) from exc
    except (URLError, TimeoutError, OSError, ValueError, UnicodeDecodeError) as exc:
        raise GitHubAppError(msg("integrations.github.unreachable")) from exc
    return payload if isinstance(payload, dict) else {}


def _repo(repository: str) -> str:
    if not isinstance(repository, str) or not REPO_PATTERN.fullmatch(repository) or ".." in repository:
        raise GitHubAppError(msg("integrations.github.invalid_repository"))
    return repository


def open_pull_requests(installation_id: int, repository: str) -> list[dict]:
    token = installation_token(installation_id)
    rows = _get(f"{API}/repos/{_repo(repository)}/pulls?state=open&per_page=50&sort=updated&direction=desc", token,
                forbidden=PULLS_FORBIDDEN)
    if not isinstance(rows, list):
        raise GitHubAppError(msg("integrations.github.invalid_pulls"))
    return [_pull(item) for item in rows if isinstance(item, dict)]


BRANCH_PATTERN = re.compile(r"[A-Za-z0-9._/-]{1,200}")


def valid_branch(branch) -> bool:
    """Branch names we accept anywhere: letters, digits and `._/-`, never a path trick or an option."""
    return (isinstance(branch, str) and BRANCH_PATTERN.fullmatch(branch) is not None and not branch.startswith(("-", "/"))
            and ".." not in branch and "//" not in branch)


class BranchNotFound(GitHubAppError):
    """The branch doesn't exist in the repository (GitHub answered 404)."""


def branch_head(installation_id: int, repository: str, branch: str) -> str:
    """Latest commit of a branch."""
    if not valid_branch(branch):
        raise GitHubAppError(msg("integrations.github.invalid_branch"))
    missing = msg("integrations.github.branch_not_found", branch=branch)
    try:
        payload = _get(f"{API}/repos/{_repo(repository)}/branches/{quote(branch, safe='')}", installation_token(installation_id),
                       missing=missing)
    except GitHubAppError as exc:
        if exc.message == missing:
            raise BranchNotFound(missing) from exc
        raise
    sha = ((payload.get("commit") or {}).get("sha") if isinstance(payload, dict) else None)
    if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise GitHubAppError(msg("integrations.github.no_branch_head"))
    return sha


def pull_request(installation_id: int, repository: str, number: int) -> dict:
    if not isinstance(number, int) or not 0 < number < 10**9:
        raise GitHubAppError(msg("integrations.github.invalid_pr_number"))
    payload = _get(f"{API}/repos/{_repo(repository)}/pulls/{number}", installation_token(installation_id), forbidden=PULLS_FORBIDDEN)
    if not isinstance(payload, dict):
        raise GitHubAppError(msg("integrations.github.invalid_pull"))
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
            raise GitHubAppError(msg("integrations.github.invalid_files"))
        files.extend({"filename": item.get("filename"), "status": item.get("status"), "patch": item.get("patch")}
                     for item in rows if isinstance(item, dict) and isinstance(item.get("filename"), str))
        if len(rows) < 100:
            break
    return files


def upsert_pr_comment(installation_id: int, repository: str, number: int, body, marker: str = COMMENT_MARKER) -> str:
    """Un solo comentario por PR, que se reescribe en cada revisión en lugar de acumular ruido."""
    token = installation_token(installation_id)
    repository = _repo(repository)
    body = f"{marker}\n{text(body, default_locale())}"[:65_000]  # GitHub caps comment bodies at 65 536 characters
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


def set_commit_status(installation_id: int, repository: str, sha: str, state: str, description) -> None:
    """`description` may be a message: GitHub shows one language, so it renders in TAMANDUA_DEFAULT_LOCALE."""
    if state not in ("success", "failure", "error", "pending") or not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise GitHubAppError(msg("integrations.github.invalid_status"))
    _send_json("POST", f"{API}/repos/{_repo(repository)}/statuses/{sha}", installation_token(installation_id),
               {"state": state, "context": "tamandua", "description": text(description, default_locale())[:140]})


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
    if not valid_branch(branch):
        raise GitHubAppError(msg("integrations.github.invalid_branch"))
    tree = _get(f"{API}/repos/{repository}/git/trees/{quote(branch, safe='')}?recursive=1", token)
    entries = tree.get("tree") if isinstance(tree, dict) else None
    if not isinstance(entries, list):
        raise GitHubAppError(msg("integrations.github.invalid_tree"))
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
