"""Each installation's own GitHub App: you create it on GitHub and connect it here.

Tamandua is self-hosted: each person or team creates **their own** GitHub App ("Any account"
if they need several organizations) following the panel's guide and pastes two values here: the App ID
and the private key (.pem). The panel verifies them against GitHub before storing them and
gets the name, account and permissions from there; no client secret, OAuth or personal
token is needed.

- **App private key**: stored encrypted in the store (`vault`), never in plain
  text nor in `data/`. The environment (`GITHUB_APP_ID` + `GITHUB_APP_PRIVATE_KEY_FILE`)
  wins over the store, for whoever prefers to mount it as a secret.
- **Installation token** (1 h). This is the one that reads code. It is minted in memory by signing
  a JWT with the private key; of the installation only its identifier is stored, and it is
  checked against GitHub before being accepted.
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
from tamandua.shared import http, settings
from tamandua.shared.i18n import default_locale, msg, text
from tamandua.version import USER_AGENT

API = "https://api.github.com"
WEB = "https://github.com"
# The App's credentials are ours and must survive a restart.
# They live outside the repository, with restricted permissions; when containerized they
# are mounted as a secret and the environment takes precedence over this store.
# The App JWT allows at most 10 minutes; we leave margin for clock skew.
JWT_TTL = 540
CLOCK_SKEW = 30
# Renewed before it expires so a long scan doesn't run out of token halfway through.
TOKEN_MARGIN = 300


class GitHubAppError(RuntimeError):
    """`message` is what people read (rendered per reader); str() stays English, for logs."""

    def __init__(self, message):
        super().__init__(text(message, "en"))
        self.message = message


VAULT_NAME = "github_app"


def _stored() -> dict:
    """Credentials stored when the App was created from the panel. Their absence is not an error."""
    from tamandua.shared.vault import VaultError, get
    try:
        data = get(VAULT_NAME)
    except VaultError:
        return {}
    return data if isinstance(data, dict) else {}


def _resolved() -> dict:
    """The environment wins over the store, so a deployment can mount its own secrets."""
    stored = _stored()
    key_file = settings.text("GITHUB_APP_PRIVATE_KEY_FILE")
    from_env = settings.is_set("GITHUB_APP_ID")
    return {"app_id": settings.text("GITHUB_APP_ID") or str(stored.get("app_id") or ""),
            "slug": settings.text("GITHUB_APP_SLUG") or str(stored.get("slug") or ""),
            "key_file": key_file, "pem": "" if key_file else str(stored.get("pem") or ""),
            "owner": stored.get("owner"), "name": stored.get("name"), "html_url": stored.get("html_url"),
            "source": "environment" if from_env else "vault" if stored else None}


def config() -> dict:
    """What is missing before connecting. No secret leaves this function."""
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
    """RS256 JWT signed with the App's private key (authentication as the App)."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    now = int(time.time())
    encode = lambda data: base64.urlsafe_b64encode(json.dumps(data, separators=(",", ":")).encode()).rstrip(b"=")
    signing_input = encode({"alg": "RS256", "typ": "JWT"}) + b"." + encode(
        {"iat": now - CLOCK_SKEW, "exp": now + JWT_TTL, "iss": str(app_id)})
    signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return (signing_input + b"." + base64.urlsafe_b64encode(signature).rstrip(b"=")).decode()


def verify_app(app_id, private_key) -> dict:
    """Checks against GitHub that the App ID and the key match, and returns what GitHub says about the App.

    Nothing is stored if it fails. The key only travels from the browser to this server; GitHub
    only gets a JWT signed with it, never the key.
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
    """Stores the verified App, encrypted; the private key never touches the disk in plain text."""
    from tamandua.shared.vault import put
    put(VAULT_NAME, {key: credentials.get(key) for key in ("app_id", "pem", "slug", "name", "owner", "html_url")})
    _tokens.clear()


def forget_app() -> bool:
    """Forgets the App on this server. It still exists on GitHub: delete it there."""
    from tamandua.shared.vault import delete
    _tokens.clear()
    return delete(VAULT_NAME)


def install_url() -> str:
    """GitHub page where you choose the account and the specific repositories to scan."""
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
    """Every account where the App is installed, following additional pages."""
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
    """1 h installation token, cached in memory and renewed before it expires."""
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
    """Drops the cached catalog ("Refresh list" or on disconnect)."""
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
    """The installation's account and scope, to show what was granted."""
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
MAX_REPO_PAGES = 100  # 10 000 repositories
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
    # Compatibility with responses without total_count: the number of pages can't be known in advance here.
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
    """Every repository the account granted to the App, paginated (GitHub gives 100 per page).

    `uid` is GitHub's numeric identifier: it doesn't change when the repository is renamed or
    transferred, so it is the identity findings and decisions are grouped by.
    Raises if the whole list couldn't be read: a partial list must not be taken
    as "those repositories no longer exist".
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
    """Returns what is already available and syncs the rest outside the HTTP thread."""
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


# ------------------------------------------------------------ paged catalog
# Listing a whole large organization costs dozens of calls. Views ask only for the page they
# show, GitHub does the searching, and checking one specific repository doesn't require
# listing the others. The full list is left to the PR watcher, which needs it to detect
# removed repositories, and its cache is reused here while it is fresh.

PAGE_TTL = 60
SEARCH_LIMIT = 1000  # GitHub returns no more results than this per search
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
    """What GitHub just listed for the installation validates that selection without another call."""
    for row in rows:
        _store(_known, (installation_id, row["id"]), row)
        _store(_known, (installation_id, row["uid"]), row)


def _complete(installation_id: int) -> list[dict] | None:
    with _repos_guard:
        cached = _repos_cache.get(installation_id)
    return cached[1] if cached and cached[0] + REPOS_TTL > time.time() else None


def installation_info(installation_id: int) -> dict:
    """Cached `installation_details`: account and scope rarely change and are read on every page."""
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
    """One catalog page with the total: a single GitHub call, without walking the other pages."""
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
    """Searches by name. Returns (rows, total, partial).

    With access to all the account's repositories, GitHub does the search (`/search/repositories`
    scoped to that account). With selected repositories GitHub's search would also return
    public repositories that weren't granted, so the installation's list is filtered instead; if
    it is still being read, the result is partial.
    """
    _check_page(page, per_page)
    needle = text.strip().casefold()
    start = (page - 1) * per_page
    full = _complete(installation_id)
    if full is None:
        info = installation_info(installation_id)
        account = info.get("account")
        # Only letters, digits and separators: the text can't add qualifiers (`org:`, `user:`…).
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
                # Search has its own rate limit (30/min); fall back to the installation's list.
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
    """GitHub only mints a token for repositories granted to the installation: that is the proof of membership.

    The token is requested with the minimum (read access to that repository's metadata) and discarded.
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
    """One specific repository of the installation (`github:owner/repo`), without listing the rest."""
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
    """Like `installation_repository`, by stable identity (`github#123`), which survives renames."""
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
    # A public repository can be read even if it wasn't granted: membership is confirmed separately.
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
    """The PR's files with their patch. GitHub stops at 3000 files and omits the patch of large ones."""
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
    """A single comment per PR, rewritten on every review instead of piling up noise."""
    token = installation_token(installation_id)
    repository = _repo(repository)
    body = f"{marker}\n{text(body, default_locale())}"[:65_000]  # GitHub caps comment bodies at 65 536 characters
    comments = _get(f"{API}/repos/{repository}/issues/{number}/comments?per_page=100", token)
    # Only a comment created by this App is rewritten: the marker alone isn't enough, anyone can paste it.
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


# ------------------------------------------------------------ least privilege

# All the product needs: read code and leave the review's result on the PR.
REQUIRED_PERMISSIONS = {"contents": "read", "metadata": "read", "pull_requests": "write", "statuses": "write"}
_LEVEL = {"read": 1, "write": 2, "admin": 3}
_app_cache: dict = {}


def app_permissions(max_age: int = 60) -> dict:
    """Permissions the App declares (not the installation). Cached: it is a call authenticated as the App."""
    cached = _app_cache.get("value")
    if cached and _app_cache.get("at", 0) + max_age > time.time():
        return cached
    payload = _get(f"{API}/app", _app_jwt(), jwt=True)
    permissions = {name: value for name, value in ((payload or {}).get("permissions") or {}).items()
                   if isinstance(name, str) and isinstance(value, str)} if isinstance(payload, dict) else {}
    _app_cache.update(value=permissions, at=time.time())
    return permissions


def permission_review(declared: dict, granted: dict) -> dict:
    """Compares what is declared and granted with what is needed: what is extra and what is missing."""
    excess = sorted(name for name, level in declared.items()
                    if _LEVEL.get(level, 0) > _LEVEL.get(REQUIRED_PERMISSIONS.get(name, ""), 0))
    missing = sorted(name for name, level in REQUIRED_PERMISSIONS.items()
                     if _LEVEL.get(granted.get(name, ""), 0) < _LEVEL[level])
    pending = sorted(name for name, level in declared.items() if granted.get(name) != level)
    return {"required": REQUIRED_PERMISSIONS, "declared": declared, "granted": granted,
            "excess": excess, "missing": missing, "pending_acceptance": pending}


# ------------------------------------------------------------ manifests

MANIFEST_NAMES = re.compile(r"(package\.json|requirements[\w.-]*\.txt|pyproject\.toml|go\.mod|Cargo\.toml|Dockerfile|"
                            r"(docker-)?compose[\w.-]*\.ya?ml)")
MANIFEST_SKIP = {"node_modules", ".git", "vendor", "dist", "build", ".next", "venv", ".venv", "__pycache__", "fixtures", "test", "tests"}


def repository_tree(installation_id: int, repository: str, branch: str) -> list[dict]:
    """Repository files (path, sha, size) without downloading them. GitHub stops at ~100 000 entries."""
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
    """Only the files that describe the architecture, read through the git API: without cloning the repository."""
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
