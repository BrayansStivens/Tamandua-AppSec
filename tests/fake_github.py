"""GitHub simulado a nivel HTTP para probar el catálogo por páginas sin red.

`repos` es {instalación: [(id numérico, "owner/repo"), ...]} y `accounts` es
{instalación: (cuenta, "all" | "selected")}. `branches` es {"owner/repo": {rama: sha}}; sin él, cada
repositorio solo tiene `main`. Se registran las URL pedidas en `calls` para comprobar que no se
recorre el catálogo entero.
"""

from __future__ import annotations

import re
from contextlib import contextmanager
from urllib.parse import parse_qs, unquote, urlsplit
from unittest.mock import patch

from tamandua.modules.integrations import github as github_app


def _item(uid: int, name: str) -> dict:
    return {"id": uid, "full_name": name, "private": True, "default_branch": "main"}


@contextmanager
def fake_github(repos: dict[int, list[tuple[int, str]]], accounts: dict[int, tuple[str, str]],
                branches: dict[str, dict[str, str]] | None = None):
    calls: list[str] = []

    def get(url: str, token: str, *, jwt: bool = False, forbidden: str | None = None, missing: str | None = None):
        calls.append(url)
        parts = urlsplit(url)
        query = {key: values[0] for key, values in parse_qs(parts.query).items()}
        if parts.path == "/installation/repositories":
            rows = repos[int(token.removeprefix("token-"))]
            per_page, page = int(query["per_page"]), int(query["page"])
            return {"total_count": len(rows), "repositories": [_item(*row) for row in rows[(page - 1) * per_page:page * per_page]]}
        if parts.path == "/search/repositories":
            installation = int(token.removeprefix("token-"))
            term = unquote(query["q"]).split(" in:name", 1)[0].casefold()
            rows = [row for row in repos[installation] if term in row[1].casefold()]
            per_page, page = int(query["per_page"]), int(query["page"])
            return {"total_count": len(rows), "items": [_item(*row) for row in rows[(page - 1) * per_page:page * per_page]]}
        match = re.fullmatch(r"/repositories/(\d+)", parts.path)
        if match:
            for rows in repos.values():
                for uid, name in rows:
                    if uid == int(match.group(1)):
                        return _item(uid, name)
            raise github_app.GitHubAppError(forbidden or "HTTP 404")
        match = re.fullmatch(r"/repos/([^/]+/[^/]+)/branches/([^/]+)", parts.path)
        if match:
            sha = (branches or {}).get(match.group(1), {"main": "a" * 40}).get(unquote(match.group(2)))
            if sha is None:
                raise github_app.GitHubAppError(missing or forbidden or "HTTP 404")
            return {"name": unquote(match.group(2)), "commit": {"sha": sha}}
        match = re.fullmatch(r"/app/installations/(\d+)", parts.path)
        if match:
            account, selection = accounts[int(match.group(1))]
            return {"account": {"login": account, "type": "Organization"}, "repository_selection": selection, "permissions": {}}
        raise AssertionError(f"URL inesperada: {url}")

    def scoped(installation: int, name: str):
        calls.append(f"scoped:{installation}:{name}")
        account = accounts[installation][0]
        found = next((row for row in repos[installation] if row[1] == f"{account}/{name}"), None)
        return github_app._repo_rows({"repositories": [_item(*found)]})[0] if found else None

    github_app.forget()
    try:
        with patch("tamandua.modules.integrations.github._get", side_effect=get), \
                patch("tamandua.modules.integrations.github.installation_token", side_effect=lambda installation: f"token-{installation}"), \
                patch("tamandua.modules.integrations.github._scoped_repository", side_effect=scoped), \
                patch("tamandua.modules.integrations.github._app_jwt", return_value="jwt"):
            yield calls
    finally:
        github_app.forget()
