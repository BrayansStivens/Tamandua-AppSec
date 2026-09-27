"""GitHub or GitLab tokens pasted in the panel to list and scan repositories without a GitHub App.

They are sealed in the vault (not kept in one process's memory), so every instance of the API and every worker sees
the same connection. They never go back to the browser.
"""

from __future__ import annotations

from tamandua.shared import vault

VAULT_NAME = "code_tokens"
PROVIDERS = ("github", "gitlab")


def current() -> dict[str, str]:
    """{provider: token} for the connected providers."""
    stored = vault.get(VAULT_NAME) or {}
    return {provider: entry["token"] for provider, entry in stored.items()
            if provider in PROVIDERS and isinstance(entry, dict) and isinstance(entry.get("token"), str)}


def connect(provider: str, token: str) -> None:
    stored = vault.get(VAULT_NAME) or {}
    vault.put(VAULT_NAME, {**stored, provider: {"token": token}})


def disconnect(provider: str) -> None:
    stored = vault.get(VAULT_NAME) or {}
    if stored.pop(provider, None) is not None:
        vault.put(VAULT_NAME, stored) if stored else vault.delete(VAULT_NAME)
