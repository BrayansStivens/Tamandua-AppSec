"""AI credential the user brings, validated before it is stored.

The user enters the key from the interface and it is **theirs**: they pay for its usage and
can withdraw it. It never goes back to the browser (only its status and its last four
characters) and the user is never asked for it through an environment variable. The
environment variable still exists, but it is meant for the deployment's operator.

Storing the key enables nothing by itself: today the analysis is deterministic and
calls no model. Enabling it will require per-run consent, a budget and redaction of
secrets.
"""

from __future__ import annotations

import json
from urllib.error import HTTPError, URLError
from urllib.request import Request
from tamandua.shared import http, settings
from tamandua.shared.i18n import msg, text
from tamandua.version import USER_AGENT


PROVIDERS = {
    "openai": {"env": "OPENAI_API_KEY", "url": "https://api.openai.com/v1/models"},
    "anthropic": {"env": "ANTHROPIC_API_KEY", "url": "https://api.anthropic.com/v1/models?limit=1"},
}


class ProviderError(ValueError):
    """`message` is what people read (rendered per reader); str() stays English, for logs."""

    def __init__(self, message):
        super().__init__(text(message, "en"))
        self.message = message


def _load() -> dict:
    from tamandua.shared.vault import VaultError, get
    try:
        data = get("ai_keys")
    except VaultError:
        return {}
    return data if isinstance(data, dict) else {}


def _write(data: dict) -> None:
    from tamandua.shared.vault import put
    put("ai_keys", data)


def _key(name: str) -> str | None:
    """The user's key wins; the environment's is the operator's fallback."""
    stored = _load().get(name)
    if isinstance(stored, dict) and isinstance(stored.get("api_key"), str) and stored["api_key"]:
        return stored["api_key"]
    return settings.text(PROVIDERS[name]["env"]) or None


def provider_status() -> list[dict]:
    stored = _load()
    rows = []
    for name, config in PROVIDERS.items():
        entry = stored.get(name) if isinstance(stored.get(name), dict) else None
        from_user = bool(entry and entry.get("api_key"))
        rows.append({"id": name, "configured": bool(_key(name)),
                     "owner": "user" if from_user else "server" if settings.is_set(config["env"]) else None,
                     "last4": entry.get("last4") if from_user else None,
                     "saved_at": entry.get("saved_at") if from_user else None,
                     "env": config["env"]})
    return rows


def save_provider_key(name: str, api_key: str) -> dict:
    """Validates the key against the provider before storing it; if validation fails, it isn't stored."""
    if name not in PROVIDERS:
        raise ProviderError(msg("integrations.ai.unsupported"))
    if (not isinstance(api_key, str) or not 20 <= len(api_key) <= 400
            or any(character.isspace() or ord(character) < 33 or ord(character) > 126 for character in api_key)):
        raise ProviderError(msg("integrations.ai.invalid_key"))
    result = check_provider(name, api_key=api_key)
    if result["status"] != "connected":
        raise ProviderError(result["message"])
    from datetime import datetime, timezone
    data = _load()
    data[name] = {"api_key": api_key, "last4": api_key[-4:],
                  "saved_at": datetime.now(timezone.utc).isoformat()}
    _write(data)
    return {**result, "last4": api_key[-4:]}


def forget_provider_key(name: str) -> None:
    if name not in PROVIDERS:
        raise ProviderError(msg("integrations.ai.unsupported"))
    data = _load()
    if data.pop(name, None) is not None:
        _write(data)


def check_provider(name: str, api_key: str | None = None) -> dict:
    if name not in PROVIDERS:
        raise ProviderError(msg("integrations.ai.unsupported"))
    config = PROVIDERS[name]
    key = api_key or _key(name)
    if not key:
        return {"provider": name, "status": "not_configured",
                "message": msg("integrations.ai.not_configured")}
    headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
    if name == "openai":
        headers["Authorization"] = f"Bearer {key}"
    else:
        headers["x-api-key"] = key
        headers["anthropic-version"] = "2023-06-01"
    request = Request(config["url"], headers=headers)
    try:
        with http.opener().open(request, timeout=8) as response:
            content = response.read(256_001)
            if len(content) > 256_000:
                return {"provider": name, "status": "error", "message": msg("integrations.ai.too_large")}
            payload = json.loads(content)
    except HTTPError as exc:
        status = "invalid_credentials" if exc.code in (401, 403) else "rate_limited" if exc.code == 429 else "error"
        return {"provider": name, "status": status, "http_status": exc.code,
                "message": msg("integrations.ai.rejected")}
    except (URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError):
        return {"provider": name, "status": "unreachable", "message": msg("integrations.ai.unreachable")}
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
        return {"provider": name, "status": "error", "message": msg("integrations.ai.unexpected")}
    return {"provider": name, "status": "connected", "models_visible": len(payload["data"]),
            "message": msg("integrations.ai.connected")}
