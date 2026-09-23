"""Credencial de IA que aporta el propio usuario, validada antes de guardarla.

La clave la pone el usuario desde la interfaz y es **suya**: paga su consumo y
puede retirarla. Nunca se devuelve al navegador —solo su estado y los cuatro
últimos caracteres— y nunca se pide por variable de entorno al usuario. La
variable de entorno sigue existiendo, pero es para el operador del despliegue.

Guardar la clave no habilita nada por sí solo: hoy el análisis es determinista y
no llama a ningún modelo. Cuando se habilite hará falta consentimiento por
ejecución, presupuesto y redacción de secretos.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener


PROVIDERS = {
    "openai": {"env": "OPENAI_API_KEY", "url": "https://api.openai.com/v1/models"},
    "anthropic": {"env": "ANTHROPIC_API_KEY", "url": "https://api.anthropic.com/v1/models?limit=1"},
}


class _NoRedirect(HTTPRedirectHandler):
    """Nunca reenviar una credencial a un destino indicado por una redirección."""

    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


class ProviderError(ValueError):
    pass


def _load() -> dict:
    from .vault import VaultError, get
    try:
        data = get("ai_keys")
    except VaultError:
        return {}
    return data if isinstance(data, dict) else {}


def _write(data: dict) -> None:
    from .vault import put
    put("ai_keys", data)


def _key(name: str) -> str | None:
    """La clave del usuario manda; la del entorno es el respaldo del operador."""
    stored = _load().get(name)
    if isinstance(stored, dict) and isinstance(stored.get("api_key"), str) and stored["api_key"]:
        return stored["api_key"]
    return os.environ.get(PROVIDERS[name]["env"]) or None


def provider_status() -> list[dict]:
    stored = _load()
    rows = []
    for name, config in PROVIDERS.items():
        entry = stored.get(name) if isinstance(stored.get(name), dict) else None
        from_user = bool(entry and entry.get("api_key"))
        rows.append({"id": name, "configured": bool(_key(name)),
                     "owner": "usuario" if from_user else "servidor" if os.environ.get(config["env"]) else None,
                     "last4": entry.get("last4") if from_user else None,
                     "saved_at": entry.get("saved_at") if from_user else None,
                     "env": config["env"]})
    return rows


def save_provider_key(name: str, api_key: str) -> dict:
    """Valida la clave contra el proveedor antes de guardarla; si falla, no se guarda."""
    if name not in PROVIDERS:
        raise ProviderError("Proveedor no admitido")
    if (not isinstance(api_key, str) or not 20 <= len(api_key) <= 400
            or any(character.isspace() or ord(character) < 33 or ord(character) > 126 for character in api_key)):
        raise ProviderError("Clave inválida")
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
        raise ProviderError("Proveedor no admitido")
    data = _load()
    if data.pop(name, None) is not None:
        _write(data)


def check_provider(name: str, api_key: str | None = None) -> dict:
    if name not in PROVIDERS:
        raise ValueError("Proveedor no admitido")
    config = PROVIDERS[name]
    key = api_key or _key(name)
    if not key:
        return {"provider": name, "status": "not_configured",
                "message": "Añade tu clave de API para habilitar la asistencia con IA"}
    headers = {"Accept": "application/json", "User-Agent": "AppSecAgent/0.2"}
    if name == "openai":
        headers["Authorization"] = f"Bearer {key}"
    else:
        headers["x-api-key"] = key
        headers["anthropic-version"] = "2023-06-01"
    request = Request(config["url"], headers=headers)
    try:
        with build_opener(_NoRedirect).open(request, timeout=8) as response:
            content = response.read(256_001)
            if len(content) > 256_000:
                return {"provider": name, "status": "error", "message": "Respuesta demasiado grande"}
            payload = json.loads(content)
    except HTTPError as exc:
        status = "invalid_credentials" if exc.code in (401, 403) else "rate_limited" if exc.code == 429 else "error"
        return {"provider": name, "status": status, "http_status": exc.code,
                "message": "El proveedor rechazó la comprobación"}
    except (URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError):
        return {"provider": name, "status": "unreachable", "message": "No se pudo verificar el proveedor"}
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
        return {"provider": name, "status": "error", "message": "Respuesta inesperada del proveedor"}
    return {"provider": name, "status": "connected", "models_visible": len(payload["data"]),
            "message": "Credencial aceptada; la inferencia y el modelo elegido aún no se han probado"}
