"""Conexiones a proveedores de código: qué instalación se autorizó y quién lo hizo.

Aquí no se guarda ninguna credencial. El identificador de instalación no es un
secreto: sin la clave privada de la App no sirve para leer nada. Los tokens se
acuñan en memoria cuando hacen falta (ver `github_app`).
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path


class IntegrationError(ValueError):
    pass


def _path(data_dir: Path) -> Path:
    return data_dir / "integrations.json"


def load(data_dir: Path) -> dict:
    try:
        data = json.loads(_path(data_dir).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    if not isinstance(data, dict):
        raise IntegrationError("Registro de integraciones inválido")
    return data


def _write(data_dir: Path, data: dict) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)
    target = _path(data_dir)
    temporary = target.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, target)


def save_github(data_dir: Path, installation_id: int, details: dict, connected_by: str | None) -> dict:
    if not isinstance(installation_id, int) or not 0 < installation_id < 2**63:
        raise IntegrationError("Identificador de instalación inválido")
    record = {"provider": "github", "installation_id": installation_id,
              "account": details.get("account"), "account_type": details.get("account_type"),
              "repository_selection": details.get("repository_selection"),
              "permissions": details.get("permissions") or {},
              "connected_by": connected_by,
              "connected_at": datetime.now(timezone.utc).isoformat()}
    data = load(data_dir)
    data["github"] = record
    _write(data_dir, data)
    return record


def github_installation(data_dir: Path) -> int | None:
    record = load(data_dir).get("github")
    if not isinstance(record, dict):
        return None
    installation_id = record.get("installation_id")
    return installation_id if isinstance(installation_id, int) and installation_id > 0 else None


def clear_github(data_dir: Path) -> None:
    data = load(data_dir)
    if data.pop("github", None) is not None:
        _write(data_dir, data)
