"""Conexiones a proveedores de código: qué instalación se autorizó y quién lo hizo.

Aquí no se guarda ninguna credencial. El identificador de instalación no es un
secreto: sin la clave privada de la App no sirve para leer nada. Los tokens se
acuñan en memoria cuando hacen falta (ver `github_app`).
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from tamandua.shared import documents


class IntegrationError(ValueError):
    pass


def load(data_dir: Path) -> dict:
    data = documents.load(data_dir, "integrations", {})
    if not isinstance(data, dict):
        raise IntegrationError("Registro de integraciones inválido")
    return data


def _write(data_dir: Path, data: dict) -> None:
    documents.save(data_dir, "integrations", data)


def save_github(data_dir: Path, installation_id: int, details: dict, connected_by: str | None) -> dict:
    if not isinstance(installation_id, int) or not 0 < installation_id < 2**63:
        raise IntegrationError("Identificador de instalación inválido")
    record = {"provider": "github", "installation_id": installation_id,
              "account": details.get("account"), "account_type": details.get("account_type"),
              "repository_selection": details.get("repository_selection"),
              "permissions": details.get("permissions") or {},
              "connected_by": connected_by,
              "connected_at": datetime.now(timezone.utc).isoformat()}
    with documents.lock(data_dir, "integrations"):
        data = load(data_dir)
        records = github_connections(data_dir)
        records = [item for item in records if item["installation_id"] != installation_id]
        records.append(record)
        data["github"] = records
        _write(data_dir, data)
    return record


def github_connections(data_dir: Path) -> list[dict]:
    """Instalaciones conectadas."""
    value = load(data_dir).get("github")
    rows = value if isinstance(value, list) else []
    return [row for row in rows if isinstance(row, dict) and isinstance(row.get("installation_id"), int)
            and not isinstance(row["installation_id"], bool) and row["installation_id"] > 0]


def github_installations(data_dir: Path) -> list[int]:
    return [row["installation_id"] for row in github_connections(data_dir)]


def github_installation(data_dir: Path) -> int | None:
    rows = github_installations(data_dir)
    return rows[0] if rows else None


def clear_github(data_dir: Path, installation_id: int | None = None) -> None:
    with documents.lock(data_dir, "integrations"):
        data = load(data_dir)
        if installation_id is None:
            changed = data.pop("github", None) is not None
        else:
            current = github_connections(data_dir)
            rows = [row for row in current if row["installation_id"] != installation_id]
            changed = len(rows) != len(current)
            if rows:
                data["github"] = rows
            else:
                data.pop("github", None)
        if changed:
            _write(data_dir, data)
