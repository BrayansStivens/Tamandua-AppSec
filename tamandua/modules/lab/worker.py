"""Proceso efímero para una secuencia de pruebas sobre el fixture aprobado.

Separar el proceso evita compartir estado del objetivo entre descubrimiento y
reproducción. Este proceso NO es una sandbox para código de clientes.
"""

from __future__ import annotations

import hashlib
import json
import runpy
import sys
from pathlib import Path

from tamandua.modules.lab.fixture import _request, validate_fixture_code


def _observe(status: int, payload: dict) -> dict:
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return {
        "status": status,
        "json_keys": sorted(payload.keys()),
        "tenant": payload.get("tenant"),
        "role": payload.get("role"),
        "document_tenants": sorted({row["tenant"] for row in payload.get("documents", [])
                                    if isinstance(row, dict) and isinstance(row.get("tenant"), str)}),
        "response_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
    }


def main() -> int:
    raw = sys.stdin.read(8193)
    if len(raw) > 8192:
        raise ValueError("Solicitud demasiado grande")
    task = json.loads(raw)
    variant = task["variant"]
    steps = task["steps"]
    if variant not in ("vulnerable", "fixed") or not isinstance(steps, list) or not 1 <= len(steps) <= 4:
        raise ValueError("Solicitud de prueba inválida")
    fixture_dir = validate_fixture_code(Path(task["fixture"]))
    lab_class = runpy.run_path(str(fixture_dir / "app.py"), run_name="approved_fixture")["TenantLab"]
    app = lab_class(variant == "vulnerable")
    try:
        observations = []
        for step in steps:
            if (step.get("method") not in ("GET", "POST", "PATCH")
                    or not isinstance(step.get("path"), str)
                    or not step["path"].startswith("/api/")
                    or step.get("token") not in ("token-alice", "token-bob", "token-admin")):
                raise ValueError("Paso fuera del laboratorio permitido")
            status, payload = _request(app, step)
            observations.append(_observe(status, payload))
    finally:
        app.db.close()
    print(json.dumps({"observations": observations}, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, KeyError, OSError) as exc:
        print(f"Error del worker: {exc}", file=sys.stderr)
        raise SystemExit(1)
