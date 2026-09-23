"""Ejecución determinista del único laboratorio sintético aprobado."""

from __future__ import annotations

import hashlib
import io
import json
import runpy
from pathlib import Path
from urllib.parse import urlsplit


TRUSTED_HASHES = {
    "app.py": "b2423f5b1c823d343370a46cb5c2db45fa3ec2f63d67745ed14c35765348eeb7",
    "cases.json": "d43a1fb4e3cb395a9a8d205c87ee99e53ae8dbd724c46166372bd23b88fae20e",
}


class FixtureError(ValueError):
    pass


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_fixture_code(fixture_dir: Path) -> Path:
    """Permite ejecutar únicamente el código del laboratorio fijado por hash.

    El motor de detección no abre ni consulta ``cases.json``.
    """
    fixture_dir = fixture_dir.resolve(strict=True)
    path = fixture_dir / "app.py"
    if (fixture_dir.name != "tenant-api-lab" or not path.is_file()
            or path.is_symlink() or _sha256(path) != TRUSTED_HASHES["app.py"]):
        raise FixtureError("Código del laboratorio no aprobado o modificado")
    return fixture_dir


def _request(app, spec: dict) -> tuple[int, dict]:
    body = json.dumps(spec["json"]).encode("utf-8") if "json" in spec else b""
    target = urlsplit(spec["path"])
    environ = {
        "REQUEST_METHOD": spec["method"],
        "PATH_INFO": target.path,
        "QUERY_STRING": target.query,
        "HTTP_AUTHORIZATION": f"Bearer {spec['token']}",
        "CONTENT_LENGTH": str(len(body)),
        "wsgi.input": io.BytesIO(body),
    }
    result: dict = {}

    def start_response(status: str, _headers: list) -> None:
        result["status"] = int(status.split()[0])

    payload = b"".join(app(environ, start_response))
    return result["status"], json.loads(payload)


def _checks(expected: dict, status: int, payload: dict) -> list[dict]:
    checks = [{"assertion": "status", "expected": expected["status"], "observed": status}]
    for key, value in expected.get("json", {}).items():
        checks.append({"assertion": f"json.{key}", "expected": value, "observed": payload.get(key)})
    if "has_key" in expected:
        key = expected["has_key"]
        checks.append({"assertion": f"has_key.{key}", "expected": True, "observed": key in payload})
    if "missing_key" in expected:
        key = expected["missing_key"]
        checks.append({"assertion": f"missing_key.{key}", "expected": True, "observed": key not in payload})
    tenants = {row.get("tenant") for row in payload.get("documents", []) if isinstance(row, dict)}
    if "documents_include_tenant" in expected:
        tenant = expected["documents_include_tenant"]
        checks.append({"assertion": f"includes_tenant.{tenant}", "expected": True, "observed": tenant in tenants})
    if "documents_exclude_tenant" in expected:
        tenant = expected["documents_exclude_tenant"]
        checks.append({"assertion": f"excludes_tenant.{tenant}", "expected": True, "observed": tenant not in tenants})
    for check in checks:
        check["passed"] = check["expected"] == check["observed"]
    return checks


def verify_fixture(fixture_dir: Path) -> dict:
    fixture_dir = fixture_dir.resolve(strict=True)
    if not fixture_dir.is_dir():
        raise FixtureError("El fixture debe ser un directorio")
    for name, digest in TRUSTED_HASHES.items():
        path = fixture_dir / name
        if not path.is_file() or path.is_symlink() or _sha256(path) != digest:
            raise FixtureError(f"Fixture no aprobado o modificado: {name}")
    cases = json.loads((fixture_dir / "cases.json").read_text(encoding="utf-8"))
    if cases.get("fixture") != "tenant-api-lab" or len(cases.get("cases", [])) != 10:
        raise FixtureError("Catálogo del fixture inesperado")
    lab_class = runpy.run_path(str(fixture_dir / "app.py"), run_name="approved_fixture")["TenantLab"]
    results = []
    for case in cases["cases"]:
        app = lab_class(case["variant"] == "vulnerable")
        try:
            status, payload = _request(app, case["request"])
        finally:
            app.db.close()
        checks = _checks(case["expected"], status, payload)
        results.append({
            "id": case["id"],
            "variant": case["variant"],
            "category": case["category"],
            "cwe": case["cwe"],
            "request": case["request"],
            "checks": checks,
            "passed": all(item["passed"] for item in checks),
        })
    return {"fixture": cases["fixture"], "fixture_version": cases["dataset_version"],
            "source_sha256": TRUSTED_HASHES.copy(), "cases": results}
