"""Registro de objetivos HTTPS con prueba DNS TXT antes de cualquier DAST."""

from __future__ import annotations

import http.client
import ipaddress
import json
import os
import re
import secrets
import socket
import ssl
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit


class DomainError(ValueError):
    pass


KINDS = ("web", "api", "surface")
CONTEXT_LIMIT = 400


def _path(data_dir: Path) -> Path:
    return data_dir / "domains.json"


def list_domains(data_dir: Path) -> list[dict]:
    try:
        rows = json.loads(_path(data_dir).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    if not isinstance(rows, list):
        raise DomainError("Registro de dominios inválido")
    return rows


def _host(url: str) -> tuple[str, str]:
    if not isinstance(url, str) or len(url) > 300:
        raise DomainError("URL inválida")
    try:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port
    except ValueError as exc:
        raise DomainError("URL o puerto inválido") from exc
    if (parsed.scheme != "https" or parsed.username or parsed.password or port is not None
            or parsed.fragment or parsed.query or not host or len(host) > 253):
        raise DomainError("Usa una URL HTTPS de dominio público, sin usuario, puerto, query ni fragmento")
    labels = host.split(".")
    if (len(labels) < 2 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)
            or not re.fullmatch(r"[a-z]{2,63}", labels[-1])
            or labels[-1] in {"local", "test", "invalid", "internal", "localhost"}):
        raise DomainError("Dominio público inválido")
    return host, f"https://{host}{parsed.path or '/'}"


def _declared_context(value) -> str:
    if value is None or value == "":
        return ""
    if not isinstance(value, str) or len(value) > CONTEXT_LIMIT:
        raise DomainError(f"El contexto admite hasta {CONTEXT_LIMIT} caracteres")
    cleaned = " ".join(value.split())
    if any(ord(character) < 32 or ord(character) == 127 for character in cleaned):
        raise DomainError("El contexto contiene caracteres de control")
    return cleaned


def _write(data_dir: Path, rows: list[dict]) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)
    target = _path(data_dir)
    temporary = target.with_suffix(".tmp")
    temporary.write_text(json.dumps(rows, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, target)


def register_domain(data_dir: Path, url: str, kind: str = "web", context: str = "") -> dict:
    host, normalized = _host(url)
    if kind not in KINDS:
        raise DomainError("Tipo de objetivo inválido")
    declared = _declared_context(context)
    rows = list_domains(data_dir)
    if any(item["host"] == host for item in rows):
        raise DomainError("El dominio ya está registrado")
    if len(rows) >= 20:
        raise DomainError("Máximo de dominios registrados alcanzado")
    record = {"id": secrets.token_hex(12), "host": host, "url": normalized, "kind": kind,
              "context": declared, "txt_name": f"_appsec-agent.{host}",
              "txt_value": f"appsec-agent-verify={secrets.token_urlsafe(24)}",
              "verified": False, "registered_at": datetime.now(timezone.utc).isoformat(), "verified_at": None}
    rows.append(record)
    _write(data_dir, rows)
    return record


def verify_domain(data_dir: Path, domain_id: str) -> dict:
    if not isinstance(domain_id, str) or not re.fullmatch(r"[0-9a-f]{24}", domain_id):
        raise DomainError("ID de dominio inválido")
    rows = list_domains(data_dir)
    record = next((item for item in rows if item["id"] == domain_id), None)
    if record is None:
        raise DomainError("Dominio no encontrado")
    try:
        result = subprocess.run(["dig", "+short", "TXT", record["txt_name"]], capture_output=True,
                                text=True, timeout=8, check=False, env={"PATH": "/usr/bin:/bin"})
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DomainError("No se pudo consultar DNS") from exc
    if result.returncode != 0:
        raise DomainError("La consulta DNS falló")
    values = [line.strip().strip('"').replace('" "', '') for line in result.stdout.splitlines()]
    if record["txt_value"] not in values:
        raise DomainError("No se encontró el TXT de verificación; revisa el nombre, el valor y la propagación")
    record["verified"] = True
    record["verified_at"] = datetime.now(timezone.utc).isoformat()
    _write(data_dir, rows)
    return record


def _is_public(address: str) -> bool:
    try:
        return ipaddress.ip_address(address.split("%")[0]).is_global
    except ValueError:
        return False


def check_reachability(url: str) -> dict:
    """Dice si el objetivo contesta por HTTPS antes de registrarlo.

    No es una prueba de seguridad ni un pentest: es un HEAD de un solo salto,
    sin redirecciones. Resuelve el host y exige que todas sus direcciones sean
    públicas antes de conectar, y luego conecta a la IP ya resuelta para que el
    sondeo no termine en una dirección interna.
    """
    host, normalized = _host(url)
    path = urlsplit(normalized).path or "/"
    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return {"host": host, "reachable": False, "status": "dns_error",
                "detail": "El dominio no resuelve en DNS."}
    addresses = sorted({info[4][0] for info in infos})
    if not addresses:
        return {"host": host, "reachable": False, "status": "dns_error",
                "detail": "El dominio no resuelve en DNS."}
    if not all(_is_public(address) for address in addresses):
        return {"host": host, "reachable": False, "status": "private_address",
                "detail": "El dominio resuelve a una dirección privada o reservada; no se sondea."}
    ssl_context = ssl.create_default_context()
    try:
        with socket.create_connection((addresses[0], 443), timeout=6) as raw:
            with ssl_context.wrap_socket(raw, server_hostname=host) as secure:
                connection = http.client.HTTPSConnection(host, 443, timeout=6)
                connection.sock = secure
                connection.request("HEAD", path, headers={
                    "Host": host, "User-Agent": "appsec-agent-local", "Accept": "*/*", "Connection": "close"})
                code = connection.getresponse().status
    except ssl.SSLCertVerificationError:
        return {"host": host, "reachable": False, "status": "tls_error",
                "detail": "El certificado TLS no valida para este host."}
    except (OSError, http.client.HTTPException):
        return {"host": host, "reachable": False, "status": "unreachable",
                "detail": "No hubo respuesta HTTPS en el puerto 443."}
    return {"host": host, "reachable": True, "status": "reachable", "http_status": code,
            "detail": f"Respuesta HTTPS {code} desde {addresses[0]}."}
