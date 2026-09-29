"""Registry of HTTPS targets, with DNS TXT proof before any DAST."""

from __future__ import annotations

import http.client
import ipaddress
import re
import secrets
import socket
import ssl
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from tamandua.shared import documents
from tamandua.shared.i18n import msg, text
from tamandua.version import USER_AGENT


class DomainError(ValueError):
    """`message` is what people read (rendered per reader); str() stays English, for logs."""

    def __init__(self, message):
        super().__init__(text(message, "en"))
        self.message = message


KINDS = ("web", "api", "surface")
CONTEXT_LIMIT = 400


def list_domains(data_dir: Path) -> list[dict]:
    rows = documents.load(data_dir, "domains", [])
    if not isinstance(rows, list):
        raise DomainError(msg("sources.domains.invalid_registry"))
    return rows


def _host(url: str) -> tuple[str, str]:
    if not isinstance(url, str) or len(url) > 300:
        raise DomainError(msg("sources.domains.invalid_url"))
    try:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port
    except ValueError as exc:
        raise DomainError(msg("sources.domains.invalid_url_port")) from exc
    if (parsed.scheme != "https" or parsed.username or parsed.password or port is not None
            or parsed.fragment or parsed.query or not host or len(host) > 253):
        raise DomainError(msg("sources.domains.https_only"))
    labels = host.split(".")
    if (len(labels) < 2 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)
            or not re.fullmatch(r"[a-z]{2,63}", labels[-1])
            or labels[-1] in {"local", "test", "invalid", "internal", "localhost"}):
        raise DomainError(msg("sources.domains.invalid_domain"))
    return host, f"https://{host}{parsed.path or '/'}"


def _declared_context(value) -> str:
    if value is None or value == "":
        return ""
    if not isinstance(value, str) or len(value) > CONTEXT_LIMIT:
        raise DomainError(msg("sources.domains.context_length", max=CONTEXT_LIMIT))
    cleaned = " ".join(value.split())
    if any(ord(character) < 32 or ord(character) == 127 for character in cleaned):
        raise DomainError(msg("sources.domains.context_control"))
    return cleaned


def _write(data_dir: Path, rows: list[dict]) -> None:
    documents.save(data_dir, "domains", rows)


def register_domain(data_dir: Path, url: str, kind: str = "web", context: str = "") -> dict:
    host, normalized = _host(url)
    if kind not in KINDS:
        raise DomainError(msg("sources.domains.invalid_kind"))
    declared = _declared_context(context)
    rows = list_domains(data_dir)
    if any(item["host"] == host for item in rows):
        raise DomainError(msg("sources.domains.already_registered"))
    if len(rows) >= 20:
        raise DomainError(msg("sources.domains.limit"))
    record = {"id": secrets.token_hex(12), "host": host, "url": normalized, "kind": kind,
              "context": declared, "txt_name": f"_tamandua.{host}",
              "txt_value": f"tamandua-verify={secrets.token_urlsafe(24)}",
              "verified": False, "registered_at": datetime.now(timezone.utc).isoformat(), "verified_at": None}
    rows.append(record)
    _write(data_dir, rows)
    return record


def verify_domain(data_dir: Path, domain_id: str) -> dict:
    if not isinstance(domain_id, str) or not re.fullmatch(r"[0-9a-f]{24}", domain_id):
        raise DomainError(msg("sources.domains.invalid_id"))
    rows = list_domains(data_dir)
    record = next((item for item in rows if item["id"] == domain_id), None)
    if record is None:
        raise DomainError(msg("sources.domains.not_found"))
    try:
        result = subprocess.run(["dig", "+short", "TXT", record["txt_name"]], capture_output=True,
                                text=True, timeout=8, check=False, env={"PATH": "/usr/bin:/bin"})
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DomainError(msg("sources.domains.dns_unavailable")) from exc
    if result.returncode != 0:
        raise DomainError(msg("sources.domains.dns_failed"))
    values = [line.strip().strip('"').replace('" "', '') for line in result.stdout.splitlines()]
    if record["txt_value"] not in values:
        raise DomainError(msg("sources.domains.txt_missing"))
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
    """Tells whether the target answers over HTTPS before registering it.

    Not a security test or a pentest: a single-hop HEAD, no redirects. It
    resolves the host and requires every address to be public before
    connecting, then connects to the already-resolved IP so the probe cannot
    end up at an internal address.
    """
    host, normalized = _host(url)
    path = urlsplit(normalized).path or "/"
    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return {"host": host, "reachable": False, "status": "dns_error",
                "detail": msg("sources.domains.check.dns_error")}
    addresses = sorted({info[4][0] for info in infos})
    if not addresses:
        return {"host": host, "reachable": False, "status": "dns_error",
                "detail": msg("sources.domains.check.dns_error")}
    if not all(_is_public(address) for address in addresses):
        return {"host": host, "reachable": False, "status": "private_address",
                "detail": msg("sources.domains.check.private_address")}
    ssl_context = ssl.create_default_context()
    try:
        with socket.create_connection((addresses[0], 443), timeout=6) as raw:
            with ssl_context.wrap_socket(raw, server_hostname=host) as secure:
                connection = http.client.HTTPSConnection(host, 443, timeout=6)
                connection.sock = secure
                connection.request("HEAD", path, headers={
                    "Host": host, "User-Agent": USER_AGENT, "Accept": "*/*", "Connection": "close"})
                code = connection.getresponse().status
    except ssl.SSLCertVerificationError:
        return {"host": host, "reachable": False, "status": "tls_error",
                "detail": msg("sources.domains.check.tls_error")}
    except (OSError, http.client.HTTPException):
        return {"host": host, "reachable": False, "status": "unreachable",
                "detail": msg("sources.domains.check.unreachable")}
    return {"host": host, "reachable": True, "status": "reachable", "http_status": code,
            "detail": msg("sources.domains.check.reachable", code=code, address=addresses[0])}


def locked(data_dir: Path):
    """Cross-process lock on the domain registry, for read-modify-write."""
    return documents.lock(data_dir, "domains")
