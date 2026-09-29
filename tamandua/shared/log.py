"""Structured application logs, without secrets.

One event per line, on standard error (what every platform collects): human-readable by default, or one JSON object
per line with TAMANDUA_LOG_FORMAT=json. TAMANDUA_LOG_FILE also writes JSON to a rotated file (a relative path is
under the data folder). TAMANDUA_LOG_LEVEL=DEBUG to debug. Bodies, headers and tokens are never logged; `redact()`
masks whatever might slip into a message.
"""

from __future__ import annotations

import json
import logging
import re
import sys
import threading
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path

from tamandua.shared import settings

SECRET_PATTERN = re.compile(r"(ghp_|ghs_|ghu_|gho_|ghr_|github_pat_|sk-[A-Za-z0-9-]|xox[abp]-|AKIA|ATATT|eyJ[A-Za-z0-9_-]{10,}"
                            r"|tamandua-verify=|Bearer |Basic |token=|apiKey=|client_secret=)[A-Za-z0-9_\-./+=]*")
PEM_PATTERN = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)", re.S)
_configured = False
_known: set[str] = set()
_known_lock = threading.Lock()


def register_secret(value: str) -> None:
    """Specific values that must never appear (keys stored in the vault)."""
    if isinstance(value, str) and len(value) >= 12:
        with _known_lock:
            _known.add(value)
            # PEMs line by line too: a traceback can split the key into pieces.
            _known.update(line for line in value.splitlines() if len(line) >= 24)


def redact(text: str) -> str:
    text = PEM_PATTERN.sub("<clave privada redactada>", str(text))
    text = SECRET_PATTERN.sub(r"\1<redactado>", text)
    with _known_lock:
        known = sorted(_known, key=len, reverse=True)
    for value in known:
        if value in text:
            text = text.replace(value, "<redactado>")
    return text


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        event = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)) + f".{int(record.msecs):03d}Z",
                 "level": record.levelname.lower(), "logger": record.name, "msg": redact(record.getMessage())}
        for key, value in record.__dict__.items():
            if key in ("request_id", "run_id", "path", "method", "status", "duration_ms", "tool", "step", "user", "client",
                        "role", "reason", "mfa", "next", "retry_in", "remaining"):
                event[key] = redact(value) if isinstance(value, str) else value
        if record.exc_info:
            event["error"] = redact(self.formatException(record.exc_info))[-1500:]
        return json.dumps(event, ensure_ascii=False)


class ConsoleFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        extra = " ".join(f"{key}={getattr(record, key)}" for key in ("request_id", "run_id", "method", "path", "status", "duration_ms", "tool",
                                                                  "user", "client", "reason", "retry_in")
                         if getattr(record, key, None) is not None)
        return redact(f"{time.strftime('%H:%M:%S', time.localtime(record.created))} {record.levelname[:4]} {record.name}: {record.getMessage()} {extra}".rstrip())


def configure(data_dir: Path) -> logging.Logger:
    global _configured
    root = logging.getLogger("tamandua")
    if _configured:
        return root
    root.setLevel(getattr(logging, settings.text("TAMANDUA_LOG_LEVEL").upper(), logging.INFO))
    root.propagate = False
    console = logging.StreamHandler(sys.stderr)
    console.setFormatter(JsonFormatter() if settings.text("TAMANDUA_LOG_FORMAT") == "json" else ConsoleFormatter())
    handlers: list[logging.Handler] = [console]
    configured = settings.text("TAMANDUA_LOG_FILE")
    if configured:
        path = Path(configured) if Path(configured).is_absolute() else data_dir / configured
        path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(path, maxBytes=10_000_000, backupCount=5, encoding="utf-8")
        file_handler.setFormatter(JsonFormatter())
        handlers.append(file_handler)
    root.handlers = handlers
    _configured = True
    return root


def get(component: str) -> logging.Logger:
    return logging.getLogger(f"tamandua.{component}")
