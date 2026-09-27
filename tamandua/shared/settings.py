"""Every setting Tamandua reads from the environment, declared in one place.

Values are read when asked for (tests and the CLI change the environment at run time), and `problems()` checks them
all once at start-up, so a typo stops the server with a clear message instead of failing later. Reading a setting
that isn't declared here is a programming error.
"""

from __future__ import annotations

import base64
import binascii
import os
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlsplit

from tamandua.shared.i18n import msg

TRUE, FALSE = ("1", "true", "yes", "on"), ("0", "false", "no", "off", "")


@dataclass(frozen=True)
class Setting:
    default: str = ""
    kind: str = "text"  # text, flag, integer, choice, url, urls, key, token
    choices: tuple[str, ...] = ()
    minimum: int | None = None
    required: bool = False


SETTINGS: dict[str, Setting] = {
    # Where things are
    "TAMANDUA_DATABASE_URL": Setting(required=True),
    "TAMANDUA_DATA_DIR": Setting(),
    "TAMANDUA_CONFIG_DIR": Setting(),
    # How the panel is reached
    "TAMANDUA_PUBLIC_URL": Setting(kind="url"),
    "TAMANDUA_ALLOWED_ORIGINS": Setting(kind="urls"),
    "TAMANDUA_ALLOW_INSECURE_HTTP": Setting(kind="flag"),
    "TAMANDUA_BIND": Setting(default="127.0.0.1"),
    "TAMANDUA_FORWARDED_ALLOW_IPS": Setting(),
    "TAMANDUA_TLS_CERT": Setting(),
    "TAMANDUA_TLS_KEY": Setting(),
    "TAMANDUA_EMBEDDED_WORKER": Setting(default="1", kind="flag"),
    # Keys and tokens
    "TAMANDUA_MASTER_KEY": Setting(kind="key"),
    "TAMANDUA_SESSION_KEY": Setting(kind="key"),
    "TAMANDUA_METRICS_TOKEN": Setting(kind="token"),
    "TAMANDUA_CRON_TOKEN": Setting(kind="token"),
    "CRON_SECRET": Setting(kind="token"),  # what Vercel Cron sends; accepted as the cron token
    "TAMANDUA_REQUIRE_TOTP": Setting(default="admins", kind="choice", choices=("admins", "all", "none")),
    # Behaviour
    "TAMANDUA_DEFAULT_LOCALE": Setting(default="en", kind="choice", choices=("en", "es")),
    "TAMANDUA_LOG_LEVEL": Setting(default="INFO", kind="choice", choices=("DEBUG", "INFO", "WARNING", "ERROR")),
    "TAMANDUA_LOG_FORMAT": Setting(default="text", kind="choice", choices=("text", "json")),
    "TAMANDUA_LOG_FILE": Setting(),
    "TAMANDUA_ENGINE_RUNNER": Setting(default="auto", kind="choice", choices=("auto", "docker", "local")),
    "TAMANDUA_PERIODIC": Setting(default="leader", kind="choice", choices=("leader", "external")),
    "TAMANDUA_PR_POLL_SECONDS": Setting(default="300", kind="integer", minimum=60),
    "TAMANDUA_BRANCH_MIN_MINUTES": Setting(default="60", kind="integer", minimum=10),
    "TAMANDUA_ADVISORY_WATCH_HOURS": Setting(default="24", kind="integer", minimum=0),
    "TAMANDUA_DOWNLOAD_TIMEOUT": Setting(default="900", kind="integer", minimum=60),
    "TAMANDUA_CVE_SYNC": Setting(default="on", kind="flag"),
    "TAMANDUA_EUVD": Setting(default="on", kind="flag"),
    "TAMANDUA_NVD_API_KEY": Setting(),
    "TAMANDUA_ALLOW_PRIVATE_REGISTRIES": Setting(kind="flag"),
    "TAMANDUA_ALLOW_PRIVATE_WEBHOOKS": Setting(kind="flag"),
    # Engines started through the Docker socket mount folders by their path on the host
    "TAMANDUA_HOST_DATA_DIR": Setting(),
    "TAMANDUA_HOST_RULES_DIR": Setting(),
    # Integrations configured by the server instead of the panel
    "GITHUB_APP_ID": Setting(),
    "GITHUB_APP_SLUG": Setting(),
    "GITHUB_APP_PRIVATE_KEY_FILE": Setting(),
    "GITHUB_TOKEN": Setting(),
    "GITLAB_TOKEN": Setting(),
    "OPENAI_API_KEY": Setting(),
    "ANTHROPIC_API_KEY": Setting(),
    # Tests only: one PostgreSQL schema per data folder
    "TAMANDUA_DB_ISOLATE": Setting(kind="choice", choices=("", "data-dir")),
}


def _raw(name: str) -> str:
    setting = SETTINGS[name]  # KeyError: declare it above first
    return os.environ.get(name, "").strip() or setting.default


def text(name: str) -> str:
    return _raw(name)


def flag(name: str) -> bool:
    return _raw(name).lower() in TRUE


def integer(name: str) -> int:
    setting = SETTINGS[name]
    try:
        value = int(_raw(name))
    except ValueError:
        value = int(setting.default)
    return max(setting.minimum, value) if setting.minimum is not None else value


def items(name: str) -> list[str]:
    return [item.strip().rstrip("/") for item in _raw(name).split(",") if item.strip()]


def is_set(name: str) -> bool:
    return bool(os.environ.get(name, "").strip())


def _url_problem(name: str, value: str):
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.path not in ("", "/") or parts.query:
        return msg("cli.settings.invalid_url", name=name, value=value)
    return None


def _check(name: str, setting: Setting, environment: Mapping[str, str]):
    value = environment.get(name, "").strip()
    if not value:
        return msg("cli.settings.missing", name=name) if setting.required else None
    if setting.kind == "flag" and value.lower() not in TRUE + FALSE:
        return msg("cli.settings.invalid_flag", name=name, value=value)
    if setting.kind == "integer":
        try:
            number = int(value)
        except ValueError:
            return msg("cli.settings.invalid_integer", name=name, value=value)
        if setting.minimum is not None and number < setting.minimum:
            return msg("cli.settings.below_minimum", name=name, value=value, minimum=setting.minimum)
    if setting.kind == "choice" and value not in setting.choices and value.lower() not in setting.choices \
            and value.upper() not in setting.choices:
        return msg("cli.settings.invalid_choice", name=name, value=value, choices=", ".join(item for item in setting.choices if item))
    if setting.kind == "url":
        return _url_problem(name, value)
    if setting.kind == "urls":
        return next((problem for item in value.split(",") if item.strip()
                     for problem in [_url_problem(name, item.strip().rstrip("/"))] if problem), None)
    if setting.kind == "key":
        try:
            decoded = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError):
            decoded = b""
        if len(decoded) != 32:
            return msg("cli.settings.invalid_key", name=name)
    if setting.kind == "token" and len(value) < 32:
        return msg("cli.settings.short_token", name=name)
    return None


def problems(environment: Mapping[str, str] | None = None) -> list[dict]:
    """Every setting that is set but invalid, or required and missing, as messages."""
    environment = os.environ if environment is None else environment
    return [problem for name, setting in SETTINGS.items() if (problem := _check(name, setting, environment))]
