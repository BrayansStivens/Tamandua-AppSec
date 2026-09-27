"""Message catalogs (en, es) and language-neutral messages.

Anything shown to a person is stored as `msg(key, **params)` and rendered with `localize(value, locale)` when it is
read: the API renders for the reader's `Accept-Language`, reports and PR comments for the chosen locale. Catalogs
live in `locales/<locale>/<namespace>.json` (same format as the panel's i18next files); keys are `namespace.path`.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

LOCALES = ("en", "es")
MARK = "$t"      # catalog message: {"$t": key, "params": {...}}
INLINE = "$l"    # text that carries its own languages (rules, user content): {"$l": {"en": ..., "es": ...}}
LOCALE_DIR = Path(__file__).resolve().parent / "locales"
_PARAM = re.compile(r"\{\{\s*(\w+)\s*\}\}")


def default_locale() -> str:
    """Locale for text nobody requests in person (PR comments, notifications, CLI): TAMANDUA_DEFAULT_LOCALE or en."""
    from tamandua.shared import settings  # settings renders its errors with this module
    value = settings.text("TAMANDUA_DEFAULT_LOCALE").lower()[:2]
    return value if value in LOCALES else "en"


def _flatten(tree: dict, prefix: str, out: dict[str, str]) -> None:
    for key, value in tree.items():
        path = f"{prefix}.{key}"
        if isinstance(value, dict):
            _flatten(value, path, out)
        else:
            out[path] = str(value)


@lru_cache(maxsize=None)
def catalog(locale: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for path in sorted((LOCALE_DIR / locale).glob("*.json")):
        _flatten(json.loads(path.read_text(encoding="utf-8")), path.stem, out)
    return out


def _lookup(key: str, locale: str, count) -> str | None:
    # Without a count (e.g. a message stored before the key became plural) the plural form still beats a raw key.
    suffixes = ((f"{key}_one" if count == 1 else f"{key}_other"),) if count is not None else (f"{key}_other",)
    for language in dict.fromkeys((locale, "en")):
        entries = catalog(language)
        for candidate in (*suffixes, key):
            if candidate in entries:
                return entries[candidate]
    return None


def t(key: str, locale: str | None = None, **params) -> str:
    locale = locale if locale in LOCALES else default_locale()
    text = _lookup(key, locale, params.get("count"))
    if text is None:
        return key
    return _PARAM.sub(lambda match: str(localize(params.get(match[1], ""), locale)), text)


def msg(key: str, **params) -> dict:
    """A message to render later, in the reader's language. Safe to store."""
    return {MARK: key, "params": params} if params else {MARK: key}


def inline(texts: dict) -> dict | str:
    """Text written in one or more languages; the reader gets theirs, then English, then whatever exists."""
    texts = {locale: str(value) for locale, value in (texts or {}).items() if isinstance(value, str) and value.strip()}
    return {INLINE: texts} if texts else ""


def is_msg(value) -> bool:
    return isinstance(value, dict) and isinstance(value.get(MARK), str)


def localize(value, locale: str | None = None):
    """Renders every message inside `value` (dicts and lists, at any depth)."""
    if isinstance(value, dict) and isinstance(value.get(INLINE), dict):
        texts = value[INLINE]
        locale = locale if locale in LOCALES else default_locale()
        return texts.get(locale) or texts.get("en") or next(iter(texts.values()), "")
    if is_msg(value):
        return t(value[MARK], locale, **{name: localize(param, locale) for name, param in (value.get("params") or {}).items()})
    if isinstance(value, dict):
        return {key: localize(item, locale) for key, item in value.items()}
    if isinstance(value, list):
        return [localize(item, locale) for item in value]
    return value


def text(value, locale: str | None = None) -> str:
    """A message or a plain string, as text."""
    rendered = localize(value, locale)
    return rendered if isinstance(rendered, str) else str(rendered or "")


def negotiate(header: str | None) -> str:
    """The best supported locale for an Accept-Language header."""
    ranked = []
    for index, part in enumerate(str(header or "").split(",")[:20]):
        tag, _, quality = part.strip().partition(";q=")
        try:
            weight = float(quality) if quality else 1.0
        except ValueError:
            continue
        base = tag.strip().lower()[:2]
        if base in LOCALES and weight > 0:
            ranked.append((-weight, index, base))
    return min(ranked)[2] if ranked else default_locale()
