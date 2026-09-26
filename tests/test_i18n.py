"""Catalogs stay complete in both languages and messages render per reader."""

import json
import re
import unittest
from pathlib import Path
from unittest.mock import patch

from tamandua.shared import i18n

ROOT = Path(__file__).resolve().parents[1]
WEB_LOCALES = ROOT / "web/src/shared/i18n/locales"


def keys(tree: dict, prefix: str = "") -> set[str]:
    out = set()
    for key, value in tree.items():
        path = f"{prefix}.{key}" if prefix else key
        out |= keys(value, path) if isinstance(value, dict) else {path}
    return out


def params(text: str) -> set[str]:
    return set(re.findall(r"\{\{\s*(\w+)", text))


def flat(tree: dict, prefix: str = "") -> dict[str, str]:
    out = {}
    for key, value in tree.items():
        path = f"{prefix}.{key}" if prefix else key
        out.update(flat(value, path) if isinstance(value, dict) else {path: str(value)})
    return out


class CatalogTests(unittest.TestCase):
    def assert_parity(self, base: Path):
        for english in sorted((base / "en").glob("*.json")):
            spanish = base / "es" / english.name
            self.assertTrue(spanish.exists(), f"missing es/{english.name}")
            en, es = flat(json.loads(english.read_text())), flat(json.loads(spanish.read_text()))
            self.assertEqual(set(en), set(es), english.name)
            for key in en:
                self.assertEqual(params(en[key]), params(es[key]), f"{english.name}: {key}")
                self.assertTrue(es[key].strip(), f"{english.name}: {key} is empty")
        self.assertEqual({path.name for path in (base / "es").glob("*.json")}, {path.name for path in (base / "en").glob("*.json")})

    def test_server_catalogs_match(self):
        self.assert_parity(i18n.LOCALE_DIR)

    def test_panel_catalogs_match(self):
        self.assert_parity(WEB_LOCALES)

    def test_every_server_key_in_code_exists(self):
        known = set(i18n.catalog("en"))
        source = "\n".join(path.read_text() for path in (ROOT / "tamandua").rglob("*.py"))
        used = set(re.findall(r"\bmsg\(\s*[\"']([\w.-]+)[\"']", source)) | set(re.findall(r"\bt\(\s*[\"']([\w.-]+)[\"']", source))
        missing = {key for key in used if key not in known and f"{key}_one" not in known}
        self.assertEqual(missing, set())

    def test_every_panel_key_in_code_exists(self):
        namespaces = {path.stem: keys(json.loads(path.read_text())) for path in (WEB_LOCALES / "en").glob("*.json")}
        missing = set()
        for path in (ROOT / "web/src").rglob("*.tsx"):
            text = path.read_text()
            default = re.search(r"useTranslation\(\s*'([\w-]+)'", text)
            for key in re.findall(r"\bt\(\s*'([\w:.-]+)'", text):
                namespace, _, name = key.rpartition(":")
                namespace = namespace or (default[1] if default else "common")
                known = namespaces.get(namespace, set())
                if name not in known and f"{name}_one" not in known and f"{name}_other" not in known:
                    missing.add(f"{path.relative_to(ROOT)}: {namespace}:{name}")
        self.assertEqual(missing, set())


class RenderTests(unittest.TestCase):
    def test_messages_render_per_reader_and_fall_back_to_english(self):
        stored = {"error": i18n.msg("api.login_required"), "items": [i18n.msg("api.not_found")]}
        self.assertEqual(i18n.localize(stored, "en")["error"], "Sign in to continue")
        self.assertEqual(i18n.localize(stored, "es")["items"], ["Ruta no encontrada"])
        self.assertEqual(i18n.t("api.no_such_key", "es"), "api.no_such_key")

    def test_inline_text_uses_the_readers_language_or_what_exists(self):
        both, only_spanish = i18n.inline({"en": "Use parameters", "es": "Usa parámetros"}), i18n.inline({"es": "Solo español"})
        self.assertEqual((i18n.localize(both, "es"), i18n.localize(both, "en")), ("Usa parámetros", "Use parameters"))
        self.assertEqual(i18n.localize(only_spanish, "en"), "Solo español")

    def test_accept_language_negotiation(self):
        with patch.dict("os.environ", {"TAMANDUA_DEFAULT_LOCALE": "en"}):
            self.assertEqual(i18n.negotiate("es-CO,es;q=0.9,en;q=0.8"), "es")
            self.assertEqual(i18n.negotiate("fr-FR,en;q=0.5"), "en")
            self.assertEqual(i18n.negotiate("de"), "en")
            self.assertEqual(i18n.negotiate(None), "en")
            self.assertEqual(i18n.negotiate("en;q=0.2, es;q=0.9"), "es")


if __name__ == "__main__":
    unittest.main()
