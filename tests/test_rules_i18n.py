"""Every Tamandua rule (rules/*.yml) carries its title and fix in English and Spanish."""

import json
import re
import unittest
from pathlib import Path

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
RULE_START = re.compile(r"^  - id: (\S+)$", re.M)
QUOTED = r'("(?:[^"\\]|\\.)*")'


def _texts(block: str, field: str) -> dict[str, str]:
    """`field: {en: "...", es: "..."}` inside a rule's metadata (no PyYAML: the rules keep this exact shape)."""
    match = re.search(rf"^\s+{field}: \{{en: {QUOTED},\s*es: {QUOTED}\}}", block, re.M)
    return {"en": json.loads(match[1]), "es": json.loads(match[2])} if match else {}


def rules() -> dict[str, str]:
    found = {}
    for path in sorted(RULES_DIR.glob("*.yml")):
        source = path.read_text(encoding="utf-8")
        starts = list(RULE_START.finditer(source))
        for index, start in enumerate(starts):
            end = starts[index + 1].start() if index + 1 < len(starts) else len(source)
            found[start[1]] = source[start.start():end]
    return found


class RuleTextsTests(unittest.TestCase):
    def test_every_rule_has_title_and_fix_in_both_languages(self):
        found = rules()
        self.assertGreaterEqual(len(found), 50)
        for rule, block in found.items():
            for field in ("title", "fix"):
                texts = _texts(block, field)
                for locale in ("en", "es"):
                    with self.subTest(rule=rule, field=field, locale=locale):
                        self.assertTrue(texts.get(locale, "").strip(), f"{rule}: metadata.{field}.{locale} missing")

    def test_message_is_the_english_fix(self):
        for rule, block in rules().items():
            with self.subTest(rule=rule):
                message = re.search(rf"^    message: {QUOTED}$", block, re.M)
                self.assertIsNotNone(message, rule)
                self.assertEqual(json.loads(message[1]), _texts(block, "fix").get("en"))

    def test_engine_keeps_both_languages_and_the_fingerprint_ignores_them(self):
        from tamandua.modules.scanning.engines import parse_opengrep
        from tamandua.shared.i18n import localize

        block = rules()["appsec.py.shell-command-non-literal"]
        title, fix = _texts(block, "title"), _texts(block, "fix")
        result = {"check_id": "rules.appsec.py.shell-command-non-literal", "path": "app.py", "start": {"line": 3},
                  "extra": {"lines": "os.system(cmd)", "severity": "ERROR", "message": fix["en"],
                            "metadata": {"cwe": [78], "owasp": "A05:2025", "category": "injection",
                                         "confidence": "MEDIUM", "title": title, "fix": fix}}}
        finding = parse_opengrep({"results": [result]})[0]
        self.assertEqual(localize(finding["title"], "en"), title["en"])
        self.assertEqual(localize(finding["title"], "es"), title["es"])
        self.assertEqual(localize(finding["remediation"], "es"), fix["es"])

        bare = {**result, "extra": {**result["extra"], "metadata": {"cwe": [78], "category": "injection"}}}
        legacy = parse_opengrep({"results": [bare]})[0]
        self.assertEqual(legacy["fingerprint"], finding["fingerprint"])
        self.assertEqual(legacy["title"], "Injection: shell command non literal")
        self.assertEqual(localize(legacy["remediation"], "es"), fix["en"])


if __name__ == "__main__":
    unittest.main()
