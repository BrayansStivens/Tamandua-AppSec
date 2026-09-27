"""Settings: declared in one place, checked at start-up with a clear message, read when asked for."""

import unittest
from unittest.mock import patch

from tamandua.shared import settings
from tamandua.shared.i18n import text


def problems(**environment) -> list[str]:
    base = {"TAMANDUA_DATABASE_URL": "postgresql+psycopg://u:p@db/t"}
    return [text(problem, "en") for problem in settings.problems({**base, **environment})]


class SettingsTests(unittest.TestCase):
    def test_a_valid_environment_has_no_problems(self):
        self.assertEqual(problems(TAMANDUA_PUBLIC_URL="https://tamandua.example.com", TAMANDUA_PR_POLL_SECONDS="120",
                                  TAMANDUA_EMBEDDED_WORKER="false", TAMANDUA_LOG_LEVEL="debug",
                                  TAMANDUA_MASTER_KEY="MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="), [])

    def test_each_mistake_is_named(self):
        found = problems(TAMANDUA_PR_POLL_SECONDS="5", TAMANDUA_EMBEDDED_WORKER="maybe", TAMANDUA_REQUIRE_TOTP="some",
                         TAMANDUA_PUBLIC_URL="tamandua.example.com", TAMANDUA_MASTER_KEY="short", TAMANDUA_METRICS_TOKEN="abc")
        self.assertEqual(len(found), 6)
        for name in ("TAMANDUA_PR_POLL_SECONDS", "TAMANDUA_EMBEDDED_WORKER", "TAMANDUA_REQUIRE_TOTP", "TAMANDUA_PUBLIC_URL",
                     "TAMANDUA_MASTER_KEY", "TAMANDUA_METRICS_TOKEN"):
            self.assertTrue(any(name in problem for problem in found), name)
        self.assertNotIn("abc", " ".join(found).replace("TAMANDUA_METRICS_TOKEN", ""))  # a secret's value is never echoed

    def test_the_database_url_is_required(self):
        self.assertIn("TAMANDUA_DATABASE_URL", text(settings.problems({})[0], "en"))

    def test_values_are_read_when_asked_with_defaults_and_minimums(self):
        with patch.dict("os.environ", {"TAMANDUA_PR_POLL_SECONDS": "10", "TAMANDUA_ALLOWED_ORIGINS": " https://a.example/ ,https://b.example"}):
            self.assertEqual(settings.integer("TAMANDUA_PR_POLL_SECONDS"), 60)
            self.assertEqual(settings.items("TAMANDUA_ALLOWED_ORIGINS"), ["https://a.example", "https://b.example"])
            self.assertTrue(settings.flag("TAMANDUA_EMBEDDED_WORKER"))  # default on
        with self.assertRaises(KeyError):
            settings.text("SOMETHING_NOT_DECLARED")

    def test_no_module_reads_the_environment_on_its_own(self):
        import pathlib
        import re
        allowed = {"shared/settings.py", "shared/paths.py", "modules/scanning/engines.py",  # engines: HOSTNAME, the child env
                   "modules/findings/fix_examples.py"}  # example code shown to users
        root = pathlib.Path(settings.__file__).resolve().parents[1]
        offenders = [str(path.relative_to(root)) for path in root.rglob("*.py")
                     if str(path.relative_to(root)) not in allowed and re.search(r"os\.environ|os\.getenv", path.read_text(encoding="utf-8"))]
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()
