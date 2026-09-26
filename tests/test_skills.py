"""Skills públicas (skills/*/SKILL.md): formato Agent Skills válido y sin opciones de la CLI que no existan."""

import re
import unittest
from pathlib import Path

from tamandua.cli.main import build_parser

ROOT = Path(__file__).resolve().parents[1]
SKILLS = sorted((ROOT / "skills").glob("*/SKILL.md"))
NAME = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
GIT_OPTIONS = {"--short", "--show-toplevel"}  # de las órdenes de git que acompañan a Tamandua


def frontmatter(text: str) -> dict:
    match = re.match(r"^---\n(.*?)\n---\n", text, re.DOTALL)
    assert match, "falta el frontmatter"
    return {key: value.strip() for key, _, value in (line.partition(":") for line in match.group(1).splitlines())
            if key and not key.startswith(" ")}


def scan_options() -> set[str]:
    commands = next(action for action in build_parser()._actions if action.dest == "command")
    return {option for action in commands.choices["scan"]._actions for option in action.option_strings}


class SkillTests(unittest.TestCase):
    def test_skills_follow_the_agent_skills_format(self):
        self.assertGreaterEqual(len(SKILLS), 2)
        for path in SKILLS:
            meta = frontmatter(path.read_text(encoding="utf-8"))
            self.assertEqual(meta.get("name"), path.parent.name, path)
            self.assertRegex(meta["name"], NAME)
            self.assertLessEqual(len(meta["name"]), 64)
            self.assertTrue(0 < len(meta.get("description", "")) <= 1024, path)

    def test_skills_only_mention_options_the_cli_has(self):
        known = scan_options() | GIT_OPTIONS
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        for path in SKILLS:
            text = path.read_text(encoding="utf-8")
            self.assertEqual(set(re.findall(r"(?<![\w-])--[a-z][a-z-]+", text)) - known, set(), path)
            for target in re.findall(r"make (?:-s )?-C \S+ ([a-z-]+)", text):
                self.assertRegex(makefile, rf"(?m)^{target}:", f"{path}: make {target}")


if __name__ == "__main__":
    unittest.main()
