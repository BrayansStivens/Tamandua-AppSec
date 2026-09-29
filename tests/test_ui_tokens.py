"""The panel only uses color tokens: no stray Tailwind color or hex value in the components.

The tokens (`text-danger`, `bg-warning-soft`, `border-info-line`…) have their light and dark values
in `web/src/index.css`, with WCAG AA contrast checked. A stray color bypasses that guarantee.
"""

import re
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / "web" / "src"
PALETTE = ("slate|gray|zinc|neutral|stone|red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|"
           "violet|purple|fuchsia|pink|rose")
RAW = re.compile(rf"(?<![\w-])(?:[a-z0-9\[\]&=_.-]+:)*(?:text|bg|border|ring|fill|stroke|decoration|outline|divide|from|to|via|"
                 rf"shadow|accent|placeholder|caret)-(?:(?:{PALETTE})-\d{{2,3}}|white|black)(?:/\d+)?(?![\w-])")
HEX = re.compile(r"#[0-9a-fA-F]{6}\b")
# The logo is an illustration with its own colors, not part of the interface.
EXEMPT = {"brand-mark.tsx"}


class TokenTests(unittest.TestCase):
    def test_components_use_only_color_tokens(self):
        found = []
        for path in sorted(SOURCE.rglob("*.ts*")):
            if path.name in EXEMPT:
                continue
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                for match in (*RAW.finditer(line), *HEX.finditer(line)):
                    found.append(f"{path.relative_to(SOURCE)}:{number} {match.group(0)}")
        self.assertEqual(found, [], "Usa los tokens de web/src/index.css en lugar de colores sueltos:\n" + "\n".join(found[:40]))


if __name__ == "__main__":
    unittest.main()
