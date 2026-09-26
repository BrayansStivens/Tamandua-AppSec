"""Capas del panel (FSD ligero): app → pages → features → shared. Una capa no importa de las de arriba."""

import re
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "web" / "src"
ORDER = ["app", "pages", "features", "shared"]  # de arriba abajo
IMPORT = re.compile(r"""from\s+['"]@/(?P<layer>[a-z]+)/""")


class WebLayersTests(unittest.TestCase):
    def test_no_layer_imports_from_a_layer_above(self):
        violations = []
        for path in sorted(SRC.rglob("*.ts*")):
            parts = path.relative_to(SRC).parts
            if parts[0] not in ORDER:
                continue
            here = ORDER.index(parts[0])
            for match in IMPORT.finditer(path.read_text(encoding="utf-8")):
                target = match.group("layer")
                if target in ORDER and ORDER.index(target) < here:
                    violations.append(f"{path.relative_to(SRC)} importa de @/{target}")
        self.assertEqual(violations, [])


if __name__ == "__main__":
    unittest.main()
