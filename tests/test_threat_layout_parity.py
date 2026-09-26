"""El editor (threat-layout.ts) y las exportaciones (threat_diagram.py) colocan el diagrama igual.

Se ejecuta el TypeScript con Node (≥ 22.6 quita los tipos sin compilar). Sin Node, la prueba se omite.
"""

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from tamandua.modules.threats import diagram as threat_diagram
from tamandua.modules.threats import model as tm

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = sorted((ROOT / "web/src/examples/threat-models").glob("*.json"))


def _node_ok() -> bool:
    node = shutil.which("node")
    if not node:
        return False
    version = subprocess.run([node, "--version"], capture_output=True, text=True).stdout.strip().lstrip("v").split(".")
    return (int(version[0]), int(version[1])) >= (22, 6)


@unittest.skipUnless(_node_ok(), "Node ≥ 22.6 no disponible")
class LayoutParityTests(unittest.TestCase):
    def test_editor_and_exports_place_every_example_the_same(self):
        with tempfile.TemporaryDirectory() as folder:
            script = Path(folder) / "layout.ts"
            shutil.copy(ROOT / "web/src/components/threat-layout.ts", script)
            for path in EXAMPLES:
                model = tm.from_portable(json.loads(path.read_text(encoding="utf-8")))
                model = {**model, "components": [{**item, "position": None} for item in model["components"]]}
                (Path(folder) / "model.json").write_text(json.dumps(model))
                code = ("const {autoLayout} = await import(process.argv[1]); import fs from 'fs';"
                        "console.log(JSON.stringify(autoLayout(JSON.parse(fs.readFileSync(process.argv[2])))))")
                output = subprocess.run(["node", "--no-warnings", "--input-type=module", "-e", code, str(script), str(Path(folder) / "model.json")],
                                        capture_output=True, text=True, check=True).stdout
                editor = json.loads(output)
                exported = threat_diagram.auto_layout(model)
                with self.subTest(example=path.name):
                    self.assertEqual(editor["positions"], exported["nodes"])
                    self.assertEqual(editor["boxes"], exported["boundaries"])


if __name__ == "__main__":
    unittest.main()
