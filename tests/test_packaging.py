"""El empaquetado no se desincroniza: versión, rutas de build y scripts de arranque."""

import re
import subprocess
import unittest
from pathlib import Path

from tamandua.app.http.core import VERSION
from tamandua.modules.scanning.engines import IMAGES

ROOT = Path(__file__).resolve().parents[1]


class PackagingTests(unittest.TestCase):
    def test_compose_version_and_build_paths_match_the_code(self):
        compose = (ROOT / "compose.yaml").read_text()
        self.assertIn(f"${{APPSEC_VERSION:-{VERSION}}}", compose)
        for path in re.findall(r"dockerfile: (\S+)", compose) + re.findall(r"build: (docker/\S+)", compose):
            self.assertTrue((ROOT / path).exists() or (ROOT / path / "Dockerfile").exists(), path)
        self.assertIn(IMAGES["opengrep"]["image"], compose)

    def test_container_is_hardened(self):
        compose = (ROOT / "compose.yaml").read_text()
        for setting in ("read_only: true", "no-new-privileges:true", "cap_drop:", '"${APPSEC_BIND:-127.0.0.1}'):
            self.assertIn(setting, compose)
        dockerfile = (ROOT / "docker/app/Dockerfile").read_text()
        self.assertIn("USER appsec", dockerfile)
        self.assertRegex(dockerfile, r"FROM python:[^\s]+@sha256:[0-9a-f]{64}")
        self.assertRegex((ROOT / "docker/engines/opengrep/Dockerfile").read_text(), r"sha256sum -c")

    def test_scripts_are_valid_posix_sh(self):
        for script in sorted((ROOT / "scripts").glob("*.sh")):
            with self.subTest(script=script.name):
                self.assertEqual(subprocess.run(["sh", "-n", str(script)], capture_output=True).returncode, 0)

    def test_every_make_target_is_documented(self):
        makefile = (ROOT / "Makefile").read_text()
        targets = re.findall(r"^([a-z-]+):(?!=)", makefile, re.M)
        undocumented = [name for name in targets if name != "ps" and not re.search(rf"^{name}:.*## ", makefile, re.M)]
        self.assertEqual(undocumented, [])
        self.assertIn("up", targets)


if __name__ == "__main__":
    unittest.main()
