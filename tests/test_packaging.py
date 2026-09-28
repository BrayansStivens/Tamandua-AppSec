"""El empaquetado no se desincroniza: versión, rutas de build y scripts de arranque."""

import json
import os
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

from tamandua.version import VERSION
from tamandua.modules.scanning.engines import IMAGES

ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILES = ("compose.yaml", "compose.prod.yaml", "compose.images.yaml")


class PackagingTests(unittest.TestCase):
    def test_compose_version_and_build_paths_match_the_code(self):
        compose = (ROOT / "compose.yaml").read_text()
        self.assertIn(f"${{TAMANDUA_VERSION:-{VERSION}}}", compose)
        for path in re.findall(r"dockerfile: (\S+)", compose) + re.findall(r"build: (docker/\S+)", compose):
            self.assertTrue((ROOT / path).exists() or (ROOT / path / "Dockerfile").exists(), path)
        self.assertIn(IMAGES["opengrep"]["image"], compose)

    def test_host_settings_never_reach_the_app(self):
        """.env entra entero en el contenedor (env_file): una variable del host con el nombre de una de la app la pisaría
        (p. ej. la interfaz publicada en el host acabaría siendo la de escucha dentro del contenedor)."""
        compose = "\n".join((ROOT / name).read_text() for name in COMPOSE_FILES)
        host = {name for line in compose.splitlines() if re.match(r"\s*(- |user:|image:|FROM )", line)
                for name in re.findall(r"\$\{(TAMANDUA_[A-Z_]+)", line)}
        # Only for compose and Caddy: the app gets the URL and origins already derived from it.
        host |= {"TAMANDUA_DOMAIN", "TAMANDUA_BACKUP_INTERVAL_HOURS", "TAMANDUA_BACKUP_KEEP_DAYS"}
        self.assertTrue({"TAMANDUA_HOST_BIND", "TAMANDUA_IMAGE", "TAMANDUA_IMAGE_TAG", "TAMANDUA_BACKUP_DIR"} <= host, host)
        source = "\n".join(path.read_text() for path in (ROOT / "tamandua").rglob("*.py"))
        self.assertEqual({name for name in host if name in source}, set())

    def test_every_image_is_pinned(self):
        """Third-party images by digest (compose and Dockerfiles); ours are built here or come from TAMANDUA_IMAGE."""
        for name in COMPOSE_FILES:
            for image in re.findall(r"^\s*image: *\"?([^\"\s]+)", (ROOT / name).read_text(), re.M):
                with self.subTest(file=name, image=image):
                    self.assertTrue(re.search(r"@sha256:[0-9a-f]{64}$", image) or image.startswith(("localhost/tamandua/", "${TAMANDUA_IMAGE")), image)
        for dockerfile in (ROOT / "docker").rglob("Dockerfile"):
            text = dockerfile.read_text()
            stages = set(re.findall(r"^FROM .+ AS (\S+)$", text, re.M))
            for base in re.findall(r"^FROM (?:--platform=\S+ )?(\S+)", text, re.M):
                if base in stages:  # an earlier stage of the same file, not an image
                    continue
                with self.subTest(file=str(dockerfile.relative_to(ROOT)), base=base):
                    self.assertRegex(base, r"@sha256:[0-9a-f]{64}$")
        self.assertRegex((ROOT / "compose.prod.yaml").read_text(), r"image: caddy:[0-9.]+-alpine@sha256:[0-9a-f]{64}")

    def test_proxy_limits_sit_above_the_apps(self):
        """Caddy's request limit is above the app's (the app gives the precise error) and its upstream keep-alive below
        uvicorn's, so it never reuses a connection the app is closing (a random 502)."""
        from tamandua.app.api import MAX_BODY
        caddyfile = (ROOT / "docker/caddy/Caddyfile").read_text()
        self.assertIn("./docker/caddy/Caddyfile:/etc/caddy/Caddyfile:ro", (ROOT / "compose.prod.yaml").read_text())
        self.assertGreaterEqual(int(re.search(r"max_size (\d+)MB", caddyfile).group(1)) * 1_000_000, MAX_BODY)
        server = (ROOT / "tamandua/app/api/server.py").read_text()
        self.assertLess(int(re.search(r"keepalive (\d+)s", caddyfile).group(1)), int(re.search(r"timeout_keep_alive=(\d+)", server).group(1)))
        self.assertIn("reverse_proxy api:8766", caddyfile)
        self.assertNotRegex(caddyfile, r"(?i)Strict-Transport-Security|Content-Security-Policy")  # the app's, only once

    def test_published_images_overlay_matches_the_code(self):
        overlay = (ROOT / "compose.images.yaml").read_text()
        self.assertIn(f"${{TAMANDUA_VERSION:-{VERSION}}}", overlay)
        self.assertIn(f"-opengrep:{IMAGES['opengrep']['version']}", overlay)
        self.assertIn(f"OPENGREP_VERSION={IMAGES['opengrep']['version']}", (ROOT / "docker/engines/opengrep/Dockerfile").read_text())
        for service in ("api", "worker"):
            self.assertRegex(overlay, rf"  {service}:\n    <<: \*published\n    build: !reset null")

    def test_workflows_pin_actions_and_start_without_permissions(self):
        for workflow in sorted((ROOT / ".github/workflows").glob("*.yml")):
            text = workflow.read_text()
            with self.subTest(workflow=workflow.name):
                self.assertRegex(text, r"(?m)^permissions: \{\}$")
                for action in re.findall(r"^\s*(?:- )?uses: *(\S+)", text, re.M):
                    self.assertRegex(action, r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
        release = (ROOT / ".github/workflows/release.yml").read_text()
        for needed in ("platforms: linux/amd64,linux/arm64", "sbom: true", "provenance: mode=max", "cosign sign --yes",
                       "id-token: write", "packages: write"):
            self.assertIn(needed, release)
        self.assertNotIn("${{ github.ref_name }}\n", release.split("REF_NAME:")[0])  # the tag reaches scripts via env only

    @unittest.skipUnless(shutil.which("docker"), "needs docker compose")
    def test_production_overlays_are_valid_compose(self):
        env = {**os.environ, "TAMANDUA_DB_PASSWORD": "x", "TAMANDUA_DOMAIN": "tamandua.example.com",
               "TAMANDUA_IMAGE": "ghcr.io/example/tamandua", "COMPOSE_FILE": "", "COMPOSE_PROFILES": ""}
        command = ["docker", "compose", "--project-directory", str(ROOT), "-f", str(ROOT / "compose.yaml"),
                   "-f", str(ROOT / "compose.prod.yaml"), "-f", str(ROOT / "compose.images.yaml"), "--profile", "backup",
                   "config", "--format", "json"]
        completed = subprocess.run(command, capture_output=True, text=True, env=env, timeout=60)
        if completed.returncode != 0 and "unknown" in completed.stderr and "format" in completed.stderr:
            self.skipTest("docker compose too old for --format json")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        services = json.loads(completed.stdout)["services"]
        self.assertFalse(services["api"].get("ports"))  # only through Caddy
        self.assertEqual(services["api"]["environment"]["TAMANDUA_PUBLIC_URL"], "https://tamandua.example.com")
        self.assertEqual(services["worker"]["environment"]["TAMANDUA_ALLOWED_ORIGINS"], "https://tamandua.example.com")
        self.assertEqual({(p["published"], p["protocol"]) for p in services["caddy"]["ports"]},
                         {("80", "tcp"), ("443", "tcp"), ("443", "udp")})
        self.assertEqual(set(services["caddy"]["networks"]), {"edge"})
        self.assertNotIn("build", services["api"])
        self.assertEqual(services["api"]["image"], f"ghcr.io/example/tamandua:{VERSION}")
        self.assertEqual(services["opengrep"]["image"], IMAGES["opengrep"]["image"])
        self.assertNotIn("env_file", services["backup"])  # only the database password, not the whole .env

    def test_container_is_hardened(self):
        compose = (ROOT / "compose.yaml").read_text()
        for setting in ("read_only: true", "no-new-privileges:true", "cap_drop:", '"${TAMANDUA_HOST_BIND:-127.0.0.1}'):
            self.assertIn(setting, compose)
        dockerfile = (ROOT / "docker/app/Dockerfile").read_text()
        self.assertIn("USER tamandua", dockerfile)
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


class StandaloneComposeTests(unittest.TestCase):
    """deploy/compose.yaml: one file for any server or platform, generated from the repository's own files."""

    def test_it_is_current(self):
        completed = subprocess.run([sys.executable, str(ROOT / "scripts" / "standalone-compose.py"), "--check"],
                                   capture_output=True, text=True, timeout=30)
        self.assertEqual(completed.returncode, 0, completed.stderr)

    @unittest.skipUnless(shutil.which("docker"), "needs docker compose")
    def test_it_is_valid_and_never_touches_the_hosts_docker(self):
        env = {**os.environ, "TAMANDUA_DB_PASSWORD": "x", "TAMANDUA_MASTER_KEY": "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
               "TAMANDUA_PUBLIC_URL": "https://tamandua.example.com", "COMPOSE_FILE": "", "COMPOSE_PROFILES": ""}
        completed = subprocess.run(["docker", "compose", "-f", str(ROOT / "deploy" / "compose.yaml"), "--profile", "https",
                                    "--profile", "backup", "config", "--format", "json"], capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        document = json.loads(completed.stdout)
        services = document["services"]
        self.assertNotIn("docker.sock", completed.stdout)
        self.assertTrue(all(volume["type"] == "volume" or volume["target"] == "/backups"
                            for service in services.values() for volume in service.get("volumes", [])))
        self.assertEqual(services["worker"]["image"], f"ghcr.io/brayansstivens/tamandua-worker:{VERSION}")
        # `config` shows the content still escaped; when the service starts, Compose turns $$ into $ (checked by hand
        # with a throwaway container), so Caddy reads {$TAMANDUA_PUBLIC_URL} and the script its own variables.
        self.assertIn("{$$TAMANDUA_PUBLIC_URL}", document["configs"]["caddyfile"]["content"])
        self.assertEqual(document["configs"]["backup"]["content"],
                         (ROOT / "scripts" / "backup-service.sh").read_text().replace("$", "$$"))


class StandaloneWorkerImageTests(unittest.TestCase):
    """The worker-standalone image runs the same engines as the Docker runner: same digests, same Opengrep binary."""

    def test_engine_digests_and_opengrep_checksums_match(self):
        import re
        from tamandua.modules.scanning.engines import IMAGES
        root = Path(__file__).resolve().parents[1]
        app = (root / "docker" / "app" / "Dockerfile").read_text(encoding="utf-8")
        for key in ("trivy", "osv-scanner", "gitleaks", "grype", "zizmor"):
            self.assertIn(f"FROM {IMAGES[key]['image']} AS {key}", app, key)
        engine = (root / "docker" / "engines" / "opengrep" / "Dockerfile").read_text(encoding="utf-8")
        for name in ("OPENGREP_VERSION", "SHA_AMD64", "SHA_ARM64"):
            pattern = re.compile(rf"^ARG {name}=(\S+)$", re.M)
            self.assertEqual(pattern.findall(app), pattern.findall(engine), name)
        self.assertEqual(re.search(r"^ARG CHECKOV_VERSION=(\S+)$", app, re.M).group(1), IMAGES["checkov"]["version"])
        # Checkov and its dependencies are installed by hash: the lock pins the same version, and every package has one.
        lock = (root / "docker" / "checkov" / "requirements.txt").read_text(encoding="utf-8")
        self.assertIn(f"checkov=={IMAGES['checkov']['version']} \\", lock)
        self.assertIn(f"checkov=={IMAGES['checkov']['version']}", (root / "docker" / "checkov" / "requirements.in").read_text(encoding="utf-8"))
        packages = re.findall(r"^([A-Za-z0-9_.-]+)==\S+ \\\n((?:\s+--hash=sha256:[0-9a-f]{64}(?: \\)?\n)+)", lock, re.M)
        self.assertEqual(len(packages), len(re.findall(r"^[A-Za-z0-9_.-]+==", lock, re.M)))
        self.assertIn("--require-hashes", app)
        self.assertEqual(re.search(r"^ARG OPENGREP_VERSION=(\S+)$", app, re.M).group(1), IMAGES["opengrep"]["version"])


if __name__ == "__main__":
    unittest.main()


class LocalImageTests(unittest.TestCase):
    def test_locally_built_engines_are_never_pulled_and_are_not_docker_hub_names(self):
        from unittest.mock import patch
        from tamandua.modules.scanning import engines
        self.assertTrue(IMAGES["opengrep"]["image"].startswith("localhost/"))
        with patch.object(engines.shutil, "which", return_value="docker"), \
                patch.dict("os.environ", {"TAMANDUA_ENGINE_RUNNER": "docker"}), \
                patch.object(engines.subprocess, "run") as run:
            engines._run("opengrep", ["--version"], None)
            engines._run("gitleaks", ["version"], None)
        opengrep, gitleaks = (call.args[0] for call in run.call_args_list)
        self.assertIn("--pull", opengrep)
        self.assertEqual(opengrep[opengrep.index("--pull") + 1], "never")
        self.assertNotIn("--pull", gitleaks)  # pinned by digest: immutable, may be pulled

