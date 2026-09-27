"""Contrato del flujo de repositorio: selección, escaneo y límites de confianza."""

import io
import json
import tarfile
import tempfile
import unittest

from tamandua.modules.runs.store import artifact as store_artifact
from pathlib import Path
from unittest.mock import patch

from tamandua.modules.sources.domains import DomainError, check_reachability, register_domain, verify_domain
from tamandua.modules.scanning.repository import scan_repository
from tamandua.modules.sources.repositories import SourceError, _analyzable, _extract_limited, available_sources, list_repositories, snapshot_source
from tamandua.modules.runs.store import save_repository_scan
from tamandua.shared.i18n import localize, text


class RepositoryWorkflowTests(unittest.TestCase):
    def setUp(self):
        # Estas pruebas cubren el camino interno (sin motores en contenedor). Con Docker
        # presente lanzarían Trivy/Opengrep de verdad: lento y con otro resultado.
        patcher = patch.dict("tamandua.modules.scanning.engines._docker_state", {"ok": False})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_local_scan_finds_candidates_without_network_or_secret_value(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app.py").write_text('db.execute(f"SELECT * FROM users WHERE id={user_id}")\n')
            secret = "ghp_" + "A" * 36
            (root / "settings.env").write_text(f"TOKEN={secret}\n")
            (root / "requirements.txt").write_text("requests==2.30.0\n")
            with patch("tamandua.modules.scanning.repository._query_osv", side_effect=AssertionError("OSV llamado")):
                result = scan_repository(root, {"id": "local:fixture", "name": "fixture", "provider": "local"})
            self.assertEqual(result["summary"]["sast"], 1)
            self.assertEqual(result["summary"]["secrets"], 1)
            self.assertEqual(result["summary"]["dependencies"], 1)
            self.assertEqual(next(step for step in result["steps"] if step["id"] == "sca")["status"], "not_tested")
            self.assertNotIn(secret, json.dumps(result))
            stored = save_repository_scan(root / "runs", result)
            self.assertNotIn(secret, store_artifact(root / "runs", stored["id"], "report.md").decode())

    def test_osv_is_only_queried_with_explicit_opt_in(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "requirements.txt").write_text("requests==2.30.0\n")
            with patch("tamandua.modules.scanning.repository._query_osv", return_value=[{"vulns": [{"id": "CVE-2026-12345"}]}]) as query:
                result = scan_repository(root, {"id": "local:fixture", "name": "fixture"}, allow_osv_upload=True)
            query.assert_called_once()
            self.assertEqual(result["summary"]["sca"], 1)
            self.assertEqual(result["findings"][0]["cve"], ["CVE-2026-12345"])
            self.assertEqual(result["findings"][0]["verdict"], "candidate")

    def test_source_selection_and_archive_paths_are_bounded(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(SourceError):
                snapshot_source("local:/etc", root)
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode="w:gz") as archive:
                for name in ("repo-good/ok.py", "repo-good/../../escape.py", "repo-good/.env"):
                    content = b"print('safe')\n"
                    info = tarfile.TarInfo(name)
                    info.size = len(content)
                    archive.addfile(info, io.BytesIO(content))
            _extract_limited(stream.getvalue(), root)
            self.assertTrue((root / "ok.py").is_file())
            self.assertFalse((root / "escape.py").exists())
            self.assertFalse((root / ".env").exists())

    def test_github_source_comes_from_token_scoped_listing(self):
        listing = json.dumps([{"full_name": "owner/project", "private": True, "default_branch": "main"}]).encode()
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as archive:
            content = b"print('sample')\n"
            info = tarfile.TarInfo("owner-project-123/app.py")
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
        with tempfile.TemporaryDirectory() as temporary, \
                patch.dict("os.environ", {"GITHUB_TOKEN": "test-token"}), \
                patch("tamandua.modules.sources.repositories._request", side_effect=[listing, listing]) as request, \
                patch("tamandua.modules.sources.repositories._download_archive",
                      side_effect=lambda *args, **kwargs: args[3].write_bytes(stream.getvalue())) as download:
            entries = list_repositories("github")
            self.assertEqual(entries[0]["id"], "github:owner/project")
            root, selected = snapshot_source(entries[0]["id"], Path(temporary))
            self.assertEqual((root / "app.py").read_bytes(), content)
            self.assertEqual(selected["name"], "owner/project")
            self.assertEqual(request.call_count, 2)
            self.assertEqual(download.call_args.kwargs["redirect_host"], "codeload.github.com")
            # El tarball se borra tras extraerlo: no se queda un archivo intermedio.
            self.assertFalse((Path(temporary).parent / "repository.tar.gz").exists())

    def test_session_token_is_used_for_listing_and_snapshot_without_persisting_it(self):
        listing = json.dumps([{"full_name": "owner/project", "private": True, "default_branch": "main"}]).encode()
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as archive:
            content = b"print('sample')\n"
            info = tarfile.TarInfo("owner-project-123/app.py")
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
        with tempfile.TemporaryDirectory() as temporary, \
                patch.dict("os.environ", {"GITHUB_TOKEN": ""}), \
                patch("tamandua.modules.sources.repositories._request", side_effect=[listing, listing]) as request, \
                patch("tamandua.modules.sources.repositories._download_archive",
                      side_effect=lambda *args, **kwargs: args[3].write_bytes(stream.getvalue())) as download:
            sources = available_sources({"github": "session-secret"})
            self.assertEqual(sources["providers"]["github"]["origin"], "session")
            self.assertNotIn("session-secret", str(sources))
            _, selected = snapshot_source("github:owner/project", Path(temporary), {"github": "session-secret"})
            self.assertEqual(selected["files"], 1)
            self.assertNotIn("session-secret", str(selected))
            self.assertEqual([call.args[1] for call in request.call_args_list], ["session-secret"] * 2)
            self.assertEqual(download.call_args.args[1], "session-secret")

    def test_manifests_are_never_filtered_out_of_the_snapshot(self):
        """Un lockfile descartado deja el SCA a ciegas sin que nadie lo note."""
        for name in ("package-lock.json", "package.json", "yarn.lock", "pnpm-lock.yaml",
                     "requirements.txt", "go.sum", "pom.xml", "Gemfile.lock", "Cargo.lock",
                     "composer.lock", "Dockerfile", ".env.example"):
            with self.subTest(name=name):
                self.assertTrue(_analyzable(Path(f"proyecto/{name}")), name)
        for name in ("app.min.js", "types.d.ts", "logo.png", "video.mp4", "vendor.chunk.js"):
            with self.subTest(name=name):
                self.assertFalse(_analyzable(Path(f"proyecto/{name}")), name)

    def test_a_decompression_bomb_is_refused_and_says_why(self):
        """El único caso en que negarse es correcto: el archivo miente sobre su tamaño."""
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w:gz") as tar:
            content = b"\0" * 100_000
            for index in range(20):
                info = tarfile.TarInfo(f"repo-main/relleno_{index}.py")
                info.size = len(content)
                tar.addfile(info, io.BytesIO(content))
        blob = archive.getvalue()
        # Comprime muy bien: pocos KB en disco declarando 2 MB de contenido.
        self.assertLess(len(blob), 100_000)
        with tempfile.TemporaryDirectory() as temporary, \
                patch("tamandua.modules.sources.repositories.MAX_EXPANSION", 500_000):
            with self.assertRaises(SourceError) as caught:
                _extract_limited(blob, Path(temporary))
        self.assertIn("bomba de descompresión", text(caught.exception.message))

    def test_a_big_repository_is_truncated_and_declared_instead_of_failing(self):
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w:gz") as tar:
            def add(name, content):
                info = tarfile.TarInfo(f"repo-main/{name}")
                info.size = len(content)
                tar.addfile(info, io.BytesIO(content))
            add("logo.png", b"x" * 500)            # no analizable
            add("app.min.js", b"x" * 500)          # bundle
            add("enorme.py", b"x" * 5_000)         # excede el tamaño por archivo
            for index in range(6):
                add(f"src/modulo_{index}.py", b"value = 1\n")
        blob = archive.getvalue()

        with tempfile.TemporaryDirectory() as temporary, \
                patch("tamandua.modules.sources.repositories.MAX_FILE", 1_000), \
                patch("tamandua.modules.sources.repositories.MAX_FILES", 4):
            root = Path(temporary)
            # Pasarse de los límites no puede ser un error: deja al usuario sin nada.
            stats = _extract_limited(blob, root)
        self.assertEqual(stats["files"], 4)
        self.assertEqual(stats["skipped_not_analyzable"], 2)
        self.assertEqual(stats["skipped_too_large"], 1)
        self.assertEqual(stats["skipped_over_budget"], 2)
        self.assertTrue(stats["truncated"])

    def test_truncated_snapshot_is_visible_in_the_run_and_never_reads_as_complete(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "code"
            root.mkdir()
            (root / "app.py").write_text("value = 1\n")
            scan = scan_repository(root, {"id": "local:demo", "name": "demo", "provider": "local",
                                          "snapshot": {"files": 1, "bytes": 11, "skipped_over_budget": 900,
                                                       "skipped_not_analyzable": 5, "truncated": True}})
        scan = localize(scan)
        snapshot_step = next(step for step in scan["steps"] if step["id"] == "snapshot")
        self.assertEqual(snapshot_step["status"], "partial")
        self.assertIn("900", snapshot_step["detail"])
        self.assertIn("presupuesto", snapshot_step["detail"])
        # Un snapshot truncado no puede presentarse como ejecución completa.
        self.assertEqual(scan["status"], "incomplete")
        self.assertTrue(any("cobertura de este repositorio es parcial" in item for item in scan["limitations"]))

    def test_target_kind_and_context_are_validated_and_stored(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record = register_domain(root, "https://app.example.com/", "api", "  API de agenda\n con JWT  ")
            self.assertEqual(record["kind"], "api")
            self.assertEqual(record["context"], "API de agenda con JWT")
            with self.assertRaises(DomainError):
                register_domain(root, "https://otro.example.com/", "pwn")
            with self.assertRaises(DomainError):
                register_domain(root, "https://largo.example.com/", "web", "x" * 401)
            self.assertEqual(register_domain(root, "https://simple.example.com/")["kind"], "web")

    def test_reachability_refuses_private_targets_without_opening_a_socket(self):
        addresses = [(2, 1, 6, "", ("127.0.0.1", 443))]
        with patch("tamandua.modules.sources.domains.socket.getaddrinfo", return_value=addresses), \
                patch("tamandua.modules.sources.domains.socket.create_connection", side_effect=AssertionError("conexión abierta")):
            result = check_reachability("https://interno.example.com/")
        self.assertFalse(result["reachable"])
        self.assertEqual(result["status"], "private_address")

    def test_reachability_pins_the_resolved_public_address(self):
        addresses = [(2, 1, 6, "", ("93.184.216.34", 443))]
        with patch("tamandua.modules.sources.domains.socket.getaddrinfo", return_value=addresses), \
                patch("tamandua.modules.sources.domains.socket.create_connection", side_effect=OSError("sin ruta")) as connect:
            result = check_reachability("https://app.example.com/panel")
        self.assertEqual(connect.call_args.args[0], ("93.184.216.34", 443))
        self.assertEqual(result["status"], "unreachable")

    def test_declared_context_travels_with_the_run_and_its_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "code"
            root.mkdir()
            (root / "app.py").write_text("value = 1\n")
            scan = scan_repository(root, {"id": "local:demo", "name": "demo", "provider": "local"},
                                   context="  Panel interno\n sin PII  ")
            self.assertEqual(scan["context"], "Panel interno sin PII")
            data_dir = Path(temporary) / "data"
            record = save_repository_scan(data_dir, scan)
            report = store_artifact(data_dir, record["id"], "report.md").decode()
            self.assertIn("Panel interno sin PII", report)
            self.assertIn("no una verificación del sistema", report)

    def test_domain_requires_public_https_and_dns_proof(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for url in ("http://example.com", "https://localhost", "https://127.0.0.1", "https://user@example.com", "https://example.com:8443"):
                with self.subTest(url=url), self.assertRaises(DomainError):
                    register_domain(root, url)
            record = register_domain(root, "https://app.example.com/path")
            self.assertFalse(record["verified"])
            with patch("tamandua.modules.sources.domains.subprocess.run") as run:
                run.return_value.returncode = 0
                run.return_value.stdout = f'"{record["txt_value"]}"\n'
                verified = verify_domain(root, record["id"])
            self.assertTrue(verified["verified"])
            run.assert_called_once()
            self.assertEqual(run.call_args.args[0][0], "dig")


class DownloadTests(unittest.TestCase):
    """Una descarga lenta informa de lo recibido y tiene plazo total: no se queda «pegada» en silencio."""

    class Slow:
        def __init__(self, chunks, step):
            self.chunks, self.step = list(chunks), step
        def __enter__(self):
            return self
        def __exit__(self, *_):
            return False
        def read1(self, _size):
            self.step()
            return self.chunks.pop(0) if self.chunks else b""

    def run_download(self, chunks, *, timeout="900"):
        from tamandua.modules.sources import repositories as repository_sources
        clock = [0.0]
        response = self.Slow(chunks, lambda: clock.__setitem__(0, clock[0] + 11))
        messages = []
        opener = type("Opener", (), {"open": lambda self, *a, **k: response})()
        with tempfile.TemporaryDirectory() as temporary, \
                patch.dict("os.environ", {"TAMANDUA_DOWNLOAD_TIMEOUT": timeout}), \
                patch("tamandua.shared.http.build_opener", return_value=opener), \
                patch("tamandua.modules.sources.repositories.time.monotonic", side_effect=lambda: clock[0]):
            written = repository_sources._download_archive("https://api.github.com/x", "t", "github", Path(temporary) / "a.tar.gz",
                                                           progress=lambda level, message: messages.append(message))
        return written, messages

    def test_progress_is_reported_while_downloading(self):
        written, messages = self.run_download([b"x" * 1_048_576] * 3)
        self.assertEqual(written, 3 * 1_048_576)
        self.assertTrue(any("MB recibidos" in text(message) for message in messages))
        self.assertIn("Extrayendo", text(messages[-1]))

    def test_a_download_that_never_ends_fails_with_a_clear_message(self):
        from tamandua.modules.sources.repositories import SourceError
        with self.assertRaises(SourceError) as caught:
            self.run_download([b"x"] * 1000, timeout="60")
        self.assertIn("superó 1 min", text(caught.exception.message))


if __name__ == "__main__":
    unittest.main()


class EnginesDownTests(unittest.TestCase):
    """Si los motores no corren (imágenes sin construir), la ejecución no puede presentarse como limpia."""

    def test_scan_without_engines_is_incomplete_and_says_why(self):
        from tamandua.modules.scanning import repository as repository_scan
        from tamandua.modules.scanning.engines import _result
        down = lambda key: _result(key, "inconclusive", "Imagen no construida")
        messages = []
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(repository_scan, "engines_available", return_value=True), \
                patch.object(repository_scan, "run_opengrep", side_effect=lambda *_: down("opengrep")), \
                patch.object(repository_scan, "run_gitleaks", side_effect=lambda *_: down("gitleaks")), \
                patch.object(repository_scan, "run_trivy", side_effect=lambda *_: down("trivy")), \
                patch.object(repository_scan, "run_checkov", side_effect=lambda *_: down("checkov")), \
                patch.object(repository_scan, "run_zizmor", side_effect=lambda *_: down("zizmor")), \
                patch.object(repository_scan, "load_feeds", return_value={"kev": {}, "epss": {}}):
            root = Path(temporary)
            (root / "app.py").write_text("print('hola')\n", encoding="utf-8")
            scan = repository_scan.scan_repository(root, {"id": "github:org/app", "name": "org/app", "provider": "github", "files": 1},
                                                   data_dir=root, progress=lambda level, message: messages.append((level, message)))
        self.assertEqual(scan["status"], "incomplete")
        self.assertTrue(any(level == "warn" and "no equivale" in text(message) for level, message in messages))


class EngineCauseTests(unittest.TestCase):
    def test_the_docker_error_is_shown_without_tokens_or_host_paths(self):
        import subprocess
        from tamandua.modules.scanning.engines import with_cause
        failed = subprocess.CompletedProcess([], 125, "", "\x1b[31mdocker: Error response from daemon: invalid mount /c/Users/yo/tamandua/data/work/x "
                                                             "token ghp_abcdefghijklmnopqrstuvwxyz123456\x1b[0m\n")
        with patch.dict("os.environ", {"TAMANDUA_HOST_DATA_DIR": "/c/Users/yo/tamandua/data"}):
            rendered = text(with_cause("Gitleaks terminó con error.", failed))
        self.assertTrue(rendered.startswith("Gitleaks terminó con error: docker: Error response from daemon: invalid mount <datos>/work/x"))
        self.assertNotIn("ghp_", rendered)
        self.assertEqual(with_cause("Sin causa.", subprocess.CompletedProcess([], 1, "", "")), "Sin causa.")

    def test_the_host_path_is_asked_to_docker_on_any_platform(self):
        import subprocess
        from tamandua.modules.scanning import engines as scanners
        mounts = json.dumps([{"Type": "bind", "Source": "/run/desktop/mnt/host/c/Users/yo/tamandua/data", "Destination": "/data"},
                             {"Type": "bind", "Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock"}])
        scanners._own_mounts.update(at=None, mounts={})
        # En PowerShell `${PWD}` llega vacío y compose deja la ruta del host en `/data`.
        with patch.dict("os.environ", {"TAMANDUA_DATA_DIR": "/data", "TAMANDUA_HOST_DATA_DIR": "/data", "HOSTNAME": "074eeb4e2cfd"}), \
                patch.object(scanners, "in_container", return_value=True), \
                patch.object(scanners.shutil, "which", return_value="/usr/bin/docker"), \
                patch.object(scanners.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, mounts, "")), \
                patch.object(Path, "resolve", lambda self, strict=False: self):
            self.assertEqual(scanners.host_path(Path("/data/work/snap")), "/run/desktop/mnt/host/c/Users/yo/tamandua/data/work/snap")
            self.assertIsNone(scanners.host_mount_problem())
        scanners._own_mounts.update(at=None, mounts={})

    def test_without_docker_answer_a_bad_env_path_is_explained(self):
        from tamandua.modules.scanning import engines as scanners
        scanners._own_mounts.update(at=None, mounts={})
        with patch.dict("os.environ", {"TAMANDUA_DATA_DIR": "/data", "TAMANDUA_HOST_DATA_DIR": "/data", "HOSTNAME": "x"}), \
                patch.object(scanners, "in_container", return_value=True):
            self.assertIn("TAMANDUA_HOST_DATA_DIR", text(scanners.host_mount_problem()))
        with patch.dict("os.environ", {"TAMANDUA_DATA_DIR": "/data", "TAMANDUA_HOST_DATA_DIR": "/home/yo/tamandua/data", "HOSTNAME": "x"}), \
                patch.object(scanners, "in_container", return_value=True):
            self.assertIsNone(scanners.host_mount_problem())
        scanners._own_mounts.update(at=None, mounts={})


class DockerAccessTests(unittest.TestCase):
    """Linux y WSL con Docker nativo: el socket es del grupo `docker` y el contenedor puede no estar en él."""

    def tearDown(self):
        from tamandua.modules.scanning import engines as scanners
        scanners._docker_state.clear()

    def test_a_socket_without_permission_is_explained_with_its_group(self):
        from tamandua.modules.scanning import engines as scanners
        with tempfile.TemporaryDirectory() as temporary:
            socket = Path(temporary) / "docker.sock"
            socket.write_text("")
            with patch.object(scanners, "DOCKER_SOCKET", socket), patch.object(scanners.os, "access", return_value=False):
                message = scanners.socket_problem()
            self.assertIn(f"grupo {socket.stat().st_gid}", text(message))
            self.assertIn("DOCKER_SOCKET_GID", text(message))
            with patch.object(scanners, "DOCKER_SOCKET", socket), patch.object(scanners.os, "access", return_value=True):
                self.assertIsNone(scanners.socket_problem())

    def test_a_docker_that_was_down_is_asked_again(self):
        import subprocess
        from tamandua.modules.scanning import engines as scanners
        scanners._docker_state.clear()
        down = subprocess.CompletedProcess([], 1, "", "Cannot connect to the Docker daemon")
        up = subprocess.CompletedProcess([], 0, "27.5.1\n", "")
        with patch.object(scanners.shutil, "which", return_value="/usr/bin/docker"), \
                patch.object(scanners, "socket_problem", return_value=None), \
                patch.object(scanners.subprocess, "run", side_effect=[down, up]) as run:
            self.assertFalse(scanners.docker_available())
            self.assertFalse(scanners.docker_available())  # within the minute: not asked again
            scanners._docker_state["at"] -= scanners.RECHECK_SECONDS + 1
            self.assertTrue(scanners.docker_available())
            self.assertTrue(scanners.docker_available())  # a Docker that answers stays answered
        self.assertEqual(run.call_count, 2)
        scanners._docker_state.clear()

    def test_docker_info_without_server_version_is_not_available(self):
        import subprocess
        from tamandua.modules.scanning import engines as scanners
        scanners._docker_state.clear()
        answer = subprocess.CompletedProcess([], 0, "\n", "permission denied while trying to connect to the Docker daemon socket")
        with patch.object(scanners.shutil, "which", return_value="/usr/bin/docker"), \
                patch.object(scanners.subprocess, "run", return_value=answer), \
                patch.object(scanners, "socket_problem", return_value=None):
            self.assertFalse(scanners.docker_available())
            self.assertIn("permission denied", scanners.docker_problem())


class MakefileEnginesTests(unittest.TestCase):
    def test_make_engines_sees_every_published_image(self):
        """`make engines` lee las imágenes con sed; si cambia su formato en scanners.py, esto avisa."""
        import re
        import subprocess
        from tamandua.modules.scanning.engines import IMAGES
        root = Path(__file__).resolve().parents[1]
        command = re.search(r"^ENGINE_IMAGES := (.+)$", (root / "Makefile").read_text(encoding="utf-8"), re.M).group(1)
        listed = subprocess.run(command, shell=True, cwd=root, capture_output=True, text=True, check=True).stdout.split()
        self.assertEqual(listed, [meta["image"] for meta in IMAGES.values() if "@sha256:" in meta["image"]])
