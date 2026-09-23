"""Contrato del flujo de repositorio: selección, escaneo y límites de confianza."""

import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from appsec_agent.domains import DomainError, check_reachability, register_domain, verify_domain
from appsec_agent.repository_scan import scan_repository
from appsec_agent.repository_sources import SourceError, _analyzable, _extract_limited, available_sources, list_repositories, snapshot_source
from appsec_agent.store import save_repository_scan


class RepositoryWorkflowTests(unittest.TestCase):
    def setUp(self):
        # Estas pruebas cubren el camino interno (sin motores en contenedor). Con Docker
        # presente lanzarían Trivy/Opengrep de verdad: lento y con otro resultado.
        patcher = patch.dict("appsec_agent.scanners._docker_state", {"ok": False})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_local_scan_finds_candidates_without_network_or_secret_value(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app.py").write_text('db.execute(f"SELECT * FROM users WHERE id={user_id}")\n')
            secret = "ghp_" + "A" * 36
            (root / "settings.env").write_text(f"TOKEN={secret}\n")
            (root / "requirements.txt").write_text("requests==2.30.0\n")
            with patch("appsec_agent.repository_scan._query_osv", side_effect=AssertionError("OSV llamado")):
                result = scan_repository(root, {"id": "local:fixture", "name": "fixture", "provider": "local"})
            self.assertEqual(result["summary"]["sast"], 1)
            self.assertEqual(result["summary"]["secrets"], 1)
            self.assertEqual(result["summary"]["dependencies"], 1)
            self.assertEqual(next(step for step in result["steps"] if step["id"] == "sca")["status"], "not_tested")
            self.assertNotIn(secret, json.dumps(result))
            stored = save_repository_scan(root / "runs", result)
            self.assertNotIn(secret, (root / "runs" / "runs" / stored["id"] / "report.md").read_text())

    def test_osv_is_only_queried_with_explicit_opt_in(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "requirements.txt").write_text("requests==2.30.0\n")
            with patch("appsec_agent.repository_scan._query_osv", return_value=[{"vulns": [{"id": "CVE-2026-12345"}]}]) as query:
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
                patch("appsec_agent.repository_sources._request", side_effect=[listing, listing]) as request, \
                patch("appsec_agent.repository_sources._download_archive",
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
                patch("appsec_agent.repository_sources._request", side_effect=[listing, listing]) as request, \
                patch("appsec_agent.repository_sources._download_archive",
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
                patch("appsec_agent.repository_sources.MAX_EXPANSION", 500_000):
            with self.assertRaises(SourceError) as caught:
                _extract_limited(blob, Path(temporary))
        self.assertIn("bomba de descompresión", str(caught.exception))

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
                patch("appsec_agent.repository_sources.MAX_FILE", 1_000), \
                patch("appsec_agent.repository_sources.MAX_FILES", 4):
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
        with patch("appsec_agent.domains.socket.getaddrinfo", return_value=addresses), \
                patch("appsec_agent.domains.socket.create_connection", side_effect=AssertionError("conexión abierta")):
            result = check_reachability("https://interno.example.com/")
        self.assertFalse(result["reachable"])
        self.assertEqual(result["status"], "private_address")

    def test_reachability_pins_the_resolved_public_address(self):
        addresses = [(2, 1, 6, "", ("93.184.216.34", 443))]
        with patch("appsec_agent.domains.socket.getaddrinfo", return_value=addresses), \
                patch("appsec_agent.domains.socket.create_connection", side_effect=OSError("sin ruta")) as connect:
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
            report = (data_dir / "runs" / record["id"] / "report.md").read_text(encoding="utf-8")
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
            with patch("appsec_agent.domains.subprocess.run") as run:
                run.return_value.returncode = 0
                run.return_value.stdout = f'"{record["txt_value"]}"\n'
                verified = verify_domain(root, record["id"])
            self.assertTrue(verified["verified"])
            run.assert_called_once()
            self.assertEqual(run.call_args.args[0][0], "dig")


if __name__ == "__main__":
    unittest.main()
