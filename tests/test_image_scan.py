import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tamandua.shared import paths
from tamandua.modules.scanning import image as image_scan
from tamandua.modules.identity.auth import Users
from tamandua.modules.scanning.image import ImageError, config_findings, merge_packages, parse_reference

from tests.test_auth import PASSWORD, HttpCase

TOKEN = "ghp_" + "t" * 36


def grype_match(name, version, identifier, related=(), severity="High", fix=("2.0.0",)):
    return {"vulnerability": {"id": identifier, "severity": severity, "description": f"{name} vulnerable",
                              "cvss": [{"version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "metrics": {"baseScore": 9.8}}],
                              "fix": {"versions": list(fix), "state": "fixed"}, "cwes": [{"cwe": "CWE-79"}], "urls": ["https://example.test/a"]},
            "relatedVulnerabilities": [{"id": item} for item in related],
            "artifact": {"name": name, "version": version, "type": "deb", "locations": [{"path": "/var/lib/dpkg/status"}]}}


class ReferenceTests(unittest.TestCase):
    def test_references_are_normalized_and_hostile_input_rejected(self):
        self.assertEqual(parse_reference("nginx")["reference"], "docker.io/library/nginx:latest")
        self.assertEqual(parse_reference("ghcr.io/acme/api:1.4")["asset"], "image:ghcr.io/acme/api")
        self.assertEqual(parse_reference("index.docker.io/bitnami/redis:7")["registry"], "docker.io")
        digest = parse_reference("ghcr.io/acme/api@sha256:" + "a" * 64)
        self.assertEqual((digest["tag"], digest["digest"][:7]), (None, "sha256:"))
        for bad in ("", "http://evil/x", "../../etc/passwd", "nginx:bad tag", "UPPER/x", "a;id", "--help", "-v/:/host", "x" * 400):
            with self.subTest(reference=bad), self.assertRaises(ImageError):
                parse_reference(bad)

    def test_private_registries_need_explicit_permission(self):
        with patch.dict(os.environ, {}, clear=True):
            for host in ("localhost:5000", "127.0.0.1:5000", "10.0.0.5:5000"):
                with self.subTest(host=host), self.assertRaises(ImageError):
                    image_scan.check_registry_address(host)
        with patch.dict(os.environ, {"APPSEC_AGENT_ALLOW_PRIVATE_REGISTRIES": "1"}):
            image_scan.check_registry_address("localhost:5000")


class CredentialTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        patcher = patch.object(paths, "CONFIG_DIR", Path(self.directory.name) / "config")
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_tokens_are_encrypted_and_never_listed(self):
        rows = image_scan.save_registry("GHCR.io", "brayan", TOKEN, by="admin")
        self.assertEqual(rows[0]["registry"], "ghcr.io")
        self.assertNotIn(TOKEN, json.dumps(rows))
        for path in (Path(self.directory.name) / "config").iterdir():
            self.assertNotIn(TOKEN.encode(), path.read_bytes())
        self.assertEqual(image_scan.credentials_for("ghcr.io")["token"], TOKEN)
        for bad in (("ghcr.io/acme", "u", TOKEN), ("ghcr.io", "", TOKEN), ("ghcr.io", "u", "corto"), ("ghcr.io", "u", "con espacio 123")):
            with self.subTest(values=bad[:2]), self.assertRaises(ImageError):
                image_scan.save_registry(*bad, by="admin")
        self.assertEqual(image_scan.forget_registry("ghcr.io"), [])

    def test_registry_token_travels_by_environment_not_argv(self):
        captured = {}

        def fake_run(command, **kwargs):
            captured["argv"], captured["env"] = command, kwargs.get("env") or {}
            class Done:
                returncode, stdout, stderr = 0, json.dumps({"Results": [], "Metadata": {}}), ""
            return Done()
        with patch("tamandua.modules.scanning.image.docker_available", return_value=True), \
                patch("tamandua.modules.scanning.engines.subprocess.run", side_effect=fake_run):
            image_scan.run_trivy_image("ghcr.io/acme/api:1", Path(self.directory.name) / "cache", {}, {"username": "brayan", "token": TOKEN})
        self.assertNotIn(TOKEN, " ".join(captured["argv"]))
        self.assertIn("TRIVY_PASSWORD", captured["argv"])
        self.assertEqual(captured["env"]["TRIVY_PASSWORD"], TOKEN)
        self.assertIn("--cap-drop", captured["argv"])


class FindingTests(unittest.TestCase):
    def test_two_engines_merge_on_package_version_and_alias(self):
        trivy = [{"rule_id": "CVE-2024-1", "cve": ["CVE-2024-1"], "ghsa": [], "confidence": 8, "scanner": "sca",
                  "package": {"name": "openssl", "version": "1.1", "ecosystem": "debian", "fixed_version": None}}]
        grype = [image_scan._grype_finding(grype_match("openssl", "1.1", "GHSA-x", related=("CVE-2024-1",)), {}),
                 image_scan._grype_finding(grype_match("zlib", "1.2", "CVE-2024-9", severity="Negligible"), {})]
        merged, agreement = merge_packages(trivy, grype)
        self.assertEqual(agreement, {"trivy": 1, "grype": 2, "both": 1, "only_trivy": 0, "only_grype": 1})
        self.assertEqual(merged[0]["also_detected_by"], ["grype"])
        self.assertEqual((merged[0]["confidence"], merged[0]["package"]["fixed_version"]), (9, "2.0.0"))
        self.assertEqual(merged[1]["package"]["name"], "zlib")
        # Misma huella para el mismo aviso venga de quien venga: el ciclo de vida no se duplica.
        a = image_scan._finish_package({**merged[0], "fingerprint": "x"})
        b = image_scan._finish_package(grype[0])
        self.assertEqual(a["fingerprint"], b["fingerprint"])

    def test_config_rules_find_baked_credentials_without_copying_them(self):
        metadata = {"ImageConfig": {"created": "2020-01-01T00:00:00Z", "config": {
            "User": "", "Env": ["PATH=/bin", "NPM_TOKEN=npm_secretvalue123", "API_KEY=$API_KEY"], "ExposedPorts": {"22/tcp": {}}},
            "history": [{"created_by": "|1 NPM_TOKEN=npm_secretvalue123 /bin/sh -c npm ci"},
                        {"created_by": "/bin/sh -c pip install -i https://ci:hunter2hunter@pypi.acme.io/simple x"},
                        {"created_by": "/bin/sh -c #(nop)  ARG NPM_TOKEN"}]}}
        findings = config_findings(metadata, parse_reference("ghcr.io/acme/api"))
        rules = sorted(item["rule_id"] for item in findings)
        self.assertEqual(rules, sorted(["IMG-ROOT", "IMG-ENV-SECRET", "IMG-BUILD-SECRET", "IMG-BUILD-URL-CREDENTIAL", "IMG-SSH",
                                        "IMG-NO-HEALTHCHECK", "IMG-LATEST", "IMG-STALE"]))
        text = json.dumps(findings)
        for value in ("npm_secretvalue123", "hunter2hunter"):
            self.assertNotIn(value, text)
        clean = config_findings({"ImageConfig": {"created": "2099-01-01T00:00:00Z", "config": {"User": "app", "Healthcheck": {"Test": ["CMD", "true"]}},
                                                 "history": []}}, parse_reference("ghcr.io/acme/api:1.0"))
        self.assertEqual(clean, [])


class ImageRoutesTests(HttpCase):
    def setUp(self):
        super().setUp()
        Users(self.data_dir).create("admin", PASSWORD, role="admin")
        Users(self.data_dir).create("miembro", PASSWORD)
        self.admin, self.member = self.cookie("admin"), self.cookie("miembro")

    def cookie(self, username):
        _, _, cookies = self.post("/api/auth/login", "login", {"username": username, "password": PASSWORD})
        return cookies[0].split("; ")[0]

    def test_scan_validation_and_registry_admin_only(self):
        self.assertEqual(self.post("/api/images/scans", "scan-image", {"reference": "http://x"}, self.member)[0], 400)
        with patch.dict(os.environ, {"APPSEC_AGENT_ALLOW_PRIVATE_REGISTRIES": ""}):
            status, body, _ = self.post("/api/images/scans", "scan-image", {"reference": "localhost:5000/app:1"}, self.member)
        self.assertEqual(status, 400)
        self.assertIn("privada", body["error"])
        with patch("tamandua.modules.scanning.image.check_registry_address"), \
                patch.object(self.state.jobs, "enqueue_image_scan", return_value={"id": "r1", "status": "queued"}) as enqueue:
            status, body, _ = self.post("/api/images/scans", "scan-image", {"reference": "ghcr.io/acme/api:1"}, self.member)
        self.assertEqual((status, body["image"]["reference"]), (202, "ghcr.io/acme/api:1"))
        self.assertEqual(enqueue.call_args.kwargs["requested_by"], "miembro")
        save = {"action": "save", "registry": "ghcr.io", "username": "u", "token": TOKEN}
        self.assertEqual(self.post("/api/registries", "save-registry", save, self.member)[0], 403)
        status, body, _ = self.post("/api/registries", "save-registry", save, self.admin)
        self.assertEqual((status, body["registries"][0]["last4"]), (200, TOKEN[-4:]))
        status, body, _ = self.call("GET", "/api/registries", headers={"Cookie": self.member})
        self.assertEqual(status, 200)
        self.assertNotIn(TOKEN, json.dumps(body))


if __name__ == "__main__":
    unittest.main()
