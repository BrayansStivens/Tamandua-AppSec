"""Contrato de la GitHub App: qué se firma, qué se guarda y qué nunca se persiste."""

import base64
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from appsec_agent import github_app
from appsec_agent.github_app import GitHubAppError, config, install_url
from appsec_agent.integrations import clear_github, github_installation, github_installations, load, save_github

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    CRYPTO = True
except ImportError:
    CRYPTO = False


def _environment(key_file: str) -> dict:
    return {"GITHUB_APP_ID": "123456", "GITHUB_APP_SLUG": "appsec-agent-local",
            "GITHUB_APP_CLIENT_ID": "Iv1.0123456789abcdef", "GITHUB_APP_CLIENT_SECRET": "s" * 40,
            "GITHUB_APP_PRIVATE_KEY_FILE": key_file}


class GitHubAppTests(unittest.TestCase):
    def setUp(self):
        github_app.forget()
        # Sin aislar el almacén, las pruebas leerían las credenciales reales de quien las corre.
        self.store = tempfile.TemporaryDirectory()
        patcher = patch.object(github_app, "CONFIG_DIR", Path(self.store.name) / "config")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.store.cleanup)

    def test_missing_configuration_is_named_and_never_invents_a_url(self):
        with patch.dict(os.environ, {}, clear=True):
            state = config()
            self.assertFalse(state["configured"])
            self.assertEqual(state["missing"], ["App ID", "clave privada", "GITHUB_APP_SLUG"])
            with self.assertRaises(GitHubAppError):
                install_url()

    def test_install_url_points_at_the_selection_screen(self):
        with tempfile.NamedTemporaryFile() as key, patch.dict(os.environ, _environment(key.name), clear=True):
            self.assertEqual(install_url(), "https://github.com/apps/appsec-agent-local/installations/new")

    @unittest.skipUnless(CRYPTO, "requiere cryptography (.venv)")
    def test_verified_app_is_stored_encrypted_and_bad_input_is_refused(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                serialization.NoEncryption()).decode()
        seen = []

        def fake_get(url, token, **_):
            seen.append((url, token))
            # GitHub valida el JWT; aquí basta con comprobar que lo firma esta clave.
            header, payload, signature = token.split(".")
            pad = lambda value: value + "=" * (-len(value) % 4)
            key.public_key().verify(base64.urlsafe_b64decode(pad(signature)), f"{header}.{payload}".encode(),
                                    padding.PKCS1v15(), hashes.SHA256())
            return {"id": 4242, "slug": "appsec-de-acme", "name": "AppSec de Acme", "owner": {"login": "acme", "type": "Organization"},
                    "html_url": "https://github.com/apps/appsec-de-acme", "permissions": dict(github_app.REQUIRED_PERMISSIONS), "events": []}
        for app_id, private_key in (("", pem), ("abc", pem), ("0", pem), ("4242", ""), ("4242", "no es una clave"), ("4242", "x" * 20_000)):
            with self.subTest(app_id=app_id, key=private_key[:12]), self.assertRaises(GitHubAppError):
                github_app.verify_app(app_id, private_key)
        weak = rsa.generate_private_key(public_exponent=65537, key_size=1024).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
        with self.assertRaises(GitHubAppError):
            github_app.verify_app("4242", weak)
        with patch.dict(os.environ, {}, clear=True), patch("appsec_agent.github_app._get", side_effect=fake_get):
            verified = github_app.verify_app(" 4242 ", pem)
            self.assertEqual(seen[0][0], "https://api.github.com/app")
            self.assertNotIn("PRIVATE KEY", seen[0][1])  # a GitHub va un JWT, nunca la clave
            github_app.save_credentials(verified)
            files = {path.name: path.read_bytes() for path in (Path(self.store.name) / "config").iterdir()}
            self.assertEqual(set(files), {"secrets.vault", "master.key"})
            self.assertNotIn(b"PRIVATE KEY", files["secrets.vault"])
            self.assertEqual(oct((Path(self.store.name) / "config" / "secrets.vault").stat().st_mode & 0o777), "0o600")
            state = github_app.config()
            self.assertEqual((state["configured"], state["slug"], state["owner"], state["source"]), (True, "appsec-de-acme", "acme", "almacén cifrado"))
            self.assertNotIn("PRIVATE", json.dumps(state))
            github_app._app_jwt()  # firma con la clave descifrada del almacén
            self.assertTrue(github_app.forget_app())
            self.assertFalse(github_app.config()["configured"])
        with patch.dict(os.environ, {}, clear=True), patch("appsec_agent.github_app._get", side_effect=GitHubAppError("401")):
            with self.assertRaises(GitHubAppError):
                github_app.verify_app("4242", pem)

    @unittest.skipUnless(CRYPTO, "requiere cryptography (.venv)")
    def test_app_jwt_is_rs256_signed_and_bounded_in_time(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with tempfile.TemporaryDirectory() as temporary:
            key_file = Path(temporary) / "app.pem"
            key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                                   serialization.PrivateFormat.PKCS8,
                                                   serialization.NoEncryption()))
            with patch.dict(os.environ, _environment(str(key_file)), clear=True):
                token = github_app._app_jwt()
        header_raw, payload_raw, signature_raw = token.split(".")
        pad = lambda value: value + "=" * (-len(value) % 4)
        header = json.loads(base64.urlsafe_b64decode(pad(header_raw)))
        payload = json.loads(base64.urlsafe_b64decode(pad(payload_raw)))
        self.assertEqual(header, {"alg": "RS256", "typ": "JWT"})
        self.assertEqual(payload["iss"], "123456")
        self.assertLessEqual(payload["exp"] - payload["iat"], 600)
        self.assertGreater(payload["exp"], time.time())
        # La firma tiene que validar con la clave pública: no es un JWT decorativo.
        key.public_key().verify(base64.urlsafe_b64decode(pad(signature_raw)),
                                f"{header_raw}.{payload_raw}".encode(),
                                padding.PKCS1v15(), hashes.SHA256())

    def test_permission_review_flags_excess_and_missing(self):
        declared = {"contents": "read", "metadata": "read", "pull_requests": "write", "statuses": "write",
                    "secrets": "write", "actions": "write", "issues": "read"}
        granted = {"contents": "read", "metadata": "read"}
        review = github_app.permission_review(declared, granted)
        self.assertEqual(review["excess"], ["actions", "issues", "secrets"])
        self.assertEqual(review["missing"], ["pull_requests", "statuses"])
        self.assertIn("secrets", review["pending_acceptance"])
        clean = github_app.permission_review(github_app.REQUIRED_PERMISSIONS, github_app.REQUIRED_PERMISSIONS)
        self.assertEqual((clean["excess"], clean["missing"], clean["pending_acceptance"]), ([], [], []))

    def test_installation_token_is_reused_until_it_is_close_to_expiring(self):
        github_app._tokens[99] = ("ghs_vigente", time.time() + 3600)
        with patch("appsec_agent.github_app.build_opener", side_effect=AssertionError("pidió token de nuevo")):
            self.assertEqual(github_app.installation_token(99), "ghs_vigente")
        github_app._tokens[99] = ("ghs_por_caducar", time.time() + 60)
        with patch("appsec_agent.github_app._app_jwt", return_value="jwt"), \
                patch("appsec_agent.github_app.build_opener") as opener:
            response = opener.return_value.open.return_value.__enter__.return_value
            response.read.return_value = json.dumps({"token": "ghs_nuevo"}).encode()
            self.assertEqual(github_app.installation_token(99), "ghs_nuevo")
        for bad in (0, -1, "99", None):
            with self.subTest(installation=bad), self.assertRaises(GitHubAppError):
                github_app.installation_token(bad)

    def test_stored_connection_holds_no_credential(self):
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary)
            details = {"account": "acme", "account_type": "Organization",
                       "repository_selection": "selected", "permissions": {"contents": "read"}}
            record = save_github(data_dir, 4242, details, "brayanstivens")
            self.assertEqual(github_installation(data_dir), 4242)
            self.assertEqual(record["repository_selection"], "selected")
            self.assertEqual(record["connected_by"], "brayanstivens")
            raw = (data_dir / "integrations.json").read_text(encoding="utf-8")
            for secret in ("ghs_", "ghu_", "token", "secret", "PRIVATE KEY"):
                self.assertNotIn(secret, raw)
            self.assertEqual(set(load(data_dir)), {"github"})
            with self.assertRaises(ValueError):
                save_github(data_dir, 0, details, None)

    def test_connections_migrate_from_single_record_and_can_remove_one_account(self):
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary)
            save_github(data_dir, 77, {"account": "acme"}, "admin")
            self.assertIsInstance(load(data_dir)["github"], dict)
            save_github(data_dir, 88, {"account": "beta"}, "admin")
            self.assertEqual(github_installations(data_dir), [77, 88])
            self.assertEqual([row["account"] for row in load(data_dir)["github"]], ["acme", "beta"])
            clear_github(data_dir, 77)
            self.assertEqual(github_installations(data_dir), [88])
            self.assertIsInstance(load(data_dir)["github"], dict)

    def test_app_installations_reads_more_than_one_page(self):
        first = [{"id": index, "account": {"login": "org" + str(index), "type": "Organization"}}
                 for index in range(1, 101)]
        second = [{"id": 101, "account": {"login": "extra", "type": "Organization"}}]
        with patch("appsec_agent.github_app._app_jwt", return_value="jwt"), \
                patch("appsec_agent.github_app._get", side_effect=[first, second]) as fetch:
            rows = github_app.app_installations()
        self.assertEqual((len(rows), rows[-1]["account"]), (101, "extra"))
        self.assertIn("page=2", fetch.call_args_list[-1].args[0])


if __name__ == "__main__":
    unittest.main()
