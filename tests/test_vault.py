import base64
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tamandua.modules.integrations import github as github_app
from tamandua.shared import paths
from tamandua.shared import log as logging_setup
from tamandua.shared import vault

# Valores sintéticos armados por partes: el repositorio no lleva literales con forma de credencial.
OPENAI_KEY = "-".join(("sk", "proj", "valor", "muy", "secreto", "123"))
CLIENT_SECRET = "".join(format(digit, "x") for digit in range(16)) * 2 + "01234567"


class VaultTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.config = Path(self.directory.name) / "config"
        patcher = patch.object(paths, "CONFIG_DIR", self.config)
        patcher.start()
        self.addCleanup(patcher.stop)
        environment = patch.dict(os.environ, {}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)

    def test_round_trip_is_encrypted_and_bound_to_the_name(self):
        vault.put("ai_keys", {"openai": {"api_key": OPENAI_KEY, "last4": "-123"}})
        self.assertEqual(vault.get("ai_keys")["openai"]["api_key"], OPENAI_KEY)
        raw = (self.config / "secrets.vault").read_text()
        self.assertNotIn("valor-muy-secreto", raw)
        # Mover el cifrado de una entrada a otra no descifra: el nombre va como dato asociado.
        payload = json.loads(raw)
        payload["jira"] = payload["ai_keys"]
        (self.config / "secrets.vault").write_text(json.dumps(payload))
        with self.assertRaises(vault.VaultError):
            vault.get("jira")
        self.assertIsNone(vault.get("inexistente"))
        self.assertTrue(vault.delete("ai_keys"))
        self.assertFalse(vault.delete("ai_keys"))

    def test_tampering_or_another_key_fails_closed(self):
        vault.put("jira", {"token": "ATATT3xFfGF0-token-de-prueba"})
        payload = json.loads((self.config / "secrets.vault").read_text())
        data = bytearray(base64.b64decode(payload["jira"]["data"]))
        data[0] ^= 1
        payload["jira"]["data"] = base64.b64encode(bytes(data)).decode()
        (self.config / "secrets.vault").write_text(json.dumps(payload))
        with self.assertRaises(vault.VaultError):
            vault.get("jira")
        vault.put("jira", {"token": "ATATT3xFfGF0-token-de-prueba"})
        with patch.dict(os.environ, {"APPSEC_AGENT_MASTER_KEY": base64.b64encode(b"k" * 32).decode()}):
            with self.assertRaises(vault.VaultError):
                vault.get("jira")
        with patch.dict(os.environ, {"APPSEC_AGENT_MASTER_KEY": "corta"}):
            with self.assertRaises(vault.VaultError):
                vault.put("x", "y")

    def test_master_key_from_environment_is_never_written(self):
        with patch.dict(os.environ, {"APPSEC_AGENT_MASTER_KEY": base64.b64encode(b"m" * 32).decode()}):
            vault.put("jira", {"token": "ATATT3xFfGF0-otro-token"})
            self.assertEqual(vault.get("jira")["token"], "ATATT3xFfGF0-otro-token")
        self.assertFalse((self.config / "master.key").exists())

    def test_known_secrets_and_patterns_are_scrubbed_from_logs(self):
        vault.put("github_app", {"client_secret": CLIENT_SECRET, "slug": "appsec"})
        vault.get("github_app")
        line = logging_setup.redact(f"fallo con {CLIENT_SECRET} y github_pat_11ABCDEFG y "
                                    "Authorization: Basic c2VjOnRva2Vu -----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----")
        for leaked in (CLIENT_SECRET, "11ABCDEFG", "c2VjOnRva2Vu", "MIIE"):
            self.assertNotIn(leaked, line)
        self.assertIn("appsec", logging_setup.redact("slug appsec"))  # lo que no es secreto se conserva


if __name__ == "__main__":
    unittest.main()
