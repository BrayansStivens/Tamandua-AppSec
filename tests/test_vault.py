import base64
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sqlalchemy import select

import testenv
from tamandua.shared import paths
from tamandua.shared import log as logging_setup
from tamandua.shared import vault
from tamandua.shared.i18n import text

# Synthetic values built from pieces: the repository holds no credential-shaped literals.
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
        environment = patch.dict(os.environ, testenv.base(), clear=True)
        environment.start()
        self.addCleanup(environment.stop)

    def rows(self) -> dict:
        from tamandua.shared import db
        with db.separate_transaction(self.config) as connection:
            return {row.name: {"nonce": row.nonce, "data": row.data}
                    for row in connection.execute(select(vault.vault_entries.c.name, vault.vault_entries.c.nonce, vault.vault_entries.c.data))}

    def overwrite(self, name: str, entry: dict) -> None:
        from sqlalchemy.dialects.postgresql import insert
        from tamandua.shared import db
        statement = insert(vault.vault_entries).values(name=name, **entry)
        with db.separate_transaction(self.config) as connection:
            connection.execute(statement.on_conflict_do_update(index_elements=["tenant_id", "name"],
                                                               set_={"nonce": statement.excluded.nonce, "data": statement.excluded.data}))

    def test_round_trip_is_encrypted_and_bound_to_the_name(self):
        vault.put("ai_keys", {"openai": {"api_key": OPENAI_KEY, "last4": "-123"}})
        self.assertEqual(vault.get("ai_keys")["openai"]["api_key"], OPENAI_KEY)
        stored = self.rows()
        self.assertNotIn("valor-muy-secreto", json.dumps(stored))
        self.assertFalse((self.config / "secrets.vault").exists())  # nothing but the master key on disk
        # Moving one entry's ciphertext to another doesn't decrypt: the name is associated data.
        self.overwrite("jira", stored["ai_keys"])
        with self.assertRaises(vault.VaultError):
            vault.get("jira")
        self.assertIsNone(vault.get("inexistente"))
        self.assertTrue(vault.delete("ai_keys"))
        self.assertFalse(vault.delete("ai_keys"))

    def test_tampering_or_another_key_fails_closed(self):
        vault.put("jira", {"token": "ATATT3xFfGF0-token-de-prueba"})
        entry = self.rows()["jira"]
        data = bytearray(base64.b64decode(entry["data"]))
        data[0] ^= 1
        self.overwrite("jira", {**entry, "data": base64.b64encode(bytes(data)).decode()})
        with self.assertRaises(vault.VaultError):
            vault.get("jira")
        vault.put("jira", {"token": "ATATT3xFfGF0-token-de-prueba"})
        with patch.dict(os.environ, {"TAMANDUA_MASTER_KEY": base64.b64encode(b"k" * 32).decode()}):
            with self.assertRaises(vault.VaultError):
                vault.get("jira")
        with patch.dict(os.environ, {"TAMANDUA_MASTER_KEY": "corta"}):
            with self.assertRaises(vault.VaultError) as raised:
                vault.put("x", "y")
        # English for logs; the message renders in each reader's language.
        self.assertEqual(str(raised.exception), "TAMANDUA_MASTER_KEY isn't valid base64")
        self.assertEqual(text(raised.exception.message, "es"), "TAMANDUA_MASTER_KEY no es base64 válido")

    def test_master_key_from_environment_is_never_written(self):
        with patch.dict(os.environ, {"TAMANDUA_MASTER_KEY": base64.b64encode(b"m" * 32).decode()}):
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
        self.assertIn("appsec", logging_setup.redact("slug appsec"))  # what isn't a secret is kept

    def test_the_vault_file_of_earlier_versions_is_imported_once(self):
        vault.put("jira", {"token": "ATATT3xFfGF0-nuevo"})
        vault.put("ai_keys", {"openai": {"api_key": OPENAI_KEY}})
        legacy = self.rows()
        vault.delete("ai_keys")
        vault.put("jira", {"token": "ATATT3xFfGF0-mas-nuevo"})
        (self.config / "secrets.vault").write_text(json.dumps(legacy))
        self.assertEqual(vault.import_file(), 1)  # ai_keys comes back; jira keeps the database's newer value
        self.assertEqual((vault.get("jira")["token"], vault.get("ai_keys")["openai"]["api_key"]), ("ATATT3xFfGF0-mas-nuevo", OPENAI_KEY))
        self.assertFalse((self.config / "secrets.vault").exists())
        self.assertTrue((self.config / "secrets.vault.imported").exists())
        self.assertEqual(vault.import_file(), 0)

    def test_several_processes_agree_on_one_generated_value(self):
        first = vault.put_if_absent("session-key", {"session_key": "uno"})
        second = vault.put_if_absent("session-key", {"session_key": "dos"})
        self.assertEqual((first, second), ({"session_key": "uno"}, {"session_key": "uno"}))


if __name__ == "__main__":
    unittest.main()
