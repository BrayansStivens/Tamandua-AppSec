"""La conexión de IA conserva las claves en el servidor y no consume inferencia."""

import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError

from tamandua.modules.integrations import github as github_app
from tamandua.shared import paths
from tamandua.modules.integrations.ai_providers import _NoRedirect, check_provider, provider_status


class FakeResponse:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self, _limit):
        return b'{"data":[{"id":"modelo-de-prueba"}]}'


class ProviderTests(unittest.TestCase):
    def setUp(self):
        # El almacén de claves se aísla: sin esto las pruebas leerían la credencial
        # real de quien las ejecuta y podrían filtrarla en un mensaje de fallo.
        self.store = tempfile.TemporaryDirectory()
        patcher = patch.object(paths, "CONFIG_DIR", Path(self.store.name) / "config")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.store.cleanup)

    def test_missing_keys_never_call_network(self):
        with patch.dict("os.environ", {"OPENAI_API_KEY": "", "ANTHROPIC_API_KEY": ""}), \
                patch("tamandua.modules.integrations.ai_providers.build_opener") as transport:
            self.assertEqual([item["configured"] for item in provider_status()], [False, False])
            self.assertEqual(check_provider("openai")["status"], "not_configured")
            transport.assert_not_called()

    def test_accepted_credentials_are_sent_only_to_fixed_provider_hosts(self):
        for provider, env_name, hostname, header in (
            ("openai", "OPENAI_API_KEY", "api.openai.com", "Authorization"),
            ("anthropic", "ANTHROPIC_API_KEY", "api.anthropic.com", "X-api-key"),
        ):
            with self.subTest(provider=provider), patch.dict("os.environ", {env_name: "test-secret"}), \
                    patch("tamandua.modules.integrations.ai_providers.build_opener") as opener:
                opener.return_value.open.return_value = FakeResponse()
                result = check_provider(provider)
                self.assertEqual(result["status"], "connected")
                self.assertNotIn("test-secret", json.dumps(result))
                self.assertIs(opener.call_args.args[0], _NoRedirect)
                request = opener.return_value.open.call_args.args[0]
                self.assertEqual(request.host, hostname)
                self.assertIn("test-secret", request.headers[header])

    def test_provider_error_does_not_echo_credential_or_response_body(self):
        error = HTTPError("https://api.openai.com/v1/models", 401, "secret in remote body", {}, io.BytesIO(b"test-secret"))
        with patch.dict("os.environ", {"OPENAI_API_KEY": "test-secret"}), \
                patch("tamandua.modules.integrations.ai_providers.build_opener") as opener:
            opener.return_value.open.side_effect = error
            result = check_provider("openai")
        self.assertEqual(result["status"], "invalid_credentials")
        self.assertNotIn("secret", json.dumps(result))

    def test_redirect_is_rejected_before_reusing_a_credential(self):
        self.assertIsNone(_NoRedirect().redirect_request(None, None, 302, "moved", {}, "https://other.example/models"))


if __name__ == "__main__":
    unittest.main()
