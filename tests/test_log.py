"""Logs go to the process output (what every platform collects); a file only when asked for."""

import io
import json
import logging
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tamandua.shared import log


class LogTests(unittest.TestCase):
    def setUp(self):
        self.root = logging.getLogger("tamandua")
        self.saved = (log._configured, list(self.root.handlers), self.root.level)
        log._configured = False

    def tearDown(self):
        for handler in self.root.handlers:
            if handler not in self.saved[1]:
                handler.close()
        log._configured, self.root.handlers, level = self.saved
        self.root.setLevel(level)

    def test_json_on_the_process_output_and_no_file_by_default(self):
        stream = io.StringIO()
        with tempfile.TemporaryDirectory() as folder, patch.dict("os.environ", {"TAMANDUA_LOG_FORMAT": "json"}), \
                patch.object(log.sys, "stderr", stream):
            log.configure(Path(folder))
            log.get("test").info("hello", extra={"run_id": "r1", "reason": "token=ghp_abcdefghijklmnopqrstuvwxyz0123456789"})
            self.assertFalse((Path(folder) / "logs").exists())
        event = json.loads(stream.getvalue().strip())
        self.assertEqual((event["msg"], event["run_id"], event["level"]), ("hello", "r1", "info"))
        self.assertNotIn("ghp_abcdefghijklmnopqrstuvwxyz", event["reason"])

    def test_a_relative_log_file_lives_under_the_data_folder(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict("os.environ", {"TAMANDUA_LOG_FILE": "logs/app.log"}), \
                patch.object(log.sys, "stderr", io.StringIO()):
            log.configure(Path(folder))
            log.get("test").warning("written")
            for handler in self.root.handlers:
                handler.flush()
            lines = (Path(folder) / "logs" / "app.log").read_text().splitlines()
        self.assertEqual(json.loads(lines[-1])["msg"], "written")


if __name__ == "__main__":
    unittest.main()
