"""The local runner: the engines installed next to the worker, for platforms without a Docker socket."""

import json
import os
import stat
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from tamandua.modules.scanning import engines

# A stand-in engine: prints what it received (arguments, part of its environment, what it can read).
FAKE = """#!/bin/sh
printf '{"args": "%s", "home": "%s", "db": "%s", "key": "%s", "cache": "%s"}\\n' "$*" "$HOME" "$TAMANDUA_DATABASE_URL" "$TAMANDUA_MASTER_KEY" "$OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"
cat "$2/app.py" >&2
"""
SLEEPER = """#!/bin/sh
sleep 30 &
wait
"""


class LocalRunnerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        self.bin, self.snapshot, self.cache = root / "bin", root / "snapshot", root / "cache"
        for folder in (self.bin, self.snapshot, self.cache):
            folder.mkdir()
        (self.snapshot / "app.py").write_text("print('hi')\n")
        path = f"{self.bin}:/usr/bin:/bin"  # only the stand-ins, whatever the machine has installed
        environment = patch.dict(os.environ, {"PATH": path, "TAMANDUA_ENGINE_RUNNER": "local",
                                              "TAMANDUA_MASTER_KEY": "bm90LWEtcmVhbC1rZXktanVzdC1hLXRlc3QtMTIzNA=="})
        environment.start()
        self.addCleanup(environment.stop)

    def install(self, name: str, script: str) -> None:
        path = self.bin / name
        path.write_text(script)
        path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def test_container_paths_become_real_folders_and_back(self):
        self.install("osv-scanner", FAKE)
        completed = engines._run("osv-scanner", ["scan", "/src", "--cache", "/cache/db"], self.snapshot,
                                 env={"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": "/cache"},
                                 mounts=["-v", f"{engines.host_path(self.cache)}:/cache"])
        seen = json.loads(completed.stdout)
        self.assertEqual(seen["args"], "scan /src --cache /cache/db")  # the parsers keep seeing container paths
        self.assertEqual(seen["cache"], "/cache")
        self.assertEqual(completed.stderr, "print('hi')\n")  # but the engine read the real snapshot
        self.assertEqual((seen["db"], seen["key"]), ("", ""))  # never the worker's settings
        self.assertNotEqual(seen["home"], os.environ.get("HOME"))

    def test_readiness_follows_what_is_installed(self):
        self.assertFalse(engines.engine_ready("gitleaks"))
        self.assertIn("Gitleaks", str(engines.unavailable("gitleaks", "docker message")))
        self.install("gitleaks", FAKE)
        self.assertTrue(engines.engine_ready("gitleaks"))
        self.assertIsNone(engines.unavailable("gitleaks", "docker message"))
        self.assertTrue(engines.engines_available())

    def test_a_timeout_kills_the_engine_and_what_it_started(self):
        self.install("zizmor", SLEEPER)
        started = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):
            engines._run("zizmor", ["/src"], self.snapshot, timeout=1)
        self.assertLess(time.monotonic() - started, 10)
        leftovers = subprocess.run(["pgrep", "-f", "sleep 30"], capture_output=True, text=True).stdout.split()
        self.assertEqual([pid for pid in leftovers if int(pid) != os.getpid()], [])

    def test_opengrep_rule_ids_are_the_same_whatever_the_rules_folder(self):
        self.assertEqual(engines._rule_id("rules.appsec.py.eval-exec-non-literal"), "appsec.py.eval-exec-non-literal")
        self.assertEqual(engines._rule_id("data.work.scan-2l5.opengrep-rules.appsec.py.eval-exec-non-literal"),
                         "appsec.py.eval-exec-non-literal")

    def test_arguments_reach_the_engine_untouched_and_no_core_dumps(self):
        self.install("gitleaks", '#!/bin/sh\nprintf "%s|" "$@"; ulimit -c\n')
        tricky = ["dir", "/src", "--report-path", "a b; echo pwned", "$(id)", "`id`", "*"]
        completed = engines._run("gitleaks", tricky, self.snapshot)
        self.assertEqual(completed.stdout.strip(), "dir|/src|--report-path|a b; echo pwned|$(id)|`id`|*|0")



PREFIX = ["/usr/bin/unshare", "--user", "--map-current-user", "--net", "--"]


class NetworkIsolationTests(unittest.TestCase):
    """Local engines that need no network get an empty network namespace where the platform allows it."""

    def setUp(self):
        engines._netns_state.clear()
        self.addCleanup(engines._netns_state.clear)

    def launched(self, network: bool) -> list[str]:
        seen = {}

        class Process:
            pid, returncode = 1, 0

            def __init__(self, command, **_):
                seen["command"] = command

            def communicate(self, timeout=None):
                return "", ""
        with patch.dict(os.environ, {"TAMANDUA_ENGINE_RUNNER": "local"}), \
                patch.object(engines.shutil, "which", return_value="/usr/local/bin/gitleaks"), \
                patch.object(engines, "network_isolation", return_value=PREFIX), \
                patch.object(engines.subprocess, "Popen", Process):
            engines._run("gitleaks", ["dir", "/src"], Path("/tmp"), network=network)
        return seen["command"]

    def test_only_engines_without_network_are_isolated(self):
        self.assertEqual(self.launched(network=False)[:len(PREFIX)], PREFIX)
        self.assertEqual(self.launched(network=True)[0], "/bin/sh")

    def test_the_probe_falls_back_and_is_asked_once(self):
        answers = [subprocess.CompletedProcess([], 1), subprocess.CompletedProcess([], 0)]
        with patch.object(engines.shutil, "which", return_value="/usr/bin/unshare"), \
                patch.object(engines.subprocess, "run", side_effect=answers) as run:
            self.assertEqual(engines.network_isolation(), ["/usr/bin/unshare", "--user", "--map-root-user", "--net", "--"])
            engines.network_isolation()
        self.assertEqual(run.call_count, 2)

    def test_without_unshare_engines_run_as_before_and_it_is_logged(self):
        with patch.object(engines.shutil, "which", return_value=None), self.assertLogs("tamandua.engines", "WARNING") as logs:
            self.assertEqual(engines.network_isolation(), [])
        self.assertIn("local_engines_share_the_network", logs.output[0])

    def test_an_isolated_engine_cannot_reach_the_network(self):
        if not engines.network_isolation():
            self.skipTest("this platform doesn't allow user and network namespaces")
        probe = "import socket\ntry:\n    socket.create_connection(('1.1.1.1', 53), 3)\nexcept OSError as exc:\n    print(exc.errno)\nelse:\n    print('reached')\n"
        completed = subprocess.run([*engines.network_isolation(), "python3", "-c", probe], capture_output=True, text=True, timeout=30)
        self.assertNotEqual(completed.stdout.strip(), "reached")

if __name__ == "__main__":
    unittest.main()
