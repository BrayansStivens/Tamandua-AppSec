"""The GitHub Action (action.yml): the image of this version, no expressions inside scripts, pinned actions, inputs
documented in docs/cli.md, and the exact commands its scripts hand Docker (run against a fake `docker`)."""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tamandua.version import VERSION

ROOT = Path(__file__).resolve().parents[1]
ACTION = (ROOT / "action.yml").read_text(encoding="utf-8")
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
DOCS = (ROOT / "docs" / "cli.md", ROOT / "docs" / "es" / "cli.md")


def section(text: str, key: str) -> list[str]:
    """The lines under a top-level YAML key (no PyYAML: action.yml is simple enough to read by indentation)."""
    lines = text.splitlines()
    start = lines.index(f"{key}:") + 1
    end = next((i for i in range(start, len(lines)) if re.match(r"^[a-z]", lines[i])), len(lines))
    return lines[start:end]


def keys(text: str, key: str) -> list[str]:
    return [match.group(1) for line in section(text, key) if (match := re.match(r"^  ([a-z-]+):$", line))]


def defaults(text: str) -> dict[str, str]:
    found, current = {}, None
    for line in section(text, "inputs"):
        if match := re.match(r"^  ([a-z-]+):$", line):
            current = match.group(1)
        elif current and (match := re.match(r"^    default: (.*)$", line)):
            found[current] = json.loads(match.group(1)) if match.group(1).startswith('"') else match.group(1)
    return found


def steps(text: str) -> list[dict]:
    """Each composite step: its env ({VARIABLE: input}) and its `run: |` script, dedented."""
    found: list[dict] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if re.match(r"^    - ", line):
            found.append({"env": {}, "run": ""})
        elif match := re.match(r"^        ([A-Z_]+): \$\{\{ inputs\.([a-z-]+) \}\}$", line):
            found[-1]["env"][match.group(1)] = match.group(2)
        elif re.match(r"^      run: \|$", line):
            block = []
            i += 1
            while i < len(lines) and (not lines[i].strip() or lines[i].startswith("        ")):
                block.append(lines[i][8:])
                i += 1
            found[-1]["run"] = "\n".join(block).strip() + "\n"
            continue
        i += 1
    return found


def run_blocks(text: str) -> list[str]:
    """Every `run:` script (inline or block) in a workflow or action file."""
    blocks, lines, i = [], text.splitlines(), 0
    while i < len(lines):
        match = re.match(r"^(\s*)(?:- )?run: ?(.*)$", lines[i])
        i += 1
        if not match:
            continue
        indent, rest = len(match.group(1)), match.group(2)
        if rest.strip() not in ("|", ">", "|-", ">-"):
            blocks.append(rest)
            continue
        block = []
        while i < len(lines) and (not lines[i].strip() or len(lines[i]) - len(lines[i].lstrip()) > indent):
            block.append(lines[i])
            i += 1
        blocks.append("\n".join(block))
    return blocks


def documented(path: Path, header: str) -> list[str]:
    """First-column names of the markdown table whose header starts with `header`."""
    rows = path.read_text(encoding="utf-8").splitlines()
    start = next(i for i, row in enumerate(rows) if re.match(rf"^\| ({header}) \|", row))
    names = []
    for row in rows[start + 2:]:
        if not row.startswith("|"):
            break
        names.append(re.match(r"^\| `([a-z-]+)` \|", row).group(1))
    return names


FAKE_DOCKER = f"""#!{sys.executable}
import json, os, sys
log = os.environ["FAKE_LOG"]
calls = open(log).read().count("\\n") if os.path.exists(log) else 0
record = {{"argv": sys.argv[1:], "token": os.environ.get("TAMANDUA_IMPORT_TOKEN"),
           "docker_config": os.environ.get("DOCKER_CONFIG"), "stdin": sys.stdin.read() if "login" in sys.argv else None}}
open(log, "a").write(json.dumps(record) + "\\n")
if "scan" in sys.argv:
    open(os.path.join(os.environ["RUNNER_TEMP"], "tamandua", "result.sarif"), "w").write('{{"version": "2.1.0"}}')
codes = os.environ.get("FAKE_CODES", "").split(",")
sys.exit(int(codes[calls]) if calls < len(codes) and codes[calls] else 0)
"""


class ActionDefinitionTests(unittest.TestCase):
    def test_the_default_image_is_this_version(self):
        self.assertEqual(defaults(ACTION)["image"], f"ghcr.io/brayansstivens/tamandua-worker:{VERSION}")

    def test_scripts_never_interpolate_expressions(self):
        for path in (ROOT / "action.yml", *WORKFLOWS):
            for block in run_blocks(path.read_text(encoding="utf-8")):
                self.assertNotIn("${{", block, path)
        self.assertEqual(len(run_blocks(ACTION)), 2)

    def test_every_action_is_pinned_by_commit(self):
        for path in (ROOT / "action.yml", *WORKFLOWS):
            for reference in re.findall(r"^\s*(?:- )?uses: (\S+)", path.read_text(encoding="utf-8"), re.M):
                if reference != "./":
                    self.assertRegex(reference, r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$", path)

    def test_the_docs_list_the_same_inputs_and_outputs(self):
        for path in DOCS:
            self.assertEqual(documented(path, "Input|Entrada"), keys(ACTION, "inputs"), path)
            self.assertEqual(documented(path, "Output|Salida"), keys(ACTION, "outputs"), path)
            self.assertIn(f"tamandua-worker:{VERSION}", path.read_text(encoding="utf-8"), path)

    def test_the_self_test_job_uses_the_local_action(self):
        self.assertRegex((ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"), r"(?m)^\s+uses: \./(\s|$)")


@unittest.skipUnless(shutil.which("bash"), "needs bash")
class ActionScriptTests(unittest.TestCase):
    """The action's scripts, run as GitHub runs them (`bash -e -o pipefail`), with a fake docker that logs its calls."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        for folder in ("bin", "temp", "workspace/sub/dir", "workspace/reports"):
            (self.root / folder).mkdir(parents=True)
        docker = self.root / "bin" / "docker"
        docker.write_text(FAKE_DOCKER)
        docker.chmod(0o755)
        (self.root / "workspace" / "a.sarif").write_text("{}")
        (self.root / "workspace" / "reports" / "b.sarif").write_text("{}")
        self.log = self.root / "calls.jsonl"
        self.output = self.root / "output"

    def run_step(self, index: int, inputs: dict | None = None, codes: str = "", **env) -> tuple[int, list[dict], dict]:
        step = steps(ACTION)[index]
        values = {**defaults(ACTION), **(inputs or {})}
        environment = {
            "PATH": f"{self.root / 'bin'}{os.pathsep}{os.environ['PATH']}", "RUNNER_TEMP": str(self.root / "temp"),
            "GITHUB_WORKSPACE": str(self.root / "workspace"), "GITHUB_OUTPUT": str(self.output),
            "GITHUB_REPOSITORY": "acme/shop", "GITHUB_ACTOR": "octocat", "FAKE_LOG": str(self.log), "FAKE_CODES": codes,
            **{variable: values[name] for variable, name in step["env"].items()}, **env}
        completed = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", step["run"]],
                                   env=environment, capture_output=True, text=True, timeout=60)
        calls = [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []
        outputs = dict(line.split("=", 1) for line in self.output.read_text().splitlines()) if self.output.exists() else {}
        return completed.returncode, calls, outputs

    def command(self, call: dict) -> list[str]:
        """What runs inside the container: everything after the image."""
        return call["argv"][call["argv"].index(defaults(ACTION)["image"]) + 1:]

    def test_a_pull_request_scans_what_it_introduces(self):
        code, calls, outputs = self.run_step(1, GITHUB_BASE_REF="main")
        self.assertEqual(code, 0)
        self.assertEqual(len(calls), 1)
        argv = calls[0]["argv"]
        self.assertEqual(self.command(calls[0]), ["python", "-m", "tamandua", "scan", "/src", "--name", "shop",
                                                  "--fail-on", "high", "--format", "sarif", "--output",
                                                  "/data/result.sarif", "--summary", "/data/summary.md", "--base", "origin/main"])
        self.assertEqual(argv[:2], ["run", "--rm"])
        self.assertIn(f"{self.root / 'workspace'}:/src:ro", argv)
        self.assertIn(f"{self.root / 'temp' / 'tamandua'}:/data", argv)
        self.assertIn("TAMANDUA_ENGINE_RUNNER=local", argv)
        self.assertIn(f"{os.getuid()}:{os.getgid()}", argv)
        self.assertEqual(argv[argv.index("--cap-drop") + 1], "ALL")
        self.assertFalse(any("docker.sock" in item for item in argv))
        self.assertIsNone(calls[0]["token"])
        sarif = self.root / "temp" / "tamandua.sarif"
        self.assertEqual(outputs, {"sarif": str(sarif), "exit-code": "0"})
        self.assertTrue(sarif.is_file())

    def test_inputs_become_arguments_without_a_shell(self):
        code, calls, outputs = self.run_step(1, {
            "path": "./sub/dir/", "base": "main; touch pwned", "fail-on": "critical", "name": "$(touch pwned)",
            "exclude": "fixtures/\n  **/testdata  \n\n", "allow-incomplete": "true", "sarif": "out/tamandua.sarif"},
            codes="1")
        self.assertEqual(code, 1)
        self.assertEqual(self.command(calls[0]), [
            "python", "-m", "tamandua", "scan", "/src/sub/dir", "--name", "$(touch pwned)", "--fail-on", "critical",
            "--format", "sarif", "--output", "/data/result.sarif", "--summary", "/data/summary.md", "--base", "main; touch pwned",
            "--exclude", "fixtures/", "--exclude", "**/testdata", "--allow-incomplete"])
        self.assertEqual(outputs, {"sarif": str(self.root / "workspace" / "out" / "tamandua.sarif"), "exit-code": "1"})
        self.assertEqual(list(self.root.rglob("pwned")), [])

    def test_base_none_scans_everything_even_on_a_pull_request(self):
        code, calls, _ = self.run_step(1, {"base": "none"}, codes="3", GITHUB_BASE_REF="main")
        self.assertEqual(code, 3)
        self.assertNotIn("--base", self.command(calls[0]))

    def test_usage_errors_stop_before_docker(self):
        for inputs in ({"path": "../elsewhere"}, {"path": "/etc"}, {"path": "sub/../../x"}, {"allow-incomplete": "yes"},
                       {"scan": "false"}, {"import-sarif": "a.sarif", "server": "https://t.example"},
                       {"import-sarif": "missing.sarif", "server": "https://t.example", "token": "t"}):
            with self.subTest(inputs=inputs):
                self.log.unlink(missing_ok=True)
                self.output.unlink(missing_ok=True)
                code, calls, outputs = self.run_step(1, inputs)
                self.assertEqual((code, outputs.get("exit-code")), (2, "2"))
                self.assertEqual(calls, [])

    def test_import_only_passes_the_token_through_the_environment(self):
        code, calls, outputs = self.run_step(1, {
            "scan": "false", "import-sarif": "a.sarif\n reports/b.sarif \n", "server": "https://tamandua.example.com",
            "token": "s3cret-token", "import-partial": "true"})
        self.assertEqual(code, 0)
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.command(calls[0]), [
            "python", "-m", "tamandua", "import-sarif", "/data/import/1-a.sarif", "/data/import/2-b.sarif",
            "--asset", "acme/shop", "--server", "https://tamandua.example.com", "--partial"])
        self.assertEqual(calls[0]["token"], "s3cret-token")
        argv = calls[0]["argv"]
        self.assertIn("TAMANDUA_IMPORT_TOKEN", argv)
        self.assertFalse(any("s3cret" in item for item in argv))
        self.assertEqual(outputs, {"exit-code": "0"})
        self.assertFalse((self.root / "temp" / "tamandua" / "import").exists())

    def test_scan_then_import_keeps_the_scan_verdict(self):
        code, calls, outputs = self.run_step(1, {"import-sarif": "a.sarif", "server": "https://t.example",
                                                 "token": "t", "asset": "team/api"}, codes="1,0")
        self.assertEqual(code, 1)
        self.assertEqual([self.command(call)[3] for call in calls], ["scan", "import-sarif"])
        self.assertIsNone(calls[0]["token"])
        self.assertIn("team/api", self.command(calls[1]))
        self.assertEqual(outputs["exit-code"], "1")
        self.log.unlink()
        code, _, _ = self.run_step(1, {"scan": "false", "import-sarif": "a.sarif", "server": "https://t.example",
                                       "token": "t"}, codes="2")
        self.assertEqual(code, 2)

    def test_registry_login_reads_the_token_from_stdin_and_forgets_it(self):
        code, calls, _ = self.run_step(0, {"registry-token": "ghs_example"})
        self.assertEqual(code, 0)
        login, pull = calls
        self.assertEqual(login["argv"], ["login", "ghcr.io", "--username", "octocat", "--password-stdin"])
        self.assertEqual(login["stdin"], "ghs_example")
        self.assertEqual(pull["argv"], ["pull", "--quiet", defaults(ACTION)["image"]])
        self.assertTrue(login["docker_config"].startswith(str(self.root / "temp")))
        self.assertFalse(Path(login["docker_config"]).exists())


if __name__ == "__main__":
    unittest.main()
