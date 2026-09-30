"""SARIF import: any tool's findings into an asset's registry, fixed only by a later full import of the same tool."""

import io
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from tamandua.modules.findings import registry, triage
from tamandua.modules.runs import registry as run_registry
from tamandua.modules.runs.imports import ImportRefused, import_sarif
from tamandua.modules.runs.store import load_run, render_repository_report, render_repository_sarif, save_repository_scan
from tamandua.modules.scanning.engines import _stable, parse_opengrep
from tamandua.modules.scanning.sarif_import import MAX_RESULTS, MAX_RUNS, SarifError, parse
from tamandua.shared.i18n import text

from test_auth import ORIGIN, PASSWORD, HttpCase
from test_dashboard import _finding, _scan

FIXTURE = Path(__file__).resolve().parent / "engine-outputs" / "import.sarif"
KEY = "github#7"
A = "a" * 64
USER = {"username": "ana", "role": "member"}
TOKEN = "i" * 40


def fixture() -> dict:
    return json.loads(FIXTURE.read_text())


def sarif(tool: str, results: list[dict], rules: list[dict] | None = None) -> dict:
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": tool, "rules": rules or []}}, "results": results}]}


def result(rule="rule.one", path="src/app.py", line=10, snippet="eval(x)", **extra) -> dict:
    region = {"startLine": line, **({"snippet": {"text": snippet}} if snippet is not None else {})}
    return {"ruleId": rule, "message": {"text": f"{rule} matched"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": path}, "region": region}}], **extra}


def only(document: dict, **options) -> list[dict]:
    return parse(document, **options)[0]["findings"]


class ParserTests(unittest.TestCase):
    def test_fixture_one_entry_per_tool_with_severity_cwe_and_location(self):
        runs = parse(fixture())
        self.assertEqual([(run["tool"], run["version"], run["results"], run["skipped"]) for run in runs],
                         [("Semgrep OSS", "1.90.0", 3, 1), ("CodeQL", "2.19.0", 1, 0)])
        sql, evaluated = runs[0]["findings"]
        self.assertEqual((sql["scanner"], sql["severity"], sql["cwe"], sql["path"], sql["line"], sql["confidence"], sql["tool"]),
                         ("sast", "high", [89], "src/app/db.py", 42, 8, "Semgrep OSS"))
        self.assertEqual(sql["title"], "SQL built by string concatenation")  # third-party text, stored as published
        self.assertEqual((sql["priority"]["action"], sql["reason"]["$t"]),
                         ("attend", "scanning.sarif.reason"))
        self.assertEqual((evaluated["severity"], evaluated["path"], evaluated["cwe"]), ("medium", "app/tools.py", [95]))
        xss = runs[1]["findings"][0]
        self.assertEqual((xss["severity"], xss["cwe"], xss["rule_id"], xss["priority"]["action"]), ("critical", [79, 116], "js/xss", "act"))
        self.assertEqual((len(xss["fingerprint"]), xss["finding_id"]), (64, xss["fingerprint"][:16]))

    def test_severity_from_security_severity_then_level(self):
        def severity(**properties):
            level = properties.pop("level", None)
            return only(sarif("X", [result(**({"level": level} if level else {}), properties=properties)]))[0]["severity"]
        self.assertEqual([severity(**{"security-severity": value}) for value in ("9.0", "8.9", "7", "4.0", "3.9", "0.1", "0")],
                         ["critical", "high", "high", "medium", "low", "low", "info"])
        self.assertEqual([severity(level=level) for level in ("error", "warning", "note", "none")], ["high", "medium", "low", "info"])
        self.assertEqual(severity(), "medium")  # SARIF's default level is warning
        self.assertEqual(severity(**{"security-severity": "high", "level": "note"}), "low")  # not a number: the level decides
        rule = {"id": "rule.one", "defaultConfiguration": {"level": "error"}, "properties": {"security-severity": "9.8"}}
        self.assertEqual(only(sarif("X", [result()], [rule]))[0]["severity"], "critical")

    def test_cwe_from_tags_and_taxa_and_identifiers_from_the_rule(self):
        finding = only(sarif("X", [result(rule="CVE-2021-44228", properties={"tags": ["external/cwe/cwe-502", "GHSA-jfh8-c2jp-5v3q"]},
                                          taxa=[{"id": "20", "toolComponent": {"name": "CWE"}}])]))[0]
        self.assertEqual((finding["cwe"], finding["cve"], finding["ghsa"], finding["scanner"]),
                         ([20, 502], ["CVE-2021-44228"], ["GHSA-jfh8-c2jp-5v3q"], "sca"))

    def test_scanner_from_the_tool_or_the_tags(self):
        def scanner(tool, **extra):
            return only(sarif(tool, [result(**extra)]))[0]
        leak = scanner("gitleaks")
        self.assertEqual((leak["scanner"], leak["severity"]), ("secrets", "critical"))  # an exposed secret is always critical
        self.assertEqual(scanner("Trivy", properties={"tags": ["secret"]})["scanner"], "secrets")
        self.assertEqual(scanner("Trivy", properties={"tags": ["misconfiguration"]})["scanner"], "iac")
        self.assertEqual(scanner("Trivy")["scanner"], "sca")
        self.assertEqual(scanner("Checkov")["scanner"], "iac")
        self.assertEqual(scanner("zizmor")["scanner"], "cicd")
        self.assertEqual(scanner("Snyk Open Source")["scanner"], "sca")
        self.assertEqual(scanner("SnykCode")["scanner"], "sast")
        self.assertEqual(scanner("Claude Security")["scanner"], "sast")

    def test_fingerprint_ignores_the_line_and_is_namespaced_per_tool(self):
        before = only(sarif("Semgrep", [result(line=10)]))[0]["fingerprint"]
        self.assertEqual(only(sarif("Semgrep", [result(line=90)]))[0]["fingerprint"], before)  # lines added above
        self.assertEqual(only(sarif("semgrep", [result(line=90)]))[0]["fingerprint"], before)  # tool name case
        self.assertNotEqual(only(sarif("Semgrep", [result(snippet="eval(y)")]))[0]["fingerprint"], before)
        self.assertNotEqual(only(sarif("CodeQL", [result()]))[0]["fingerprint"], before)
        partial = {"partialFingerprints": {"primaryLocationLineHash": "abc:1"}}
        moved = only(sarif("CodeQL", [result(line=5, snippet="a", **partial)]))[0]["fingerprint"]
        self.assertEqual(only(sarif("CodeQL", [result(line=50, snippet="b", **partial)]))[0]["fingerprint"], moved)
        full = {"fingerprints": {"matchBasedId/v1": "f00"}}
        self.assertEqual(only(sarif("Semgrep", [result(path="a.py", **full)]))[0]["fingerprint"],
                         only(sarif("Semgrep", [result(path="renamed/a.py", **full)]))[0]["fingerprint"])
        twice = only(sarif("Semgrep", [result(line=1), result(line=2)]))
        self.assertEqual(len({item["fingerprint"] for item in twice}), 2)  # identical keys, told apart by order
        self.assertEqual(twice[0]["fingerprint"], before)

    def test_never_collides_with_tamandua_engines(self):
        opengrep = parse_opengrep({"results": [{"check_id": "rule.one", "path": "/src/src/app.py", "start": {"line": 10},
                                                "extra": {"lines": "eval(x)", "severity": "ERROR", "metadata": {}}}]})[0]
        imported = only(sarif("opengrep", [result()]))[0]
        self.assertEqual(opengrep["fingerprint"], _stable("sast", "rule.one", "src/app.py", "eval(x)"))
        self.assertNotEqual(imported["fingerprint"], opengrep["fingerprint"])

    def test_skips_suppressed_passing_and_absent_results(self):
        document = sarif("X", [result(), result(path="b.py", kind="pass"), result(path="c.py", baselineState="absent"),
                               result(path="d.py", suppressions=[{"kind": "external", "status": "accepted"}]),
                               result(path="e.py", suppressions=[{"kind": "external", "status": "rejected"}])])
        run = parse(document)[0]
        self.assertEqual(([item["path"] for item in run["findings"]], run["skipped"]), (["src/app.py", "e.py"], 3))

    def test_runs_of_the_same_tool_are_one_and_the_tool_can_be_named(self):
        document = {"version": "2.1.0", "runs": [*sarif("Semgrep", [result()])["runs"], *sarif("semgrep", [result(path="b.py")])["runs"]]}
        self.assertEqual([(run["tool"], len(run["findings"])) for run in parse(document)], [("Semgrep", 2)])
        named = parse(fixture(), tool="Strix")
        self.assertEqual([(run["tool"], len(run["findings"])) for run in named], [("Strix", 3)])

    def test_bounds_and_refusals(self):
        def refused(document, **options):
            with self.assertRaises(SarifError) as caught:
                parse(document, **options)
            return caught.exception.message["$t"]
        self.assertEqual(refused({"version": "2.0.0", "runs": []}), "scanning.sarif.errors.version")
        self.assertEqual(refused([]), "scanning.sarif.errors.version")
        self.assertEqual(refused({"version": "2.1.0", "runs": []}), "scanning.sarif.errors.no_runs")
        self.assertEqual(refused({"version": "2.1.0", "runs": [sarif("X", [])["runs"][0]] * (MAX_RUNS + 1)}), "scanning.sarif.errors.too_many_runs")
        self.assertEqual(refused(sarif("X", [result()] * (MAX_RESULTS + 1))), "scanning.sarif.errors.too_many_results")
        self.assertEqual(refused(sarif("", [result()])), "scanning.sarif.errors.no_tool")
        self.assertEqual(refused(sarif("X", [result()]), tool="  "), "scanning.sarif.errors.no_tool")
        long = only(sarif("X" * 500, [result(path="/" + "d/" * 900 + "f.py", rule="r" * 500)],
                          [{"id": "r" * 200, "shortDescription": {"text": "t" * 900}}]))[0]
        self.assertEqual((len(long["tool"]), len(long["path"]), len(long["rule_id"]), len(long["title"])), (100, 1000, 200, 300))
        garbage = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "X"}}, "results": [None, 3, {"locations": "x", "message": 5}]}]}
        self.assertEqual(only(garbage)[0]["path"], "")


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data_dir = Path(self.directory.name)
        self.clock = datetime.now(timezone.utc)
        self.scan([_finding(A)])

    def scan(self, findings, *, pr=None):
        self.clock += timedelta(hours=1)
        record = _scan("org/api", findings, self.clock.isoformat())
        record["source"]["uid"] = KEY
        record["finished_at"] = self.clock.isoformat()
        if pr:
            record.update(type="pr_review", pull_request={"number": pr, "head_sha": "1" * 40, "head_ref": "feat"})
        return save_repository_scan(self.data_dir, record, created_at=self.clock.isoformat())

    def import_(self, document, **options):
        with patch("tamandua.modules.runs.imports.datetime") as clock:
            self.clock += timedelta(hours=1)
            clock.now.return_value = self.clock
            return import_sarif(self.data_dir, document, **{"asset": "org/api", "requested_by": "ana", **options})

    def entries(self):
        return registry.load(self.data_dir, KEY)["findings"]

    def status(self, tool=None):
        return {digest: entry["status"] for digest, entry in self.entries().items()
                if tool is None or (entry.get("origin") or {}).get("tool") == tool}

    def test_an_import_opens_one_run_per_tool_with_import_origin(self):
        outcome = self.import_(fixture(), commit="ABCDEF1", branch="main")
        self.assertEqual((outcome["asset"], outcome["name"]), (KEY, "org/api"))
        self.assertEqual([(run["tool"], run["findings"], run["opened"], run["fixed"], run["skipped"]) for run in outcome["runs"]],
                         [("Semgrep OSS", 2, 2, 0, 1), ("CodeQL", 1, 1, 0, 0)])
        record = load_run(self.data_dir, outcome["runs"][0]["id"])
        self.assertEqual((record["type"], record["status"], record["requested_by"], record["trigger"]["scope"], record["source"]["commit"],
                          record["source"]["branch"], record["source"]["uid"]),
                         ("sarif_import", "completed", "ana", "full", "abcdef1", "main", KEY))
        self.assertEqual(record["summary"]["severities"]["high"], 1)
        origins = {(entry["origin"]["kind"], entry["origin"].get("tool")) for entry in self.entries().values()}
        self.assertEqual(origins, {("scan", None), ("import", "Semgrep OSS"), ("import", "CodeQL")})
        # The run renders like any other: Markdown, SARIF export.
        self.assertIn("Semgrep OSS", render_repository_report(record, locale="en"))
        self.assertEqual(len(render_repository_sarif(record)["runs"][0]["results"]), 2)

    def test_a_full_import_of_the_same_tool_fixes_what_it_no_longer_reports(self):
        self.import_(fixture())
        semgrep = self.status("Semgrep OSS")
        without = fixture()
        without["runs"][0]["results"] = without["runs"][0]["results"][:1]  # the eval finding is gone
        outcome = self.import_({"version": "2.1.0", "runs": without["runs"][:1]})
        self.assertEqual((outcome["runs"][0]["opened"], outcome["runs"][0]["fixed"]), (0, 1))
        self.assertEqual(sorted(self.status("Semgrep OSS").values()), ["fixed", "open"])
        gone = next(entry for digest, entry in self.entries().items() if digest in semgrep and entry["status"] == "fixed")
        self.assertIn("Semgrep OSS", text(gone["fixed"]["how"], "en"))
        self.assertEqual(set(self.status("CodeQL").values()), {"open"})  # another tool's import vouches for nothing else
        self.assertEqual(self.status()[A], "open")                     # nor for Tamandua's own findings
        self.import_(fixture())
        self.assertEqual(set(self.status("Semgrep OSS").values()), {"open"})  # it came back: it reopens

    def test_a_partial_import_never_fixes(self):
        self.import_(fixture())
        outcome = self.import_(sarif("Semgrep OSS", []), scope="partial")
        self.assertEqual(outcome["runs"][0]["fixed"], 0)
        self.assertEqual(set(self.status("Semgrep OSS").values()), {"open"})
        self.assertEqual(load_run(self.data_dir, outcome["runs"][0]["id"])["steps"][0]["status"], "partial")

    def test_another_tools_full_import_fixes_nothing(self):
        self.import_(fixture())
        self.import_(sarif("Snyk Code", []))
        self.assertEqual(set(self.status().values()), {"open"})

    def test_tamandua_scans_and_pr_reviews_never_fix_imported_findings(self):
        self.import_(fixture())
        self.scan([])
        self.scan([], pr=3)
        states = self.status()
        self.assertEqual(states.pop(A), "fixed")  # the full scan does fix its own
        self.assertEqual(set(states.values()), {"open"})
        run_registry.rebuild(self.data_dir)      # replaying every run gives the same state
        self.assertEqual({digest: status for digest, status in self.status().items() if digest != A}, states)

    def test_triage_survives_new_imports(self):
        outcome = self.import_(fixture())
        record = load_run(self.data_dir, outcome["runs"][1]["id"])
        digest = record["findings"][0]["fingerprint"]
        triage.decide(self.data_dir, record, [digest], "false_positive", reason="sanitized upstream", user=USER)
        self.import_(fixture())
        self.assertEqual(triage.load(self.data_dir)[KEY][digest]["status"], "false_positive")
        self.assertEqual(registry.summarize(self.data_dir, KEY)["suppressed"], 1)

    def test_the_asset_must_exist(self):
        with self.assertRaises(ImportRefused) as caught:
            self.import_(fixture(), asset="org/unknown")
        self.assertEqual(caught.exception.status, 404)
        self.assertEqual(self.import_(fixture(), asset=KEY)["asset"], KEY)  # by key too
        self.assertEqual(self.import_(fixture(), asset="ORG/API")["asset"], KEY)  # names ignore case
        for options, status in (({"scope": "all"}, 400), ({"commit": "xyz"}, 400), ({"branch": "../x"}, 400), ({"asset": ""}, 400)):
            with self.assertRaises(ImportRefused) as caught:
                self.import_(fixture(), **options)
            self.assertEqual(caught.exception.status, status, options)

    def test_a_repository_the_app_covers_counts_as_an_asset(self):
        from tamandua.modules.sources import assets as source_assets
        source_assets.set_scan_branch(self.data_dir, "github#9", None, name="org/new", source_id="github:org/new", by="ana")
        outcome = self.import_(fixture(), asset="org/new")
        self.assertEqual(outcome["asset"], "github#9")
        self.assertEqual(load_run(self.data_dir, outcome["runs"][0]["id"])["source"]["id"], "github:org/new")

    def test_all_runs_of_a_document_or_none(self):
        from tamandua.modules.runs import imports, store
        calls = []

        def failing(*args, **kwargs):
            calls.append(1)
            if len(calls) == 2:
                raise RuntimeError("boom")
            return store.save_and_apply(*args, **kwargs)
        before = len(store.find_runs(self.data_dir))
        with patch.object(imports, "save_and_apply", failing), self.assertRaises(RuntimeError):
            self.import_(fixture())
        self.assertEqual(len(store.find_runs(self.data_dir)), before)
        self.assertEqual(set(self.status()), {A})

    def test_the_dashboard_counts_imported_findings(self):
        from tamandua.modules.reporting import dashboard
        self.import_(fixture())
        without = fixture()
        without["runs"][0]["results"] = without["runs"][0]["results"][:1]
        self.import_({"version": "2.1.0", "runs": without["runs"][:1]})
        data = dashboard.compute(self.data_dir)
        asset = next(row for row in data["top_assets"] if row["name"] == "org/api")
        self.assertEqual((asset["open"], asset["critical"]), (3, 1))  # Tamandua's one + Semgrep's one + CodeQL's one
        self.assertEqual(data["kpis"]["fixed_in_window"], 1)


class ApiTests(HttpCase):
    def setUp(self):
        super().setUp()
        from tamandua.modules.identity.auth import Users
        record = _scan("org/api", [_finding(A)], datetime.now(timezone.utc).isoformat())
        record["source"]["uid"] = KEY
        save_repository_scan(self.data_dir, record)
        Users(self.data_dir).create("analista", PASSWORD)
        _, _, cookies = self.post("/api/auth/login", "login", {"username": "analista", "password": PASSWORD})
        self.member = cookies[0].split("; ")[0]

    def ci(self, body, *, token=TOKEN, query="", headers=None, raw=None):
        import asgi
        response = asgi.request(self.client, "POST", "/api/ci/sarif" + query, raw if raw is not None else json.dumps(body),
                                {**({"Authorization": f"Bearer {token}"} if token else {}), "Content-Type": "application/json", **(headers or {})})
        return response.status_code, response.json(), response.headers

    def test_members_import_from_the_panel_with_csrf(self):
        envelope = {"asset": "org/api", "sarif": fixture()}
        self.assertEqual(self.post("/api/imports/sarif", "import-sarif", envelope)[0], 401)
        self.assertEqual(self.post("/api/imports/sarif", "scan-repository", envelope, self.member)[0], 403)
        self.assertEqual(self.call("POST", "/api/imports/sarif", envelope, {"Cookie": self.member, "Origin": "http://evil.test",
                                                                            "X-Tamandua-Action": "import-sarif"})[0], 403)
        status, body, _ = self.post("/api/imports/sarif", "import-sarif", envelope, self.member)
        self.assertEqual((status, [run["tool"] for run in body["runs"]], body["asset"]), (200, ["Semgrep OSS", "CodeQL"], KEY))
        self.assertEqual(load_run(self.data_dir, body["runs"][0]["id"])["requested_by"], "analista")
        status, body, _ = self.post("/api/imports/sarif", "import-sarif", {**envelope, "asset": "org/nope"}, self.member)
        self.assertEqual(status, 404)
        self.assertEqual(self.post("/api/imports/sarif", "import-sarif", {**envelope, "sarif": {"version": "1"}}, self.member)[0], 400)
        self.assertEqual(self.post("/api/imports/sarif", "import-sarif", {**envelope, "extra": 1}, self.member)[0], 400)
        # Tamandua can't re-run another tool: re-verifying an imported finding asks for a new import.
        _, imported, _ = self.post("/api/imports/sarif", "import-sarif", envelope, self.member)
        run = load_run(self.data_dir, imported["runs"][1]["id"])
        status, answer, _ = self.post("/api/findings/reverify", "reverify-finding",
                                      {"run_id": run["id"], "fingerprint": run["findings"][0]["fingerprint"]}, self.member)
        self.assertEqual(status, 409)
        self.assertIn("CodeQL", answer["error"])

    def test_ci_route_is_off_without_a_long_token_and_bearer_only(self):
        envelope = {"asset": "org/api", "sarif": fixture()}
        self.assertEqual(self.ci(envelope)[0], 404)
        with patch.dict(os.environ, {"TAMANDUA_IMPORT_TOKEN": "short"}):
            self.assertEqual(self.ci(envelope, token="short")[0], 404)
        with patch.dict(os.environ, {"TAMANDUA_IMPORT_TOKEN": TOKEN}):
            status, _, headers = self.ci(envelope, token=None)
            self.assertEqual((status, headers["www-authenticate"]), (401, 'Bearer realm="tamandua-import"'))
            self.assertEqual(self.ci(envelope, token="x" * 40)[0], 401)
            self.assertEqual(self.ci(envelope, token=None, headers={"Authorization": f"Basic {TOKEN}"})[0], 401)
            status, body, _ = self.ci(envelope, headers={"X-Tamandua-Actor": "octo cat\n<script>"})
            self.assertEqual((status, len(body["runs"])), (200, 2))
            self.assertEqual(load_run(self.data_dir, body["runs"][0]["id"])["requested_by"], "ci:octocatscript")
            status, body, _ = self.ci(fixture(), query="?asset=org/api&tool=Strix&scope=partial")  # bare SARIF, options in the query
            self.assertEqual((status, [(run["tool"], run["scope"]) for run in body["runs"]]), (200, [("Strix", "partial")]))
            self.assertEqual(self.ci({**envelope, "asset": "org/nope"})[0], 404)
            self.assertEqual(self.ci(None, raw="[" * 100_000 + "]" * 100_000)[0], 400)  # nested too deep
            self.assertEqual(self.ci(None, raw="{not json")[0], 400)

    def test_only_the_import_routes_accept_large_bodies(self):
        large = b" " * 2_000_000 + json.dumps({"asset": "org/api", "sarif": fixture()}).encode()
        with patch.dict(os.environ, {"TAMANDUA_IMPORT_TOKEN": TOKEN}):
            self.assertEqual(self.ci(None, raw=large)[0], 200)
            too_large = b" " * 10_000_001
            self.assertEqual(self.ci(None, raw=too_large)[0], 413)
        headers = {"Cookie": self.member, "Origin": ORIGIN, "X-Tamandua-Action": "import-sarif"}
        import asgi
        self.assertEqual(asgi.request(self.client, "POST", "/api/imports/sarif", large, headers).status_code, 200)
        self.assertEqual(asgi.request(self.client, "POST", "/api/imports/sarif", too_large, headers).status_code, 413)
        self.assertEqual(asgi.request(self.client, "POST", "/api/repositories/scans", large,
                                      {**headers, "X-Tamandua-Action": "scan-repository"}).status_code, 413)


class CliTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data_dir = Path(self.directory.name)
        record = _scan("org/api", [_finding(A)], datetime.now(timezone.utc).isoformat())
        record["source"]["uid"] = KEY
        save_repository_scan(self.data_dir, record)

    def cli(self, *arguments, environment=None):
        from tamandua.cli.main import main
        with patch("sys.stdout", io.StringIO()) as out, patch("sys.stderr", io.StringIO()) as err, \
                patch.dict(os.environ, environment or {}):
            code = main(["--data-dir", str(self.data_dir), "import-sarif", *arguments])
        return code, out.getvalue(), err.getvalue()

    def test_local_import_into_the_database(self):
        code, out, _ = self.cli(str(FIXTURE), "--asset", "org/api", "--commit", "abcdef1")
        self.assertEqual(code, 0)
        self.assertIn("Semgrep OSS", out)
        self.assertEqual(len([line for line in out.splitlines() if "CodeQL" in line]), 1)
        second = self.data_dir / "second.sarif"
        second.write_text(json.dumps(sarif("CodeQL", [])))
        code, out, _ = self.cli(str(FIXTURE), str(second), "--asset", "org/api", "--partial")  # several files, one import
        self.assertEqual(code, 0)
        self.assertEqual(len([line for line in out.splitlines() if "CodeQL" in line]), 1)
        self.assertEqual(self.cli(str(FIXTURE), "--asset", "org/unknown")[0], 2)
        bad = self.data_dir / "bad.sarif"
        bad.write_text("{nope")
        code, _, err = self.cli(str(bad), "--asset", "org/api")
        self.assertEqual(code, 2)
        self.assertIn("bad.sarif", err)

    def test_remote_import_needs_the_token_and_https(self):
        self.assertEqual(self.cli(str(FIXTURE), "--asset", "org/api", "--server", "https://tamandua.example.com")[0], 2)
        env = {"TAMANDUA_IMPORT_TOKEN": TOKEN}
        for server in ("http://tamandua.example.com", "ftp://x", "https://user@x.example.com", "https://x.example.com/?a=1"):
            self.assertEqual(self.cli(str(FIXTURE), "--asset", "org/api", "--server", server, environment=env)[0], 2, server)

    def test_remote_import_posts_to_the_ci_route_without_redirects(self):
        sent = []

        class Response(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        class Opener:
            def open(self, request, timeout):
                sent.append(request)
                return Response(json.dumps({"asset": KEY, "name": "org/api", "runs": [
                    {"id": "f" * 32, "tool": "CodeQL", "version": None, "scope": "full", "status": "completed", "findings": 1,
                     "excluded": 0, "skipped": 0, "opened": 1, "fixed": 0}]}).encode())
        with patch("tamandua.shared.http.opener", return_value=Opener()):
            code, out, _ = self.cli(str(FIXTURE), "--asset", "org/api", "--tool", "CodeQL", "--server", "http://127.0.0.1:8766/",
                                    environment={"TAMANDUA_IMPORT_TOKEN": TOKEN})
        self.assertEqual(code, 0)
        self.assertIn("CodeQL", out)
        request = sent[0]
        self.assertEqual((request.full_url, request.get_header("Authorization")), ("http://127.0.0.1:8766/api/ci/sarif", f"Bearer {TOKEN}"))
        payload = json.loads(request.data)
        self.assertEqual((payload["asset"], payload["tool"], payload["scope"], len(payload["sarif"]["runs"])), ("org/api", "CodeQL", "full", 2))
        self.assertNotIn(TOKEN, " ".join(request.full_url.split("?")))

    def test_remote_http_errors_exit_2(self):
        from urllib.error import HTTPError

        class Opener:
            def open(self, request, timeout):
                raise HTTPError(request.full_url, 404, "Not Found", {}, io.BytesIO(b'{"error": "No asset"}'))
        with patch("tamandua.shared.http.opener", return_value=Opener()):
            code, _, err = self.cli(str(FIXTURE), "--asset", "org/api", "--server", "https://tamandua.example.com",
                                    environment={"TAMANDUA_IMPORT_TOKEN": TOKEN})
        self.assertEqual(code, 2)
        self.assertIn("404", err)


if __name__ == "__main__":
    unittest.main()
