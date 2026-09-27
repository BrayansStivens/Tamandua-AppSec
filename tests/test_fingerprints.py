"""Stable fingerprints: a secret keeps its identity when lines move, an advisory on a package has one fingerprint
whichever engine reports it, and a finding whose fingerprint changed formula keeps its state, triage, issue and
verification."""

import copy
import re
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from tamandua.modules.findings import registry, tickets, triage, verifications
from tamandua.modules.intel.advisories import dependency_finding, fingerprint
from tamandua.modules.pullrequests.review import classify
from tamandua.modules.runs import registry as run_registry
from tamandua.modules.runs.store import save_repository_scan
from tamandua.modules.scanning import engines, image
from test_dashboard import _finding, _scan

# Placeholders stand where the secrets were: the parser only reads what precedes each one.
FIRST, SECOND, PAIR_A, PAIR_B = "A" * 40, "B" * 40, "C" * 40, "D" * 40
KEY_VALUE = "E" * 32


def source(first=FIRST, pair_a=PAIR_A):
    return (f'GITHUB_TOKEN = "{first}"\n# comment\n  token: {SECOND}\napi_key = "{KEY_VALUE}"\n'
            f'pair = ["{pair_a}", "{PAIR_B}"]\n')


def gitleaks(shift: int) -> list[dict]:
    """What Gitleaks 8.30.1 reported (--redact) for `source()`, and with `shift` lines added on top (recorded).
    It counts columns from 1 on a file's first line and from 2 on the rest."""
    first = 17 if shift == 0 else 18
    return [{"RuleID": "github-pat", "File": "/src/app.py", "StartLine": 1 + shift, "StartColumn": first, "EndColumn": first + 39,
             "Match": "REDACTED", "Entropy": 4.9},
            {"RuleID": "github-pat", "File": "/src/app.py", "StartLine": 3 + shift, "StartColumn": 11, "EndColumn": 50,
             "Match": "REDACTED", "Entropy": 4.9},
            {"RuleID": "github-pat", "File": "/src/app.py", "StartLine": 5 + shift, "StartColumn": 11, "EndColumn": 50,
             "Match": "REDACTED", "Entropy": 5.1},
            {"RuleID": "github-pat", "File": "/src/app.py", "StartLine": 5 + shift, "StartColumn": 55, "EndColumn": 94,
             "Match": "REDACTED", "Entropy": 5.2},
            {"RuleID": "generic-api-key", "File": "/src/app.py", "StartLine": 4 + shift, "StartColumn": 2, "EndColumn": 45,
             "Match": 'api_key = "REDACTED"', "Entropy": 5.0}]


def trivy(shift: int) -> dict:
    """What Trivy 0.74.0 reported for the same file (recorded): `Match` masks every secret on the line."""
    mask = "*" * 40
    secrets = [(1, f'GITHUB_TOKEN = "{mask}"'), (3, f"  token: {mask}"), (5, f'pair = ["{mask}", "{mask}"]'),
               (5, f'pair = ["{mask}", "{mask}"]')]
    return {"Results": [{"Target": "app.py", "Class": "secret", "Secrets": [
        {"RuleID": "github-pat", "Category": "GitHub", "Severity": "CRITICAL", "Title": "GitHub Personal Access Token",
         "StartLine": line + shift, "EndLine": line + shift, "Match": match} for line, match in secrets]}]}


class SecretIdentityTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)

    def snapshot(self, text: str) -> Path:
        root = Path(self.folder.name) / str(len(list(Path(self.folder.name).iterdir())))
        root.mkdir()
        (root / "app.py").write_text(text)
        return root

    def test_gitleaks_secrets_keep_their_fingerprint_when_lines_are_added_above(self):
        before = engines.parse_gitleaks(gitleaks(0), None, self.snapshot(source()))
        after = engines.parse_gitleaks(gitleaks(2), None, self.snapshot("import os\n\n" + source()))
        self.assertEqual([item["fingerprint"] for item in before], [item["fingerprint"] for item in after])
        self.assertEqual(len({item["fingerprint"] for item in before}), 5)
        # The former, line-based fingerprint travels along so the registry can carry the finding over.
        self.assertEqual(before[0]["previous_fingerprint"], engines._stable("secrets", "github-pat", "app.py", "1"))
        self.assertEqual([item["line"] for item in after], [3, 5, 7, 7, 6])

    def test_no_secret_value_goes_into_a_fingerprint(self):
        """The second secret on a line is identified by what precedes it with the first one masked: changing the
        first one's value changes nothing."""
        before = engines.parse_gitleaks(gitleaks(0), None, self.snapshot(source()))
        rotated = engines.parse_gitleaks(gitleaks(0), None, self.snapshot(source(first="F" * 40, pair_a="G" * 40)))
        self.assertEqual([item["fingerprint"] for item in before], [item["fingerprint"] for item in rotated])

    def test_trivy_secrets_keep_their_fingerprint_when_lines_are_added_above(self):
        before = engines.parse_trivy(trivy(0), {})
        after = engines.parse_trivy(trivy(2), {})
        self.assertEqual([item["fingerprint"] for item in before], [item["fingerprint"] for item in after])
        self.assertEqual(len({item["fingerprint"] for item in before}), 4)  # both on the pair line are kept
        self.assertEqual(before[0]["previous_fingerprint"], engines._stable("secrets", "github-pat", "app.py", "1"))

    def test_without_the_snapshot_a_secret_keeps_the_line_based_fingerprint(self):
        found = engines.parse_gitleaks(gitleaks(0))
        self.assertEqual(found[0]["fingerprint"], engines._stable("secrets", "github-pat", "app.py", "1"))
        self.assertNotIn("previous_fingerprint", found[0])

    def test_internal_patterns_keep_their_fingerprint_when_lines_are_added_above(self):
        from tamandua.modules.scanning.repository import _secret_candidates
        token = "ghp_" + "Q" * 36
        before = _secret_candidates(self.snapshot(f'TOKEN = "{token}"\n') / "app.py", "app.py")
        after = _secret_candidates(self.snapshot(f'import os\n\nTOKEN = "{token}"\n') / "app.py", "app.py")
        self.assertEqual([item["fingerprint"] for item in before], [item["fingerprint"] for item in after])
        self.assertEqual((before[0]["line"], after[0]["line"]), (1, 3))

    def test_a_long_line_full_of_secrets_is_read_in_bounded_windows(self):
        import time
        count = 2000
        line = "".join(f'k{index} = "{FIRST}"; ' for index in range(count))
        starts = [found.start() for found in re.finditer(FIRST, line)]
        self.assertEqual(len(starts), count)
        report = [{"RuleID": "github-pat", "File": "/src/app.py", "StartLine": 1, "StartColumn": start + 1, "EndColumn": start + 40,
                   "Match": "REDACTED", "Entropy": 4.9} for start in starts]
        started = time.monotonic()
        found = engines.parse_gitleaks(report, None, self.snapshot(line + "\n"))
        self.assertLess(time.monotonic() - started, 5)
        self.assertEqual(len({item["fingerprint"] for item in found}), count)

    def test_a_path_outside_the_snapshot_is_never_read(self):
        root = self.snapshot(source())
        outside = [{**gitleaks(0)[0], "File": "/src/../../etc/passwd"}]
        found = engines.parse_gitleaks(outside, None, root)
        self.assertNotIn("previous_fingerprint", found[0])


class DependencyFingerprintTests(unittest.TestCase):
    """The same advisory on the same package version, as each engine names it."""

    def test_every_engine_gives_the_same_fingerprint(self):
        trivy_finding = engines._trivy_vulnerability(
            {"VulnerabilityID": "CVE-2026-1111", "PkgName": "Typing_Extensions", "InstalledVersion": "4.0.0", "Severity": "HIGH"},
            "requirements.txt", "pip", {})
        advisory = {"id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2026-1111"], "summary": "Bad"}
        osv_api = dependency_finding({"ecosystem": "PyPI", "name": "typing-extensions", "version": "4.0.0", "path": "requirements.txt"},
                                     advisory, {})
        osv_scanner = engines.parse_osv_scanner({"results": [{"source": {"path": "/src/requirements.txt"}, "packages": [
            {"package": {"name": "typing-extensions", "version": "4.0.0", "ecosystem": "PyPI"},
             "vulnerabilities": [advisory], "groups": [{"ids": ["GHSA-aaaa-bbbb-cccc"], "aliases": ["CVE-2026-1111"]}]}]}]}, {})[0]
        grype = image._grype_finding({"vulnerability": {"id": "GHSA-aaaa-bbbb-cccc", "severity": "High"},
                                      "relatedVulnerabilities": [{"id": "CVE-2026-1111"}],
                                      "artifact": {"name": "typing_extensions", "version": "4.0.0", "type": "python"}}, {})
        prints = {item["fingerprint"] for item in (trivy_finding, osv_api, osv_scanner, grype)}
        self.assertEqual(len(prints), 1)
        # The former fingerprints travel along, so the registry carries existing findings over.
        self.assertEqual(trivy_finding["previous_fingerprint"], fingerprint("sca", "CVE-2026-1111", "pip", "Typing_Extensions", "4.0.0"))
        self.assertEqual(osv_api["previous_fingerprint"], fingerprint("sca", "GHSA-aaaa-bbbb-cccc", "PyPI", "typing-extensions", "4.0.0"))
        self.assertNotIn("previous_fingerprint", osv_scanner)  # OSV-Scanner already used it

    def test_an_unchanged_fingerprint_carries_no_former_one(self):
        finding = engines._trivy_vulnerability({"VulnerabilityID": "CVE-2026-2222", "PkgName": "axios", "InstalledVersion": "1.0.0"},
                                               "package-lock.json", "npm", {})
        self.assertNotIn("previous_fingerprint", finding)

    def test_image_packages_keep_one_os_family(self):
        finding = image._finish_package({"rule_id": "CVE-2026-3333", "cve": ["CVE-2026-3333"], "ghsa": [],
                                         "package": {"ecosystem": "debian", "name": "openssl", "version": "3.0.1"}})
        self.assertEqual(finding["fingerprint"], fingerprint("sca", "CVE-2026-3333", "os", "openssl", "3.0.1"))
        self.assertNotIn("previous_fingerprint", finding)


KEY = "github#7"
OLD, NEW = "0" * 64, "1" * 64
USER = {"username": "ana", "role": "member"}


class CarryOverTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data_dir = Path(self.directory.name)
        self.clock = datetime.now(timezone.utc)

    def run_(self, findings):
        self.clock += timedelta(hours=1)
        record = _scan("org/api", findings, self.clock.isoformat())
        record["source"]["uid"] = KEY
        record["finished_at"] = self.clock.isoformat()
        return save_repository_scan(self.data_dir, record, created_at=self.clock.isoformat())

    def test_a_new_fingerprint_keeps_state_triage_issue_and_verification(self):
        first = self.run_([_finding(OLD)])
        state = registry.view(self.data_dir, KEY, status="all")
        triage.decide(self.data_dir, state, [OLD], "false_positive", reason="Test fixture, not a real dependency", user=USER)
        tickets._remember(self.data_dir, KEY, OLD, {"key": "SEC-1", "url": "https://jira.example/browse/SEC-1"})
        verifications.record(self.data_dir, KEY, OLD, first["id"], by="ana")

        self.run_([{**_finding(NEW), "previous_fingerprint": OLD}])
        entries = registry.load(self.data_dir, KEY)["findings"]
        self.assertEqual(set(entries), {NEW})
        self.assertEqual((entries[NEW]["first_run"], entries[NEW]["status"]), (first["id"], "open"))
        self.assertEqual(triage.load_asset(self.data_dir, KEY)[NEW]["status"], "false_positive")
        self.assertEqual(tickets.load_links(self.data_dir)[KEY][NEW]["key"], "SEC-1")
        self.assertEqual(verifications.load(self.data_dir)[KEY][NEW]["run_id"], first["id"])
        self.assertEqual(registry.summarize(self.data_dir, KEY)["suppressed"], 1)

        before = copy.deepcopy(registry.load(self.data_dir, KEY)["findings"])
        run_registry.rebuild(self.data_dir)
        after = registry.load(self.data_dir, KEY)["findings"]
        self.assertEqual({digest: entry["status"] for digest, entry in after.items()},
                         {digest: entry["status"] for digest, entry in before.items()})

    def test_a_decision_already_under_the_new_fingerprint_wins(self):
        self.run_([_finding(OLD), _finding(NEW)])
        state = registry.view(self.data_dir, KEY, status="all")
        triage.decide(self.data_dir, state, [OLD], "false_positive", reason="Old decision about the old one", user=USER)
        triage.decide(self.data_dir, state, [NEW], "in_progress", user=USER)
        self.run_([{**_finding(NEW), "previous_fingerprint": OLD}])
        self.assertEqual(triage.load_asset(self.data_dir, KEY)[NEW]["status"], "in_progress")
        # Both existed: nothing moves, and the old one is fixed by the scan that no longer sees it.
        self.assertEqual({digest: entry["status"] for digest, entry in registry.load(self.data_dir, KEY)["findings"].items()},
                         {OLD: "fixed", NEW: "open"})

    def test_a_pull_request_baseline_scanned_before_knows_the_former_fingerprint(self):
        finding = {**_finding(NEW), "previous_fingerprint": OLD}
        outcome = classify([finding], {"package-lock.json": None}, {OLD})
        self.assertEqual((outcome["introduced"], outcome["preexisting"]), ([], [finding]))


if __name__ == "__main__":
    unittest.main()
