"""The Jira issue description: written for the developer who fixes it, and safe to build from what a scan found."""

import json
import unittest

from tamandua.modules.integrations import jira
from tamandua.modules.runs.jira_brief import brief

DAYS = {"critical": 7, "high": 30, "medium": 90, "low": 180, "info": 365}
SOURCE = {"id": "github:acme/api", "name": "acme/api", "branch": "main", "commit": "a" * 40}


def ticket(fingerprint, severity="high"):
    return {"fingerprint": fingerprint, "finding_id": fingerprint[:16], "severity": severity, "priority": "High", "summary": "x"}


def nodes(document, kind):
    found = []

    def walk(node):
        if isinstance(node, dict):
            if node.get("type") == kind:
                found.append(node)
            for child in node.get("content") or []:
                walk(child)
    walk(document)
    return found


class BriefTests(unittest.TestCase):
    def write(self, group, findings, **extra):
        return brief(group, findings, asset="acme/api", source=extra.pop("source", SOURCE), first_seen=extra.pop("first_seen", {}),
                     days=DAYS, panel_url=extra.pop("panel_url", None), locale="en")

    def test_code_finding_reads_in_the_order_a_developer_needs(self):
        finding = {"fingerprint": "1" * 64, "scanner": "sast", "rule_id": "python.sql-injection", "title": "SQL injection from request input",
                   "reason": "Request input reaches a SQL query built as text", "remediation": "Use the driver's parameters",
                   "path": "app/db.py", "line": 14, "severity": "high", "cwe": [89]}
        written = self.write([ticket("1" * 64)], {"1" * 64: finding}, first_seen={"1" * 64: "2026-09-20T10:00:00+00:00"},
                             panel_url="https://tamandua.acme.io/#/hallazgos?repo=x&finding=y")
        headings = [block["heading"] for block in written["blocks"] if "heading" in block]
        self.assertEqual(headings[:5], ["The problem", "Where", "How to fix it", "How to verify it", "Deadline and context"])
        self.assertIn("Due date: 2026-10-20", written["text"])
        document = jira.adf_document(written["blocks"])
        links = [mark["attrs"]["href"] for node in nodes(document, "text") for mark in node.get("marks") or [] if mark["type"] == "link"]
        self.assertIn(f"https://github.com/acme/api/blob/{'a' * 40}/app/db.py#L14", links)
        self.assertIn("https://cwe.mitre.org/data/definitions/89.html", links)
        for jargon in ("python.sql-injection", "sast", "attend", "Priority"):
            self.assertNotIn(jargon, written["text"])

    def test_a_secret_never_carries_its_value_or_panel_instructions(self):
        finding = {"fingerprint": "2" * 64, "scanner": "secrets", "rule_id": "github-pat", "title": "Exposed GitHub token",
                   "reason": "", "remediation": "", "path": "config/settings.py", "line": 3, "severity": "critical", "cwe": [798]}
        written = self.write([ticket("2" * 64, "critical")], {"2" * 64: finding})
        self.assertIn("isn't included here on purpose", written["text"])
        self.assertIn("Revoke", written["text"])
        self.assertNotIn("Verify again", written["text"])

    def test_a_package_lists_its_vulnerabilities_and_the_version_that_closes_them(self):
        def advisory(fingerprint, cve, fixed):
            return {"fingerprint": fingerprint, "scanner": "sca", "rule_id": cve, "cve": [cve], "title": cve, "path": "package-lock.json",
                    "line": 1, "severity": "high", "package": {"ecosystem": "npm", "name": "lodash", "version": "4.17.15", "fixed_version": fixed,
                                                                "direct": True}, "advisory": {"summary": "Prototype pollution", "cvss_score": 7.4}}
        findings = {"3" * 64: advisory("3" * 64, "CVE-2020-8203", "4.17.19"), "4" * 64: advisory("4" * 64, "CVE-2021-23337", "4.17.21")}
        written = self.write([ticket("3" * 64), ticket("4" * 64)], findings)
        self.assertIn("Version 4.17.21 fixes all of them", written["text"])
        self.assertIn("npm install lodash@4.17.21", written["text"])
        self.assertNotIn("this advisory", written["text"])
        self.assertEqual([node["attrs"]["language"] for node in nodes(jira.adf_document(written["blocks"]), "codeBlock")], ["bash"])

    def test_nothing_a_finding_carries_can_become_a_link_or_markup(self):
        finding = {"fingerprint": "5" * 64, "scanner": "sast", "rule_id": "r", "severity": "medium", "path": "a.py", "line": 1,
                   "title": "[click](https://evil.example) <script>alert(1)</script> {{jira:macro}}", "reason": "",
                   "remediation": "see javascript:alert(1)"}
        document = jira.adf_document(self.write([ticket("5" * 64, "medium")], {"5" * 64: finding}, source={})["blocks"])
        hrefs = [mark["attrs"]["href"] for node in nodes(document, "text") for mark in node.get("marks") or [] if mark["type"] == "link"]
        self.assertFalse([href for href in hrefs if "evil" in href or href.startswith("javascript")])
        self.assertIn("[click](https://evil.example)", json.dumps(document))  # kept as plain text

    def test_the_document_builder_accepts_only_https_links_and_safe_languages(self):
        document = jira.adf_document([{"paragraph": [{"link": "x", "url": "http://plain.example"}, {"link": "y", "url": "https://ok.example"}]},
                                      {"code": "echo hi\x07", "language": "bash; rm"}, {"code": "print()", "language": "python"}])
        hrefs = [mark["attrs"]["href"] for node in nodes(document, "text") for mark in node.get("marks") or [] if mark["type"] == "link"]
        self.assertEqual(hrefs, ["https://ok.example"])
        blocks = nodes(document, "codeBlock")
        self.assertNotIn("attrs", blocks[0])
        self.assertNotIn("\x07", blocks[0]["content"][0]["text"])
        self.assertEqual(blocks[1]["attrs"], {"language": "python"})


if __name__ == "__main__":
    unittest.main()
