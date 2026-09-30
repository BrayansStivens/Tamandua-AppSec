"""Jira against a fake Jira: discovery, mapping, routing, automatic creation through the outbox, backfills, comments on
fix and reopen, the migration of the single project of earlier versions and the routes. Never goes out to the network."""

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from sqlalchemy import select, text, update

from tamandua.modules.findings import tickets as jira_links
from tamandua.modules.findings import triage
from tamandua.modules.integrations import jira, jira_mapping, jira_routing as routing, notifications
from tamandua.modules.integrations.tables import JIRA_CHANNEL, outbox
from tamandua.modules.runs import jira_sync
from tamandua.modules.runs.store import save_repository_scan
from tamandua.shared import db
from tamandua.modules.identity.auth import Users
from test_auth import ORIGIN, PASSWORD, HttpCase
from test_dashboard import _finding, _scan

TOKEN = "ATATT3xFfGF0-token-de-prueba-1234"
FP_A, FP_B, FP_C = "a" * 64, "b" * 64, "c" * 64
PRIORITIES = [{"id": "1", "name": "Highest"}, {"id": "2", "name": "High"}, {"id": "3", "name": "Medium"}, {"id": "4", "name": "Low"}]


def _field(identifier, name, kind, *, required=False, items=None, system=None, custom=None, allowed=None, default=False):
    schema = {"type": kind, **({"items": items} if items else {}), **({"system": system} if system else {}), **({"custom": custom} if custom else {})}
    return {"fieldId": identifier, "key": identifier, "name": name, "required": required, "hasDefaultValue": default, "schema": schema,
            **({"allowedValues": allowed} if allowed is not None else {})}


TASK_FIELDS = [
    _field("project", "Project", "project", required=True),
    _field("issuetype", "Issue Type", "issuetype", required=True),
    _field("summary", "Summary", "string", required=True, system="summary"),
    _field("description", "Description", "string", system="description"),
    _field("priority", "Priority", "priority", allowed=PRIORITIES, default=True),
    _field("labels", "Labels", "array", items="string", system="labels"),
    _field("duedate", "Due date", "date", system="duedate"),
    _field("customfield_100", "Severity", "option", custom="com.atlassian.jira.plugin.system.customfieldtypes:select",
           allowed=[{"id": "501", "value": "Critical"}, {"id": "502", "value": "High"}, {"id": "503", "value": "Medium"}, {"id": "504", "value": "Low"}]),
    _field("customfield_200", "Owner", "user", custom="com.atlassian.jira.plugin.system.customfieldtypes:userpicker"),
    _field("customfield_300", "Story points", "number", custom="com.atlassian.jira.plugin.system.customfieldtypes:float"),
]
BUG_FIELDS = [_field("summary", "Summary", "string", required=True, system="summary"),
              _field("description", "Description", "string", system="description"),
              _field("customfield_400", "Area", "option-with-child", required=True)]


class FakeJira:
    """The REST calls Tamandua makes, answered from memory. Pages of 3 so pagination is exercised."""

    def __init__(self, *, priority_field=True, existing_label=None, page=3):
        self.calls, self.issues, self.comments = [], {}, {}
        self.priority_field, self.existing_label, self.page = priority_field, existing_label, page
        self.projects = {"SEC": {"id": "10000", "key": "SEC", "name": "Seguridad"}, "PAY": {"id": "10001", "key": "PAY", "name": "Pagos"}}

    def _project(self, ref):
        return next((item for item in self.projects.values() if ref in (item["id"], item["key"])), None)

    def _paged(self, values, key, query):
        start = int(query.get("startAt", ["0"])[0])
        return {key: values[start:start + self.page], "startAt": start, "maxResults": self.page, "total": len(values)}

    def __call__(self, credentials, method, path, body=None):
        self.calls.append((method, path, body))
        assert credentials["site"] == "acme.atlassian.net" and credentials["token"] == TOKEN
        parts = urlsplit(path)
        query, route = parse_qs(parts.query), parts.path
        if route == "/rest/api/3/myself":
            return {"accountId": "abc"}
        if route == "/rest/api/3/project/search":
            wanted = query.get("query", [""])[0].lower()
            values = [item for item in self.projects.values() if wanted in item["name"].lower() or wanted in item["key"].lower()]
            return {"values": values, "total": len(values), "isLast": True}
        if route.startswith("/rest/api/3/project/"):
            found = self._project(route.rsplit("/", 1)[1])
            if not found:
                raise jira.JiraError("not found", status=404)
            return found
        if route.startswith("/rest/api/3/issue/createmeta/"):
            segments = route.split("/")
            if self._project(segments[6]) is None:
                raise jira.JiraError("not found", status=404)
            if len(segments) == 8:
                return self._paged([{"id": "10001", "name": "Task", "subtask": False}, {"id": "10002", "name": "Bug", "subtask": False}],
                                   "issueTypes", query)
            return self._paged(TASK_FIELDS if segments[8] == "10001" else BUG_FIELDS, "fields", query)
        if route == "/rest/api/3/search/jql":
            hit = self.existing_label and self.existing_label in body["jql"]
            return {"issues": [{"key": "SEC-7"}] if hit else []}
        if route == "/rest/api/3/issue":
            fields = body["fields"]
            if "priority" in fields and not self.priority_field:
                raise jira.JiraError("Jira respondió 400: priority: Field 'priority' cannot be set", status=400)
            project = fields["project"].get("key") or next(item["key"] for item in self.projects.values() if item["id"] == fields["project"]["id"])
            key = f"{project}-{101 + len(self.issues)}"
            self.issues[key] = fields
            return {"key": key}
        if route.endswith("/comment"):
            key = route.split("/")[5]
            if method == "GET":
                return {"comments": self.comments.get(key, [])}
            self.comments.setdefault(key, []).append(body)
            return {"id": "1"}
        raise AssertionError(path)


class JiraCase(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data_dir = Path(self.directory.name)
        store = patch("tamandua.shared.paths.CONFIG_DIR", self.data_dir / "config")
        store.start()
        self.addCleanup(store.stop)
        self.fake = FakeJira()
        client = patch.object(jira, "_http", self.fake)
        client.start()
        self.addCleanup(client.stop)
        self.now = datetime.now(timezone.utc)

    def connect(self):
        return jira.configure("https://acme.atlassian.net/", "sec@acme.io", TOKEN, by="operadora")

    def destination(self, project="SEC", issue_type="10001", mapping=None, name=None):
        saved, _ = routing.save_destination(self.data_dir, {"name": name or project, "project": project, "issue_type": issue_type,
                                                            "mapping": mapping}, by="admin")
        return saved

    def rule(self, **values):
        saved, _ = jira_sync.save_rule(self.data_dir, values, by="admin")
        return saved

    def scan(self, name, findings, *, when=None, **extra):
        return save_repository_scan(self.data_dir, {**_scan(name, findings, (when or self.now).isoformat()), **extra})

    def rows(self):
        with db.transaction(self.data_dir) as connection:
            return connection.execute(select(outbox.c.channel_id, outbox.c.payload, outbox.c.status, outbox.c.next_attempt_at)
                                      .where(outbox.c.channel_id == JIRA_CHANNEL).order_by(outbox.c.created_at, outbox.c.next_attempt_at)).all()

    def drain(self):
        with db.transaction(self.data_dir) as connection:
            connection.execute(update(outbox).values(next_attempt_at=text("now() - interval '1 second'")))
        return jira_sync.drain(self.data_dir, limit=100)


class ConnectorTests(JiraCase):
    def test_only_jira_cloud_hosts_are_accepted(self):
        for site in ("http://acme.atlassian.net", "https://169.254.169.254", "https://acme.atlassian.net.evil.io",
                     "https://evil.io/acme.atlassian.net", "https://acme.atlassian.net:8443", "https://user@acme.atlassian.net"):
            with self.assertRaises(jira.JiraError, msg=site):
                jira.normalize_site(site)
        self.assertEqual(jira.normalize_site("Acme.atlassian.net"), "acme.atlassian.net")
        for ref in ("../myself", "SEC/../../x", "1 OR 1", ""):
            with self.assertRaises(jira.JiraError, msg=ref):
                jira.project_ref(ref)

    def test_token_is_private_and_never_returned(self):
        state = self.connect()
        self.assertEqual((state["configured"], state["last4"]), (True, "1234"))
        self.assertNotIn(TOKEN, json.dumps(state))
        for path in (self.data_dir / "config").iterdir() if (self.data_dir / "config").exists() else []:
            self.assertNotIn(TOKEN.encode(), path.read_bytes(), path.name)
        from tamandua.shared import vault
        self.assertEqual(vault.get("jira")["token"], TOKEN)

    def test_discovery_is_normalized_and_paginated(self):
        self.connect()
        self.assertEqual(jira.projects("pag")["items"], [{"id": "10001", "key": "PAY", "name": "Pagos"}])
        self.assertEqual([item["name"] for item in jira.issue_types("SEC")["items"]], ["Task", "Bug"])
        found = jira.create_fields("SEC", "10001")
        by_id = {field["id"]: field for field in found["fields"]}
        self.assertEqual(len(by_id), len(TASK_FIELDS))  # four pages of three
        self.assertEqual({key: by_id[key]["type"] for key in by_id}, {
            "project": "managed", "issuetype": "managed", "summary": "text", "description": "rich_text", "priority": "priority",
            "labels": "labels", "duedate": "date", "customfield_100": "option", "customfield_200": "unsupported", "customfield_300": "number"})
        self.assertEqual(by_id["customfield_100"]["allowed"][0], {"id": "501", "name": "Critical"})
        self.assertFalse(by_id["customfield_200"]["fillable"])
        self.assertTrue(by_id["summary"]["required"])
        self.assertEqual(jira.normalize_field({"fieldId": "bad id!", "schema": {"type": "string"}}), None)


class LongListTests(JiraCase):
    """A field with more allowed values than the panel receives: they are searched, and a value past the first page validates."""

    COMPONENTS = [{"id": str(9000 + index), "name": f"Componente {index:03d}"} for index in range(300)]

    def setUp(self):
        super().setUp()
        long = _field("components", "Components", "array", items="component", system="components", allowed=self.COMPONENTS)
        fields = patch("test_jira.TASK_FIELDS", [*TASK_FIELDS, long])
        fields.start()
        self.addCleanup(fields.stop)
        self.connect()

    def test_the_panel_gets_a_page_and_searches_the_rest(self):
        field = next(item for item in jira.create_fields("SEC", "10001")["fields"] if item["id"] == "components")
        self.assertEqual((len(field["allowed"]), field["allowed_truncated"]), (jira.MAX_ALLOWED_VALUES, True))
        found = jira.field_values("SEC", "10001", "components", "componente 25")
        self.assertEqual([item["id"] for item in found["items"]], [str(9000 + index) for index in range(250, 260)])
        self.assertEqual((found["total"], found["truncated"]), (10, False))
        self.assertEqual(jira.field_values("SEC", "10001", "components", "", limit=5)["truncated"], True)
        for bad in ("nope", "bad id!"):
            with self.assertRaises(jira.JiraError):
                jira.field_values("SEC", "10001", bad, "x")

    def test_a_value_past_the_first_page_validates_and_only_the_choice_is_kept(self):
        saved = self.destination(mapping={"summary": {"source": "tamandua", "key": "summary"},
                                          "description": {"source": "tamandua", "key": "description"},
                                          "components": {"source": "fixed", "value": ["9280"]}})
        self.assertEqual(saved["mapping"]["components"], {"source": "fixed", "value": ["9280"]})
        stored = routing.load(self.data_dir)["destinations"][0]["fields"]["components"]["allowed"]
        self.assertEqual(stored, [{"id": "9280", "name": "Componente 280"}])


class MappingTests(JiraCase):
    def fields(self, kind="10001"):
        self.connect()
        return jira.create_fields("SEC", kind)["fields"]

    def errors(self, mapping, fields):
        with self.assertRaises(jira_mapping.MappingError) as caught:
            jira_mapping.validate(mapping, fields)
        return {item["field"]: item["error"]["$t"] for item in caught.exception.errors}

    def test_default_mapping_fills_summary_description_priority_labels_and_due_date(self):
        fields = self.fields()
        mapping = jira_mapping.default_mapping(fields)
        self.assertEqual(mapping["duedate"], {"source": "tamandua", "key": "due_date"})
        clean, snapshot, warnings = jira_mapping.validate(mapping, fields)
        self.assertEqual(set(clean), {"summary", "description", "priority", "labels", "duedate"})
        self.assertEqual(warnings, [])
        self.assertEqual(snapshot["priority"]["type"], "priority")

    def test_invalid_mappings_say_which_field_and_why(self):
        fields = self.fields()
        found = self.errors({"description": {"source": "tamandua", "key": "description"},
                             "customfield_100": {"source": "fixed", "value": "999"},
                             "customfield_200": {"source": "fixed", "value": "x"},
                             "customfield_300": {"source": "tamandua", "key": "description"},
                             "duedate": {"source": "template", "text": "{{due_date}}"},
                             "labels": {"source": "template", "text": "{{title}} {{__class__}}"},
                             "customfield_999": {"source": "fixed", "value": "x"}}, fields)
        self.assertEqual(found, {"summary": "integrations.jira.mapping.required",
                                 "customfield_100": "integrations.jira.mapping.not_allowed",
                                 "customfield_200": "integrations.jira.mapping.unsupported_type",
                                 "customfield_300": "integrations.jira.mapping.type_mismatch",
                                 "duedate": "integrations.jira.mapping.no_template",
                                 "labels": "integrations.jira.mapping.unknown_variables",
                                 "customfield_999": "integrations.jira.mapping.not_on_screen"})
        bug = jira.create_fields("SEC", "10002")["fields"]
        self.assertEqual(self.errors({"summary": {"source": "tamandua", "key": "summary"}, "description": {"source": "tamandua", "key": "description"}}, bug),
                         {"customfield_400": "integrations.jira.mapping.required_unsupported"})

    def test_templates_are_plain_substitution(self):
        values = {"title": "{{severity}} {0.__class__}", "severity": "high", "asset": "org/api"}
        self.assertEqual(jira_mapping.substitute("[{{ severity }}] {{title}} en {{asset}} {{nope}}", values),
                         "[high] {{severity}} {0.__class__} en org/api ")

    def test_fields_are_built_by_type_and_the_idempotency_label_is_always_there(self):
        self.connect()
        destination = self.destination(mapping={
            "summary": {"source": "template", "text": "{{severity}}: {{title}}\nsecond line"},
            "description": {"source": "tamandua", "key": "description"},
            "labels": {"source": "fixed", "value": ["team payments"]},
            "customfield_100": {"source": "tamandua", "key": "severity"},
            "customfield_300": {"source": "tamandua", "key": "line"},
            "duedate": {"source": "tamandua", "key": "due_date"}})
        fields = jira_mapping.build(destination, {"severity": "high", "title": "XSS", "description": "# Fix\nline", "line": 12,
                                                  "due_date": "2026-10-29"}, [FP_A])
        self.assertEqual(fields["project"], {"id": "10000"})
        self.assertEqual(fields["issuetype"], {"id": "10001"})
        self.assertEqual(fields["summary"], "high: XSS second line")
        self.assertEqual(fields["labels"], sorted(["team-payments", jira.label_for(FP_A)]))
        self.assertEqual(fields["customfield_100"], {"id": "502"})
        self.assertEqual((fields["customfield_300"], fields["duedate"]), (12, "2026-10-29"))
        self.assertEqual(fields["description"]["content"][0]["content"][0], {"type": "text", "text": "Fix", "marks": [{"type": "strong"}]})


class RoutingTests(JiraCase):
    def setUp(self):
        super().setUp()
        self.connect()
        self.sec, self.pay = self.destination("SEC"), self.destination("PAY")

    def test_first_enabled_match_wins_then_the_default(self):
        self.rule(name="Pagos", patterns=["org/payments-*"], destination=self.pay["id"])
        self.rule(name="API", assets=["github:org/api"], destination=self.sec["id"])
        self.rule(name="Todo org", patterns=["org/*"], destination=self.sec["id"], enabled=False)
        state = routing.load(self.data_dir)
        self.assertEqual(routing.resolve(state, "github#1", "Org/Payments-Core")["name"], "Pagos")
        self.assertEqual(routing.resolve(state, "github:org/api", "org/api")["name"], "API")
        self.assertIsNone(routing.resolve(state, "github:org/web", "org/web"))  # disabled rule skipped, default off
        self.rule(id="default", destination=self.sec["id"])
        self.assertEqual(routing.resolve(routing.load(self.data_dir), "github:org/web", "org/web")["id"], "default")
        ids = [item["id"] for item in routing.load(self.data_dir)["rules"] if not item.get("default")]
        routing.reorder(self.data_dir, [ids[1], ids[0], ids[2]], by="admin")
        self.assertEqual(routing.resolve(routing.load(self.data_dir), "github:org/api", "org/payments-api")["name"], "API")

    def test_rules_and_destinations_are_validated_field_by_field(self):
        with self.assertRaises(routing.RoutingError) as caught:
            routing.save_rule(self.data_dir, {"name": "", "assets": [], "destination": "nope", "mode": "sometimes"}, by="admin")
        self.assertEqual({item["field"] for item in caught.exception.errors}, {"name", "destination", "mode"})
        with self.assertRaises(routing.RoutingError):
            routing.save_rule(self.data_dir, {"name": "x", "patterns": ["a" * 300], "destination": self.sec["id"]}, by="admin")
        self.rule(name="Pagos", patterns=["org/payments-*"], destination=self.pay["id"])
        with self.assertRaises(routing.RoutingError):
            routing.remove_destination(self.data_dir, self.pay["id"], by="admin")  # in use
        with self.assertRaises(routing.RoutingError):
            routing.remove_rule(self.data_dir, "default", by="admin")
        history = routing.view(self.data_dir)["history"]
        self.assertEqual((history[0]["action"], history[0]["by"]), ("rule_saved", "admin"))

    def test_rules_follow_assets_that_gain_a_stable_identity(self):
        self.rule(name="API", assets=["github:org/api", "github#9"], destination=self.sec["id"])
        routing.rename_assets(self.data_dir, {"github:org/api": "github#9"})
        self.assertEqual(routing.load(self.data_dir)["rules"][0]["assets"], ["github#9"])

    def test_limits(self):
        with patch.object(routing, "MAX_DESTINATIONS", 2), self.assertRaises(routing.RoutingError):
            self.destination("SEC", name="Otra")


class ExportTests(JiraCase):
    def setUp(self):
        super().setUp()
        self.connect()
        self.sec, self.pay = self.destination("SEC"), self.destination("PAY")
        self.api = self.scan("org/api", [_finding(FP_A), _finding(FP_B, "critical", package="lodash")])
        self.payments = self.scan("org/payments-core", [_finding(FP_C, "high", package="express")])

    def annotated(self, record):
        return triage.annotate(self.data_dir, record)

    def test_one_export_routes_each_asset_to_its_project_and_is_idempotent(self):
        self.rule(name="Pagos", patterns=["org/payments-*"], destination=self.pay["id"])
        self.rule(id="default", destination=self.sec["id"])
        self.fake.existing_label = jira.label_for(FP_B)
        result = jira_sync.export(self.data_dir, [(self.annotated(self.api), [FP_A, FP_B]), (self.annotated(self.payments), [FP_C])], by="analista")
        self.assertEqual(sorted((item["project"], item["key"]) for item in result["created"]), [("PAY", "PAY-102"), ("SEC", "SEC-101")])
        self.assertEqual([item["key"] for item in result["existing"]], ["SEC-7"])
        issue = self.fake.issues["SEC-101"]
        self.assertEqual((issue["project"], issue["issuetype"]), ({"id": "10000"}, {"id": "10001"}))
        self.assertIn(jira.label_for(FP_A), issue["labels"])
        self.assertEqual(issue["description"]["type"], "doc")
        due = (datetime.fromisoformat(self.api["created_at"]).date() + timedelta(days=30)).isoformat()
        self.assertEqual(issue["duedate"], due)  # first detection + the high SLA (30 days)
        again = jira_sync.export(self.data_dir, [(self.annotated(self.api), [FP_A, FP_B]), (self.annotated(self.payments), [FP_C])], by="analista")
        self.assertEqual((len(again["created"]), len(again["existing"]), len(self.fake.issues)), (0, 3, 2))
        annotated = jira_links.annotate(self.data_dir, self.api)
        self.assertEqual({item["ticket"]["key"] for item in annotated["findings"]}, {"SEC-101", "SEC-7"})

    def test_without_a_destination_the_findings_fail_and_say_why(self):
        result = jira_sync.export(self.data_dir, [(self.annotated(self.api), [FP_A])], by="analista")
        self.assertEqual((result["created"], result["failed"][0]["error"]["$t"]), ([], "integrations.jira.no_destination"))

    def test_suppressed_findings_are_not_exportable(self):
        self.rule(id="default", destination=self.sec["id"])
        triage.decide(self.data_dir, self.api, [FP_A], "false_positive", reason="Contenido estático del repositorio",
                      user={"username": "analista", "role": "member"})
        with self.assertRaises(jira.JiraError):
            jira_sync.export(self.data_dir, [(self.annotated(self.api), [FP_A])], by="analista")

    def test_advisories_of_one_package_become_one_issue(self):
        self.rule(id="default", destination=self.sec["id"])
        second = {**_finding(FP_C, "critical"), "rule_id": "CVE-2026-2", "cve": ["CVE-2026-2"]}
        second["package"] = {**second["package"], "fixed_version": "1.2.0"}
        record = self.scan("org/web", [_finding(FP_A), second])
        result = jira_sync.export(self.data_dir, [(self.annotated(record), [FP_A, FP_C])], by="analista")
        self.assertEqual({item["key"] for item in result["created"]}, {"SEC-101"})
        issue = self.fake.issues["SEC-101"]
        self.assertEqual(issue["summary"], "[CRITICAL] Actualizar axios 1.0.0 a 1.2.0 · 2 avisos")
        self.assertEqual(issue["priority"], {"id": "2"})  # High, matched by name among the allowed values
        self.assertTrue({jira.label_for(FP_A), jira.label_for(FP_C)} <= set(issue["labels"]))


class MigrationTests(JiraCase):
    def test_the_single_project_becomes_a_destination_and_the_manual_default_rule(self):
        from tamandua.app import data_migrations
        from tamandua.shared import vault
        old = {"site": "acme.atlassian.net", "email": "sec@acme.io", "token": TOKEN, "project": "SEC", "project_name": "Seguridad",
               "issue_type": "Task", "saved_by": "operadora"}
        vault.put("jira", old)
        self.assertEqual(data_migrations._jira_routing(self.data_dir), 1)
        self.assertEqual(data_migrations._jira_routing(self.data_dir), 0)  # idempotent
        self.assertEqual(vault.get("jira"), old)  # the credential stays as it was
        state = routing.load(self.data_dir)
        destination, default = state["destinations"][0], state["rules"][-1]
        self.assertEqual((destination["project"]["key"], destination["issue_type"]["name"], destination["legacy"]), ("SEC", "Task", True))
        self.assertEqual((default["destination"], default["mode"], default["enabled"]), (destination["id"], "manual", True))
        # It keeps exporting as before: project key, issue type name and priority dropped when the screen lacks it.
        self.fake.priority_field = False
        record = self.scan("org/api", [_finding(FP_A)])
        result = jira_sync.export(self.data_dir, [(triage.annotate(self.data_dir, record), [FP_A])], by="analista")
        issue = self.fake.issues[result["created"][0]["key"]]
        self.assertEqual((issue["project"], issue["issuetype"], "priority" in issue), ({"key": "SEC"}, {"name": "Task"}, False))
        self.assertIn(jira.label_for(FP_A), issue["labels"])

    def test_nothing_to_migrate_without_a_project(self):
        from tamandua.app import data_migrations
        self.assertEqual(data_migrations._jira_routing(self.data_dir), 0)
        self.assertEqual(routing.load(self.data_dir)["destinations"], [])


class AutomaticTests(JiraCase):
    def setUp(self):
        super().setUp()
        self.connect()
        self.sec = self.destination("SEC")

    def test_new_findings_are_queued_and_created_by_the_worker(self):
        self.rule(name="API", assets=["github:org/api"], destination=self.sec["id"], mode="auto", min_severity="high")
        self.scan("org/api", [_finding(FP_A, "high"), _finding(FP_B, "medium", package="lodash")])
        rows = self.rows()
        self.assertEqual([row.payload["fingerprints"] for row in rows], [[FP_A]])  # medium is below the rule's minimum
        self.assertEqual(self.fake.issues, {})  # nothing reaches Jira from inside the scan
        # A notification drain leaves Jira's rows alone.
        with patch.object(notifications, "_vault", return_value={}):
            notifications.drain(self.data_dir)
        self.assertEqual(self.rows()[0].status, "pending")
        self.assertEqual(self.drain(), 1)
        self.assertEqual(list(self.fake.issues), ["SEC-101"])
        self.assertEqual(self.rows()[0].status, "sent")
        self.assertEqual(jira_links.load_links(self.data_dir)["github:org/api"][FP_A]["key"], "SEC-101")
        self.scan("org/api", [_finding(FP_A, "high")])
        self.assertEqual(len(self.rows()), 1)  # seen again: not new, nothing queued

    def test_jira_down_is_retried_and_nothing_is_lost(self):
        self.rule(id="default", destination=self.sec["id"], mode="auto", min_severity="low")
        self.scan("org/api", [_finding(FP_A)])
        with patch.object(jira, "_http", side_effect=jira.JiraError("down")):
            self.drain()
        row = self.rows()[0]
        self.assertEqual(row.status, "pending")
        self.assertGreater(row.next_attempt_at, datetime.now(timezone.utc))
        self.drain()
        self.assertEqual((self.rows()[0].status, list(self.fake.issues)), ("sent", ["SEC-101"]))

    def test_a_rejected_issue_fails_and_a_broken_queue_never_breaks_the_scan(self):
        self.rule(id="default", destination=self.sec["id"], mode="auto", min_severity="low")
        self.scan("org/api", [_finding(FP_A)])
        with patch.object(jira, "create_issue", side_effect=jira.JiraError("customfield_1: required", status=400)):
            self.drain()
        row = self.rows()[0]
        self.assertEqual(row.status, "failed")  # Jira said no: retrying would say no again
        with patch.object(jira_sync, "_on_run", side_effect=RuntimeError("boom")):
            record = self.scan("org/web", [_finding(FP_B)])
        from tamandua.modules.findings import registry
        self.assertEqual(registry.load(self.data_dir, "github:org/web")["findings"][FP_B]["first_run"], record["id"])

    def test_pull_request_reviews_and_triaged_findings_create_nothing(self):
        self.rule(id="default", destination=self.sec["id"], mode="auto", min_severity="low")
        self.scan("org/api", [_finding(FP_A)], type="pr_review", pull_request={"number": 4, "head_sha": "abc1234", "head_ref": "feat"})
        self.assertEqual(self.rows(), [])
        # Manual rule while the first scan lands; FP_A dismissed; it goes away and comes back with the rule automatic.
        self.rule(id="default", destination=self.sec["id"], mode="manual")
        first = self.scan("org/web", [_finding(FP_A), _finding(FP_B, package="lodash")])
        triage.decide(self.data_dir, first, [FP_A], "false_positive", reason="Contenido estático del repositorio",
                      user={"username": "analista", "role": "member"})
        self.rule(id="default", destination=self.sec["id"], mode="auto", min_severity="low")
        self.scan("org/web", [], when=self.now + timedelta(minutes=1))
        self.scan("org/web", [_finding(FP_A), _finding(FP_B, package="lodash")], when=self.now + timedelta(minutes=2))
        self.assertEqual([row.payload["fingerprints"] for row in self.rows()], [[FP_B]])
        # Dismissed while it waited in the queue: skipped when delivered.
        triage.decide(self.data_dir, first, [FP_B], "false_positive", reason="Contenido estático del repositorio",
                      user={"username": "analista", "role": "member"})
        self.drain()
        self.assertEqual(self.fake.issues, {})

    def test_the_advisory_watch_creates_too(self):
        self.rule(id="default", destination=self.sec["id"], mode="auto", min_severity="low")
        self.scan("org/api", [_finding(FP_A)], type="advisory_watch")
        self.assertEqual(len(self.rows()), 1)


class BackfillTests(JiraCase):
    def setUp(self):
        super().setUp()
        self.connect()
        self.sec = self.destination("SEC")
        self.scan("org/api", [_finding(FP_A, "critical"), _finding(FP_B, "high", package="lodash"), _finding(FP_C, "low", package="express")])
        self.scan("org/other", [_finding(FP_A, "critical")])

    def test_preview_backfill_pacing_status_and_idempotency(self):
        values = {"name": "API", "assets": ["github:org/api"], "destination": self.sec["id"], "mode": "auto", "min_severity": "high",
                  "backfill": True}
        self.assertEqual(jira_sync.preview(self.data_dir, values), {"assets": 1, "findings": 2, "issues": 2, "linked": 0, "truncated": False})
        saved, started = jira_sync.save_rule(self.data_dir, values, by="admin")
        self.assertEqual((started["queued"], started["findings"], started["pending"]), (2, 2, 2))
        rows = self.rows()
        self.assertEqual(rows[1].next_attempt_at - rows[0].next_attempt_at, timedelta(seconds=jira_sync.BACKFILL_SPACING))
        # Saving it again unchanged starts nothing; running it again while those wait queues nothing new.
        self.assertIsNone(jira_sync.save_rule(self.data_dir, {**values, "id": saved["id"]}, by="admin")[1])
        self.assertEqual(jira_sync.backfill(self.data_dir, saved["id"], by="admin")["batch"], started["batch"])
        self.assertEqual(len(self.rows()), 2)
        self.drain()
        status = {item["rule"]: item for item in jira_sync.backfill_status(self.data_dir)}[saved["id"]]
        self.assertEqual((status["created"], status["pending"]), (2, 0))
        self.assertEqual(len(self.fake.issues), 2)
        jira_sync.backfill(self.data_dir, saved["id"], by="admin")
        self.assertEqual((len(self.rows()), len(self.fake.issues)), (2, 2))  # everything already has its issue
        self.assertEqual(jira_sync.preview(self.data_dir, {**values, "id": saved["id"]})["linked"], 2)

    def test_counts_per_rule(self):
        saved, started = jira_sync.save_rule(self.data_dir, {"name": "API", "assets": ["github:org/api"], "destination": self.sec["id"],
                                                             "mode": "auto", "min_severity": "low", "backfill": True}, by="admin")
        self.fake.existing_label = jira.label_for(FP_C)
        self.drain()
        status = {item["rule"]: item for item in jira_sync.backfill_status(self.data_dir)}[saved["id"]]
        self.assertEqual((status["queued"], status["created"], status["existing"], status["pending"]), (3, 2, 1, 0))
        self.assertIsNotNone(status["finished_at"])


class CommentTests(JiraCase):
    def setUp(self):
        super().setUp()
        self.connect()
        self.sec = self.destination("SEC")
        self.rule(id="default", destination=self.sec["id"])

    def comments(self):
        return [(row.payload["event"], row.payload["key"]) for row in self.rows() if row.payload["type"] == "comment"]

    def test_fixed_then_reappeared(self):
        record = self.scan("org/api", [_finding(FP_A)])
        jira_sync.export(self.data_dir, [(triage.annotate(self.data_dir, record), [FP_A])], by="analista")
        self.scan("org/api", [_finding(FP_A)], type="pr_review", pull_request={"number": 4, "head_sha": "abc1234", "head_ref": "feat"})
        fixed = self.scan("org/api", [], when=self.now + timedelta(minutes=1))
        self.assertEqual(self.comments(), [("fixed", "SEC-101")])
        self.drain()
        body = self.fake.comments["SEC-101"][0]
        self.assertIn(fixed["id"][:12], json.dumps(body["body"], ensure_ascii=False))
        self.assertIn("verificó la corrección", json.dumps(body["body"], ensure_ascii=False))  # TAMANDUA_DEFAULT_LOCALE (es)
        self.assertEqual(body["properties"][0]["value"], {"event": "fixed", "run": fixed["id"]})
        # Delivered twice (at least once): the property keeps it from commenting twice.
        self.assertEqual(jira_sync.deliver(self.data_dir, self.rows()[0].payload), "existing")
        self.assertEqual(len(self.fake.comments["SEC-101"]), 1)
        self.scan("org/api", [_finding(FP_A)], when=self.now + timedelta(minutes=2))
        self.assertEqual(self.comments(), [("fixed", "SEC-101"), ("reopened", "SEC-101")])
        self.drain()
        self.assertEqual(len(self.fake.comments["SEC-101"]), 2)

    def test_a_grouped_issue_is_commented_when_all_its_findings_are_fixed(self):
        second = {**_finding(FP_C), "rule_id": "CVE-2026-2", "cve": ["CVE-2026-2"]}
        record = self.scan("org/api", [_finding(FP_A), second])
        jira_sync.export(self.data_dir, [(triage.annotate(self.data_dir, record), [FP_A, FP_C])], by="analista")
        self.scan("org/api", [second], when=self.now + timedelta(minutes=1))
        self.assertEqual(self.comments(), [])
        self.scan("org/api", [], when=self.now + timedelta(minutes=2))
        self.assertEqual(self.comments(), [("fixed", "SEC-101")])
        self.assertEqual(self.rows()[-1].payload["count"], 2)


class RouteTests(HttpCase):
    def setUp(self):
        super().setUp()
        self.fake = FakeJira()
        client = patch.object(jira, "_http", self.fake)
        client.start()
        self.addCleanup(client.stop)
        self.now = datetime.now(timezone.utc)
        users = Users(self.data_dir)
        users.create("admin", PASSWORD, role="admin")
        users.create("ana", PASSWORD)
        self.admin = self.login("admin", PASSWORD)
        self.member = self.login("ana", PASSWORD)

    def login(self, name, password):
        _, _, cookies = self.post("/api/auth/login", "login", {"username": name, "password": password})
        return cookies[0].split("; ")[0]

    def get(self, path, cookie, **headers):
        return self.call("GET", path, headers={"Cookie": cookie, **headers})

    def test_configuration_and_discovery_are_for_administrators(self):
        status, body, _ = self.post("/api/integrations/jira", "connect-jira", {"action": "save", "site": "acme.atlassian.net",
                                         "email": "sec@acme.io", "token": TOKEN, "project": "SEC", "issue_type": "Task"}, self.admin)
        self.assertEqual((status, body["project"], body["issue_type"], body["destinations"]), (200, "SEC", "Task", 1))
        self.assertNotIn(TOKEN, json.dumps(body))
        for path in ("/api/integrations/jira/projects", "/api/integrations/jira/projects/SEC/issue-types",
                     "/api/integrations/jira/projects/SEC/issue-types/10001/fields", "/api/integrations/jira/variables",
                     "/api/integrations/jira/routing", "/api/integrations/jira/backfill"):
            self.assertEqual(self.get(path, self.member)[0], 403, path)
            self.assertEqual(self.get(path, self.admin)[0], 200, path)
        status, fields, _ = self.get("/api/integrations/jira/projects/SEC/issue-types/10001/fields", self.admin)
        self.assertEqual(fields["suggested"]["summary"], {"source": "tamandua", "key": "summary"})
        status, _, _ = self.post("/api/integrations/jira/destinations", "jira-routing",
                                      {"name": "PAY", "project": "PAY", "issue_type": "10001"}, self.member)
        self.assertEqual(status, 403)
        self.assertIn(self.get("/api/integrations/jira/projects/..%2Fmyself/issue-types", self.admin)[0], (400, 404))
        self.assertEqual(self.get("/api/integrations/jira/projects/1%20OR%201/issue-types", self.admin)[0], 400)
        variables = self.get("/api/integrations/jira/variables", self.admin)[1]["variables"]
        self.assertIn({"key": "due_date", "type": "date", "label": "Plazo de corrección (SLA)"}, variables)

    def test_validation_errors_are_field_specific_and_localized(self):
        self.post("/api/integrations/jira", "connect-jira", {"action": "save", "site": "acme.atlassian.net", "email": "sec@acme.io",
                                                                  "token": TOKEN}, self.admin)
        status, body, _ = self.call("POST", "/api/integrations/jira/destinations",
                                         {"name": "Seg", "project": "SEC", "issue_type": "10001",
                                          "mapping": {"description": {"source": "tamandua", "key": "description"}}},
                                         {"Origin": ORIGIN, "X-Tamandua-Action": "jira-routing", "Cookie": self.admin,
                                          "Accept-Language": "en"})
        self.assertEqual(status, 400)
        self.assertEqual(body["errors"], [{"field": "summary", "error": "\"Summary\" is required in Jira: map it"}])
        status, body, _ = self.post("/api/integrations/jira/rules", "jira-routing", {"name": "x", "mode": "later"}, self.admin)
        self.assertEqual((status, body["errors"][0]["field"]), (400, "mode"))
        status, saved, _ = self.post("/api/integrations/jira/destinations", "jira-routing",
                                          {"name": "Seg", "project": "SEC", "issue_type": "10001"}, self.admin)
        self.assertEqual((status, saved["destination"]["project"]["key"]), (200, "SEC"))
        status, body, _ = self.post("/api/integrations/jira/rules", "jira-routing",
                                         {"name": "API", "patterns": ["org/*"], "destination": saved["destination"]["id"]}, self.admin)
        self.assertEqual((status, body["rule"]["name"], body["backfill"], len(body["routing"]["rules"])), (200, "API", None, 2))
        status, preview, _ = self.post("/api/integrations/jira/rules/preview", "jira-preview",
                                            {"name": "API", "patterns": ["org/*"], "destination": saved["destination"]["id"], "mode": "auto"},
                                            self.admin)
        self.assertEqual((status, preview["findings"]), (200, 0))

    def test_members_create_issues_from_a_run_and_from_an_asset_view(self):
        self.post("/api/integrations/jira", "connect-jira", {"action": "save", "site": "acme.atlassian.net", "email": "sec@acme.io",
                                                                  "token": TOKEN, "project": "SEC"}, self.admin)
        record = save_repository_scan(self.data_dir, _scan("org/api", [_finding(FP_A), _finding(FP_B, package="lodash")], self.now.isoformat()))
        status, result, _ = self.post("/api/integrations/jira/issues", "export-jira", {"run_id": record["id"], "fingerprints": [FP_A]}, self.member)
        self.assertEqual((status, result["created"][0]["project"]), (200, "SEC"))
        status, result, _ = self.post("/api/integrations/jira/issues", "export-jira",
                                           {"selections": [{"asset": "github:org/api", "fingerprints": [FP_A, FP_B]}]}, self.member)
        self.assertEqual((status, len(result["created"]), len(result["existing"])), (200, 1, 1))
        status, _, _ = self.post("/api/integrations/jira/issues", "export-jira", {"run_id": record["id"], "asset": "x", "fingerprints": [FP_A]},
                                      self.member)
        self.assertEqual(status, 400)


if __name__ == "__main__":
    unittest.main()
