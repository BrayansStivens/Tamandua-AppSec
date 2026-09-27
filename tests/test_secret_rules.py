"""Secret detection settings (defaults and per repository): validation, merge, generated engine configs, engine wiring
and who may change them."""

import json
import re
import subprocess
import tempfile
import tomllib
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import testenv

from tamandua.app import wiring
from tamandua.modules.identity.auth import Users
from tamandua.modules.scanning import engines
from tamandua.modules.runs.store import save_repository_scan
from tamandua.modules.scanning import secret_rules as sr
from tamandua.modules.runs import assets
from tamandua.shared import documents
from tamandua.shared.i18n import text
from test_auth import ORIGIN, PASSWORD, HttpCase
from test_dashboard import _scan

wiring.configure()  # like every Tamandua process: domain events and injected readers

ADMIN = {"username": "operadora", "role": "admin"}
RULE = {"id": "acme-token", "description": "ACME internal token", "regex": r"ACME-TOKEN-[0-9a-f]{32}",
        "keywords": ["ACME-TOKEN"]}
KEY = "github#7"
QUERY_KEY = "github%237"


def settings(**changes):
    base = {"allowlist": {"regexes": [], "paths": [], "stopwords": []}, "rules": [], "disabled_rules": []}
    return {**base, **changes}


class ValidationTests(unittest.TestCase):
    def assert_rejected(self, raw, field=None):
        with self.assertRaises(sr.SecretRulesError) as caught:
            sr.normalize(raw)
        if field:
            self.assertEqual(caught.exception.field, field)
        return caught.exception

    def test_only_re2_compatible_regexes(self):
        for pattern, construct in ((r"(?<=x)abc", "lookaround"), (r"(?=abc)x", "lookaround"), (r"(?!a)b", "lookaround"),
                                   (r"(a)\1", "backreference"), (r"(?P<n>a)(?P=n)", "backreference"), (r"(?>ab)c", "atomic"),
                                   (r"a++b", "possessive"), (r"a{2}+", "possessive"), (r"(a)?(?(1)b|c)", "conditional"),
                                   (r"abc\Z", "escape"), (r"a{2000}", "repeat"), (r"a{,3}", "repeat"), (r"(?#c)abc", "group")):
            with self.subTest(pattern=pattern):
                self.assertEqual(sr.unsupported_construct(pattern), construct)
                self.assert_rejected(settings(rules=[{**RULE, "regex": pattern}]), "rules.0.regex")
        for pattern in (r"(?i)token_[a-z]{8,64}", r"(?P<key>ab)[\]\\(?=]c", r"[(?<=]x", r"\(\?=x", r"a{2,5}?", r"(?i:ab)c"):
            with self.subTest(pattern=pattern):
                self.assertIsNone(sr.unsupported_construct(pattern))
                sr.normalize(settings(rules=[{**RULE, "regex": pattern}]))

    def test_regexes_must_compile_and_never_match_empty_text(self):
        self.assert_rejected(settings(rules=[{**RULE, "regex": "(abc"}]), "rules.0.regex")
        self.assert_rejected(settings(rules=[{**RULE, "regex": r"\p{L}+"}]), "rules.0.regex")  # Go only
        self.assert_rejected(settings(rules=[{**RULE, "regex": "a*"}]), "rules.0.regex")
        error = self.assert_rejected(settings(allowlist={"regexes": [".*"], "paths": [], "stopwords": []}), "allowlist.regexes.0")
        self.assertEqual(error.message["$t"], "scanning.secret_rules.errors.allow_everything")

    def test_limits_and_ids(self):
        self.assert_rejected(settings(rules=[{**RULE, "id": f"r{index}"} for index in range(sr.MAX_RULES + 1)]), "rules")
        self.assert_rejected(settings(allowlist={"regexes": [f"x{index}" for index in range(101)]}), "allowlist.regexes")
        self.assert_rejected(settings(rules=[{**RULE, "regex": "a" * 501}]), "rules.0.regex")
        for bad in ("Acme", "acme_token", "", "a" * 61, "acme token"):
            with self.subTest(id=bad):
                self.assert_rejected(settings(rules=[{**RULE, "id": bad}]), "rules.0.id")
        self.assert_rejected(settings(rules=[RULE, RULE]), "rules.1.id")
        # Custom detectors have no severity (a secret is always critical): an old client's value is dropped.
        self.assertNotIn("severity", sr.normalize(settings(rules=[{**RULE, "severity": "low"}]))["rules"][0])
        self.assert_rejected(settings(rules=[{**RULE, "description": "x"}]), "rules.0.description")
        self.assert_rejected(settings(rules=[{**RULE, "keywords": [f"k{index}" for index in range(11)]}]), "rules.0.keywords")
        self.assert_rejected(settings(disabled_rules=["not-a-gitleaks-rule"]), "disabled_rules")
        for path in ("**", "*", "../x", "/abs", "a b"):
            with self.subTest(path=path):
                self.assert_rejected(settings(allowlist={"paths": [path]}), "allowlist.paths.0")
        self.assert_rejected(settings(allowlist={"stopwords": ["ab"]}), "allowlist.stopwords.0")

    def test_control_characters_and_triple_quotes_are_rejected(self):
        for field, value in (("description", "Token\nnext"), ("description", "bad\x00"), ("regex", "abc'''def"),
                             ("regex", "a\nb"), ("description", "lone \ud800 surrogate"), ("description", "line\u2028separator")):
            with self.subTest(value=value):
                self.assert_rejected(settings(rules=[{**RULE, field: value}]), f"rules.0.{field}")

    def test_normalizes(self):
        result = sr.normalize(settings(rules=[{**RULE, "description": "  ACME   token  "}], disabled_rules=["jwt", "jwt"],
                                       allowlist={"regexes": ["abc", "abc"], "paths": ["fixtures/"], "stopwords": ["Dummy"]}))
        self.assertEqual(result["rules"][0]["description"], "ACME token")
        self.assertEqual(result["rules"][0]["keywords"], ["acme-token"])
        self.assertEqual(result["allowlist"], {"regexes": ["abc"], "paths": ["fixtures/**"], "stopwords": ["dummy"]})
        self.assertEqual(result["disabled_rules"], ["jwt"])

    def test_reason_is_required_and_history_records_changes(self):
        with tempfile.TemporaryDirectory() as folder:
            data_dir = Path(folder)
            with self.assertRaises(sr.SecretRulesError) as caught:
                sr.save(data_dir, settings(rules=[RULE]), reason="  ok ", user=ADMIN)
            self.assertEqual(caught.exception.field, "reason")
            self.assertIsNone(sr.for_scan(data_dir))
            sr.save(data_dir, settings(rules=[RULE]), reason="Internal ACME tokens", user=ADMIN)
            saved = sr.save(data_dir, settings(disabled_rules=["jwt"]), reason="Test JWTs everywhere", user=ADMIN)
            self.assertEqual(saved["by"], "operadora")
            self.assertEqual([entry["reason"] for entry in saved["history"]], ["Internal ACME tokens", "Test JWTs everywhere"])
            self.assertEqual(saved["history"][-1]["changes"], {"rules": {"removed": ["acme-token"]}, "disabled_rules": {"added": ["jwt"]}})
            self.assertEqual(sr.for_scan(data_dir)["disabled_rules"], ["jwt"])
            for index in range(sr.HISTORY + 3):
                sr.save(data_dir, settings(), reason=f"Change number {index}", user=ADMIN)
            self.assertEqual(len(sr.get(data_dir)["history"]), sr.HISTORY)
            self.assertIsNone(sr.for_scan(data_dir))


class ReadLimitsTests(unittest.TestCase):
    def test_reading_keeps_the_limits_the_api_declares_even_for_an_older_document(self):
        from tamandua.shared import documents
        with tempfile.TemporaryDirectory() as folder:
            data_dir = Path(folder)
            many = [f"item-{index}" for index in range(sr.MAX_ENTRIES + 50)]
            documents.save(data_dir, sr.DOCUMENT, {
                "allowlist": {"regexes": many, "paths": many, "stopwords": many},
                "rules": [{**RULE, "id": f"rule-{index}", "keywords": many} for index in range(sr.MAX_RULES + 5)],
                "disabled_rules": many * 3,
                "history": [{"at": "2026-09-26", "by": "ana", "reason": "x", "changes": {"paths": {"added": many}}}] * (sr.HISTORY + 5)})
            view = sr.get(data_dir)
            self.assertEqual({name: len(items) for name, items in view["allowlist"].items()},
                             {"regexes": sr.MAX_ENTRIES, "paths": sr.MAX_ENTRIES, "stopwords": sr.MAX_ENTRIES})
            self.assertEqual((len(view["rules"]), len(view["rules"][0]["keywords"]), len(view["disabled_rules"])),
                             (sr.MAX_RULES, sr.MAX_KEYWORDS, sr.MAX_DISABLED))
            self.assertEqual((len(view["history"]), len(view["history"][0]["changes"]["paths"]["added"])), (sr.HISTORY, sr.CHANGES_SHOWN))


class GitleaksConfigTests(unittest.TestCase):
    def test_extends_defaults_with_rules_disabled_and_one_allowlist(self):
        config = tomllib.loads(sr.gitleaks_toml(sr.normalize(settings(
            rules=[RULE], disabled_rules=["jwt"], allowlist={"regexes": ["AKIA[0-9]{4}"], "paths": ["fixtures/", "**/testdata/*.json"],
                                                           "stopwords": ["example"]}))))
        self.assertEqual(config["extend"], {"useDefault": True, "disabledRules": ["jwt"]})
        self.assertEqual(config["rules"], [{"id": "tamandua-acme-token", "description": "ACME internal token",
                                            "regex": r"ACME-TOKEN-[0-9a-f]{32}", "keywords": ["acme-token"]}])
        allowlist = config["allowlists"][0]
        self.assertEqual(allowlist["regexes"], ["AKIA[0-9]{4}"])
        self.assertEqual(allowlist["stopwords"], ["example"])
        self.assertEqual(allowlist["paths"], [r"^/src/fixtures/.*(?:/.*)?$", r"^/src/(?:.*/)?testdata/[^/]*\.json(?:/.*)?$"])

    def test_nothing_configured_writes_no_allowlist(self):
        config = tomllib.loads(sr.gitleaks_toml(sr.normalize(settings(rules=[RULE]))))
        self.assertNotIn("allowlists", config)
        self.assertEqual(config["extend"], {"useDefault": True})

    def test_hostile_values_stay_values(self):
        hostile = [
            'x"\n[[rules]]\nid = "evil',
            "x'\n[extend]\nuseDefault = false",
            'back\\slash "quoted" \'single\'',
            "unicode ñ — 😀  ",
        ]
        for description in hostile:
            with self.subTest(description=description):
                rule = {"id": "acme-token", "description": description, "regex": r"KEY='[A-Z]{10}'\\d", "keywords": []}
                raw = sr.gitleaks_toml({**sr.empty(), "rules": [rule]})
                config = tomllib.loads(raw)
                self.assertEqual(config["rules"], [{"id": "tamandua-acme-token", "description": description,
                                                    "regex": r"KEY='[A-Z]{10}'\\d"}])
                self.assertEqual(config["extend"], {"useDefault": True})
        # Through normalize, line breaks never even get there.
        with self.assertRaises(sr.SecretRulesError):
            sr.normalize(settings(rules=[{**RULE, "description": hostile[0]}]))

    def test_literal_strings_only_when_exact(self):
        self.assertEqual(sr._toml(r"a\d+"), r"'a\d+'")
        self.assertEqual(sr._toml("it's"), '"it\'s"')
        self.assertEqual(sr._toml('a"b\\c'), "'a\"b\\c'")
        self.assertEqual(tomllib.loads(f"v = {sr._toml(chr(7) + 'x')}")["v"], "\x07x")


class TrivyConfigTests(unittest.TestCase):
    def test_allowlist_rules_and_disabled_equivalents(self):
        config = json.loads(sr.trivy_secret_config(sr.normalize(settings(
            rules=[RULE], disabled_rules=["jwt", "aws-access-token", "adafruit-api-key"],
            allowlist={"regexes": ["AKIA[0-9]{4}"], "paths": ["fixtures/"], "stopwords": ["exa.mple"]}))))
        self.assertEqual(config["rules"], [{"id": "tamandua-acme-token", "category": "Tamandua", "title": "ACME internal token",
                                            "severity": "CRITICAL", "regex": r"ACME-TOKEN-[0-9a-f]{32}", "keywords": ["acme-token"]}])
        self.assertEqual(config["allow-rules"], [
            {"id": "tamandua-path-1", "description": "Tamandua", "path": r"^fixtures/.*(?:/.*)?$"},
            {"id": "tamandua-regex-1", "description": "Tamandua", "regex": "AKIA[0-9]{4}"},
            {"id": "tamandua-stopword-1", "description": "Tamandua", "regex": r"(?i)exa\.mple"}])
        # adafruit-api-key has no Trivy detector: Trivy keeps running as is for it.
        self.assertEqual(config["disable-rules"], ["aws-access-key-id", "jwt-token"])

    def test_empty_sections_are_omitted(self):
        self.assertEqual(json.loads(sr.trivy_secret_config(sr.normalize(settings(disabled_rules=["adafruit-api-key"])))), {})


def _mounts(command_mounts: list[str]) -> dict[str, tuple[str, str]]:
    """{container path: (host path, options)} from `-v host:container[:ro]` pairs."""
    out = {}
    for flag, value in zip(command_mounts[::2], command_mounts[1::2]):
        if flag == "-v":
            host, container, *options = value.split(":")
            out[container] = (host, ":".join(options))
    return out


class EngineWiringTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.snapshot = Path(self.folder.name) / "snapshot"
        self.snapshot.mkdir()
        self.settings = sr.normalize(settings(rules=[RULE], allowlist={"regexes": [], "paths": ["fixtures/"], "stopwords": []}))
        self.calls = []
        docker = patch.dict(engines._docker_state, {"ok": True})
        docker.start()
        self.addCleanup(docker.stop)
        testenv.docker_runner(self)
        self.addCleanup(self.folder.cleanup)

    def gitleaks(self, report=None, returncode=0, stderr=""):
        def fake(key, arguments, snapshot, *, mounts=None, **kwargs):
            mounted = _mounts(mounts or [])
            config = Path(mounted["/cfg"][0]) / "gitleaks.toml" if "/cfg" in mounted else None
            self.calls.append({"arguments": arguments, "mounts": mounted, "config": config.read_text() if config else None})
            if report is not None:
                (Path(mounted["/out"][0]) / "report.json").write_text(json.dumps(report))
            return subprocess.CompletedProcess(arguments, returncode, "", stderr)
        return patch.object(engines, "_run", side_effect=fake)

    def test_no_settings_no_config(self):
        with self.gitleaks([]):
            result = engines.run_gitleaks(self.snapshot)
        self.assertEqual(result["status"], "completed")
        self.assertNotIn("--config", self.calls[0]["arguments"])
        self.assertNotIn("/cfg", self.calls[0]["mounts"])

    def test_settings_mounted_read_only_and_custom_findings_mapped(self):
        report = [{"RuleID": "tamandua-acme-token", "File": "/src/app/settings.py", "StartLine": 3, "Entropy": 4.1},
                  {"RuleID": "github-pat", "File": "/src/app/other.py", "StartLine": 1, "Entropy": 4.4}]
        with self.gitleaks(report):
            result = engines.run_gitleaks(self.snapshot, self.settings)
        call = self.calls[0]
        self.assertEqual(call["arguments"][call["arguments"].index("--config") + 1], "/cfg/gitleaks.toml")
        self.assertEqual(call["mounts"]["/cfg"][1], "ro")
        self.assertEqual(call["mounts"]["/out"][1], "")
        self.assertNotEqual(call["mounts"]["/cfg"][0], call["mounts"]["/out"][0])
        self.assertIn("tamandua-acme-token", call["config"])
        self.assertEqual(result["status"], "completed")
        self.assertIn("1", text(result["detail"], "en"))
        custom, builtin = result["findings"]
        self.assertEqual((custom["title"], custom["severity"], custom["rule_id"], custom["tool"]),
                         ("ACME internal token", "critical", "tamandua-acme-token", "gitleaks"))
        self.assertEqual(custom["priority"]["action"], "act")
        self.assertEqual(custom["remediation"], {"$t": "scanning.secrets.rotate"})
        self.assertEqual(custom["fingerprint"], engines._stable("secrets", "tamandua-acme-token", "app/settings.py", "3"))
        self.assertNotEqual(builtin["title"], "ACME internal token")
        # The fingerprint doesn't depend on the (editable) description.
        renamed = {**self.settings, "rules": [{**self.settings["rules"][0], "description": "Other text", "severity": "low"}]}
        again = engines.parse_gitleaks(report, sr.custom_rules(renamed))[0]
        self.assertEqual(again["fingerprint"], custom["fingerprint"])
        self.assertEqual((again["title"], again["severity"]), ("Other text", "critical"))

    def test_rejected_config_is_inconclusive_never_clean(self):
        stderr = "8:22AM FTL unable to load gitleaks config, err: While parsing config: toml: bad\n"
        with self.gitleaks(None, returncode=1, stderr=stderr):
            result = engines.run_gitleaks(self.snapshot, self.settings)
        self.assertEqual(result["status"], "inconclusive")
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["detail"]["$t"], "scanning.gitleaks.config_failed_cause")
        self.assertIn("unable to load gitleaks config", result["detail"]["params"]["cause"])
        panic = "panic: regexp: Compile(`(?<=x)`): error parsing regexp\n\ngoroutine 1 [running]:\nregexp.MustCompile(...)\n\t/go/src/github.com/zricethezav/gitleaks/v8/config/config.go:127\nmain.main()\n"
        with self.gitleaks(None, returncode=2, stderr=panic):
            result = engines.run_gitleaks(self.snapshot, self.settings)
        self.assertEqual(result["status"], "inconclusive")
        self.assertTrue(result["detail"]["params"]["cause"].startswith("panic: regexp"))
        # A report missing with exit code 0 isn't "no secrets" either when settings were applied.
        with self.gitleaks(None, returncode=0, stderr="error loading config"):
            self.assertEqual(engines.run_gitleaks(self.snapshot, self.settings)["status"], "inconclusive")

    def test_trivy_gets_secret_config_and_retries_without_it_when_rejected(self):
        payload = {"Results": [{"Target": "app/settings.py", "Class": "secret", "Secrets": [
            {"RuleID": "tamandua-acme-token", "StartLine": 3, "Severity": "CRITICAL", "Title": "ACME internal token"}]}]}
        calls = []

        def fake(key, arguments, snapshot, *, mounts=None, **kwargs):
            mounted = _mounts(mounts or [])
            config = Path(mounted["/cfg"][0]) / "trivy-secret.yaml" if "/cfg" in mounted else None
            calls.append({"arguments": arguments, "mounts": mounted, "config": config.read_text() if config else None})
            return subprocess.CompletedProcess(arguments, 0, json.dumps(payload), "")

        with patch.object(engines, "_run", side_effect=fake):
            result = engines.run_trivy(self.snapshot, Path(self.folder.name) / "cache", {}, self.settings)
        call = calls[0]
        self.assertEqual(call["arguments"][call["arguments"].index("--secret-config") + 1], "/cfg/trivy-secret.yaml")
        self.assertEqual(call["mounts"]["/cfg"][1], "ro")
        self.assertIn("tamandua-path-1", call["config"])
        self.assertEqual(result["status"], "completed")
        finding = result["findings"][0]
        self.assertEqual((finding["title"], finding["severity"], finding["tool"]), ("ACME internal token", "critical", "trivy"))

        calls.clear()
        rejected = subprocess.CompletedProcess([], 1, "", "FATAL Fatal error run error: secret config error: secrets config decode error: regexp")

        def failing_once(key, arguments, snapshot, *, mounts=None, **kwargs):
            calls.append(arguments)
            return rejected if len(calls) == 1 else subprocess.CompletedProcess(arguments, 0, json.dumps({"Results": []}), "")

        with patch.object(engines, "_run", side_effect=failing_once):
            result = engines.run_trivy(self.snapshot, Path(self.folder.name) / "cache", {}, self.settings)
        self.assertEqual(len(calls), 2)
        self.assertNotIn("--secret-config", calls[1])
        self.assertEqual(calls[1][calls[1].index("--scanners") + 1], "vuln,misconfig")
        self.assertEqual(result["status"], "partial")
        self.assertIn("secret", text(result["detail"], "en").lower())

    def test_trivy_without_settings_is_unchanged(self):
        calls = []

        def fake(key, arguments, snapshot, *, mounts=None, **kwargs):
            calls.append((arguments, _mounts(mounts or [])))
            return subprocess.CompletedProcess(arguments, 0, "{}", "")

        with patch.object(engines, "_run", side_effect=fake):
            engines.run_trivy(self.snapshot, Path(self.folder.name) / "cache", {})
        self.assertNotIn("--secret-config", calls[0][0])
        self.assertNotIn("/cfg", calls[0][1])


class SecretRulesApiTests(HttpCase):
    def setUp(self):
        super().setUp()
        Users(self.data_dir).create("analista", PASSWORD)
        Users(self.data_dir).create("operadora", PASSWORD, role="admin")

    def cookie(self, username):
        _, _, cookies = self.post("/api/auth/login", "login", {"username": username, "password": PASSWORD})
        return cookies[0].split("; ")[0]

    def save(self, action, body, cookie, **headers):
        return self.call("POST", "/api/secrets/config", body,
                         {"Origin": ORIGIN, "X-Tamandua-Action": action, "Content-Type": "application/json", "Cookie": cookie, **headers})

    def body(self, **changes):
        return {**settings(rules=[RULE]), "reason": "ACME tokens leak in configs", **changes}

    def test_members_read_admins_write_with_csrf(self):
        self.assertEqual(self.call("GET", "/api/secrets/config")[0], 401)
        member, admin = self.cookie("analista"), self.cookie("operadora")
        status, view, _ = self.call("GET", "/api/secrets/config", headers={"Cookie": member})
        self.assertEqual((status, view["rules"], view["limits"]["rules"]), (200, [], sr.MAX_RULES))
        status, builtin, _ = self.call("GET", "/api/secrets/builtin-rules", headers={"Cookie": member})
        self.assertEqual(status, 200)
        self.assertIn({"id": "aws-access-token", "trivy": "aws-access-key-id"}, builtin["rules"])
        self.assertEqual(self.save("save-secret-rules", self.body(), member)[0], 403)
        self.assertEqual(self.save("wrong-action", self.body(), admin)[0], 403)
        self.assertEqual(self.save("save-secret-rules", self.body(), admin, Origin="https://evil.example")[0], 403)
        self.assertEqual(self.save("save-secret-rules", {**self.body(), "extra": 1}, admin)[0], 400)
        status, saved, _ = self.save("save-secret-rules", self.body(), admin)
        self.assertEqual((status, saved["rules"][0]["id"], saved["by"]), (200, "acme-token", "operadora"))
        self.assertEqual(saved["history"][0]["reason"], "ACME tokens leak in configs")
        status, view, _ = self.call("GET", "/api/secrets/config", headers={"Cookie": member})
        self.assertEqual(view["rules"][0]["description"], "ACME internal token")
        # A member sees the shape, never the patterns (an allowlisted regex may contain a real secret).
        self.assertEqual(view["rules"][0]["regex"], "••••••")
        self.assertNotIn(saved["rules"][0]["regex"], json.dumps(view, ensure_ascii=False))
        admin_view = self.call("GET", "/api/secrets/config", headers={"Cookie": admin})[1]
        self.assertEqual(admin_view["rules"][0]["regex"], saved["rules"][0]["regex"])

    def test_errors_are_localized_and_point_at_the_field(self):
        admin = self.cookie("operadora")
        bad = self.body(rules=[{**RULE, "regex": "(?<=x)abc"}])
        status, body, _ = self.save("save-secret-rules", bad, admin)
        self.assertEqual((status, body["field"]), (400, "rules.0.regex"))
        self.assertIn("Gitleaks y Trivy no admiten", body["error"])
        status, body, _ = self.save("save-secret-rules", bad, admin, **{"Accept-Language": "en"})
        self.assertIn("which Gitleaks and Trivy don't support", body["error"])
        status, body, _ = self.save("save-secret-rules", self.body(reason="no"), admin)
        self.assertEqual((status, body["field"]), (400, "reason"))
        self.assertEqual(self.call("GET", "/api/secrets/config", headers={"Cookie": admin})[1]["rules"], [])



OWN = {"id": "beta-key", "description": "Beta partner key", "regex": r"BETA-[0-9A-F]{24}", "keywords": ["beta-"]}


class RepositorySettingsTests(unittest.TestCase):
    """A repository's own entries add to the defaults; they never replace or weaken them."""

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.data_dir = Path(self.folder.name)

    def test_effective_settings_are_the_union_of_defaults_and_the_repository(self):
        sr.save(self.data_dir, settings(rules=[RULE], disabled_rules=["jwt"], allowlist={"paths": ["fixtures/"], "stopwords": ["example"]}),
                reason="Organization defaults", user=ADMIN)
        sr.save(self.data_dir, settings(rules=[OWN], disabled_rules=["jwt", "generic-api-key"],
                                        allowlist={"paths": ["fixtures/", "samples/"], "regexes": ["BETA-0{24}"]}),
                reason="Beta partner integration", user=ADMIN, asset=KEY, name="org/app")
        effective = sr.for_scan(self.data_dir, KEY)
        self.assertEqual([rule["id"] for rule in effective["rules"]], ["acme-token", "beta-key"])
        self.assertEqual(effective["disabled_rules"], ["generic-api-key", "jwt"])
        self.assertEqual(effective["allowlist"], {"regexes": ["BETA-0{24}"], "paths": ["fixtures/**", "samples/**"], "stopwords": ["example"]})
        # Other repositories (and a scan without a repository) get the defaults alone; the defaults document is untouched.
        for other in ("github#8", None):
            self.assertEqual([rule["id"] for rule in sr.for_scan(self.data_dir, other)["rules"]], ["acme-token"])
        self.assertEqual(sr.get(self.data_dir)["disabled_rules"], ["jwt"])
        self.assertEqual(sr.get(self.data_dir, KEY)["history"][0]["reason"], "Beta partner integration")
        # Only a repository's entries: a scan still applies them with no defaults at all.
        sr.save(self.data_dir, settings(), reason="Back to the engine defaults", user=ADMIN)
        self.assertEqual([rule["id"] for rule in sr.for_scan(self.data_dir, KEY)["rules"]], ["beta-key"])
        self.assertIsNone(sr.for_scan(self.data_dir, "github#8"))

    def test_rule_ids_never_clash_between_defaults_and_repositories(self):
        sr.save(self.data_dir, settings(rules=[RULE]), reason="Organization defaults", user=ADMIN)
        with self.assertRaises(sr.SecretRulesError) as caught:
            sr.save(self.data_dir, settings(rules=[OWN, {**RULE, "description": "Same id"}]), reason="Clash with a default", user=ADMIN, asset=KEY)
        self.assertEqual((caught.exception.field, caught.exception.message["$t"]), ("rules.1.id", "scanning.secret_rules.errors.rule_id_default"))
        sr.save(self.data_dir, settings(rules=[OWN]), reason="Beta partner integration", user=ADMIN, asset=KEY, name="org/app")
        with self.assertRaises(sr.SecretRulesError) as caught:
            sr.save(self.data_dir, settings(rules=[RULE, OWN]), reason="Clash with a repository", user=ADMIN)
        self.assertEqual(caught.exception.field, "rules.1.id")
        self.assertEqual(text(caught.exception.message, "en"), "The ID beta-key is already used by a rule of org/app. Choose another one.")
        # Should a clash still reach a scan (two saves at once), the default rule wins and the engines see one id.
        documents.save(self.data_dir, sr.ASSET_PREFIX + KEY, {**settings(rules=[{**RULE, "description": "Repository copy"}])})
        rules = sr.for_scan(self.data_dir, KEY)["rules"]
        self.assertEqual([(rule["id"], rule["description"]) for rule in rules], [("acme-token", "ACME internal token")])

    def test_stored_severity_is_ignored(self):
        documents.save(self.data_dir, sr.DOCUMENT, settings(rules=[{**RULE, "severity": "low"}]))
        documents.save(self.data_dir, sr.ASSET_PREFIX + KEY, settings(rules=[{**OWN, "severity": "medium"}]))
        for rule in sr.for_scan(self.data_dir, KEY)["rules"]:
            self.assertNotIn("severity", rule)
        self.assertEqual(json.loads(sr.trivy_secret_config(sr.for_scan(self.data_dir, KEY)))["rules"][1]["severity"], "CRITICAL")

    def test_purging_a_repository_forgets_its_settings(self):
        sr.save(self.data_dir, settings(rules=[OWN]), reason="Beta partner integration", user=ADMIN, asset=KEY)
        sr.save(self.data_dir, settings(rules=[RULE]), reason="Organization defaults", user=ADMIN)
        assets.purge(self.data_dir, KEY)
        self.assertEqual(sr.get(self.data_dir, KEY)["rules"], [])
        self.assertEqual(documents.names(self.data_dir, sr.ASSET_PREFIX), [])
        self.assertEqual([rule["id"] for rule in sr.get(self.data_dir)["rules"]], ["acme-token"])

    def test_a_repository_scan_applies_its_own_entries(self):
        sr.save(self.data_dir, settings(rules=[OWN]), reason="Beta partner integration", user=ADMIN, asset=KEY)
        from tamandua.modules.scanning import repository
        seen = []
        with patch.object(repository, "engines_available", return_value=True), \
                patch.object(repository, "run_opengrep", return_value=_tool("opengrep")), \
                patch.object(repository, "run_gitleaks", side_effect=lambda root, applied: seen.append(applied) or _tool("gitleaks")), \
                patch.object(repository, "run_trivy", side_effect=lambda root, cache, feeds, applied: seen.append(applied) or _tool("trivy")), \
                patch.object(repository, "run_osv_scanner", return_value=_tool("osv-scanner")), \
                patch.object(repository, "run_checkov", return_value=_tool("checkov")), \
                patch.object(repository, "run_zizmor", return_value=_tool("zizmor")), \
                patch.object(repository, "host_mount_problem", return_value=None), \
                patch.object(repository, "load_feeds", return_value={"kev": {}, "epss": {}}):
            root = self.data_dir / "snapshot"
            root.mkdir()
            repository.scan_repository(root, {"id": "github:org/app", "uid": KEY, "name": "org/app", "provider": "github"}, data_dir=self.data_dir)
            repository.scan_repository(root, {"id": "github:org/other", "uid": "github#8", "name": "org/other", "provider": "github"}, data_dir=self.data_dir)
        self.assertEqual([rule["id"] for rule in seen[0]["rules"]], ["beta-key"])
        self.assertIs(seen[0], seen[1])
        self.assertEqual(seen[2:], [None, None])


def _tool(key):
    return {"tool": key, "name": key, "version": "1", "image": "x", "duration_s": 0, "status": "completed", "detail": "", "findings": []}


class SecretsAreAlwaysCriticalTests(unittest.TestCase):
    def test_every_secret_engine_reports_critical(self):
        generic = [{"RuleID": "generic-api-key", "File": "/src/app.py", "StartLine": 2, "Entropy": 3.0}]
        self.assertEqual(engines.parse_gitleaks(generic)[0]["severity"], "critical")
        custom = engines.parse_gitleaks([{"RuleID": "tamandua-acme-token", "File": "/src/a.py", "StartLine": 1}],
                                        sr.custom_rules({"rules": [{**RULE, "severity": "low"}]}))[0]
        self.assertEqual((custom["severity"], custom["priority"]["action"]), ("critical", "act"))
        payload = {"Results": [{"Target": "app/settings.py", "Class": "secret", "Secrets": [
            {"RuleID": "github-pat", "StartLine": 3, "Severity": "LOW", "Title": "GitHub PAT"},
            {"RuleID": "tamandua-acme-token", "StartLine": 9, "Severity": "MEDIUM", "Title": "ACME"}]}]}
        self.assertEqual({item["severity"] for item in engines.parse_trivy(payload, {}, sr.custom_rules({"rules": [RULE]}))}, {"critical"})

    def test_images_and_the_internal_patterns_too(self):
        from tamandua.modules.scanning import repository
        from tamandua.modules.scanning.image import config_findings, parse_reference
        metadata = {"ImageConfig": {"created": "2099-01-01T00:00:00Z", "config": {"User": "app", "Env": ["NPM_TOKEN=npm_secretvalue123"],
                                                                                   "Healthcheck": {"Test": ["CMD", "true"]}}, "history": []}}
        found = [item for item in config_findings(metadata, parse_reference("ghcr.io/acme/api:1.0")) if item["scanner"] == "secrets"]
        self.assertEqual([(item["rule_id"], item["severity"]) for item in found], [("IMG-ENV-SECRET", "critical")])
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "config.py"
            path.write_text('TOKEN = "ghp_' + "a" * 36 + '"\n', encoding="utf-8")
            self.assertEqual([item["severity"] for item in repository._secret_candidates(path, "config.py")], ["critical"])


class AssetSecretApiTests(HttpCase):
    def setUp(self):
        super().setUp()
        Users(self.data_dir).create("analista", PASSWORD)
        Users(self.data_dir).create("operadora", PASSWORD, role="admin")
        record = _scan("org/app", [], datetime.now(timezone.utc).isoformat())
        record["source"].update(uid=KEY)
        save_repository_scan(self.data_dir, record)
        self.member, self.admin = self.cookie("analista"), self.cookie("operadora")

    def cookie(self, username):
        _, _, cookies = self.post("/api/auth/login", "login", {"username": username, "password": PASSWORD})
        return cookies[0].split("; ")[0]

    def save(self, body, cookie, action="save-asset-secret-rules", **headers):
        return self.call("POST", "/api/assets/secrets", body,
                         {"Origin": ORIGIN, "X-Tamandua-Action": action, "Content-Type": "application/json", "Cookie": cookie, **headers})

    def body(self, **changes):
        return {**settings(rules=[OWN], allowlist={"regexes": ["BETA-0{24}"], "paths": ["samples/"], "stopwords": []}),
                "reason": "Beta partner integration", "key": KEY, **changes}

    def test_admins_customize_a_repository_members_see_the_shape(self):
        status, view, _ = self.call("GET", f"/api/assets/secrets?key={QUERY_KEY}", headers={"Cookie": self.member})
        self.assertEqual((status, view["rules"], view["key"], view["defaults"]), (200, [], KEY, {"rules": 0, "disabled": 0, "allowlist": 0}))
        self.assertEqual(self.save(self.body(), self.member)[0], 403)
        self.assertEqual(self.save(self.body(), self.admin, action="save-secret-rules")[0], 403)
        self.assertEqual(self.save(self.body(key="github#999"), self.admin)[0], 404)
        self.assertEqual(self.save(self.body(key="image:ghcr.io/acme/api"), self.admin)[0], 400)
        self.assertEqual(self.save(self.body(key="github#7\nfake log"), self.admin)[0], 400)
        self.assertEqual(self.save({**self.body(), "rules": [{**OWN, "severity": "high"}]}, self.admin)[0], 400)
        status, saved, _ = self.save(self.body(), self.admin)
        self.assertEqual((status, saved["rules"][0]["id"], saved["by"], saved["key"]), (200, "beta-key", "operadora", KEY))
        member_view = self.call("GET", f"/api/assets/secrets?key={QUERY_KEY}", headers={"Cookie": self.member})[1]
        self.assertEqual((member_view["rules"][0]["regex"], member_view["allowlist"]["regexes"], member_view["allowlist"]["paths"]),
                         ("••••••", ["••••••"], ["samples/**"]))
        self.assertNotIn("BETA-", json.dumps(member_view))
        self.assertEqual(self.call("GET", f"/api/assets/secrets?key={QUERY_KEY}", headers={"Cookie": self.admin})[1]["rules"][0]["regex"], OWN["regex"])
        # The defaults stay as they were; a rule id already used by the repository is refused with a pointer to it.
        self.assertEqual(self.call("GET", "/api/secrets/config", headers={"Cookie": self.admin})[1]["rules"], [])
        status, body, _ = self.call("POST", "/api/secrets/config", {**settings(rules=[OWN]), "reason": "Move it to the defaults"},
                                    {"Origin": ORIGIN, "X-Tamandua-Action": "save-secret-rules", "Content-Type": "application/json",
                                     "Cookie": self.admin, "Accept-Language": "en"})
        self.assertEqual((status, body["field"]), (400, "rules.0.id"))
        self.assertIn("org/app", body["error"])

    def test_a_clash_with_a_default_is_a_400_on_the_field(self):
        status, _, _ = self.call("POST", "/api/secrets/config", {**settings(rules=[RULE]), "reason": "Organization defaults"},
                                 {"Origin": ORIGIN, "X-Tamandua-Action": "save-secret-rules", "Content-Type": "application/json", "Cookie": self.admin})
        self.assertEqual(status, 200)
        status, body, _ = self.save(self.body(rules=[OWN, RULE]), self.admin)
        self.assertEqual((status, body["field"]), (400, "rules.1.id"))
        self.assertIn("regla predeterminada", body["error"])
        view = self.call("GET", f"/api/assets/secrets?key={QUERY_KEY}", headers={"Cookie": self.member})[1]
        self.assertEqual((view["rules"], view["defaults"]["rules"]), ([], 1))

if __name__ == "__main__":
    unittest.main()


class _Engines:
    """Fake Gitleaks and Trivy that honour the generated settings like the real engines: an allowlisted or disabled
    match is dropped without a trace. `secrets`: (rule, path, line, value) in the code."""

    def __init__(self, secrets, *, fail_reference=False):
        self.secrets, self.fail_reference, self.calls = list(secrets), fail_reference, []

    def __call__(self, key, arguments, snapshot, *, mounts=None, network=False, **kwargs):
        mounted = _mounts(mounts or [])
        folder = Path(mounted["/cfg"][0]) if "/cfg" in mounted else None
        if key == "gitleaks":
            config = tomllib.loads((folder / "gitleaks.toml").read_text()) if folder else {}
            allow = (config.get("allowlists") or [{}])[0]
            paths = [pattern.removeprefix("^/src/") for pattern in allow.get("paths", [])]
            regexes, stopwords = allow.get("regexes", []), allow.get("stopwords", [])
            disabled = set((config.get("extend") or {}).get("disabledRules") or [])
        else:
            config = json.loads((folder / "trivy-secret.yaml").read_text()) if folder else {}
            allow = config.get("allow-rules") or []
            paths = [rule["path"].removeprefix("^") for rule in allow if "path" in rule]
            regexes, stopwords = [rule["regex"] for rule in allow if "regex" in rule], []
            disabled = set(config.get("disable-rules") or [])
        custom = {rule["id"] for rule in config.get("rules") or []}
        filtered = bool(paths or regexes or stopwords or disabled)
        self.calls.append({"key": key, "arguments": arguments, "config": config, "network": network, "filtered": filtered})
        if self.fail_reference and not filtered:
            return subprocess.CompletedProcess(arguments, 2, "", "boom")
        seen = [(rule, path, line) for rule, path, line, value in self.secrets
                if (not rule.startswith("tamandua-") or rule in custom) and rule not in disabled
                and not any(re.match(pattern, path) for pattern in paths)
                and not any(re.search(pattern, value) for pattern in regexes)
                and not any(word in value.lower() for word in stopwords)]
        if key == "gitleaks":
            (Path(mounted["/out"][0]) / "report.json").write_text(json.dumps(
                [{"RuleID": rule, "File": f"/src/{path}", "StartLine": line, "Entropy": 4.2} for rule, path, line in seen]))
            return subprocess.CompletedProcess(arguments, 0, "", "")
        if "secret" not in arguments[arguments.index("--scanners") + 1].split(","):
            seen = []
        return subprocess.CompletedProcess(arguments, 0, json.dumps({"Results": [
            {"Target": path, "Class": "secret", "Secrets": [{"RuleID": rule, "StartLine": line, "Title": rule}]}
            for rule, path, line in seen]}), "")


class WithheldSecretsTests(unittest.TestCase):
    """An allowlisted secret or one matched only by a disabled rule is silenced, not fixed: it is recorded as excluded."""

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.data_dir = Path(self.folder.name)
        self.snapshot = self.data_dir / "snapshot"
        self.snapshot.mkdir()
        docker = patch.dict(engines._docker_state, {"ok": True})
        docker.start()
        self.addCleanup(docker.stop)
        self.clock = datetime.now(timezone.utc)

    def gitleaks(self, secrets, applied, **options):
        fake = _Engines(secrets, **options)
        with patch.object(engines, "_run", side_effect=fake):
            return engines.run_gitleaks(self.snapshot, applied), fake.calls

    def test_no_second_run_without_an_allowlist_or_disabled_rules(self):
        secrets = [("github-pat", "app/a.py", 1, "ghp_x"), ("tamandua-acme-token", "app/b.py", 2, "ACME")]
        for applied in (None, sr.normalize(settings(rules=[RULE]))):
            result, calls = self.gitleaks(secrets, applied)
            self.assertEqual(len(calls), 1)
            self.assertNotIn("withheld", result)
        fake = _Engines(secrets)
        with patch.object(engines, "_run", side_effect=fake):
            result = engines.run_trivy(self.snapshot, self.data_dir / "cache", {}, sr.normalize(settings(rules=[RULE])))
        self.assertEqual(len(fake.calls), 1)
        self.assertNotIn("withheld", result)

    def test_allowlisted_secrets_are_withheld_with_the_reason_and_stable_fingerprints(self):
        applied = sr.normalize(settings(rules=[RULE], allowlist={"paths": ["fixtures/"], "regexes": ["EXAMPLE-[0-9]+"], "stopwords": []}))
        secrets = [("github-pat", "fixtures/key.py", 1, "ghp_fixture"), ("generic-api-key", "app/config.py", 4, "EXAMPLE-123"),
                   ("tamandua-acme-token", "fixtures/acme.py", 2, "ACME-TOKEN-1"), ("github-pat", "app/real.py", 9, "ghp_real")]
        result, calls = self.gitleaks(secrets, applied)
        self.assertEqual([call["filtered"] for call in calls], [True, False])
        reference = calls[1]
        self.assertIn("--redact", reference["arguments"])
        self.assertEqual([rule["id"] for rule in reference["config"]["rules"]], ["tamandua-acme-token"])  # custom rules still apply
        self.assertEqual(result["status"], "completed")
        self.assertEqual([item["path"] for item in result["findings"]], ["app/real.py"])
        withheld = {item["path"]: item for item in result["withheld"]}
        self.assertEqual(set(withheld), {"fixtures/key.py", "app/config.py", "fixtures/acme.py"})
        self.assertEqual(withheld["fixtures/key.py"]["fingerprint"], engines._stable("secrets", "github-pat", "fixtures/key.py", "1"))
        self.assertEqual(withheld["fixtures/acme.py"]["fingerprint"], engines._stable("secrets", "tamandua-acme-token", "fixtures/acme.py", "2"))
        self.assertEqual(withheld["fixtures/acme.py"]["title"], "ACME internal token")
        reason = withheld["fixtures/key.py"]["excluded_reason"]
        self.assertEqual((reason["$t"], reason["params"]["path"]), ("scanning.secret_rules.withheld.path", "fixtures/**"))
        self.assertEqual(withheld["app/config.py"]["excluded_reason"]["$t"], "scanning.secret_rules.withheld.entry")
        self.assertIn("fixtures/**", text(reason, "en"))
        self.assertIn("not fixed", text(reason, "en"))
        self.assertIn("no remediado", text(reason, "es"))
        # Same code, same settings: same fingerprints.
        again, _ = self.gitleaks(secrets, applied)
        self.assertEqual([item["fingerprint"] for item in again["withheld"]], [item["fingerprint"] for item in result["withheld"]])

    def test_disabled_rules_are_withheld_too_in_both_engines(self):
        applied = sr.normalize(settings(disabled_rules=["jwt"]))
        secrets = [("jwt", "app/token.py", 3, "eyJ"), ("jwt-token", "app/token.py", 3, "eyJ")]
        result, calls = self.gitleaks(secrets[:1], applied)
        self.assertEqual(len(calls), 2)
        self.assertNotIn("--config", calls[1]["arguments"])  # only the engine defaults: no config at all
        self.assertEqual(result["findings"], [])
        reason = result["withheld"][0]["excluded_reason"]
        self.assertEqual((reason["$t"], reason["params"]["rule"]), ("scanning.secret_rules.withheld.rule_disabled", "jwt"))
        fake = _Engines(secrets[1:])
        with patch.object(engines, "_run", side_effect=fake):
            trivy = engines.run_trivy(self.snapshot, self.data_dir / "cache", {}, applied)
        reference = fake.calls[1]
        self.assertEqual(reference["arguments"][reference["arguments"].index("--scanners") + 1], "secret")
        self.assertFalse(reference["network"])
        self.assertNotIn("--secret-config", reference["arguments"])
        self.assertEqual(trivy["findings"], [])
        self.assertEqual(trivy["withheld"][0]["excluded_reason"]["params"]["rule"], "jwt")  # named as the user turned it off

    def test_a_failed_reference_run_is_partial_never_silent(self):
        applied = sr.normalize(settings(allowlist={"paths": ["fixtures/"]}))
        result, _ = self.gitleaks([("github-pat", "fixtures/key.py", 1, "x")], applied, fail_reference=True)
        self.assertEqual((result["status"], result["withheld"]), ("partial", None))
        self.assertIn("incomplete", text(result["detail"], "en"))

    def scan(self, secrets, **options):
        from tamandua.modules.scanning import repository
        fake = _Engines(secrets, **options)
        with patch.object(engines, "_run", side_effect=fake), \
                patch.object(repository, "engines_available", return_value=True), \
                patch.object(repository, "run_opengrep", return_value=_tool("opengrep")), \
                patch.object(repository, "run_osv_scanner", return_value=_tool("osv-scanner")), \
                patch.object(repository, "run_checkov", return_value=_tool("checkov")), \
                patch.object(repository, "run_zizmor", return_value=_tool("zizmor")), \
                patch.object(repository, "host_mount_problem", return_value=None), \
                patch.object(repository, "load_feeds", return_value={"kev": {}, "epss": {}}):
            scan = repository.scan_repository(self.snapshot, {"id": "github:org/app", "uid": KEY, "name": "org/app", "provider": "github"},
                                              data_dir=self.data_dir)
        self.clock += timedelta(hours=1)
        return save_repository_scan(self.data_dir, scan, created_at=self.clock.isoformat()), fake.calls

    def test_the_registry_shows_an_allowlisted_secret_as_excluded_never_fixed(self):
        from tamandua.modules.findings import registry
        leak, real = ("github-pat", "fixtures/key.py", 1, "ghp_fixture"), ("github-pat", "app/real.py", 9, "ghp_real")
        digest = engines._stable("secrets", "github-pat", "fixtures/key.py", "1")

        def entry():
            return registry.load(self.data_dir, KEY)["findings"][digest]
        record, calls = self.scan([leak, real])
        self.assertEqual(len(calls), 2)  # one Gitleaks, one Trivy: nothing to diff
        self.assertEqual(entry()["status"], "open")

        sr.save(self.data_dir, settings(allowlist={"paths": ["fixtures/"]}), reason="Test fixtures", user=ADMIN, asset=KEY)
        record, calls = self.scan([leak, real])
        self.assertEqual(len(calls), 4)
        self.assertEqual(record["status"], "completed")
        self.assertEqual([item["path"] for item in record["findings"]], ["app/real.py"])
        self.assertEqual([item["fingerprint"] for item in record["excluded_findings"]], [digest])  # both engines, one finding
        self.assertTrue(any(item["$t"] == "scanning.secret_rules.withheld.limitation" for item in record["limitations"]))
        state = entry()
        self.assertEqual(state["status"], "excluded")
        self.assertNotIn("fixed", state)
        self.assertNotIn("excluded_reason", state["finding"])
        reason = text(state["excluded"]["reason"], "en")
        self.assertIn("fixtures/**", reason)
        self.assertIn("this repository's own entries", reason)
        lifecycle = registry.summarize(self.data_dir, KEY)
        self.assertEqual((lifecycle["open"], lifecycle["excluded"], lifecycle["fixed"]), (1, 1, 0))
        view = registry.view(self.data_dir, KEY, status="excluded")
        self.assertEqual(view["findings"][0]["lifecycle"]["excluded"]["reason"]["$t"], "scanning.secret_rules.withheld.path")
        # Saving the excluded paths doesn't reopen what the secret settings withhold.
        self.assertEqual(registry.apply_exclusions(self.data_dir, KEY, [], when=self.clock.isoformat()), {"excluded": 0, "reopened": 0})

        # Without the allowlist it's open again.
        sr.save(self.data_dir, settings(), reason="Fixtures cleaned up", user=ADMIN, asset=KEY)
        self.scan([leak, real])
        self.assertEqual(entry()["status"], "open")
        self.assertNotIn("excluded", entry())

        # Allowlisted again, then a failed unfiltered run: the scan is incomplete and nothing is fixed.
        sr.save(self.data_dir, settings(allowlist={"paths": ["fixtures/"]}), reason="Test fixtures", user=ADMIN, asset=KEY)
        record, _ = self.scan([real], fail_reference=True)
        self.assertEqual(record["status"], "incomplete")
        self.assertEqual(entry()["status"], "open")
        self.scan([leak, real])
        self.assertEqual(entry()["status"], "excluded")
        # Removed from the code: not even the unfiltered run sees it, so it's fixed.
        self.scan([real])
        self.assertEqual(entry()["status"], "fixed")
        self.assertNotIn("excluded", entry())

    def test_origins_name_where_the_filter_comes_from(self):
        sr.save(self.data_dir, settings(disabled_rules=["jwt"], allowlist={"stopwords": ["example"]}), reason="Organization defaults", user=ADMIN)
        sr.save(self.data_dir, settings(disabled_rules=["jwt"], allowlist={"paths": ["samples/"]}), reason="Samples", user=ADMIN, asset=KEY)
        applied = sr.for_scan(self.data_dir, KEY)
        self.assertEqual(applied["origins"], {"paths": {"samples/**": "repository"}, "disabled_rules": {"jwt": "defaults"}, "entries": "defaults"})

        def reason(rule, path):
            return sr.withheld({"rule_id": rule, "path": path}, applied)["excluded_reason"]
        self.assertEqual(reason("jwt", "samples/a.py")["params"]["scope"]["$t"], "scanning.secret_rules.withheld.scopes.defaults")
        self.assertEqual(reason("github-pat", "samples/a.py")["params"]["scope"]["$t"], "scanning.secret_rules.withheld.scopes.repository")
        self.assertEqual(reason("github-pat", "app/a.py")["$t"], "scanning.secret_rules.withheld.entry")
