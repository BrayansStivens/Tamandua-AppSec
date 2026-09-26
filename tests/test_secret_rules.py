"""Organization secret detection settings: validation, generated engine configs, engine wiring and who may change them."""

import json
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch

from tamandua.modules.identity.auth import Users
from tamandua.modules.scanning import engines
from tamandua.modules.scanning import secret_rules as sr
from tamandua.shared.i18n import text
from test_auth import ORIGIN, PASSWORD, HttpCase

ADMIN = {"username": "operadora", "role": "admin"}
RULE = {"id": "acme-token", "description": "ACME internal token", "regex": r"ACME-TOKEN-[0-9a-f]{32}",
        "keywords": ["ACME-TOKEN"], "severity": "critical"}


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

    def test_limits_ids_and_severity(self):
        self.assert_rejected(settings(rules=[{**RULE, "id": f"r{index}"} for index in range(sr.MAX_RULES + 1)]), "rules")
        self.assert_rejected(settings(allowlist={"regexes": [f"x{index}" for index in range(101)]}), "allowlist.regexes")
        self.assert_rejected(settings(rules=[{**RULE, "regex": "a" * 501}]), "rules.0.regex")
        for bad in ("Acme", "acme_token", "", "a" * 61, "acme token"):
            with self.subTest(id=bad):
                self.assert_rejected(settings(rules=[{**RULE, "id": bad}]), "rules.0.id")
        self.assert_rejected(settings(rules=[RULE, RULE]), "rules.1.id")
        self.assert_rejected(settings(rules=[{**RULE, "severity": "info"}]), "rules.0.severity")
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
                rule = {"id": "acme-token", "description": description, "regex": r"KEY='[A-Z]{10}'\\d", "keywords": [], "severity": "low"}
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
        self.assertEqual(again["title"], "Other text")

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


if __name__ == "__main__":
    unittest.main()
