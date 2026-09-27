import json
import unittest
from pathlib import Path
from unittest.mock import patch

from tamandua.modules.scanning import config_engines as cs
from tamandua.modules.scanning.image import config_findings, parse_reference
from tamandua.modules.scanning.engines import IMAGES, parse_trivy
from tamandua.shared.i18n import text

DATA = Path(__file__).parent / "engine-outputs"


def load(name):
    return json.loads((DATA / name).read_text(encoding="utf-8"))


def repository_findings():
    trivy = [item for item in parse_trivy(load("trivy-iac.json"), {}) if item["scanner"] == "iac"]
    return trivy, cs.parse_checkov(load("checkov-repo.json")), cs.parse_zizmor(load("zizmor.json"))


class EnginesTests(unittest.TestCase):
    def test_new_engines_are_pinned_by_digest(self):
        for key in ("checkov", "zizmor"):
            with self.subTest(engine=key):
                self.assertIn("@sha256:", IMAGES[key]["image"])


class CheckovTests(unittest.TestCase):
    def test_parse_splits_infrastructure_and_pipelines_and_never_keeps_code(self):
        findings = cs.parse_checkov(load("checkov-repo.json"))
        scanners = {item["scanner"] for item in findings}
        self.assertEqual(scanners, {"iac", "cicd"})
        pipeline = next(item for item in findings if item["scanner"] == "cicd")
        self.assertEqual((pipeline["owasp"], pipeline["framework"]), (["A03:2025"], "GitHub Actions"))
        self.assertTrue(all(not item["path"].startswith("/") for item in findings))
        self.assertTrue(all("code_block" not in item for item in findings))

    def test_severity_comes_from_trivy_when_known_and_is_conservative_otherwise(self):
        self.assertEqual(cs.checkov_severity("CKV_AWS_19", "anything"), "high")
        self.assertEqual(cs.checkov_severity("CKV_NEW_1", "Ensure the bucket has tags"), "low")
        self.assertEqual(cs.checkov_severity("CKV_NEW_2", "Ensure the database is not publicly accessible"), "high")
        self.assertEqual(cs.checkov_severity("CKV_NEW_3", "Ensure the thing is configured"), "medium")
        self.assertEqual(cs.checkov_severity("CKV_NEW_4", "Ensure S3 is encrypted by KMS using a customer managed Key"), "low")

    def test_trivy_ids_are_normalized_across_versions(self):
        for raw in ("AVD-AWS-0086", "AWS-0086", "aws-0086"):
            self.assertEqual(cs.trivy_id(raw), "AWS-0086")
        self.assertEqual(cs.trivy_id("KSV001"), "KSV-0001")
        self.assertEqual(cs.trivy_id("CKV_AWS_19"), "CKV_AWS_19")


class MergeTests(unittest.TestCase):
    def test_same_problem_seen_by_trivy_and_checkov_is_one_finding(self):
        trivy, checkov, zizmor = repository_findings()
        merged, stats = cs.merge_repository(trivy, checkov, zizmor)
        self.assertEqual(len(merged), len(trivy) + len(zizmor) + stats["checkov_new"])
        self.assertEqual(stats["joined"] + stats["checkov_new"], len(checkov))
        logging = [item for item in merged if cs.trivy_id(item["rule_id"]) == "AWS-0089"]
        self.assertTrue(logging and all(item["related_rules"] == ["CKV_AWS_18"] for item in logging))
        self.assertTrue(all("checkov" in item["also_detected_by"] for item in logging))
        # Mismo archivo y regla equivalente, pero otro bucket: no es el mismo hallazgo.
        self.assertTrue(any(item["tool"] == "checkov" and item["rule_id"] == "CKV_AWS_18" for item in merged))
        keys = [(item["path"], item["rule_id"], item["line"]) for item in merged]
        self.assertEqual(len(keys), len(set(keys)))

    def test_zizmor_leads_on_github_actions(self):
        trivy, checkov, zizmor = repository_findings()
        merged, _ = cs.merge_repository(trivy, checkov, zizmor)
        self.assertFalse([item for item in merged if item["rule_id"] == "CKV2_GHA_1"])
        permissions = [item for item in merged if item["rule_id"] == "excessive-permissions"]
        self.assertTrue(permissions and all(item["related_rules"] == ["CKV2_GHA_1"] for item in permissions))

    def test_equivalent_rule_in_another_place_is_not_merged(self):
        primary = [{"rule_id": "AWS-0089", "title": "S3 Bucket Logging", "path": "a.tf", "line": 1, "end_line": 10,
                    "tool": "trivy", "confidence": 8}]
        other = [{"rule_id": "CKV_AWS_18", "title": "Ensure the S3 bucket has access logging enabled", "path": "a.tf",
                  "line": 20, "end_line": 30, "tool": "checkov", "confidence": 7},
                 {"rule_id": "CKV_AWS_18", "title": "Ensure the S3 bucket has access logging enabled", "path": "b.tf",
                  "line": 1, "end_line": 10, "tool": "checkov", "confidence": 7}]
        merged, joined = cs.merge_equivalent(primary, other, cs.TRIVY_CHECKOV, normalize=cs.trivy_id)
        self.assertEqual((len(merged), joined), (3, 0))

    def test_similar_titles_merge_when_the_table_does_not_know_the_pair(self):
        primary = [{"rule_id": "AZU-9999", "title": "Ensure RBAC is enabled on AKS clusters", "path": "k.tf", "line": 3,
                    "end_line": 3, "tool": "trivy", "confidence": 8}]
        other = [{"rule_id": "CKV_AZURE_9999", "title": "Ensure that RBAC is enabled on AKS clusters", "path": "k.tf",
                  "line": 1, "end_line": 12, "tool": "checkov", "confidence": 7}]
        merged, joined = cs.merge_equivalent(primary, other, {}, by_title=0.75)
        self.assertEqual((len(merged), joined, merged[0]["also_detected_by"]), (1, 1, ["checkov"]))


class ZizmorTests(unittest.TestCase):
    def test_parse_translates_and_locates(self):
        findings = cs.parse_zizmor(load("zizmor.json"))
        unpinned = next(item for item in findings if item["rule_id"] == "unpinned-uses")
        self.assertEqual(unpinned["severity"], "medium")  # zizmor dice alta; se rebaja un nivel, documentado.
        self.assertEqual(unpinned["scanner"], "cicd")
        self.assertTrue(unpinned["path"].startswith(".github/workflows/"))
        self.assertGreater(unpinned["line"], 1)
        self.assertIn("SHA", text(unpinned["title"]))
        self.assertEqual(len({item["fingerprint"] for item in findings}), len(findings))

    def test_repository_without_workflows_is_not_run(self):
        with patch.object(cs, "unavailable", return_value=None), patch.object(cs, "_run") as run:
            import tempfile
            with tempfile.TemporaryDirectory() as folder:
                result = cs.run_zizmor(Path(folder))
        run.assert_not_called()
        self.assertEqual((result["status"], result["findings"]), ("completed", []))


class ImageTests(unittest.TestCase):
    def test_dockerfile_is_rebuilt_from_both_history_formats(self):
        text, step_of = cs.dockerfile_from_history(load("image-history.json"))
        lines = text.splitlines()
        self.assertEqual(lines[0], "FROM scratch")
        self.assertEqual(lines[1], "COPY rootfs /")  # la capa base no es un ADD del autor
        self.assertIn("RUN curl -k https://example.com/install.sh | sh", lines)
        self.assertIn("RUN pip install --trusted-host pypi.example.com flask", lines)
        self.assertIn("EXPOSE 22/tcp 8080/tcp", lines)
        self.assertEqual(step_of[lines.index("USER root") + 1], 8)

    def test_config_user_and_healthcheck_are_added_when_history_lacks_them(self):
        text, _ = cs.dockerfile_from_history(["RUN /bin/sh -c true # buildkit"], {"User": "101", "Healthcheck": {"Test": ["NONE"]}})
        self.assertIn("USER 101", text)
        self.assertIn("HEALTHCHECK CMD true", text)

    def test_checkov_adds_what_own_rules_miss_and_joins_the_rest(self):
        history = load("image-history.json")
        _, step_of = cs.dockerfile_from_history(history)
        image = parse_reference("ghcr.io/acme/api:1.0")
        checkov = cs.parse_checkov(load("checkov-image.json"), image=image, step_of=step_of)
        metadata = {"ImageConfig": {"config": {"User": "root", "ExposedPorts": {"22/tcp": {}}},
                                    "history": [{"created_by": step} for step in history]}}
        own = config_findings(metadata, image)
        merged, joined = cs.merge_image(own, [], checkov)
        rules = {item["rule_id"] for item in merged}
        self.assertTrue({"IMG-ROOT", "IMG-SSH", "IMG-NO-HEALTHCHECK"} <= rules)
        self.assertFalse(rules & {"CKV_DOCKER_1", "CKV_DOCKER_2", "CKV_DOCKER_8"})  # ya cubiertas por reglas propias
        self.assertTrue({"CKV2_DOCKER_2", "CKV2_DOCKER_4", "CKV2_DOCKER_6"} <= rules)  # curl -k, pip --trusted-host, NODE_TLS
        curl = next(item for item in merged if item["rule_id"] == "CKV2_DOCKER_2")
        self.assertEqual(curl["path"], "image-history/step-5")
        self.assertEqual(joined, 3)
        root = next(item for item in merged if item["rule_id"] == "IMG-ROOT")
        self.assertEqual((root["also_detected_by"], root["related_rules"]), (["checkov"], ["CKV_DOCKER_8"]))


if __name__ == "__main__":
    unittest.main()


class SnapshotDotfilesTests(unittest.TestCase):
    def test_pipelines_enter_the_snapshot_but_credential_files_do_not(self):
        from tamandua.modules.sources.repositories import _safe_name
        for name in ("repo/.github/workflows/ci.yml", "repo/.gitlab-ci.yml", "repo/.circleci/config.yml",
                     "repo/.github/actions/x/action.yml"):
            with self.subTest(name=name):
                self.assertIsNotNone(_safe_name(name))
        for name in ("repo/.git/config", "repo/.idea/workspace.xml", "repo/.cache/x.yml", "repo/.vscode/settings.json",
                     "repo/api/.env", "repo/.npmrc", "repo/.github/.env"):
            with self.subTest(name=name):
                self.assertIsNone(_safe_name(name))


class OpengrepDuplicatesTests(unittest.TestCase):
    def test_same_rule_twice_on_one_line_is_one_finding(self):
        from tamandua.modules.scanning.engines import parse_opengrep
        match = {"check_id": "rules.appsec.js.dom-xss-sink", "path": "/src/app.js", "start": {"line": 9},
                 "extra": {"lines": "a.innerHTML=x;b.innerHTML=y", "severity": "ERROR", "message": "m", "metadata": {}}}
        self.assertEqual(len(parse_opengrep({"results": [match, {**match, "start": {"line": 9, "col": 40}}]})), 1)

    def test_minified_bundles_are_detected_for_sast_exclusion_only(self):
        import tempfile
        from tamandua.modules.scanning.engines import minified_files
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "assets").mkdir()
            (root / "assets" / "index-Ab12.js").write_text("var a=1;" * 2000)
            (root / "app.js").write_text("const a = 1\n" * 50)
            (root / "styles.css").write_text("body { color: red }\n")
            self.assertEqual(minified_files(root), ["assets/index-Ab12.js"])


class EngineUserTests(unittest.TestCase):
    """En Linux, root sin capacidades no entra en las carpetas 0700 de la app: los motores corren con su UID."""

    def test_engines_run_as_the_app_user(self):
        import os
        from tamandua.modules.scanning import engines as scanners
        with patch.object(scanners.subprocess, "run") as run, patch.object(scanners.shutil, "which", return_value="/usr/bin/docker"):
            scanners._run("gitleaks", ["dir", "/src"], Path("/tmp"))
        command = run.call_args.args[0]
        self.assertIn("--cap-drop", command)
        self.assertEqual(command[command.index("--user") + 1], f"{os.getuid()}:{os.getgid()}")
        self.assertIn("HOME=/tmp", command)

    def test_unwritable_cache_falls_back_to_a_fresh_one(self):
        import os
        import tempfile
        from tamandua.modules.scanning.engines import writable_cache
        with tempfile.TemporaryDirectory() as folder:
            cache = Path(folder) / "trivy-cache"
            self.assertEqual(writable_cache(cache), cache)
            with patch.object(os, "access", side_effect=lambda path, mode: Path(path) != cache):
                fallback = writable_cache(cache)
            self.assertNotEqual(fallback, cache)
            self.assertTrue(fallback.is_dir())
