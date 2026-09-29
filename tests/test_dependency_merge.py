"""Dependencies from several engines: one advisory, one finding. With real Trivy and OSV-Scanner output."""

import json
import unittest
from pathlib import Path

from tamandua.modules.scanning.dependency_merge import family, merge_dependencies, package_name
from tamandua.modules.sources.repositories import _analyzable, is_manifest
from tamandua.modules.scanning.engines import parse_osv_scanner, parse_trivy

OUTPUTS = Path(__file__).parent / "engine-outputs"
FEEDS = {"kev": {}, "epss": {}}


class MergeTests(unittest.TestCase):
    def setUp(self):
        self.trivy = [item for item in parse_trivy(json.loads((OUTPUTS / "trivy-deps.json").read_text()), FEEDS) if item["scanner"] == "sca"]
        self.osv = parse_osv_scanner(json.loads((OUTPUTS / "osv-scanner.json").read_text()), FEEDS)

    def test_osv_scanner_groups_aliases_into_one_finding(self):
        starlette = [item for item in self.osv if item["package"]["name"] == "starlette"]
        # OSV reports each advisory under several names (PYSEC and GHSA): one per group, not one per name.
        self.assertEqual(len(starlette), len({item["fingerprint"] for item in starlette}))
        self.assertTrue(all(item["tool"] == "osv-scanner" and item["cve"] for item in starlette))
        newtonsoft = next(item for item in self.osv if item["package"]["name"] == "Newtonsoft.Json")
        self.assertEqual((newtonsoft["path"], newtonsoft["package"]["fixed_version"], newtonsoft["cve"]),
                         ("api/Api.csproj", "13.0.1", ["CVE-2024-21907"]))

    def test_the_same_advisory_from_both_engines_is_one_finding(self):
        merged, stats = merge_dependencies(self.trivy, ("osv-scanner", self.osv))
        keys = [(item["package"]["name"].lower(), item["package"]["version"], min(item["cve"] or [item["rule_id"]])) for item in merged]
        self.assertEqual(len(keys), len(set(keys)), "un mismo aviso sobre el mismo paquete aparece dos veces")
        self.assertEqual(len({item["fingerprint"] for item in merged}), len(merged))
        # What both see stays one Trivy finding (its fingerprint doesn't change) confirmed by OSV-Scanner.
        joined = [item for item in merged if item.get("also_detected_by") == ["osv-scanner"]]
        self.assertEqual(len(joined), stats["joined"])
        self.assertTrue(joined and all(item["tool"] == "trivy" for item in joined))
        self.assertEqual({item["fingerprint"] for item in self.trivy} <= {item["fingerprint"] for item in merged}, True)
        # Trivy doesn't read .csproj: OSV-Scanner covers .NET.
        self.assertIn("Newtonsoft.Json", {item["package"]["name"] for item in merged if item["tool"] == "osv-scanner"})

    def test_merging_twice_does_not_duplicate(self):
        merged, _ = merge_dependencies(self.trivy, ("osv-scanner", self.osv), ("osv-scanner", self.osv))
        once, _ = merge_dependencies(self.trivy, ("osv-scanner", self.osv))
        self.assertEqual(len(merged), len(once))

    def test_names_and_ecosystems_are_normalized(self):
        self.assertEqual({family(name) for name in ("pip", "poetry", "PyPI", "uv", "python")}, {"pypi"})
        self.assertEqual({family(name) for name in ("nuget", "dotnet-core", "NuGet", "packages-props")}, {"nuget"})
        self.assertEqual(package_name("PyPI", "Typing_Extensions"), package_name("pip", "typing-extensions"))


class ManifestTests(unittest.TestCase):
    def test_manifests_enter_the_snapshot_by_name_not_by_size(self):
        for name in ("App.csproj", "Directory.Packages.props", "Pipfile.lock", "uv.lock", "gradle.lockfile", "pubspec.lock",
                     "Package.resolved", "Podfile.lock", "bun.lock", "requirements-dev.txt", "package-lock.json"):
            self.assertTrue(is_manifest(Path(name)) and _analyzable(Path("repo") / name), name)
        self.assertFalse(is_manifest(Path("app.min.js")))

    def test_a_large_lockfile_is_kept_and_large_code_is_not(self):
        import io
        import tarfile
        import tempfile
        from tamandua.modules.sources.repositories import MAX_FILE, _extract_limited
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for name, size in (("repo/web/package-lock.json", MAX_FILE + 10), ("repo/web/app.js", MAX_FILE + 10)):
                data = b"x" * size
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        with tempfile.TemporaryDirectory() as temporary:
            stats = _extract_limited(buffer.getvalue(), Path(temporary))
            self.assertTrue((Path(temporary) / "web" / "package-lock.json").is_file())
            self.assertFalse((Path(temporary) / "web" / "app.js").exists())
        self.assertEqual((stats["files"], stats["skipped_too_large"]), (1, 1))


if __name__ == "__main__":
    unittest.main()
