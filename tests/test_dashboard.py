"""Índice de ejecuciones, paginación, cobertura OWASP real y agregados del panel."""

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from tamandua.modules.reporting import dashboard
from tamandua.modules.intel.advisories import _parse_nvd
from tamandua.modules.scanning.coverage import owasp_coverage, rules_by_category
from tamandua.modules.runs.store import list_runs, page_runs, rebuild_index, save_repository_scan


def _finding(fingerprint, severity="high", cwe=(79,), kev=None, epss=None, package="axios"):
    return {"finding_id": fingerprint[:16], "fingerprint": fingerprint, "scanner": "sca", "rule_id": "CVE-2026-1",
            "title": f"{package} vulnerable", "path": "package-lock.json", "line": 1, "severity": severity,
            "confidence": 8, "verdict": "candidate", "cwe": list(cwe), "owasp": ["A03:2025"], "cve": ["CVE-2026-1"],
            "ghsa": [], "package": {"ecosystem": "npm", "name": package, "version": "1.0.0", "fixed_version": "1.0.1", "introduced": None},
            "advisory": None, "kev": kev, "epss": epss, "priority": {"action": "attend", "factors": []},
            "reason": "", "remediation": ""}


def _scan(name, findings, when):
    severities = {level: sum(1 for item in findings if item["severity"] == level) for level in ("critical", "high", "medium", "low", "info")}
    return {"type": "repository_scan", "status": "completed", "source": {"id": f"github:{name}", "name": name, "provider": "github", "sha256": "x"},
            "fixture": name, "variant": "code", "context": "", "steps": [], "findings": findings, "owasp_coverage": [],
            "summary": {"files": 1, "dependencies": 1, "candidates": len(findings), "sast": 0, "secrets": 0, "sca": len(findings),
                        "severities": severities, "priorities": {}, "kev": 0, "fixable": len(findings), "tools": [], "planned": 3, "executed": 3, "confirmed": 0},
            "limitations": [], "scanned_at": when}


class IndexAndPagingTests(unittest.TestCase):
    def test_listing_uses_a_light_index_and_pages_with_filters(self):
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary)
            now = datetime.now(timezone.utc)
            for index in range(30):
                save_repository_scan(data_dir, _scan(f"org/repo-{index % 3}", [_finding(f"f{index}")], now.isoformat()),
                                     created_at=(now - timedelta(minutes=index)).isoformat())
            rows = list_runs(data_dir)
            self.assertEqual(len(rows), 30)
            self.assertTrue((data_dir / "runs" / "index.json").is_file())
            # Las filas del índice no arrastran los hallazgos.
            self.assertNotIn("findings", rows[0])
            page = page_runs(data_dir, limit=10, offset=10, kind="repository_scan")
            self.assertEqual((len(page["items"]), page["total"], page["offset"]), (10, 30, 10))
            self.assertEqual(page_runs(data_dir, query="repo-1")["total"], 10)
            # Si el índice se pierde, se reconstruye desde las carpetas.
            (data_dir / "runs" / "index.json").unlink()
            self.assertEqual(len(rebuild_index(data_dir)), 30)
            self.assertEqual(len(list_runs(data_dir)), 30)


class ConcurrentIndexTests(unittest.TestCase):
    def test_concurrent_writers_do_not_fail_or_lose_rows(self):
        """Antes: temporal con nombre fijo («x») y sin cerrojo → FileExistsError y filas perdidas."""
        import threading
        from tamandua.modules.runs.store import _index_path, update_index, _write_atomic
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary)
            (data_dir / "runs").mkdir()
            # Un temporal huérfano de un corte no bloquea nada.
            (data_dir / "runs" / "index.json.tmp").write_text("basura")
            errors = []

            def writer(start):
                try:
                    for offset in range(25):
                        update_index(data_dir, {"id": f"r{start + offset}", "type": "repository_scan", "status": "completed",
                                                "created_at": "2026-09-26T00:00:00+00:00"})
                except Exception as exc:  # noqa: BLE001 — cualquier fallo cuenta
                    errors.append(exc)
            threads = [threading.Thread(target=writer, args=(block * 100,)) for block in range(4)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(errors, [])
            self.assertEqual(len(json.loads(_index_path(data_dir).read_text())), 100)
            _write_atomic(data_dir / "x.json", "{}")
            self.assertEqual([path.name for path in data_dir.iterdir() if path.name.endswith(".tmp") and path.name != "index.json.tmp"], [])


class CoverageTests(unittest.TestCase):
    def test_rules_declare_their_owasp_category(self):
        counts = rules_by_category()
        self.assertGreaterEqual(counts.get("A05", 0), 20)
        self.assertGreaterEqual(sum(counts.values()), 50)

    def test_coverage_reflects_what_ran_with_numbers_and_reasons(self):
        findings = [_finding("a", severity="high"), {**_finding("b"), "owasp": ["A05:2025"], "scanner": "sast"}]
        rows = {item["id"]: item for item in owasp_coverage(findings, sast_ran=True, sca_status="partial", iac_ran=True,
                                                           iac_files=0, secrets_ran=True, engines=True)}
        self.assertEqual(rows["A03"]["status"], "partial")
        self.assertIn("Trivy", rows["A03"]["reason"])
        self.assertIn("1 hallazgo", rows["A03"]["reason"])
        self.assertEqual(rows["A05"]["status"], "partial")
        self.assertIn("reglas propias", rows["A05"]["reason"])
        self.assertEqual(rows["A05"]["findings"], 1)
        # Sin archivos de infraestructura, A02 lo dice en vez de fingir cobertura.
        self.assertIn("no encontró archivos de infraestructura", rows["A02"]["reason"])
        # Lo que un análisis estático no cubre se declara con su motivo concreto.
        self.assertEqual(rows["A06"]["status"], "not_tested")
        self.assertIn("modelado de amenazas", rows["A06"]["reason"])
        without = {item["id"]: item for item in owasp_coverage([], sast_ran=False, sca_status="not_tested", iac_ran=False,
                                                              iac_files=0, secrets_ran=True, engines=False)}
        self.assertEqual(without["A03"]["status"], "not_tested")
        self.assertIn("reglas AST internas", without["A05"]["reason"])


class DashboardTests(unittest.TestCase):
    def test_open_fixed_mttr_and_exploitability_come_from_consecutive_runs(self):
        with tempfile.TemporaryDirectory() as temporary, \
                patch("tamandua.modules.reporting.dashboard.load_feeds", return_value={"kev": {"__meta__": {"version": "2026.09.22"}, "CVE-2026-1": {"date_added": "2026-09-20", "ransomware": True, "name": "Prueba"}}}), \
                patch("tamandua.modules.reporting.dashboard.load_recent_cves", return_value={"__meta__": {"total": 3}, "items": [{"cve": "CVE-2026-9", "published": "2026-09-23T00:00:00", "score": 9.8, "severity": "critical", "description": "axios does something bad"}]}):
            data_dir = Path(temporary)
            (data_dir / "feeds").mkdir(parents=True)
            now = datetime.now(timezone.utc)
            first = now - timedelta(days=5)
            second = now - timedelta(days=1)
            kev = {"date_added": "2026-09-20", "ransomware": True}
            save_repository_scan(data_dir, _scan("org/app", [_finding("keep", "critical", kev=kev), _finding("gone", "medium"), _finding("low", "low")], first.isoformat()), created_at=first.isoformat())
            save_repository_scan(data_dir, _scan("org/app", [_finding("keep", "critical", kev=kev), _finding("new", "high", epss={"score": 0.42, "percentile": 0.99})], second.isoformat()), created_at=second.isoformat())
            result = dashboard.compute(data_dir, 30)
        kpis = result["kpis"]
        # Abierto = última ejecución del activo; corregido = huella que desapareció.
        self.assertEqual(kpis["open"]["total"], 2)
        self.assertEqual(kpis["open"]["critical"], 1)
        self.assertEqual(kpis["fixed_in_window"], 2)
        self.assertEqual(kpis["found_in_window"], 4)
        self.assertEqual(kpis["fix_rate"], 50.0)
        self.assertAlmostEqual(kpis["mttr_days"], 4.0, delta=0.1)
        self.assertEqual(kpis["kev_open"], 1)
        # riesgo = 8·1 crítico + 3·1 alto + 15·1 KEV + 5·1 EPSS alto = 31 → 100·e^(−31/150)
        self.assertEqual(kpis["security_score"]["value"], 81.3)
        self.assertEqual(kpis["security_score"]["risk"], 31.0)
        self.assertIn("e^", kpis["security_score"]["formula"])
        self.assertEqual(result["cve_news"]["published_7d"], 3)
        self.assertEqual(result["top_assets"][0]["name"], "org/app")
        self.assertEqual(result["top_assets"][0]["trend"], -1)
        self.assertEqual(result["by_cwe"][0]["cwe"], 79)
        self.assertEqual(len(result["exploitability"]["kev"]), 1)
        self.assertEqual(result["exploitability"]["high_epss"][0]["epss"], 0.42)
        self.assertTrue(result["kev_news"]["items"][0]["affects"])
        self.assertTrue(result["cve_news"]["items"][0]["affects"], "menciona un paquete abierto (axios)")
        self.assertEqual(len(result["activity"]), 365)
        self.assertEqual(sum(day["runs"] for day in result["activity"]), 2)

    def test_days_are_counted_in_the_viewer_timezone_and_cached(self):
        """«Hoy» es el de quien mira: en Bogotá, un análisis a las 21:00 del 25 cuenta el 25, no el 26 (UTC)."""
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary)
            evening = datetime(2026, 9, 26, 2, 0, tzinfo=timezone.utc)  # 21:00 del 25 en Bogotá
            save_repository_scan(data_dir, _scan("org/app", [], evening.isoformat()), created_at=evening.isoformat())
            bogota = dashboard.zone("America/Bogota")
            with patch.object(dashboard, "datetime", wraps=datetime) as clock:
                clock.now = lambda tz=None: datetime(2026, 9, 26, 3, 0, tzinfo=timezone.utc).astimezone(tz) if tz else datetime(2026, 9, 26, 3, 0)
                local = {row["day"]: row["runs"] for row in dashboard.compute(data_dir, 30, bogota)["activity"] if row["runs"]}
                utc = {row["day"]: row["runs"] for row in dashboard.compute(data_dir, 30)["activity"] if row["runs"]}
            self.assertEqual((local, utc), ({"2026-09-25": 1}, {"2026-09-26": 1}))
            for bad in ("../../etc/passwd", "Nada/Inventado", "", None, "x" * 80):
                self.assertIs(dashboard.zone(bad), timezone.utc)
            first = dashboard.cached(data_dir, 30, bogota)
            self.assertIs(dashboard.cached(data_dir, 30, bogota), first)  # sin cambios: no recalcula
            save_repository_scan(data_dir, _scan("org/otra", [], evening.isoformat()))
            self.assertIsNot(dashboard.cached(data_dir, 30, bogota), first)  # una ejecución nueva invalida

    def test_nvd_feed_parses_scores_and_descriptions(self):
        body = json.dumps({"totalResults": 1, "timestamp": "2026-09-23T00:00:00", "vulnerabilities": [{"cve": {
            "id": "CVE-2026-777", "published": "2026-09-22T10:00:00.000",
            "descriptions": [{"lang": "es", "value": "no"}, {"lang": "en", "value": "Something bad in tar plugin"}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]}}}]}).encode()
        parsed = _parse_nvd(body)
        self.assertEqual(parsed["__meta__"]["total"], 1)
        self.assertEqual(parsed["items"][0], {"cve": "CVE-2026-777", "published": "2026-09-22T10:00:00.000", "score": 7.5,
                                              "severity": "high", "description": "Something bad in tar plugin"})


if __name__ == "__main__":
    unittest.main()


class NvdRefreshTests(unittest.TestCase):
    def test_refresh_asks_for_the_newest_page_and_counts(self):
        import tempfile
        from tamandua.modules.intel import advisories
        calls = []

        def fetch(params):
            calls.append(params)
            if params["resultsPerPage"] == 1:
                return json.dumps({"totalResults": 3381 if "startIndex" not in params else 0}).encode()
            return json.dumps({"totalResults": 3381, "vulnerabilities": [
                {"cve": {"id": "CVE-2026-2", "published": "2026-09-23T10:00:00", "descriptions": [{"lang": "en", "value": "b"}]}},
                {"cve": {"id": "CVE-2026-1", "published": "2026-09-22T10:00:00", "descriptions": [{"lang": "en", "value": "a"}]}}]}).encode()

        with tempfile.TemporaryDirectory() as directory:
            advisories.refresh_recent_cves(Path(directory), pause=0, fetch=fetch)
            page = calls[-1]
            self.assertEqual((page["resultsPerPage"], page["startIndex"]), (2000, 3381 - 2000))
            self.assertEqual(len([call for call in calls if call["resultsPerPage"] == 1]), 9)  # 7 días, 30 días y 7 por día
            with patch("tamandua.modules.intel.advisories._refresh_in_background"):
                advisories._feed_cache.pop("nvd-recent", None)
                recent = advisories.load_recent_cves(Path(directory))
            self.assertEqual(recent["items"][0]["cve"], "CVE-2026-2")
            self.assertEqual((recent["__meta__"]["total_7d"], len(recent["__meta__"]["per_day"])), (3381, 7))
