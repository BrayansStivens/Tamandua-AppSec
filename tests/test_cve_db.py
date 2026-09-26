import json
import tempfile
import unittest
from unittest.mock import patch
from datetime import datetime, timedelta, timezone
from pathlib import Path

from tamandua.modules.intel import cve_db
from tamandua.modules.intel import euvd
from tamandua.modules.findings import registry as findings_registry
from tamandua.modules.findings import triage
from tamandua.modules.identity.auth import Users

from tests.test_auth import PASSWORD, HttpCase

NOW = datetime(2026, 9, 20, 12, 0, tzinfo=timezone.utc)


def nvd_entry(identifier, published, *, score=9.8, severity="CRITICAL", description="Remote code execution in parser", status="Analyzed"):
    return {"cve": {"id": identifier, "published": published, "lastModified": published, "vulnStatus": status,
                    "descriptions": [{"lang": "en", "value": description}, {"lang": "es", "value": "otra"}],
                    "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": score, "baseSeverity": severity,
                                                                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]},
                    "weaknesses": [{"description": [{"value": "CWE-502"}, {"value": "NVD-CWE-Other"}]}],
                    "references": [{"url": "https://example.test/advisory", "tags": ["Vendor Advisory"]}, {"url": "javascript:alert(1)"}]}}


class FakeNvd:
    """NVD de mentira: 2500 CVE en orden ascendente, paginados como la API real."""

    def __init__(self, total=2500):
        self.entries = [nvd_entry(f"CVE-2026-{index:05d}", (NOW - timedelta(days=total - index)).strftime("%Y-%m-%dT%H:%M:%S.000"),
                                  score=[9.8, 7.5, 5.0, 2.1][index % 4], severity=["CRITICAL", "HIGH", "MEDIUM", "LOW"][index % 4],
                                  description=f"Bug {index} in {'log4j' if index % 10 == 0 else 'parser'}")
                        for index in range(total)]
        self.calls = []

    def __call__(self, params):
        self.calls.append(params)
        if "lastModStartDate" in params:
            return {"totalResults": 1, "vulnerabilities": [nvd_entry("CVE-2026-00001", "2024-01-01T00:00:00.000", description="Updated text")]}
        start, size = params.get("startIndex", 0), params["resultsPerPage"]
        return {"totalResults": len(self.entries), "vulnerabilities": self.entries[start:start + size]}


class CveDbTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.directory.name)

    def tearDown(self):
        self.directory.cleanup()

    def sync_all(self, fake):
        steps = []
        while (step := cve_db.sync_step(self.data_dir, fetch=fake, now=NOW)) == "backfill":
            steps.append(step)
        return steps

    def test_backfill_goes_newest_first_and_resumes(self):
        fake = FakeNvd()
        cve_db.sync_step(self.data_dir, fetch=fake, now=NOW)  # total
        cve_db.sync_step(self.data_dir, fetch=fake, now=NOW)  # primera página: la más reciente
        self.assertEqual(fake.calls[1]["startIndex"], 2000)
        overview = cve_db.overview(self.data_dir, now=NOW)
        self.assertEqual((overview["count"], overview["sync"]["phase"]), (500, "backfill"))
        # Tras un reinicio se sigue por donde iba, sin volver a pedir el total.
        self.sync_all(fake)
        self.assertEqual([call.get("startIndex") for call in fake.calls[2:]], [1000, 0])
        overview = cve_db.overview(self.data_dir, now=NOW)
        self.assertEqual((overview["count"], overview["sync"]["phase"], overview["sync"]["progress"]), (2500, "ready", 1.0))

    def test_search_filters_paginate_and_rank(self):
        self.sync_all(FakeNvd())
        page = cve_db.search(self.data_dir, limit=10)
        self.assertEqual((page["total"], len(page["items"])), (2500, 10))
        self.assertEqual(page["items"][0]["id"], "CVE-2026-02499")  # lo más reciente primero
        self.assertEqual(cve_db.search(self.data_dir, query="log4j")["total"], 250)
        self.assertEqual(cve_db.search(self.data_dir, query="cve-2026-0249")["total"], 10)
        self.assertEqual(cve_db.search(self.data_dir, severity="critical")["total"], 625)
        self.assertEqual(cve_db.search(self.data_dir, year=2025)["total"], 0)
        self.assertEqual(cve_db.search(self.data_dir, sort="score", limit=1)["items"][0]["score"], 9.8)
        # Texto hostil para FTS5: se sanea a palabras, no rompe la consulta ni inyecta operadores.
        self.assertEqual(cve_db.search(self.data_dir, query='parser" *')["total"], 2250)
        self.assertEqual(cve_db.search(self.data_dir, query='log4j" OR id:* NEAR(')["total"], 0)  # todas las palabras, literales
        self.assertEqual(cve_db.search(self.data_dir, query="%_%")["total"], 2500)

    def test_kev_epss_rejected_and_detail(self):
        self.sync_all(FakeNvd(total=20))
        connection = cve_db.connect(self.data_dir)
        with connection:
            cve_db.upsert(connection, [nvd_entry("CVE-2026-09999", "2026-09-19T00:00:00.000", status="Rejected")])
        connection.close()
        cve_db.load_signals(self.data_dir, {"kev": {"__meta__": {"version": "1"}, "CVE-2026-00003": {"date_added": "2026-09-01", "ransomware": True, "name": "Parser RCE"}},
                                            "epss": {"__meta__": {"header": "v"}, "CVE-2026-00003": (0.91, 0.99), "CVE-2026-00004": (0.2, 0.5)}})
        self.assertEqual(cve_db.search(self.data_dir)["total"], 20)  # los rechazados no cuentan
        kev = cve_db.search(self.data_dir, kev=True)
        self.assertEqual([item["id"] for item in kev["items"]], ["CVE-2026-00003"])
        self.assertEqual(cve_db.search(self.data_dir, sort="epss", limit=1)["items"][0]["id"], "CVE-2026-00003")
        item = cve_db.detail(self.data_dir, "CVE-2026-00003")
        self.assertEqual((item["cwe"], item["kev_detail"]["ransomware"], item["epss"]), (["CWE-502"], True, 0.91))
        self.assertEqual([reference["url"] for reference in item["references"]], ["https://example.test/advisory"])
        self.assertEqual(cve_db.overview(self.data_dir, now=NOW)["latest_kev"][0]["id"], "CVE-2026-00003")

    def test_incremental_after_backfill(self):
        fake = FakeNvd(total=5)
        self.sync_all(fake)
        self.assertEqual(cve_db.sync_step(self.data_dir, fetch=fake, now=NOW), "idle")
        later = NOW + timedelta(hours=3)
        self.assertEqual(cve_db.sync_step(self.data_dir, fetch=fake, now=later), "incremental")
        self.assertIn("lastModStartDate", fake.calls[-1])
        self.assertEqual(cve_db.detail(self.data_dir, "CVE-2026-00001")["description"], "Updated text")
        self.assertEqual(cve_db.sync_step(self.data_dir, fetch=fake, now=later), "idle")


class CveRoutesTests(HttpCase):
    def setUp(self):
        super().setUp()
        # Las pruebas no salen a la red: EUVD responde desde aquí.
        self.europe = {"CVE-2026-12345": {"items": [{"id": "EUVD-2026-1", "aliases": "CVE-2026-12345\n", "baseScore": 8.1,
                                                     "baseScoreVersion": "3.1", "exploitedSince": "Sep 1, 2026, 12:00:00 AM"}]}}
        fake = patch("tamandua.modules.intel.euvd._fetch", side_effect=lambda cve: euvd.parse(self.europe.get(cve, {}), cve))
        fake.start()
        self.addCleanup(fake.stop)
        Users(self.data_dir).create("analista", PASSWORD)
        _, _, cookies = self.post("/api/auth/login", "login", {"username": "analista", "password": PASSWORD})
        self.cookie = {"Cookie": cookies[0].split("; ")[0]}
        connection = cve_db.connect(self.data_dir)
        with connection:
            cve_db.upsert(connection, [nvd_entry("CVE-2026-12345", "2026-09-19T00:00:00.000")])
        connection.close()

    def test_requires_session_and_validates(self):
        self.assertEqual(self.call("GET", "/api/cve-db")[0], 401)
        status, body, _ = self.call("GET", "/api/cve-db?q=parser&severity=critical&limit=10", headers=self.cookie)
        self.assertEqual((status, body["total"]), (200, 1))
        for bad in ("severity=urgent", "sort=id;drop", "limit=500", "offset=999999", "year=1200", "q=" + "a" * 101, "limit=x"):
            self.assertEqual(self.call("GET", f"/api/cve-db?{bad}", headers=self.cookie)[0], 400, bad)
        self.assertEqual(self.call("GET", "/api/cve-db/item?id=../../etc", headers=self.cookie)[0], 400)
        self.assertEqual(self.call("GET", "/api/cve-db/item?id=CVE-2020-0001", headers=self.cookie)[0], 404)

    def test_item_says_which_repositories_it_affects(self):
        findings_registry._save(self.data_dir, {"asset": "github#1", "name": "acme/web", "findings": {
            "abc": {"status": "open", "finding": {"cve": ["CVE-2026-12345"], "package": {"name": "fastjson"}}}}})
        status, body, _ = self.call("GET", "/api/cve-db/item?id=cve-2026-12345", headers=self.cookie)
        self.assertEqual(status, 200)
        self.assertEqual(body["affected"], [{"asset": "github#1", "name": "acme/web", "open": 1, "fixed": 0, "packages": ["fastjson"]}])
        # NVD lo puntúa: EUVD solo añade que se explota; la puntuación sigue siendo la de NVD.
        self.assertEqual((body["score_source"], body["score"], body["euvd"]["exploited_since"]), ("nvd", 9.8, "2026-09-01"))
        status, body, _ = self.call("GET", "/api/cve-db/overview", headers=self.cookie)
        self.assertEqual((status, body["count"], body["sync"]["phase"]), (200, 1, "pending"))
        self.assertNotIn("nvd_api_key", json.dumps(body).lower())

    def test_only_mine_filters_to_open_cves_in_my_assets(self):
        connection = cve_db.connect(self.data_dir)
        with connection:
            cve_db.upsert(connection, [nvd_entry("CVE-2026-20001", "2026-09-18T00:00:00.000"), nvd_entry("CVE-2026-20002", "2026-09-17T00:00:00.000"),
                                       nvd_entry("CVE-2026-20003", "2026-09-16T00:00:00.000")])
        connection.close()
        findings_registry._save(self.data_dir, {"asset": "github#1", "name": "acme/web", "findings": {
            "a": {"status": "open", "finding": {"cve": ["CVE-2026-12345"]}},
            "b": {"status": "fixed", "finding": {"cve": ["CVE-2026-20001"]}},  # remediado: ya no es tuyo
            "c": {"status": "open", "finding": {"cve": ["CVE-2026-20002"]}},  # descartado en triage abajo
            "d": {"status": "open", "finding": {"cve": ["CVE-2026-99999"]}}}})  # aún no está en la copia local
        triage._save_asset(self.data_dir, "github#1", {"c": {"status": "false_positive", "reason": "x"}})
        status, body, _ = self.call("GET", "/api/cve-db?mine=1", headers=self.cookie)
        self.assertEqual((status, [item["id"] for item in body["items"]], body["mine_total"]), (200, ["CVE-2026-12345"], 2))
        _, body, _ = self.call("GET", "/api/cve-db", headers=self.cookie)
        self.assertEqual({item["id"]: item["affects"] for item in body["items"]},
                         {"CVE-2026-12345": True, "CVE-2026-20001": False, "CVE-2026-20002": False, "CVE-2026-20003": False})
        # La caché se invalida al cambiar el registro.
        findings_registry._save(self.data_dir, {"asset": "github#2", "name": "acme/api", "findings": {
            "e": {"status": "open", "finding": {"cve": ["CVE-2026-20003"]}}}})
        _, body, _ = self.call("GET", "/api/cve-db?mine=1&sort=score", headers=self.cookie)
        self.assertEqual({item["id"] for item in body["items"]}, {"CVE-2026-12345", "CVE-2026-20003"})


if __name__ == "__main__":
    unittest.main()
