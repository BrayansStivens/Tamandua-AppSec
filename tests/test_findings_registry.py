"""Ciclo de vida de los hallazgos: abiertos, remediados solos, reabiertos, PRs y remediación manual."""

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from tamandua.modules.findings import registry
from tamandua.modules.findings import triage
from tamandua.modules.runs import registry as run_registry
from tamandua.modules.runs.store import save_repository_scan
from test_dashboard import _finding, _scan
from tamandua.shared.i18n import text

KEY = "github#7"
A, B, C = "a" * 64, "b" * 64, "c" * 64
USER = {"username": "ana", "role": "member"}


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.directory.name)
        self.clock = datetime.now(timezone.utc)

    def tearDown(self):
        self.directory.cleanup()

    def run_(self, findings, *, pr=None, head="1" * 40, status="completed"):
        self.clock += timedelta(hours=1)
        record = {**_scan("org/api", findings, self.clock.isoformat()), "status": status}
        record["source"]["uid"] = KEY
        record["finished_at"] = self.clock.isoformat()
        if pr:
            record.update(type="pr_review", pull_request={"number": pr, "head_sha": head, "head_ref": "feat"})
        return save_repository_scan(self.data_dir, record, created_at=self.clock.isoformat())

    def status(self):
        return {digest: entry["status"] for digest, entry in registry.load(self.data_dir, KEY)["findings"].items()}

    def test_full_scans_open_fix_and_reopen(self):
        self.run_([_finding(A), _finding(B)])
        self.run_([_finding(A)])
        self.assertEqual(self.status(), {A: "open", B: "fixed"})
        fixed = registry.load(self.data_dir, KEY)["findings"][B]["fixed"]
        self.assertTrue(fixed["auto"] and "escaneo completo" in text(fixed["how"]))
        self.run_([_finding(A), _finding(B)])
        self.assertEqual(self.status(), {A: "open", B: "open"})
        self.assertEqual(registry.summarize(self.data_dir, KEY)["open"], 2)

    def test_an_incomplete_scan_never_fixes_anything(self):
        """Si un motor no corrió (Docker, imágenes, red), no aparecer no prueba que se corrigió."""
        self.run_([_finding(A), _finding(B)])
        self.run_([], status="incomplete")
        self.assertEqual(self.status(), {A: "open", B: "open"})
        # Lo que sí ve un escaneo incompleto se abre igual.
        C = "c" * 64
        self.run_([_finding(C)], status="incomplete")
        self.assertEqual(self.status(), {A: "open", B: "open", C: "open"})
        # El siguiente escaneo completo sí remedia lo que ya no está.
        self.run_([_finding(A)])
        self.assertEqual(self.status(), {A: "open", B: "fixed", C: "fixed"})

    def test_the_dashboard_ignores_incomplete_scans(self):
        from tamandua.modules.reporting import dashboard
        self.run_([_finding(A), _finding(B)])
        self.run_([], status="incomplete")
        data = dashboard.compute(self.data_dir)
        asset = next(row for row in data["top_assets"] if row["name"] == "org/api")
        self.assertEqual(asset["open"], 2)

    def test_pull_request_findings_live_and_die_with_the_pr(self):
        self.run_([_finding(A)])
        self.run_([_finding(C)], pr=4)
        entry = registry.load(self.data_dir, KEY)["findings"][C]
        self.assertEqual((entry["status"], entry["origin"]["kind"], entry["origin"]["pr"]), ("open", "pr", 4))
        self.run_([_finding(A)])                   # un escaneo de main no borra lo que vive en la rama del PR
        self.assertEqual(self.status()[C], "open")
        self.run_([], pr=4, head="2" * 40)         # nuevo commit del PR sin el hallazgo
        self.assertEqual(self.status()[C], "fixed")
        self.assertIn("2222222", text(registry.load(self.data_dir, KEY)["findings"][C]["fixed"]["how"]))

    def test_closed_and_merged_pull_requests(self):
        self.run_([_finding(B)], pr=5)
        self.run_([_finding(C)], pr=6)
        registry.pull_closed(self.data_dir, KEY, 5, merged=False, when="2026-09-02")
        registry.pull_closed(self.data_dir, KEY, 6, merged=True, when="2026-09-02")
        self.assertEqual(self.status(), {B: "fixed", C: "open"})
        self.run_([])                              # el escaneo de main tras el merge ya no lo ve
        self.assertEqual(self.status()[C], "fixed")

    def test_manual_fix_needs_a_reason_and_reopens_if_it_comes_back(self):
        self.run_([_finding(A)])
        state = registry.view(self.data_dir, KEY, status="all")
        with self.assertRaises(triage.TriageError):
            triage.decide(self.data_dir, state, [A], "fixed", reason="", user=USER)
        triage.decide(self.data_dir, state, [A], "fixed", reason="Parche aplicado en producción, pendiente de desplegar", user=USER)
        self.assertEqual([item["fingerprint"] for item in registry.view(self.data_dir, KEY, status="fixed")["findings"]], [A])
        self.assertEqual(registry.view(self.data_dir, KEY, status="open")["findings"], [])
        self.run_([_finding(A)])                   # vuelve a salir: no estaba remediado
        self.assertEqual(triage.effective(triage.load(self.data_dir)[KEY][A])["status"], "open")
        self.assertEqual(len(registry.view(self.data_dir, KEY, status="open")["findings"]), 1)

    def test_rebuild_matches_incremental(self):
        self.run_([_finding(A), _finding(B)])
        self.run_([_finding(A)])
        before = self.status()
        run_registry.rebuild(self.data_dir)
        self.assertEqual(self.status(), before)


if __name__ == "__main__":
    unittest.main()
