"""Identidad estable de los repositorios: renombrados agrupados, retirados borrados tras el margen."""

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from appsec_agent import assets, pr_watch, triage
from appsec_agent.store import list_runs, page_runs, save_repository_scan
from test_dashboard import _finding, _scan


def scan(name, uid, findings, when):
    record = _scan(name, findings, when)
    record["source"].update(uid=uid)
    return record


class AssetTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.directory.name)
        now = datetime.now(timezone.utc)
        self.old = save_repository_scan(self.data_dir, scan("org/viejo", "github#7", [_finding("a" * 64)], now.isoformat()),
                                        created_at=(now - timedelta(days=2)).isoformat())
        self.new = save_repository_scan(self.data_dir, scan("org/nuevo", "github#7", [_finding("a" * 64), _finding("b" * 64, "critical")], now.isoformat()))

    def tearDown(self):
        self.directory.cleanup()

    def test_rename_keeps_one_asset_and_its_decisions(self):
        triage.decide(self.data_dir, self.old, ["a" * 64], "false_positive", reason="Dato de ejemplo en un test", user={"username": "ana", "role": "member"})
        rows = assets.overview(self.data_dir)
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["name"], rows[0]["scans"], rows[0]["open"]["total"], rows[0]["open"]["critical"]), ("org/nuevo", 2, 1, 1))
        self.assertEqual(page_runs(self.data_dir, asset="github#7")["total"], 2)

    def test_removed_repository_is_purged_after_grace(self):
        now = datetime.now(timezone.utc)
        pr_watch.configure(self.data_dir, "github#7", enabled=True, by="ana")
        first = assets.reconcile(self.data_dir, [], now=now)
        self.assertEqual((first["marked"], first["purged"]), (["github#7"], []))
        self.assertEqual(len(list_runs(self.data_dir)), 2)          # dentro del margen no se toca nada
        self.assertIsNotNone(assets.overview(self.data_dir)[0]["removed_at"])
        back = assets.reconcile(self.data_dir, [{"uid": "github#7", "id": "github:org/nuevo", "name": "org/nuevo"}], now=now)
        self.assertEqual(back["marked"], [])                          # volvió: se desmarca
        assets.reconcile(self.data_dir, [], now=now)
        gone = assets.reconcile(self.data_dir, [], now=now + timedelta(hours=25))
        self.assertEqual(gone["purged"], ["github#7"])
        self.assertEqual(list_runs(self.data_dir), [])
        self.assertNotIn("github#7", pr_watch.load(self.data_dir)["repositories"])

    def test_backfill_gives_old_runs_their_stable_identity(self):
        legacy = _scan("org/legado", [_finding("c" * 64)], datetime.now(timezone.utc).isoformat())
        record = save_repository_scan(self.data_dir, legacy)
        triage.decide(self.data_dir, record, ["c" * 64], "in_progress", user={"username": "ana", "role": "member"})
        self.assertIn("github:org/legado", triage.load(self.data_dir))
        assets.backfill(self.data_dir, [{"id": "github:org/legado", "uid": "github#9", "name": "org/legado"}])
        self.assertIn("github#9", {row["key"] for row in assets.overview(self.data_dir)})
        self.assertEqual(set(triage.load(self.data_dir)), {"github#9"})


if __name__ == "__main__":
    unittest.main()
