"""Pull request watch and repository registry in tables: each change writes its own rows, never the whole state."""

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import select

from tamandua.modules.pullrequests import watch
from tamandua.modules.sources import assets
from tamandua.modules.sources.tables import repo_registry
from tamandua.shared import db


class WatchStorageTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data_dir = Path(self.directory.name)

    def test_reviews_are_marked_closed_and_counted(self):
        watch.mark(self.data_dir, "github#1", 4, "a" * 40, "1" * 32)
        watch.mark(self.data_dir, "github#1", 5, "b" * 40, "2" * 32)
        watch.mark_closed(self.data_dir, "github#1", 4)
        self.assertEqual(watch.reviewed(self.data_dir, "github#1")["4"], {"head_sha": "a" * 40, "run_id": "1" * 32, "closed": True})
        watch.mark(self.data_dir, "github#1", 4, "c" * 40, "3" * 32)  # a new commit reopens the review
        self.assertNotIn("closed", watch.reviewed(self.data_dir, "github#1")["4"])
        self.assertEqual(watch.review_counts(self.data_dir, ["github#1", "github#2"]), {"github#1": 2})
        self.assertEqual(watch.load(self.data_dir, reviews=False)["reviewed"], {})

    def test_settings_saved_by_name_move_to_the_stable_key_and_what_it_holds_wins(self):
        watch.configure(self.data_dir, "github:org/api", enabled=True, by="ana")
        watch.mark(self.data_dir, "github:org/api", 1, "a" * 40, "1" * 32)
        watch.mark(self.data_dir, "github:org/api", 2, "b" * 40, "2" * 32)
        watch.configure(self.data_dir, "github#1", gate="critical", by="ana")
        watch.mark(self.data_dir, "github#1", 2, "c" * 40, "3" * 32)
        watch.migrate(self.data_dir, [{"id": "github:org/api", "uid": "github#1"}])
        state = watch.load(self.data_dir)
        self.assertEqual(set(state["repositories"]), {"github#1"})
        self.assertEqual((state["repositories"]["github#1"]["gate"], state["repositories"]["github#1"]["enabled"]), ("critical", False))
        self.assertEqual({number: review["head_sha"] for number, review in state["reviewed"]["github#1"].items()},
                         {"1": "a" * 40, "2": "c" * 40})
        self.assertNotIn("github:org/api", state["reviewed"])

    def test_forget_removes_settings_heads_and_reviews(self):
        watch.configure(self.data_dir, "github#1", enabled=True, by="ana")
        watch.mark_branch(self.data_dir, "github#1", "a" * 40, "1" * 32, "main")
        watch.mark(self.data_dir, "github#1", 1, "a" * 40, "1" * 32)
        watch.forget(self.data_dir, "github#1")
        self.assertEqual(watch.load(self.data_dir), {"repositories": {}, "reviewed": {}, "branches": {}})


class RegistryStorageTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data_dir = Path(self.directory.name)

    def written(self) -> dict:
        with db.transaction(self.data_dir) as connection:
            return dict(connection.execute(select(repo_registry.c.uid, repo_registry.c.updated_at)).all())

    def test_a_reconciliation_writes_only_the_repositories_that_changed(self):
        now = datetime(2026, 9, 27, 10, tzinfo=timezone.utc)
        listing = [{"uid": "github#1", "id": "github:org/api", "name": "org/api"}, {"uid": "github#2", "id": "github:org/web", "name": "org/web"}]
        assets.retire(self.data_dir, listing, {"github#1": "org/api", "github#2": "org/web"}, now=now)
        first = self.written()
        assets.retire(self.data_dir, listing, {}, now=now + timedelta(hours=1))  # same day, nothing new
        self.assertEqual(self.written(), first)
        renamed = [{**listing[0], "name": "org/api-v2"}, listing[1]]
        assets.retire(self.data_dir, renamed, {}, now=now + timedelta(hours=2))
        changed = {uid for uid, stamp in self.written().items() if stamp != first[uid]}
        self.assertEqual(changed, {"github#1"})
        self.assertEqual(assets.load_registry(self.data_dir)["github#1"]["name"], "org/api-v2")

    def test_a_repository_gone_past_the_grace_period_leaves_the_registry(self):
        now = datetime(2026, 9, 27, tzinfo=timezone.utc)
        assets.set_scan_branch(self.data_dir, "github#3", "develop", name="org/gone", source_id="github:org/gone", by="ana")
        self.assertEqual(assets.retire(self.data_dir, [], {}, now=now), {"marked": ["github#3"], "purged": []})
        self.assertEqual(assets.retire(self.data_dir, [], {}, now=now + assets.GRACE), {"marked": [], "purged": ["github#3"]})
        self.assertNotIn("github#3", assets.load_registry(self.data_dir))


if __name__ == "__main__":
    unittest.main()
