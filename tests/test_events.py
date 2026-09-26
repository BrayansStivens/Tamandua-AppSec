"""Domain events: the bus (order, errors, unwired processes), the per-process wiring and the flows wired through it."""

import subprocess
import sys
import tempfile
import unittest
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from tamandua.app import wiring
from tamandua.modules.findings import exclusions, tickets, triage, verifications
from tamandua.modules.findings import registry as findings_registry
from tamandua.modules.integrations.github import GitHubAppError
from tamandua.modules.pullrequests import watch as pr_watch
from tamandua.modules.pullrequests.watch import RepositoriesListed
from tamandua.modules.runs import assets as run_assets
from tamandua.modules.runs.assets import AssetPurged
from tamandua.modules.runs.store import list_runs, save_repository_scan
from tamandua.modules.sources import assets as source_assets
from tamandua.shared import events
from test_dashboard import _finding, _scan

wiring.configure()  # like every Tamandua process: domain events and injected readers

ROOT = Path(__file__).resolve().parents[1]
USER = {"username": "ana", "role": "admin"}


@dataclass(frozen=True)
class Happened:
    value: int


@dataclass(frozen=True)
class Unrelated:
    pass


class BusTests(unittest.TestCase):
    def test_subscribers_run_in_subscription_order_and_only_for_their_event(self):
        bus, seen = events.Bus(), []
        bus.subscribe(Happened, lambda event: seen.append(("first", event.value)))
        bus.subscribe(Unrelated, lambda event: seen.append("unrelated"))
        bus.subscribe(Happened, lambda event: seen.append(("second", event.value)))
        bus.publish(Happened(7))
        self.assertEqual(seen, [("first", 7), ("second", 7)])

    def test_an_error_stops_the_rest_and_reaches_the_publisher_naming_the_subscriber(self):
        bus, seen = events.Bus(), []

        def broken(event):
            raise OSError("disk full")
        bus.subscribe(Happened, lambda event: seen.append("before"))
        bus.subscribe(Happened, broken)
        bus.subscribe(Happened, lambda event: seen.append("after"))
        with self.assertRaises(OSError) as caught:
            bus.publish(Happened(1))
        self.assertEqual(seen, ["before"])
        self.assertTrue(any("Happened" in note and "broken" in note for note in caught.exception.__notes__))

    def test_an_event_nobody_subscribed_to_is_an_error_not_a_no_op(self):
        with self.assertRaises(events.Unhandled):
            events.Bus().publish(Happened(1))


class WiringTests(unittest.TestCase):
    def python(self, code: str) -> str:
        completed = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, timeout=120)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return completed.stdout.strip().splitlines()[-1]

    def test_a_process_that_was_not_wired_refuses_to_publish(self):
        self.assertEqual(self.python(
            "from pathlib import Path\n"
            "from tamandua.shared import events\n"
            "from tamandua.modules.runs.assets import AssetPurged\n"
            "try:\n    events.publish(AssetPurged(Path('data'), 'github#1'))\n"
            "except events.Unhandled:\n    print('unwired')\n"), "unwired")

    def test_the_cli_wires_its_process_before_anything_else(self):
        self.assertEqual(self.python(
            "from tamandua.cli.main import main\n"
            "from tamandua.shared import events\n"
            "from tamandua.modules.runs.assets import AssetPurged\n"
            "from tamandua.modules.pullrequests.watch import RepositoriesListed\n"
            "try:\n    main(['--help'])\nexcept SystemExit:\n    pass\n"
            "print(len(events.subscribers(AssetPurged)), len(events.subscribers(RepositoriesListed)))\n"),
            f"{len(wiring.FORGET_ON_PURGE)} 1")

    def test_wiring_twice_keeps_one_subscription_per_handler_in_order(self):
        wiring.configure()
        wiring.configure()
        self.assertEqual([handler.__qualname__ for handler in events.subscribers(AssetPurged)],
                         [f"{forget.__module__}.{forget.__qualname__}" for forget in wiring.FORGET_ON_PURGE])
        self.assertEqual(len(events.subscribers(RepositoriesListed)), 1)

    def test_verifications_need_the_run_reader_wired(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(verifications, "_runs", None):
            data_dir = Path(directory)
            verifications.record(data_dir, "github#1", "a" * 64, "f" * 32, by="ana")
            self.assertEqual(verifications.annotate(data_dir, "github#2", [{"fingerprint": "a" * 64}]), [{"fingerprint": "a" * 64}])
            with self.assertRaises(RuntimeError):
                verifications.annotate(data_dir, "github#1", [{"fingerprint": "a" * 64}])


def _scan_of(name: str, uid: str, fingerprint: str) -> dict:
    record = _scan(name, [_finding(fingerprint)], datetime.now(timezone.utc).isoformat())
    record["source"].update(uid=uid)
    return record


class PurgeFlowTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data_dir = Path(self.directory.name)
        self.gone = save_repository_scan(self.data_dir, _scan_of("org/gone", "github#1", "a" * 64))
        self.kept = save_repository_scan(self.data_dir, _scan_of("org/kept", "github#2", "b" * 64))
        for record, key in ((self.gone, "github#1"), (self.kept, "github#2")):
            fingerprint = record["findings"][0]["fingerprint"]
            triage.decide(self.data_dir, record, [fingerprint], "in_progress", user=USER)
            tickets._remember(self.data_dir, key, fingerprint, {"key": "SEC-1"})
            pr_watch.configure(self.data_dir, key, enabled=True, by="ana")
            source_assets.set_scan_branch(self.data_dir, key, "develop", name=record["target"], source_id=record["source"]["id"], by="ana")
            exclusions.save(self.data_dir, key, ["vendor/"], reason="Third-party code", user=USER)

    def remembered(self, key: str) -> dict:
        return {"runs": any(row["target"] == ("org/gone" if key == "github#1" else "org/kept") for row in list_runs(self.data_dir)),
                "triage": key in triage.load(self.data_dir),
                "registry": bool(findings_registry.load(self.data_dir, key)["findings"]),
                "tickets": key in tickets.load_links(self.data_dir),
                "pr_watch": key in pr_watch.load(self.data_dir)["repositories"],
                "registry_entry": key in source_assets.load_registry(self.data_dir),
                "exclusions": bool(exclusions.get(self.data_dir, key)["patterns"])}

    def test_purge_deletes_the_runs_and_every_context_forgets_only_that_asset(self):
        self.assertEqual(run_assets.purge(self.data_dir, "github#1"), 1)
        self.assertEqual(set(self.remembered("github#1").values()), {False})
        self.assertEqual(set(self.remembered("github#2").values()), {True})

    def test_a_failing_subscriber_stops_the_purge_after_the_runs_and_is_reported(self):
        with patch.object(pr_watch, "load", side_effect=OSError("disk full")), self.assertRaises(OSError) as caught:
            run_assets.purge(self.data_dir, "github#1")
        self.assertTrue(any("AssetPurged" in note and "pullrequests.watch.forget" in note for note in caught.exception.__notes__))
        state = self.remembered("github#1")
        # Runs first (an interrupted purge is what `tamandua integrity` cleans up), then the subscribers in order.
        self.assertEqual((state["runs"], state["triage"], state["registry"], state["tickets"]), (False, False, False, False))
        self.assertEqual((state["registry_entry"], state["exclusions"]), (True, True))


class RepositoriesListedFlowTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data_dir = Path(self.directory.name)
        save_repository_scan(self.data_dir, _scan_of("org/api", "github#7", "a" * 64))

    class Jobs:
        def pending(self):
            return 0

    def poll(self, **listing):
        with patch("tamandua.modules.integrations.github.installation_repositories", **listing):
            return pr_watch.Watcher(self.data_dir, self.Jobs(), lambda: 7).poll()

    def test_a_complete_listing_reconciles_the_analysed_repositories(self):
        self.poll(return_value=[])
        self.assertIsNotNone(source_assets.load_registry(self.data_dir)["github#7"].get("removed_at"))

    def test_a_partial_listing_is_never_published(self):
        self.poll(side_effect=GitHubAppError("rate limited"))
        self.assertNotIn("github#7", source_assets.load_registry(self.data_dir))


if __name__ == "__main__":
    unittest.main()
