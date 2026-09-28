"""Composition root for what the contexts can't import from each other: domain event subscribers and injected readers.

Every process wires once, before doing anything else: the API (and its embedded worker) in `build_state`, the
worker process in `worker.run`, and the CLI in `main`. Subscribers run in the order registered here.
"""

from __future__ import annotations

import threading
from typing import Callable

from tamandua.modules.findings import exclusions, tickets, triage, verifications
from tamandua.modules.findings import registry as findings_registry
from tamandua.modules.pullrequests import watch as pr_watch
from tamandua.modules.pullrequests.watch import RepositoriesListed
from tamandua.modules.runs import assets as run_assets
from tamandua.modules.runs.assets import AssetPurged
from tamandua.modules.runs.store import find_runs
from tamandua.modules.scanning import secret_rules
from tamandua.modules.sources import assets as source_assets
from tamandua.shared import events

_lock = threading.Lock()
_wired = False

# What each context keeps per asset, forgotten when the asset is purged (after its runs, see runs/assets.py).
FORGET_ON_PURGE = (triage.forget_asset, findings_registry.forget_asset, tickets.forget_asset, pr_watch.forget,
                   source_assets.forget, exclusions.forget, secret_rules.forget)


def _forgetting(forget: Callable) -> Callable[[AssetPurged], None]:
    def handler(event: AssetPurged) -> None:
        forget(event.data_dir, event.key)
    handler.__qualname__ = f"{forget.__module__}.{forget.__qualname__}"
    return handler


def _reconcile(event: RepositoriesListed) -> None:
    run_assets.reconcile(event.data_dir, event.repositories, active_accounts=event.active_accounts)


def configure() -> None:
    """Idempotent: a process that calls it twice (tests build several apps) keeps one subscription per handler."""
    global _wired
    with _lock:
        if _wired:
            return
        verifications.use_runs(lambda data_dir, ids: find_runs(data_dir, ids=ids))
        events.subscribe(RepositoriesListed, _reconcile)
        for forget in FORGET_ON_PURGE:
            events.subscribe(AssetPurged, _forgetting(forget))
        _wired = True
