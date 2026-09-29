"""Re-verify a finding: scan its asset again and tell whether it is still there.

Closes the find → fix → verify loop without searching a new scan by hand. It stores which finding asked
for verification and with which run (`data/verifications.json`); the result is derived from the findings
registry when that run finishes:

- `running`: the scan is queued or in progress.
- `fixed`: the full scan no longer finds it (the registry marked it remediated).
- `present`: it still shows up.
- `inconclusive`: the scan was incomplete (an engine didn't run): it proves nothing, as in the registry.
- `failed`: the scan failed.

If a scan of that asset is already queued or running (another verification, the branch watch), the
finding joins it instead of starting another one.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from tamandua.shared import documents
from tamandua.shared.model import Finding

MAX_PER_ASSET = 500
_runs: Callable[[Path, list[str]], list[dict]] | None = None


def load(data_dir: Path) -> dict:
    payload = documents.load(data_dir, "verifications", {})
    return payload if isinstance(payload, dict) else {}


def record(data_dir: Path, key: str, fingerprint: str, run_id: str, *, by: str) -> dict:
    entry = {"run_id": run_id, "by": by, "at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    with documents.lock(data_dir, "verifications"):
        payload = load(data_dir)
        asset = payload.setdefault(key, {})
        asset[fingerprint] = entry
        if len(asset) > MAX_PER_ASSET:  # the oldest ones are forgotten
            for old in sorted(asset, key=lambda item: asset[item]["at"])[:len(asset) - MAX_PER_ASSET]:
                del asset[old]
        documents.save(data_dir, "verifications", payload)
    return entry


def carry_over(data_dir: Path, key: str, moved: dict[str, str]) -> None:
    """Findings with a new fingerprint (former → new) keep the verification asked for them."""
    requested = load(data_dir).get(key) or {}
    if not any(former in requested for former in moved):
        return
    with documents.edit(data_dir, "verifications", {}) as payload:
        asset = payload.setdefault(key, {})
        for former, new in moved.items():
            if former in asset and new not in asset:
                asset[new] = asset[former]


def use_runs(lookup: Callable[[Path, list[str]], list[dict]]) -> None:
    """Wired by the composition root (`tamandua/app/wiring.py`): how to read the rows of some runs (by id), whose
    status says how a verification went. Findings sit below runs, so they are handed the reader instead of importing it."""
    global _runs
    _runs = lookup


def _run_rows(data_dir: Path, ids: list[str]) -> list[dict]:
    if _runs is None:
        raise RuntimeError("verifications: no run reader wired in this process (see tamandua/app/wiring.py)")
    return _runs(data_dir, ids)


def annotate(data_dir: Path, key: str, findings: list[Finding]) -> list[Finding]:
    """Adds `verification` to the findings that have a verification requested."""
    requested = load(data_dir).get(key) or {}
    if not requested or not any(item.get("fingerprint") in requested for item in findings):
        return findings
    from tamandua.modules.findings.registry import load as registry
    runs = {row["id"]: row for row in _run_rows(data_dir, [entry["run_id"] for entry in requested.values() if entry.get("run_id")])}
    entries = registry(data_dir, key).get("findings", {})
    for finding in findings:
        asked = requested.get(finding.get("fingerprint"))
        if not asked:
            continue
        run = runs.get(asked["run_id"]) or {}
        status = run.get("status")
        entry = entries.get(finding["fingerprint"]) or {}
        if status in ("queued", "running"):
            state = "running"
        elif status == "failed" or not run:
            state = "failed"
        elif status != "completed":
            state = "inconclusive"
        elif entry.get("status") == "fixed":
            state = "fixed"
        else:
            state = "present"
        finding["verification"] = {**asked, "state": state, "finished_at": run.get("finished_at")}
    return findings
