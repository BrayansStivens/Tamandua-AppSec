"""The Jira issue linked to each finding, per asset and fingerprint (`jira-links`).

A link is {key, url, linked_at, by, destination, project} (plus `replaces`, the earlier issues, when someone asked to
create a new one anyway) and, once Tamandua commented on the issue, `sync`: "fixed"
after the verified-fix comment, "open" after the reappeared one. Creating issues is `runs/jira_sync.py`; the connector,
`integrations/jira.py`.
"""

from __future__ import annotations

from pathlib import Path

from tamandua.modules.findings.kinds import FINDING_RUNS
from tamandua.modules.sources.assets import asset_key
from tamandua.shared import documents


def load_links(data_dir: Path) -> dict:
    payload = documents.load(data_dir, "jira-links", {})
    return payload if isinstance(payload, dict) else {}


def _remember(data_dir: Path, asset: str, fingerprint: str, link: dict) -> None:
    with documents.lock(data_dir, "jira-links"):
        links = load_links(data_dir)
        links.setdefault(asset, {})[fingerprint] = link
        documents.save(data_dir, "jira-links", links)


remember = _remember


def forget_issues(data_dir: Path, keys: set[str]) -> int:
    """Drops every link to these issues (they no longer exist in Jira). Returns how many findings lost their link."""
    if not keys:
        return 0
    dropped = 0
    with documents.lock(data_dir, "jira-links"):
        links = load_links(data_dir)
        for asset in links.values():
            for fingerprint in [item for item, link in asset.items() if isinstance(link, dict) and link.get("key") in keys]:
                del asset[fingerprint]
                dropped += 1
        documents.save(data_dir, "jira-links", links)
    return dropped


def mark(data_dir: Path, asset: str, key: str, state: str, run_id: str) -> None:
    """Records on every finding linked to issue `key` what Tamandua last told the issue (see the module notes)."""
    with documents.edit(data_dir, "jira-links", {}) as payload:
        for link in (payload.get(asset) or {}).values():
            if isinstance(link, dict) and link.get("key") == key:
                link["sync"], link["sync_run"] = state, run_id


def annotate(data_dir: Path, record: dict) -> dict:
    """Adds to each finding the ticket already created for it, if any."""
    if record.get("type") not in (*FINDING_RUNS, "asset_state"):
        return record
    links = load_links(data_dir).get(asset_key(record), {})
    if not links:
        return record
    return {**record, "findings": [{**item, "ticket": links[item["fingerprint"]]} if item["fingerprint"] in links else item
                                   for item in record.get("findings", [])]}


def rename_assets(data_dir: Path, moved: dict[str, str]) -> None:
    """Assets that gained a stable identity (old key → new): their links move along; the new key's ones win."""
    if not moved:
        return
    with documents.edit(data_dir, "jira-links", {}) as payload:
        for old_key, uid in moved.items():
            if old_key in payload:
                merged = payload.pop(old_key)
                payload[uid] = {**merged, **payload.get(uid, {})}


def carry_over(data_dir: Path, key: str, moved: dict[str, str]) -> None:
    """Findings with a new fingerprint (former → new) keep their issue, so none is created twice."""
    links = load_links(data_dir).get(key) or {}
    if not any(former in links for former in moved):
        return
    with documents.edit(data_dir, "jira-links", {}) as payload:
        asset = payload.setdefault(key, {})
        for former, new in moved.items():
            if former in asset and new not in asset:
                asset[new] = asset[former]


def forget_asset(data_dir: Path, key: str) -> None:
    with documents.edit(data_dir, "jira-links", {}) as payload:
        payload.pop(key, None)
