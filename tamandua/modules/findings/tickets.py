"""The Jira issue linked to each finding, per asset and fingerprint (`jira-links`), and the export that creates them.

The connector (credentials, HTTP, issue fields) is `integrations/jira.py`; this side knows run records and assets.
"""

from __future__ import annotations

from pathlib import Path

from tamandua.modules.findings.kinds import FINDING_RUNS
from tamandua.modules.integrations import jira
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


def annotate(data_dir: Path, record: dict) -> dict:
    """Añade a cada hallazgo el ticket ya creado, si lo hay."""
    if record.get("type") not in (*FINDING_RUNS, "asset_state"):
        return record
    links = load_links(data_dir).get(asset_key(record), {})
    if not links:
        return record
    return {**record, "findings": [{**item, "ticket": links[item["fingerprint"]]} if item["fingerprint"] in links else item
                                   for item in record.get("findings", [])]}


def export(data_dir: Path, record: dict, tickets: list[dict], fingerprints: list, *, by: str, http=None,
           locale: str | None = None) -> dict:
    """Creates the requested tickets' issues in Jira (see `jira.export`), remembering each link under the asset."""
    asset = asset_key(record)
    return jira.export(tickets, fingerprints, load_links(data_dir).get(asset, {}),
                       lambda fingerprint, link: _remember(data_dir, asset, fingerprint, link),
                       by=by, run_id=record["id"], http=http, locale=locale)


def rename_assets(data_dir: Path, moved: dict[str, str]) -> None:
    """Assets that gained a stable identity (old key → new): their links move along; the new key's ones win."""
    if not moved:
        return
    with documents.edit(data_dir, "jira-links", {}) as payload:
        for old_key, uid in moved.items():
            if old_key in payload:
                merged = payload.pop(old_key)
                payload[uid] = {**merged, **payload.get(uid, {})}


def forget_asset(data_dir: Path, key: str) -> None:
    with documents.edit(data_dir, "jira-links", {}) as payload:
        payload.pop(key, None)
