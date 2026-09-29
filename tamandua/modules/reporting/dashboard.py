"""Panel aggregates: what is open, what got fixed, what is being exploited and where.

"Open" is what the latest run of each asset has, minus what triage dismissed
(false positive or a still-valid accepted risk); "fixed" is a fingerprint that
was in an earlier run of that asset and no longer appears in the latest one.
Dismissed findings are counted separately so they don't vanish without a trace.
"""

from __future__ import annotations

import threading
import time
from collections import Counter, defaultdict
import re
from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from tamandua.modules.findings import registry as findings_registry
from tamandua.modules.findings import sla
from tamandua.modules.findings.kinds import FULL_SCANS
from tamandua.modules.intel.advisories import load_feeds, load_recent_cves
from tamandua.modules.sources.assets import asset_key
from tamandua.modules.runs.store import list_runs, load_run
from tamandua.modules.findings.triage import annotate, is_active, load as load_triage
from tamandua.shared.i18n import msg

SEVERITIES = ("critical", "high", "medium", "low")
# How much of each list the Summary shows (the API declares these bounds).
TOP_ASSETS = 10
TOP_CWES = 8
TOP_ISSUES = 8
RECENT_RUNS = 8
ACTIVITY_DAYS = 365
MAX_TOOLS = 20
# CWEs with a short name in the catalog (`reports.dashboard.cwe.<id>`).
CWE_NAMED = frozenset((79, 89, 78, 22, 502, 798, 295, 918, 601, 347, 327, 328, 916, 95, 1333, 1321, 400, 770, 20, 200, 287, 352, 611, 94,
                       1104, 285, 306, 74, 1336, 915, 125, 787, 119, 120, 416, 415, 476, 190, 191, 401, 404, 674, 835, 362, 367, 369, 908,
                       459, 59, 732, 269, 522, 319, 297, 330, 203, 444, 113, 117, 23, 434, 639, 862, 863, 1395))


def _day(stamp: str) -> str:
    return stamp[:10]


def zone(name: str | None) -> tzinfo:
    """The viewer's time zone ("today" is their today, not the server's). An unknown or odd one means UTC."""
    if not name or len(name) > 64 or not re.fullmatch(r"[A-Za-z]+(?:[/_+-][A-Za-z0-9]+)*", name):
        return timezone.utc
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        return timezone.utc


def _day_in(where: tzinfo):
    def day(stamp: str) -> str:
        try:
            moment = datetime.fromisoformat(stamp)
        except (TypeError, ValueError):
            return (stamp or "")[:10]
        return (moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)).astimezone(where).date().isoformat()
    return day


def _score(open_by_severity: dict, kev: int = 0, high_epss: int = 0) -> dict:
    """Explicit curve: it never drops to 0 all at once, and exploitable weighs more than severe.

    It is a summary, not a measurement: the formula is shown next to it so nobody
    mistakes it for a certification.
    """
    import math
    risk = (8 * open_by_severity.get("critical", 0) + 3 * open_by_severity.get("high", 0)
            + 0.8 * open_by_severity.get("medium", 0) + 0.1 * open_by_severity.get("low", 0) + 15 * kev + 5 * high_epss)
    return {"value": round(100 * math.exp(-risk / 150), 1), "risk": round(risk, 1),
            "formula": msg("reports.dashboard.score_formula")}


def compute(data_dir: Path, days: int = 30, where: tzinfo = timezone.utc) -> dict:
    _day = _day_in(where)  # days are counted in the viewer's time zone
    now = datetime.now(timezone.utc)
    since = now - timedelta(days=days)
    rows = list_runs(data_dir)  # every run: the activity chart counts them all
    records = []
    decisions = load_triage(data_dir)
    triage_totals: Counter = Counter()
    advisories: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        if row["type"] == "advisory_watch" and row["status"] == "completed":
            # Advisories published after a scan: they count until the next full scan takes over.
            try:
                record = annotate(data_dir, load_run(data_dir, row["id"]), decisions)
                advisories[asset_key(record)].append(record)
            except (ValueError, OSError):
                pass
            continue
        if row["type"] not in FULL_SCANS or row["status"] not in ("completed", "incomplete"):
            continue
        try:
            records.append(annotate(data_dir, load_run(data_dir, row["id"]), decisions))
        except (ValueError, OSError):
            continue
    records.sort(key=lambda record: record["created_at"])

    by_asset: dict[str, list[dict]] = defaultdict(list)
    for record in records:
        # By stable identity: a renamed repository is still the same asset.
        by_asset[asset_key(record)].append(record)

    first_seen: dict[str, tuple[str, dict, str]] = {}
    deadlines: dict[tuple[str, str], dict] = {}  # by (asset, fingerprint): the same fingerprint can be in two assets
    policy_days = sla.policy(data_dir)["days"]
    fixed: dict[str, tuple[str, str]] = {}
    open_findings: list[tuple[str, dict]] = []
    top_assets = []
    for key, runs in by_asset.items():
        asset = runs[-1]["source"]["name"]  # the most recent name
        # An incomplete scan neither proves that something was fixed nor represents the repository's state:
        # complete ones count (and only if there are none, the most recent one, so the asset isn't hidden).
        runs = [record for record in runs if record["status"] == "completed"] or runs[-1:]
        seen_before: set[str] = set()
        for index, record in enumerate(runs):
            current = {item["fingerprint"]: item for item in record.get("findings", [])}
            for digest, finding in current.items():
                first_seen.setdefault(digest, (record["created_at"], finding, asset))
            for digest in seen_before - set(current):
                fixed.setdefault(digest, (first_seen[digest][0], record["created_at"]))
            seen_before |= set(current)
            if index == len(runs) - 1:
                for later in advisories.get(key, []):
                    if later["created_at"] > record["created_at"]:
                        for item in later.get("findings", []):
                            current.setdefault(item["fingerprint"], item)
                            first_seen.setdefault(item["fingerprint"], (later["created_at"], item, asset))
                triage_totals.update((item.get("triage") or {}).get("status", "open") for item in current.values())
                current = {digest: item for digest, item in current.items() if is_active(item)}
                open_findings.extend((asset, finding) for finding in current.values())
                # The deadline runs from the first detection in the registry (the same date Findings shows).
                registry = findings_registry.load(data_dir, key)["findings"]
                for digest, finding in current.items():
                    entry = registry.get(digest) or {}
                    if entry.get("status", "open") != "open":
                        continue
                    due = sla.deadline(finding.get("severity", ""), entry.get("first_seen") or first_seen[digest][0], policy_days)
                    if due:
                        deadlines[(asset, digest)] = {**due, "severity": finding.get("severity")}
                counts = Counter(item["severity"] for item in current.values())
                previous = Counter(item["severity"] for item in runs[index - 1].get("findings", [])) if index else None
                top_assets.append({"name": asset, "last_run": record["id"], "last_run_at": record["created_at"],
                                   "open": len(current), **{level: counts.get(level, 0) for level in SEVERITIES},
                                   "kev": sum(1 for item in current.values() if item.get("kev")),
                                   "trend": (len(current) - sum(previous.values())) if previous is not None else None})
    top_assets.sort(key=lambda item: (-item["critical"], -item["high"], -item["open"]))

    open_by_severity = Counter(finding["severity"] for _, finding in open_findings)
    in_window = {digest: value for digest, value in first_seen.items() if value[0] >= since.isoformat()}
    fixed_in_window = {digest: value for digest, value in fixed.items() if value[1] >= since.isoformat()}
    open_total = len(open_findings)
    fix_rate = round(100 * len(fixed_in_window) / (len(fixed_in_window) + open_total), 1) if (fixed_in_window or open_total) else None
    mttr = [(datetime.fromisoformat(end) - datetime.fromisoformat(start)).total_seconds() / 86400
            for start, end in fixed_in_window.values()]

    over_time: dict[str, Counter] = defaultdict(Counter)
    for stamp, finding, _ in in_window.values():
        over_time[_day(stamp)][finding["severity"]] += 1
    open_vs_fixed = []
    cumulative_open, cumulative_fixed = 0, 0
    for offset in range(days, -1, -1):
        day = _day((now - timedelta(days=offset)).isoformat())
        cumulative_open += sum(over_time.get(day, Counter()).values())
        cumulative_fixed += sum(1 for start, end in fixed.values() if _day(end) == day)
        open_vs_fixed.append({"day": day, "found": cumulative_open, "fixed": cumulative_fixed})

    cwe_counter: Counter = Counter()
    for _, finding in open_findings:
        for cwe in finding.get("cwe", []) or []:
            cwe_counter[cwe] += 1
    kev_items, epss_items = [], []
    for asset, finding in open_findings:
        package = finding.get("package") or {}
        if finding.get("kev"):
            kev_items.append({"cve": (finding.get("cve") or [finding["rule_id"]])[0], "package": package.get("name"),
                              "asset": asset, "fixed_version": package.get("fixed_version"),
                              "ransomware": bool(finding["kev"].get("ransomware"))})
        if finding.get("epss") and finding["epss"]["score"] >= 0.1:
            epss_items.append({"cve": (finding.get("cve") or [finding["rule_id"]])[0], "package": package.get("name"),
                               "asset": asset, "epss": finding["epss"]["score"], "fixed_version": package.get("fixed_version")})
    epss_items.sort(key=lambda item: -item["epss"])

    activity: Counter = Counter(_day(row["created_at"]) for row in rows)
    year = [{"day": _day((now - timedelta(days=offset)).isoformat()), "runs": activity.get(_day((now - timedelta(days=offset)).isoformat()), 0)}
            for offset in range(ACTIVITY_DAYS - 1, -1, -1)]

    # Feeds are read only if some run already downloaded them: opening the panel never goes to the network.
    feeds = load_feeds(data_dir) if (data_dir / "feeds").is_dir() else {"kev": {}}
    open_cves = {cve for _, finding in open_findings for cve in finding.get("cve", []) or []}
    kev_entries = [(cve, entry) for cve, entry in feeds.get("kev", {}).items() if cve != "__meta__" and isinstance(entry, dict)]
    recent_kev = sorted(kev_entries, key=lambda item: item[1].get("date_added") or "", reverse=True)
    cutoff_7 = _day((now - timedelta(days=7)).isoformat())
    cutoff_30 = _day((now - timedelta(days=30)).isoformat())
    kev_news = {"added_7d": sum(1 for _, entry in kev_entries if (entry.get("date_added") or "") >= cutoff_7),
                "added_30d": sum(1 for _, entry in kev_entries if (entry.get("date_added") or "") >= cutoff_30),
                "catalog_version": (feeds.get("kev", {}).get("__meta__") or {}).get("version"),
                "items": [{"cve": cve, "name": entry.get("name"), "date_added": entry.get("date_added"),
                           "ransomware": bool(entry.get("ransomware")), "affects": cve in open_cves}
                          for cve, entry in recent_kev[:8]]}

    recent = load_recent_cves(data_dir, 7) if (data_dir / "feeds").is_dir() or records else {"__meta__": {}, "items": []}
    week_cutoff = (now - timedelta(days=7)).isoformat()
    open_packages = {((finding.get("package") or {}).get("name") or "").lower() for _, finding in open_findings} - {""}
    # NVD returns at most 2000 per page; the real total comes in the feed's header.
    meta = recent.get("__meta__") or {}
    shown = recent["items"]
    cve_news = {"published_7d": meta.get("total_7d") or meta.get("total")
                or sum(1 for item in shown if (item.get("published") or "") >= week_cutoff[:19]),
                "published_30d": meta.get("total_30d"), "per_day": meta.get("per_day") or [],
                "fetched_at": meta.get("fetched_at"), "refreshing": bool(meta.get("refreshing")),
                "sample": len(shown),
                "by_severity": {level: sum(1 for item in shown if item.get("severity") == level) for level in ("critical", "high", "medium", "low")}
                | {"none": sum(1 for item in shown if not item.get("severity"))},
                "total_reported": meta.get("total"),
                "items": [{**item, "affects": item["cve"] in open_cves
                           or any(package and package in item["description"].lower() for package in open_packages)}
                          for item in recent["items"][:12]]}
    top_issues = sorted(open_findings, key=lambda pair: (
        {"act": 0, "attend": 1, "track": 2}.get((pair[1].get("priority") or {}).get("action"), 3),
        SEVERITIES.index(pair[1]["severity"]) if pair[1]["severity"] in SEVERITIES else 9,
        -((pair[1].get("epss") or {}).get("score") or 0)))[:TOP_ISSUES]
    latest = records[-1] if records else None
    return {
        "window_days": days, "generated_at": now.isoformat(),
        "kpis": {"security_score": _score(open_by_severity, len(kev_items), len(epss_items)), "open": {"total": open_total, **{level: open_by_severity.get(level, 0) for level in SEVERITIES}},
                 "found_in_window": len(in_window), "fixed_in_window": len(fixed_in_window), "fix_rate": fix_rate,
                 "mttr_days": round(sum(mttr) / len(mttr), 1) if mttr else None,
                 "runs_in_window": sum(1 for row in rows if row["created_at"] >= since.isoformat()),
                 "assets": len(by_asset), "kev_open": len(kev_items),
                 "sla": {**sla.counts([{"sla": due, "severity": due["severity"]} for due in deadlines.values()]), "days": policy_days},
                 "triage": {status: triage_totals.get(status, 0) for status in ("open", "in_progress", "false_positive", "accepted")}},
        "issues_over_time": [{"day": _day((now - timedelta(days=offset)).isoformat()),
                              **{level: over_time.get(_day((now - timedelta(days=offset)).isoformat()), Counter()).get(level, 0) for level in SEVERITIES}}
                             for offset in range(days, -1, -1)],
        "open_vs_fixed": open_vs_fixed,
        "top_assets": top_assets[:TOP_ASSETS],
        "by_cwe": [{"cwe": cwe, "name": msg(f"reports.dashboard.cwe.{cwe}") if cwe in CWE_NAMED else None, "count": count} for cwe, count in cwe_counter.most_common(TOP_CWES)],
        "exploitability": {"kev": kev_items[:25], "high_epss": epss_items[:25], "kev_total": len(kev_items), "epss_total": len(epss_items)},
        "activity": year,
        "recent_runs": rows[:RECENT_RUNS],
        "top_issues": [{"title": finding["title"], "severity": finding["severity"], "asset": asset,
                        "action": (finding.get("priority") or {}).get("action"), "run_id": next((r["last_run"] for r in top_assets if r["name"] == asset), None),
                        "epss": (finding.get("epss") or {}).get("score"), "kev": bool(finding.get("kev")), "fingerprint": finding["fingerprint"],
                        "sla": {key: value for key, value in deadlines[(asset, finding["fingerprint"])].items() if key != "severity"}
                        if (asset, finding["fingerprint"]) in deadlines else None}
                       for asset, finding in top_issues],
        "kev_news": kev_news, "cve_news": cve_news,
        "tools": ((latest or {}).get("summary", {}).get("tools") or [])[:MAX_TOOLS],
    }


_cache: dict[tuple, tuple[float, dict]] = {}
_cache_lock = threading.Lock()
CACHE_SECONDS = 60


def _signature(data_dir: Path) -> tuple:
    """What changes the result: runs, registry and triage (in the database: count and last modification), the
    deadlines, the exclusions and the feeds (KEV, NVD)."""
    from sqlalchemy import func, select

    from tamandua.modules.findings.tables import registry_findings, triage_decisions
    from tamandua.modules.runs.tables import runs
    from tamandua.shared import db, documents
    with db.transaction(data_dir) as connection:
        stored = tuple(connection.execute(select(func.count(), func.max(table.c.updated_at)).where(table.c.tenant_id == db.TENANT)).one()
                       for table in (runs, registry_findings, triage_decisions))
    stored = (*stored, documents.signature(data_dir, "sla", "exclusions"))
    paths = []
    feeds = data_dir / "feeds"
    if feeds.is_dir():
        paths += sorted(path for path in feeds.iterdir() if path.suffix == ".json")
    stamp = []
    for path in paths:
        try:
            status = path.stat()
            stamp.append((path.name, status.st_mtime_ns, status.st_size))
        except OSError:
            stamp.append((path.name, 0, 0))
    return (*stored, *stamp)


def cached(data_dir: Path, days: int = 30, where: tzinfo = timezone.utc) -> dict:
    """compute() reads every run: with hundreds of scans, opening the Summary can't repeat that on every visit.

    It is recomputed when something it depends on changed, when the day changed, or after CACHE_SECONDS."""
    key = (str(data_dir), days, str(where), _signature(data_dir), datetime.now(where).date().isoformat())
    now = time.monotonic()
    with _cache_lock:
        hit = _cache.get(key)
        if hit and now - hit[0] < CACHE_SECONDS:
            return hit[1]
    result = compute(data_dir, days, where)
    with _cache_lock:
        for stale in [item for item in _cache if item[0] == key[0]]:
            del _cache[stale]
        _cache[key] = (now, result)
    return result

