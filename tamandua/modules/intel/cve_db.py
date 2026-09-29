"""Local copy of NVD in PostgreSQL, with full-text search, KEV and EPSS.

The tracker queries this copy, never NVD live: searches are instant and don't depend on NVD's rate limit (5 requests
every 30 s without an API key). A background task fills it:

1. **Initial load**, newest first, page by page, resumable after a restart: this year's CVEs are there in minutes
   while the history keeps loading.
2. **Incremental updates** by modification date (`lastModStartDate`), in windows of up to 120 days (what NVD allows).
3. **KEV and EPSS** are copied to their tables whenever the downloaded file changes.

Only index and date ranges travel to NVD; nothing about the user. The optional API key (`TAMANDUA_NVD_API_KEY`) goes
in a header and is never logged. It lives in the database, so any instance of the API (even one without a persistent
disk) serves it; a copy left by earlier versions in data/feeds/cves.sqlite is imported once (`import_sqlite`).
"""

from __future__ import annotations

import json
import re
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from sqlalchemy import ARRAY, Text, and_, any_, bindparam, delete, func, literal_column, or_, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import SQLAlchemyError

from tamandua.modules.intel.tables import cve_state, cves, epss
from tamandua.modules.intel.tables import kev as exploited
from tamandua.shared import db, settings
from tamandua.shared import log as logging_setup
from tamandua.shared.i18n import msg
from tamandua.version import USER_AGENT

_log = logging_setup.get("cve-db")
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE = 1000
MAX_BODY = 80_000_000
SYNC_EVERY = 2 * 3600
WINDOW_DAYS = 120
MAX_CWES = 20
MAX_REFERENCES = 10
LATEST_KEV = 8    # latest KEV additions in the overview
DAILY_DAYS = 31   # days of published CVEs in the overview (a month, today included)
SEVERITIES = ("critical", "high", "medium", "low", "none")
SORTS = {"published": (cves.c.published.desc().nulls_last(),),
         "score": (cves.c.score.desc().nulls_last(), cves.c.published.desc().nulls_last()),
         "epss": (epss.c.score.desc().nulls_last(), cves.c.published.desc().nulls_last())}
_CVE_PREFIX = re.compile(r"(?i)cve-\d{4}(?:-\d{0,7})?")
_sync = {"running": False, "error": None}
COLUMNS = ("id", "year", "published", "modified", "status", "severity", "score", "vector", "version", "description", "cwe", "refs")
NOT_REJECTED = or_(cves.c.status.is_(None), cves.c.status != "Rejected")


def _get_state(connection, key: str) -> str | None:
    return connection.execute(select(cve_state.c.value).where(cve_state.c.key == key)).scalar_one_or_none()


def _set_state(connection, key: str, value) -> None:
    statement = insert(cve_state).values(key=key, value=None if value is None else str(value))
    connection.execute(statement.on_conflict_do_update(index_elements=[cve_state.c.key], set_={"value": statement.excluded.value}))


# --- ingestion ---------------------------------------------------------------------------

def parse_entry(entry: dict) -> tuple | None:
    """An NVD 2.0 entry to a row. The newest available metric wins: 4.0, 3.1, 3.0, 2."""
    cve = entry.get("cve") or {}
    identifier = cve.get("id")
    if not isinstance(identifier, str) or not re.fullmatch(r"CVE-\d{4}-\d{4,}", identifier):
        return None
    metrics = cve.get("metrics") or {}
    score = severity = vector = version = None
    for key, label in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        block = metrics.get(key)
        if not block:
            continue
        chosen = next((item for item in block if item.get("type") == "Primary"), block[0])
        data = chosen.get("cvssData") or {}
        score = data.get("baseScore")
        severity = (data.get("baseSeverity") or chosen.get("baseSeverity") or "").lower() or None
        vector, version = data.get("vectorString"), label
        break
    description = next((item.get("value") for item in cve.get("descriptions", []) if item.get("lang") == "en"), "") or ""
    cwes = sorted({item.get("value") for weakness in cve.get("weaknesses", []) for item in weakness.get("description", [])
                   if isinstance(item.get("value"), str) and item["value"].startswith("CWE-")})[:MAX_CWES]
    # The first 10 references with their main tag: the full detail stays in NVD and the database doesn't balloon.
    references = [{"url": item["url"][:500], "tags": (item.get("tags") or [])[:1]} for item in cve.get("references", [])
                  if isinstance(item.get("url"), str) and item["url"].startswith(("https://", "http://"))][:MAX_REFERENCES]
    return (identifier, int(identifier[4:8]), cve.get("published"), cve.get("lastModified"), cve.get("vulnStatus"),
            severity if severity in SEVERITIES else None, score if isinstance(score, (int, float)) else None,
            vector, version, description[:4000], ",".join(cwes) or None, json.dumps(references, ensure_ascii=False, separators=(",", ":")))


def upsert(data_dir: Path, entries: list[dict]) -> int:
    rows = [dict(zip(COLUMNS, row)) for row in (parse_entry(entry) for entry in entries) if row]
    if rows:
        statement = insert(cves)
        with db.transaction(data_dir) as connection:
            connection.execute(statement.on_conflict_do_update(index_elements=[cves.c.id], set_={
                name: statement.excluded[name] for name in COLUMNS if name not in ("id", "year")}), rows)
    return len(rows)


def _nvd_get(params: dict) -> dict:
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    key = settings.text("TAMANDUA_NVD_API_KEY")
    if key:
        headers["apiKey"] = key
    with urlopen(Request(f"{NVD_URL}?{urlencode(params)}", headers=headers), timeout=120) as response:
        body = response.read(MAX_BODY + 1)
    if len(body) > MAX_BODY:
        raise ValueError("NVD response too large")
    return json.loads(body)


def pause() -> float:
    # NVD's public rate limit: 5 requests / 30 s without a key, 50 / 30 s with one.
    return 0.8 if settings.is_set("TAMANDUA_NVD_API_KEY") else 6.5


def _stamp(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%S.000")


def sync_step(data_dir: Path, *, fetch=None, now: datetime | None = None) -> str:
    """One sync step (one request to NVD). Returns what it did: backfill, incremental or idle."""
    fetch = fetch or _nvd_get
    now = now or datetime.now(timezone.utc)
    with db.transaction(data_dir) as connection:
        done, following, since, offset = (_get_state(connection, key) for key in
                                          ("backfill_done", "backfill_next", "synced_at", "incremental_index"))
    if done != "1":
        if following is None:
            total = int(fetch({"resultsPerPage": 1}).get("totalResults") or 0)
            with db.transaction(data_dir) as connection:
                _set_state(connection, "backfill_total", total)
                _set_state(connection, "backfill_next", max(0, (total - 1) // PAGE * PAGE))
                _set_state(connection, "synced_at", now.isoformat())  # whatever changes meanwhile, the incremental picks up
            return "backfill"
        start = int(following)
        payload = fetch({"resultsPerPage": PAGE, "startIndex": start})
        with db.transaction(data_dir) as connection:
            upsert(data_dir, payload.get("vulnerabilities") or [])
            if start <= 0:
                _set_state(connection, "backfill_done", "1")
                _set_state(connection, "backfill_next", None)
            else:
                _set_state(connection, "backfill_next", start - PAGE)
        return "backfill"
    since_at = datetime.fromisoformat(since or now.isoformat())
    if (now - since_at).total_seconds() < SYNC_EVERY:
        return "idle"
    start_at = since_at - timedelta(minutes=5)
    end_at = min(now, start_at + timedelta(days=WINDOW_DAYS))
    offset = int(offset or 0)
    payload = fetch({"lastModStartDate": _stamp(start_at), "lastModEndDate": _stamp(end_at),
                     "resultsPerPage": PAGE, "startIndex": offset})
    with db.transaction(data_dir) as connection:
        upsert(data_dir, payload.get("vulnerabilities") or [])
        if offset + PAGE < int(payload.get("totalResults") or 0):
            _set_state(connection, "incremental_index", offset + PAGE)
        else:
            _set_state(connection, "incremental_index", 0)
            _set_state(connection, "synced_at", end_at.isoformat())
    return "incremental"


def load_signals(data_dir: Path, feeds: dict) -> None:
    """Copies KEV and EPSS into the database when the downloaded version changed."""
    kev_feed, epss_feed = feeds.get("kev") or {}, feeds.get("epss") or {}
    kev_version = str((kev_feed.get("__meta__") or {}).get("version") or "") + f":{len(kev_feed)}"
    epss_version = str((epss_feed.get("__meta__") or {}).get("header") or "") + f":{len(epss_feed)}"
    with db.transaction(data_dir) as connection:
        if len(kev_feed) > 1 and _get_state(connection, "kev_version") != kev_version:
            connection.execute(delete(exploited))
            connection.execute(insert(exploited).on_conflict_do_nothing(), [
                {"id": key, "date_added": item.get("date_added"), "due_date": item.get("due_date"),
                 "ransomware": bool(item.get("ransomware")), "name": item.get("name")}
                for key, item in kev_feed.items() if key != "__meta__"])
            _set_state(connection, "kev_version", kev_version)
        if len(epss_feed) > 1 and _get_state(connection, "epss_version") != epss_version:
            connection.execute(delete(epss))
            rows = [{"id": key, "score": value[0], "percentile": value[1]} for key, value in epss_feed.items() if key != "__meta__"]
            for index in range(0, len(rows), 20_000):
                connection.execute(insert(epss).on_conflict_do_nothing(), rows[index:index + 20_000])
            _set_state(connection, "epss_version", epss_version)


def import_sqlite(data_dir: Path) -> int:
    """Copies the SQLite copy of earlier versions (data/feeds/cves.sqlite) into the database, once, so the tracker
    doesn't start the NVD download over. The file is renamed afterwards (it can be deleted). Returns the CVEs copied."""
    import sqlite3
    path = data_dir / "feeds" / "cves.sqlite"
    if not path.is_file():
        return 0
    source = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    source.row_factory = sqlite3.Row
    copied = 0
    try:
        with db.transaction(data_dir) as connection:
            cursor = source.execute(f"SELECT {', '.join(COLUMNS)} FROM cves")  # nosemgrep: appsec.py.sql-string-building
            while rows := cursor.fetchmany(5000):
                connection.execute(insert(cves).on_conflict_do_nothing(), [dict(row) for row in rows])
                copied += len(rows)
            for row in source.execute("SELECT id, date_added, due_date, ransomware, name FROM kev"):
                connection.execute(insert(exploited).values(**{**dict(row), "ransomware": bool(row["ransomware"])}).on_conflict_do_nothing())
            cursor = source.execute("SELECT id, score, percentile FROM epss")
            while rows := cursor.fetchmany(20_000):
                connection.execute(insert(epss).on_conflict_do_nothing(), [dict(row) for row in rows])
            for row in source.execute("SELECT key, value FROM state"):
                if _get_state(connection, row["key"]) is None:
                    _set_state(connection, row["key"], row["value"])
    except sqlite3.Error:
        _log.warning("cve_sqlite_not_imported", extra={"reason": "the SQLite copy is unreadable; NVD will be downloaded again"})
        return 0
    finally:
        source.close()
    for suffix in ("", "-wal", "-shm"):  # SQLite's journal files go with it, so the renamed copy stays whole
        try:
            path.with_name(f"cves.sqlite{suffix}").rename(path.with_name(f"cves.sqlite.imported{suffix}"))
        except OSError:
            pass
    return copied


class Syncer:
    """Thread that keeps the database up to date. Only `serve` starts it; TAMANDUA_CVE_SYNC=off turns it off."""

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, name="tamandua-cve-sync", daemon=True)

    def start(self) -> None:
        if not settings.flag("TAMANDUA_CVE_SYNC"):
            return
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        from tamandua.modules.intel.advisories import load_feeds
        _sync["running"] = True
        backoff = 60
        signals_at = 0.0
        while not self._stop.is_set():
            try:
                if time.time() - signals_at > 3600:
                    load_signals(self.data_dir, load_feeds(self.data_dir))
                    signals_at = time.time()
                done = sync_step(self.data_dir)
                _sync["error"] = None
                backoff = 60
                delay = pause() if done != "idle" else 300
            except (HTTPError, URLError, TimeoutError, OSError, ValueError, SQLAlchemyError) as error:
                # No request details: the URL could end up in logs with its parameters; the key goes in a header.
                _sync["error"] = type(error).__name__
                _log.warning("cve_sync_failed", extra={"reason": type(error).__name__})
                delay, backoff = backoff, min(backoff * 2, 900)
            self._stop.wait(delay)
        _sync["running"] = False


# --- queries -------------------------------------------------------------------------------

def _tsquery(text: str) -> str | None:
    """Every word must appear, each as a prefix; only letters and digits reach the query syntax."""
    words = re.findall(r"[A-Za-z0-9]+", text)[:8]
    return " & ".join(f"{word.lower()}:*" for word in words) or None


def _item(row) -> dict:
    return {"id": row.id, "published": row.published, "severity": row.severity, "score": row.score,
            "version": row.version, "description": (row.description or "")[:400], "status": row.status,
            "kev": row.kev_added is not None, "epss": row.epss, "epss_percentile": row.epss_percentile}


LISTED = (cves.c.id, cves.c.published, cves.c.severity, cves.c.score, cves.c.version, cves.c.description, cves.c.status,
          exploited.c.date_added.label("kev_added"), epss.c.score.label("epss"), epss.c.percentile.label("epss_percentile"))
JOINED = cves.outerjoin(exploited, exploited.c.id == cves.c.id).outerjoin(epss, epss.c.id == cves.c.id)


def search(data_dir: Path, *, query: str = "", severity: str | None = None, kev: bool = False, year: int | None = None,
           sort: str = "published", limit: int = 25, offset: int = 0, only: frozenset[str] | None = None,
           mine: frozenset[str] = frozenset()) -> dict:
    """Paged search, every value a bound parameter. `only` restricts to those CVEs (e.g. the open ones in your assets);
    `mine` only marks each row with `affects`."""
    conditions = [NOT_REJECTED]
    if only is not None:
        conditions.append(cves.c.id == any_(bindparam("only", sorted(only), type_=ARRAY(Text))))
    text = query.strip()
    if _CVE_PREFIX.fullmatch(text):
        conditions.append(cves.c.id.like(text.upper().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%", escape="\\"))
    elif text:
        match = _tsquery(text)
        if match:
            conditions.append(cves.c.search.op("@@")(func.to_tsquery(literal_column("'simple'::regconfig"), match)))
    if severity == "none":
        conditions.append(or_(cves.c.severity.is_(None), cves.c.severity == "none"))  # not scored yet, or CVSS 0
    elif severity:
        conditions.append(cves.c.severity == severity)
    if kev:
        conditions.append(exploited.c.id.isnot(None))
    if year:
        conditions.append(cves.c.year == year)
    with db.transaction(data_dir) as connection:
        total = connection.execute(select(func.count()).select_from(JOINED).where(and_(*conditions))).scalar_one()
        rows = connection.execute(select(*LISTED).select_from(JOINED).where(and_(*conditions))
                                  .order_by(*SORTS[sort]).limit(limit).offset(offset)).all()
    return {"items": [{**_item(row), "affects": row.id in mine} for row in rows], "total": total, "limit": limit, "offset": offset}


def detail(data_dir: Path, identifier: str) -> dict | None:
    with db.transaction(data_dir) as connection:
        row = connection.execute(select(*LISTED, cves.c.vector, cves.c.cwe, cves.c.refs, cves.c.modified, exploited.c.due_date,
                                        exploited.c.ransomware, exploited.c.name.label("kev_name")).select_from(JOINED)
                                 .where(cves.c.id == identifier)).first()
        if row is None:
            kev_row = connection.execute(select(exploited).where(exploited.c.id == identifier)).first()
            epss_row = connection.execute(select(epss).where(epss.c.id == identifier)).first()
            if not kev_row and not epss_row:
                return None
            return {"id": identifier, "published": None, "severity": None, "score": None, "version": None, "status": None,
                    "description": (kev_row.name if kev_row else None) or msg("intel.cve.not_in_local_copy"),
                    "kev": bool(kev_row), "kev_detail": dict(kev_row._mapping) if kev_row else None,
                    "epss": epss_row.score if epss_row else None, "epss_percentile": epss_row.percentile if epss_row else None,
                    "vector": None, "cwe": [], "references": [], "modified": None}
    item = _item(row)
    item.update(description=row.description, vector=row.vector, modified=row.modified,
                cwe=(row.cwe or "").split(",")[:MAX_CWES] if row.cwe else [], references=json.loads(row.refs or "[]")[:MAX_REFERENCES],
                kev_detail={"date_added": row.kev_added, "due_date": row.due_date, "ransomware": bool(row.ransomware),
                            "name": row.kev_name} if row.kev_added else None)
    return item


def overview(data_dir: Path, *, now: datetime | None = None) -> dict:
    """What goes with the tracker: load status, years, latest KEV and published per day and severity."""
    now = now or datetime.now(timezone.utc)
    day = func.substr(cves.c.published, 1, 10).label("day")
    level = func.coalesce(cves.c.severity, "none").label("severity")
    with db.transaction(data_dir) as connection:
        count = connection.execute(select(func.count()).select_from(cves)).scalar_one()
        years = [{"year": row.year, "count": row.count} for row in connection.execute(
            select(cves.c.year, func.count().label("count")).where(NOT_REJECTED).group_by(cves.c.year).order_by(cves.c.year.desc()))]
        latest_kev = [{"id": row.id, "date_added": row.date_added, "name": row.name, "ransomware": bool(row.ransomware),
                       "severity": row.severity, "score": row.score} for row in connection.execute(
            select(exploited.c.id, exploited.c.date_added, exploited.c.name, exploited.c.ransomware, cves.c.severity, cves.c.score)
            .select_from(exploited.outerjoin(cves, cves.c.id == exploited.c.id))
            .order_by(exploited.c.date_added.desc().nulls_last(), exploited.c.id.desc()).limit(LATEST_KEV))]
        since = (now - timedelta(days=DAILY_DAYS - 1)).strftime("%Y-%m-%d")
        daily = [{"day": row.day, "severity": row.severity, "count": row.count} for row in connection.execute(
            select(day, level, func.count().label("count")).where(cves.c.published >= since, NOT_REJECTED)
            .group_by(day, level).order_by(day))]
        state = {row.key: row.value for row in connection.execute(select(cve_state))}
        kev_total = connection.execute(select(func.count()).select_from(exploited)).scalar_one()
    total = int(state.get("backfill_total") or 0)
    following = state.get("backfill_next")
    done = state.get("backfill_done") == "1"
    loaded_pages = 0 if following is None else max(0, ((total - 1) // PAGE * PAGE - int(following)) // PAGE)
    progress = 1.0 if done else (min(0.99, loaded_pages * PAGE / total) if total else 0.0)
    return {"count": count, "kev_total": kev_total, "years": years, "latest_kev": latest_kev, "daily": daily,
            "sync": {"phase": "ready" if done else "backfill" if total else "pending", "progress": round(progress, 3),
                     "nvd_total": total or None, "synced_at": state.get("synced_at") if done else None,
                     "running": _sync["running"], "error": _sync["error"]}}
