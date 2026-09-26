"""Base local de CVE: copia de NVD en SQLite con búsqueda de texto, KEV y EPSS.

El tracker consulta esta base, nunca NVD en vivo: las búsquedas son instantáneas y
no dependen del límite de NVD (5 peticiones cada 30 s sin API key). Un hilo la llena
en segundo plano:

1. **Carga inicial** de la más reciente a la más antigua, por páginas, reanudable tras
   reiniciar: lo de este año está disponible en minutos aunque el histórico tarde más.
2. **Actualización incremental** por fecha de modificación (`lastModStartDate`), en
   ventanas de hasta 120 días, que es lo que admite NVD.
3. **KEV y EPSS** se vuelcan a sus tablas cuando cambia el fichero descargado.

Solo viajan a NVD rangos de índices y de fechas; ningún dato del cliente. La API key
opcional (`TAMANDUA_NVD_API_KEY`) va en cabecera y nunca se registra.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

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
SEVERITIES = ("critical", "high", "medium", "low", "none")
SORTS = {"published": "c.published DESC", "score": "c.score IS NULL, c.score DESC, c.published DESC",
         "epss": "e.score IS NULL, e.score DESC, c.published DESC"}
_CVE_PREFIX = re.compile(r"(?i)cve-\d{4}(?:-\d{0,7})?")
_schema_lock = threading.Lock()
_sync = {"running": False, "error": None}

SCHEMA = """
CREATE TABLE IF NOT EXISTS cves (
    id TEXT PRIMARY KEY, year INTEGER NOT NULL, published TEXT, modified TEXT, status TEXT,
    severity TEXT, score REAL, vector TEXT, version TEXT, description TEXT, cwe TEXT, refs TEXT
);
CREATE INDEX IF NOT EXISTS cves_published ON cves(published DESC);
CREATE INDEX IF NOT EXISTS cves_year ON cves(year, published DESC);
CREATE INDEX IF NOT EXISTS cves_severity ON cves(severity, published DESC);
CREATE VIRTUAL TABLE IF NOT EXISTS cves_fts USING fts5(id, description, content='cves', content_rowid='rowid',
                                                       tokenize='unicode61 remove_diacritics 2');
CREATE TRIGGER IF NOT EXISTS cves_ai AFTER INSERT ON cves BEGIN
    INSERT INTO cves_fts(rowid, id, description) VALUES (new.rowid, new.id, new.description);
END;
CREATE TRIGGER IF NOT EXISTS cves_au AFTER UPDATE ON cves BEGIN
    INSERT INTO cves_fts(cves_fts, rowid, id, description) VALUES ('delete', old.rowid, old.id, old.description);
    INSERT INTO cves_fts(rowid, id, description) VALUES (new.rowid, new.id, new.description);
END;
CREATE TABLE IF NOT EXISTS kev (id TEXT PRIMARY KEY, date_added TEXT, due_date TEXT, ransomware INTEGER, name TEXT);
CREATE INDEX IF NOT EXISTS kev_added ON kev(date_added DESC);
CREATE TABLE IF NOT EXISTS epss (id TEXT PRIMARY KEY, score REAL, percentile REAL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT);
"""


def _path(data_dir: Path) -> Path:
    return data_dir / "feeds" / "cves.sqlite"


def connect(data_dir: Path) -> sqlite3.Connection:
    path = _path(data_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=NORMAL")
    with _schema_lock:
        connection.executescript(SCHEMA)
    return connection


def _get_state(connection: sqlite3.Connection, key: str) -> str | None:
    row = connection.execute("SELECT value FROM state WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else None


def _set_state(connection: sqlite3.Connection, key: str, value) -> None:
    connection.execute("INSERT INTO state(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                       (key, None if value is None else str(value)))


# --- ingesta ----------------------------------------------------------------------------

def parse_entry(entry: dict) -> tuple | None:
    """Una entrada de NVD 2.0 a una fila. La métrica más moderna disponible manda: 4.0, 3.1, 3.0, 2."""
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
    # Las 10 primeras referencias con su etiqueta principal: el detalle completo sigue en NVD y la base no se dispara.
    references = [{"url": item["url"][:500], "tags": (item.get("tags") or [])[:1]} for item in cve.get("references", [])
                  if isinstance(item.get("url"), str) and item["url"].startswith(("https://", "http://"))][:MAX_REFERENCES]
    return (identifier, int(identifier[4:8]), cve.get("published"), cve.get("lastModified"), cve.get("vulnStatus"),
            severity if severity in SEVERITIES else None, score if isinstance(score, (int, float)) else None,
            vector, version, description[:4000], ",".join(cwes) or None, json.dumps(references, ensure_ascii=False, separators=(",", ":")))


def upsert(connection: sqlite3.Connection, entries: list[dict]) -> int:
    rows = [row for row in (parse_entry(entry) for entry in entries) if row]
    connection.executemany(
        """INSERT INTO cves(id, year, published, modified, status, severity, score, vector, version, description, cwe, refs)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(id) DO UPDATE SET published = excluded.published, modified = excluded.modified,
             status = excluded.status, severity = excluded.severity, score = excluded.score, vector = excluded.vector,
             version = excluded.version, description = excluded.description, cwe = excluded.cwe, refs = excluded.refs""", rows)
    return len(rows)


def _nvd_get(params: dict) -> dict:
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    key = os.environ.get("TAMANDUA_NVD_API_KEY", "").strip()
    if key:
        headers["apiKey"] = key
    with urlopen(Request(f"{NVD_URL}?{urlencode(params)}", headers=headers), timeout=120) as response:
        body = response.read(MAX_BODY + 1)
    if len(body) > MAX_BODY:
        raise ValueError("NVD response too large")
    return json.loads(body)


def pause() -> float:
    # Límite público de NVD: 5 peticiones / 30 s sin key, 50 / 30 s con key.
    return 0.8 if os.environ.get("TAMANDUA_NVD_API_KEY", "").strip() else 6.5


def _stamp(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%S.000")


def sync_step(data_dir: Path, *, fetch=None, now: datetime | None = None) -> str:
    """Un paso de sincronización (una petición a NVD). Devuelve qué hizo: backfill, incremental o idle."""
    fetch = fetch or _nvd_get
    now = now or datetime.now(timezone.utc)
    connection = connect(data_dir)
    try:
        if _get_state(connection, "backfill_done") != "1":
            following = _get_state(connection, "backfill_next")
            if following is None:
                total = int(fetch({"resultsPerPage": 1}).get("totalResults") or 0)
                with connection:
                    _set_state(connection, "backfill_total", total)
                    _set_state(connection, "backfill_next", max(0, (total - 1) // PAGE * PAGE))
                    _set_state(connection, "synced_at", now.isoformat())  # lo modificado durante la carga lo recoge el incremental
                return "backfill"
            start = int(following)
            payload = fetch({"resultsPerPage": PAGE, "startIndex": start})
            with connection:
                upsert(connection, payload.get("vulnerabilities") or [])
                if start <= 0:
                    _set_state(connection, "backfill_done", "1")
                    _set_state(connection, "backfill_next", None)
                else:
                    _set_state(connection, "backfill_next", start - PAGE)
            return "backfill"
        since = datetime.fromisoformat(_get_state(connection, "synced_at") or now.isoformat())
        if (now - since).total_seconds() < SYNC_EVERY:
            return "idle"
        start_at = since - timedelta(minutes=5)
        end_at = min(now, start_at + timedelta(days=WINDOW_DAYS))
        offset = int(_get_state(connection, "incremental_index") or 0)
        payload = fetch({"lastModStartDate": _stamp(start_at), "lastModEndDate": _stamp(end_at),
                         "resultsPerPage": PAGE, "startIndex": offset})
        with connection:
            upsert(connection, payload.get("vulnerabilities") or [])
            if offset + PAGE < int(payload.get("totalResults") or 0):
                _set_state(connection, "incremental_index", offset + PAGE)
            else:
                _set_state(connection, "incremental_index", 0)
                _set_state(connection, "synced_at", end_at.isoformat())
        return "incremental"
    finally:
        connection.close()


def load_signals(data_dir: Path, feeds: dict) -> None:
    """Vuelca KEV y EPSS a la base cuando cambió la versión descargada."""
    kev, epss = feeds.get("kev") or {}, feeds.get("epss") or {}
    kev_version = str((kev.get("__meta__") or {}).get("version") or "") + f":{len(kev)}"
    epss_version = str((epss.get("__meta__") or {}).get("header") or "") + f":{len(epss)}"
    connection = connect(data_dir)
    try:
        with connection:
            if len(kev) > 1 and _get_state(connection, "kev_version") != kev_version:
                connection.execute("DELETE FROM kev")
                connection.executemany("INSERT OR REPLACE INTO kev VALUES (?, ?, ?, ?, ?)",
                                       [(key, item.get("date_added"), item.get("due_date"), int(bool(item.get("ransomware"))), item.get("name"))
                                        for key, item in kev.items() if key != "__meta__"])
                _set_state(connection, "kev_version", kev_version)
            if len(epss) > 1 and _get_state(connection, "epss_version") != epss_version:
                connection.execute("DELETE FROM epss")
                connection.executemany("INSERT OR REPLACE INTO epss VALUES (?, ?, ?)",
                                       [(key, value[0], value[1]) for key, value in epss.items() if key != "__meta__"])
                _set_state(connection, "epss_version", epss_version)
    finally:
        connection.close()


class Syncer:
    """Hilo que mantiene la base al día. Solo lo arranca `serve`; se puede apagar con TAMANDUA_CVE_SYNC=off."""

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, name="tamandua-cve-sync", daemon=True)

    def start(self) -> None:
        if os.environ.get("TAMANDUA_CVE_SYNC", "on").lower() in ("off", "0", "false", "no"):
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
            except (HTTPError, URLError, TimeoutError, OSError, ValueError, sqlite3.Error) as error:
                # Sin detalles de la petición: la URL podría acabar en logs con parámetros; la key va en cabecera.
                _sync["error"] = type(error).__name__
                _log.warning("cve_sync_failed", extra={"reason": type(error).__name__})
                delay, backoff = backoff, min(backoff * 2, 900)
            self._stop.wait(delay)
        _sync["running"] = False


# --- consulta -----------------------------------------------------------------------------

def _fts_query(text: str) -> str | None:
    words = re.findall(r"[A-Za-z0-9]+", text)[:8]
    return " ".join(f'"{word}"*' for word in words) or None


def _item(row: sqlite3.Row) -> dict:
    return {"id": row["id"], "published": row["published"], "severity": row["severity"], "score": row["score"],
            "version": row["version"], "description": (row["description"] or "")[:400], "status": row["status"],
            "kev": row["kev_added"] is not None, "epss": row["epss"], "epss_percentile": row["epss_percentile"]}


SELECT = """SELECT c.id, c.published, c.severity, c.score, c.version, c.description, c.status,
                   k.date_added AS kev_added, e.score AS epss, e.percentile AS epss_percentile
            FROM cves c LEFT JOIN kev k ON k.id = c.id LEFT JOIN epss e ON e.id = c.id"""


def search(data_dir: Path, *, query: str = "", severity: str | None = None, kev: bool = False, year: int | None = None,
           sort: str = "published", limit: int = 25, offset: int = 0, only: frozenset[str] | None = None,
           mine: frozenset[str] = frozenset()) -> dict:
    """Búsqueda paginada. Todo va parametrizado; el texto libre pasa por FTS5 con palabras saneadas.

    `only` restringe a esos CVE (p. ej. los abiertos en tus activos); `mine` solo marca cada fila con `affects`."""
    clauses, params = ["(c.status IS NULL OR c.status != 'Rejected')"], []
    join = ""
    if only is not None:
        # Un único parámetro JSON, sea cual sea el tamaño del conjunto (sin tope de variables de SQLite); el JOIN
        # recorre esa lista y busca cada CVE por clave primaria en vez de recorrer la tabla entera.
        join = " JOIN json_each(?) mine ON mine.value = c.id"
        params.append(json.dumps(sorted(only)))
    text = query.strip()
    if _CVE_PREFIX.fullmatch(text):
        clauses.append("c.id LIKE ? ESCAPE '\\'")
        params.append(text.upper().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
    elif text:
        match = _fts_query(text)
        if match:
            join += " JOIN cves_fts f ON f.rowid = c.rowid"
            clauses.append("cves_fts MATCH ?")
            params.append(match)
    if severity == "none":
        clauses.append("(c.severity IS NULL OR c.severity = 'none')")  # sin puntuar aún, o CVSS 0
    elif severity:
        clauses.append("c.severity = ?")
        params.append(severity)
    if kev:
        clauses.append("k.id IS NOT NULL")
    if year:
        clauses.append("c.year = ?")
        params.append(year)
    where = " WHERE " + " AND ".join(clauses)
    base = SELECT.replace("FROM cves c", f"FROM cves c{join}") + where
    # El total no necesita EPSS; KEV solo si se filtra por él.
    counting = f"SELECT COUNT(*) FROM cves c{join}" + (" LEFT JOIN kev k ON k.id = c.id" if kev else "") + where
    connection = connect(data_dir)
    try:
        total = connection.execute(counting, params).fetchone()[0]
        # Solo se interpolan fragmentos constantes y la columna de orden sale de la lista blanca SORTS
        # (la ruta rechaza cualquier otro valor); todo dato del usuario va como parámetro «?».
        rows = connection.execute(f"{base} ORDER BY {SORTS[sort]} LIMIT ? OFFSET ?", [*params, limit, offset]).fetchall()  # nosemgrep: appsec.py.sql-string-building
    finally:
        connection.close()
    return {"items": [{**_item(row), "affects": row["id"] in mine} for row in rows], "total": total, "limit": limit, "offset": offset}


def detail(data_dir: Path, identifier: str) -> dict | None:
    connection = connect(data_dir)
    try:
        row = connection.execute(SELECT.replace("c.status", "c.status, c.vector, c.cwe, c.refs, c.modified, k.due_date, k.ransomware, k.name AS kev_name")
                                 + " WHERE c.id = ?", (identifier,)).fetchone()
        if row is None:
            kev_row = connection.execute("SELECT * FROM kev WHERE id = ?", (identifier,)).fetchone()
            epss_row = connection.execute("SELECT * FROM epss WHERE id = ?", (identifier,)).fetchone()
            if not kev_row and not epss_row:
                return None
            return {"id": identifier, "published": None, "severity": None, "score": None, "version": None, "status": None,
                    "description": (kev_row["name"] if kev_row else None) or msg("intel.cve.not_in_local_copy"),
                    "kev": bool(kev_row), "kev_detail": dict(kev_row) if kev_row else None,
                    "epss": epss_row["score"] if epss_row else None, "epss_percentile": epss_row["percentile"] if epss_row else None,
                    "vector": None, "cwe": [], "references": [], "modified": None}
    finally:
        connection.close()
    item = _item(row)
    item.update(description=row["description"], vector=row["vector"], modified=row["modified"],
                cwe=(row["cwe"] or "").split(",")[:MAX_CWES] if row["cwe"] else [], references=json.loads(row["refs"] or "[]")[:MAX_REFERENCES],
                kev_detail={"date_added": row["kev_added"], "due_date": row["due_date"], "ransomware": bool(row["ransomware"]),
                            "name": row["kev_name"]} if row["kev_added"] else None)
    return item


def overview(data_dir: Path, *, now: datetime | None = None) -> dict:
    """Lo que acompaña al tracker: estado de la carga, años, últimos KEV y publicados por día y severidad."""
    now = now or datetime.now(timezone.utc)
    connection = connect(data_dir)
    try:
        count = connection.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
        years = [dict(row) for row in connection.execute(
            "SELECT year, COUNT(*) AS count FROM cves WHERE status IS NULL OR status != 'Rejected' GROUP BY year ORDER BY year DESC")]
        latest_kev = [{"id": row["id"], "date_added": row["date_added"], "name": row["name"], "ransomware": bool(row["ransomware"]),
                       "severity": row["severity"], "score": row["score"]} for row in connection.execute(
            "SELECT k.id, k.date_added, k.name, k.ransomware, c.severity, c.score FROM kev k LEFT JOIN cves c ON c.id = k.id "
            "ORDER BY k.date_added DESC, k.id DESC LIMIT 8")]
        since = (now - timedelta(days=30)).strftime("%Y-%m-%d")
        daily = [dict(row) for row in connection.execute(
            "SELECT substr(published, 1, 10) AS day, COALESCE(severity, 'none') AS severity, COUNT(*) AS count FROM cves "
            "WHERE published >= ? AND (status IS NULL OR status != 'Rejected') GROUP BY day, severity ORDER BY day", (since,))]
        state = {row["key"]: row["value"] for row in connection.execute("SELECT key, value FROM state")}
        kev_total = connection.execute("SELECT COUNT(*) FROM kev").fetchone()[0]
    finally:
        connection.close()
    total = int(state.get("backfill_total") or 0)
    following = state.get("backfill_next")
    done = state.get("backfill_done") == "1"
    loaded_pages = 0 if following is None else max(0, ((total - 1) // PAGE * PAGE - int(following)) // PAGE)
    progress = 1.0 if done else (min(0.99, loaded_pages * PAGE / total) if total else 0.0)
    return {"count": count, "kev_total": kev_total, "years": years, "latest_kev": latest_kev, "daily": daily,
            "sync": {"phase": "ready" if done else "backfill" if total else "pending", "progress": round(progress, 3),
                     "nvd_total": total or None, "synced_at": state.get("synced_at") if done else None,
                     "running": _sync["running"], "error": _sync["error"]}}
