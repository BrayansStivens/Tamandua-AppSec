"""Enriquecimiento de avisos de dependencias: de un identificador a una decisión.

`querybatch` de OSV solo dice *qué* aviso afecta a una versión. Aquí se pide el
detalle de cada uno y se cruza con dos feeds públicos para que cada hallazgo
traiga lo que un equipo necesita para actuar: resumen, CVSS calculado, versión
corregida para *esa* línea de versiones, si está en explotación activa (CISA
KEV), probabilidad de explotación (EPSS) y una prioridad cuyos factores se ven.

Los feeds se descargan en bloque y se guardan a diario: no se consulta a nadie
CVE por CVE, así que nadie se entera de qué dependencias tienen los clientes.
"""

from __future__ import annotations

import csv
import gzip
import hashlib
import io
import json
import math
import os
import re
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from tamandua.modules.intel import data_sources
from tamandua.shared.i18n import msg
from tamandua.version import USER_AGENT

OSV_VULN = "https://api.osv.dev/v1/vulns/"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_TTL = 12 * 3600
FEED_TTL = 24 * 3600
MAX_DETAILS = 80          # avisos distintos cuyo detalle se pide por ejecución
_details_cache: dict[str, dict] = {}
_feed_cache: dict[str, tuple[float, dict]] = {}


# --- CVSS v3.x: el score se calcula del vector, no se copia de nadie --------------

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(value: float) -> float:
    integer = round(value * 100_000)
    if integer % 10_000 == 0:
        return integer / 100_000
    return (math.floor(integer / 10_000) + 1) / 10


def cvss3_base_score(vector: str) -> float | None:
    """Base score CVSS 3.0/3.1 según la especificación; None si el vector no es válido."""
    match = re.fullmatch(r"CVSS:3\.[01]/(.+)", vector.strip())
    if not match:
        return None
    parts = dict(item.split(":", 1) for item in match.group(1).split("/") if ":" in item)
    try:
        changed = parts["S"] == "C"
        privileges = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[parts["PR"]]
        iss = 1 - (1 - _CIA[parts["C"]]) * (1 - _CIA[parts["I"]]) * (1 - _CIA[parts["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
        exploitability = 8.22 * _AV[parts["AV"]] * _AC[parts["AC"]] * privileges * _UI[parts["UI"]]
    except KeyError:
        return None
    if impact <= 0:
        return 0.0
    total = 1.08 * (impact + exploitability) if changed else impact + exploitability
    return _roundup(min(total, 10))


def severity_from_score(score: float | None, label: str | None = None) -> str:
    if score is not None:
        return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low" if score > 0 else "info"
    return {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}.get(
        (label or "").upper(), "medium")


# --- versiones: comparación tolerante para elegir la versión corregida correcta -----

def _version_key(version: str) -> tuple:
    text = version.strip().lstrip("vV")
    release = re.match(r"[0-9]+(?:\.[0-9]+)*", text)
    numbers = [int(part) for part in release.group(0).split(".")] if release else [0]
    rest = text[release.end():] if release else text
    # Una pre-release (1.0.0-rc1) va antes que su versión final; un post (1.0.0.post1) después.
    stage = 0 if re.match(r"^[-.]?(a|b|rc|alpha|beta|dev|pre)", rest, re.IGNORECASE) else 2 if "post" in rest else 1
    return (tuple(numbers + [0] * (6 - len(numbers))), stage)


def compare_versions(left: str, right: str) -> int:
    key_left, key_right = _version_key(left), _version_key(right)
    return (key_left > key_right) - (key_left < key_right)


def affected_range(advisory: dict, ecosystem: str, name: str, installed: str) -> dict:
    """El rango que contiene la versión instalada, con su versión corregida.

    Un aviso suele traer un rango por línea de versiones (9.x, 10.x…). Decir
    "actualiza a 10.2.3" a quien usa 9.0.5 es una recomendación equivocada.
    """
    ranges = []
    for entry in advisory.get("affected", []):
        package = entry.get("package") or {}
        if (package.get("ecosystem") or "").lower() != ecosystem.lower() or (package.get("name") or "") != name:
            continue
        for block in entry.get("ranges", []):
            if block.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            introduced, fixed = "0", None
            for event in block.get("events", []):
                introduced = event.get("introduced", introduced)
                fixed = event.get("fixed", fixed) or event.get("last_affected") and None or fixed
            ranges.append({"introduced": introduced, "fixed": fixed})
    matching = [item for item in ranges
                if compare_versions(item["introduced"], installed) <= 0
                and (item["fixed"] is None or compare_versions(installed, item["fixed"]) < 0)]
    if matching:
        with_fix = [item for item in matching if item["fixed"]]
        chosen = min(with_fix, key=lambda item: _version_key(item["fixed"])) if with_fix else matching[0]
    else:
        later = [item for item in ranges if item["fixed"] and compare_versions(item["fixed"], installed) > 0]
        chosen = min(later, key=lambda item: _version_key(item["fixed"])) if later else {"introduced": "0", "fixed": None}
    return {"introduced": chosen["introduced"], "fixed": chosen["fixed"]}


# --- OSV: detalle de cada aviso -----------------------------------------------------

def fetch_advisory(identifier: str) -> dict | None:
    if not re.fullmatch(r"[A-Za-z0-9-]{5,80}", identifier):
        return None
    if identifier in _details_cache:
        return _details_cache[identifier]
    request = Request(OSV_VULN + identifier, headers={"Accept": "application/json", "User-Agent": USER_AGENT})
    try:
        with urlopen(request, timeout=15) as response:
            body = response.read(1_000_001)
        if len(body) > 1_000_000:
            return None
        payload = json.loads(body)
    except (HTTPError, URLError, TimeoutError, OSError, ValueError):
        return None
    if not isinstance(payload, dict) or payload.get("id") != identifier:
        return None
    _details_cache[identifier] = payload
    return payload


def summarize_advisory(payload: dict) -> dict:
    vectors = [item.get("score", "") for item in payload.get("severity", []) if isinstance(item, dict)]
    v3 = next((vector for vector in vectors if vector.startswith("CVSS:3")), None)
    score = cvss3_base_score(v3) if v3 else None
    specific = payload.get("database_specific") or {}
    aliases = [alias for alias in payload.get("aliases", []) if isinstance(alias, str)]
    cwes = []
    for raw in specific.get("cwe_ids", []) or []:
        match = re.fullmatch(r"CWE-(\d+)", str(raw))
        if match:
            cwes.append(int(match.group(1)))
    references = [item["url"] for item in payload.get("references", [])
                  if isinstance(item, dict) and isinstance(item.get("url"), str) and item["url"].startswith("https://")][:8]
    return {"id": payload["id"], "aliases": aliases, "summary": (payload.get("summary") or "").strip()[:300],
            "details": (payload.get("details") or "").strip()[:2_000],
            "cvss_vector": v3 or (vectors[0] if vectors else None), "cvss_score": score,
            "severity": severity_from_score(score, specific.get("severity")),
            "cwe": cwes, "published": payload.get("published"), "modified": payload.get("modified"),
            "references": references}


# --- feeds públicos con caché diaria -------------------------------------------------

def _feed(name: str, url: str, data_dir: Path, parse) -> dict:
    cached = _feed_cache.get(name)
    if cached and time.time() - cached[0] < FEED_TTL:
        return cached[1]
    folder = data_dir / "feeds"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / name
    fresh = path.is_file() and time.time() - path.stat().st_mtime < FEED_TTL
    if not fresh:
        try:
            with urlopen(Request(url, headers={"User-Agent": USER_AGENT}), timeout=60) as response:
                body = response.read(60_000_001)
            if len(body) > 60_000_000:
                raise ValueError("feed too large")
            temporary = path.with_suffix(path.suffix + ".tmp")
            temporary.write_bytes(body)
            os.replace(temporary, path)
        except (HTTPError, URLError, TimeoutError, OSError, ValueError):
            if not path.is_file():
                return {}
    try:
        parsed = parse(path.read_bytes())
    except (ValueError, OSError, UnicodeDecodeError, KeyError, csv.Error):
        return {}
    _feed_cache[name] = (time.time(), parsed)
    return parsed


def _parse_kev(body: bytes) -> dict:
    data = json.loads(body)
    return {"__meta__": {"version": data.get("catalogVersion"), "count": data.get("count")},
            **{item["cveID"]: {"date_added": item.get("dateAdded"), "due_date": item.get("dueDate"),
                               "ransomware": item.get("knownRansomwareCampaignUse") == "Known",
                               "name": item.get("vulnerabilityName")}
               for item in data.get("vulnerabilities", []) if isinstance(item.get("cveID"), str)}}


def _parse_epss(body: bytes) -> dict:
    text = gzip.decompress(body).decode("utf-8", errors="replace")
    lines = [line for line in text.splitlines() if not line.startswith("#")]
    meta_line = next((line for line in text.splitlines() if line.startswith("#")), "")
    scores = {}
    for row in csv.DictReader(io.StringIO("\n".join(lines))):
        try:
            scores[row["cve"]] = (float(row["epss"]), float(row["percentile"]))
        except (KeyError, ValueError):
            continue
    scores["__meta__"] = {"header": meta_line.lstrip("#")}
    return scores


def load_feeds(data_dir: Path) -> dict:
    return {"kev": _feed("kev.json", KEV_URL, data_dir, _parse_kev),
            "epss": _feed("epss.csv.gz", EPSS_URL, data_dir, _parse_epss)}


def _parse_nvd(body: bytes) -> dict:
    data = json.loads(body)
    items = []
    for entry in data.get("vulnerabilities", []):
        cve = entry.get("cve") or {}
        metrics = cve.get("metrics") or {}
        score = severity = None
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
            block = metrics.get(key)
            if block:
                cvss = (block[0].get("cvssData") or {})
                score, severity = cvss.get("baseScore"), (cvss.get("baseSeverity") or "").lower() or None
                break
        description = next((item.get("value") for item in cve.get("descriptions", []) if item.get("lang") == "en"), "")
        if isinstance(cve.get("id"), str):
            items.append({"cve": cve["id"], "published": cve.get("published"), "score": score, "severity": severity,
                          "description": (description or "")[:280]})
    items.sort(key=lambda item: item.get("published") or "", reverse=True)
    return {"__meta__": {"total": data.get("totalResults"), "fetched": data.get("timestamp")}, "items": items}


NVD_PAGE = 2000
NVD_PAUSE = 6.5  # sin API key NVD admite 5 peticiones por 30 s
_nvd_refresh = {"running": False}
_nvd_lock = __import__("threading").Lock()


def _nvd_get(params: dict) -> bytes:
    from urllib.parse import urlencode
    request = Request(f"{NVD_URL}?{urlencode(params)}", headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    with urlopen(request, timeout=60) as response:
        body = response.read(40_000_001)
    if len(body) > 40_000_000:
        raise ValueError("feed too large")
    return body


def refresh_recent_cves(data_dir: Path, *, pause: float = NVD_PAUSE, fetch=None) -> None:
    """Descarga NVD: totales de 7 y 30 días, publicados por día y la página MÁS RECIENTE de la semana.

    NVD ordena de antiguo a nuevo y corta en 2000 por página: pedir la primera página
    devolvía los 2000 más antiguos de la ventana. Por eso se pide primero el total y
    luego la última página. Solo viaja un rango de fechas; ningún dato del cliente.
    """
    from datetime import datetime, timedelta, timezone
    fetch = fetch or _nvd_get
    stamp = lambda value: value.strftime("%Y-%m-%dT%H:%M:%S.000")
    now = datetime.now(timezone.utc)
    window = lambda days, end=now: {"pubStartDate": stamp(end - timedelta(days=days)), "pubEndDate": stamp(end)}
    total = lambda params: int(json.loads(fetch({**params, "resultsPerPage": 1})).get("totalResults") or 0)
    total_7 = total(window(7))
    time.sleep(pause)
    total_30 = total(window(30))
    per_day = []
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    for offset in range(6, -1, -1):
        time.sleep(pause)
        day_start = today - timedelta(days=offset)
        day_end = min(now, day_start + timedelta(days=1))
        per_day.append({"day": day_start.date().isoformat(),
                        "count": total({"pubStartDate": stamp(day_start), "pubEndDate": stamp(day_end)})})
    time.sleep(pause)
    body = fetch({**window(7), "resultsPerPage": NVD_PAGE, "startIndex": max(0, total_7 - NVD_PAGE)})
    folder = data_dir / "feeds"
    folder.mkdir(parents=True, exist_ok=True)
    for name, content in (("nvd-recent.json", body),
                          ("nvd-counts.json", json.dumps({"total_7d": total_7, "total_30d": total_30, "per_day": per_day,
                                                          "fetched_at": now.isoformat(timespec="seconds")}).encode())):
        temporary = (folder / name).with_suffix(".tmp")
        temporary.write_bytes(content)
        os.replace(temporary, folder / name)
    _feed_cache.pop("nvd-recent", None)


def _refresh_in_background(data_dir: Path) -> None:
    import threading
    with _nvd_lock:
        if _nvd_refresh["running"]:
            return
        _nvd_refresh["running"] = True

    def run():
        try:
            refresh_recent_cves(data_dir)
        except (HTTPError, URLError, TimeoutError, OSError, ValueError, KeyError):
            pass  # se reintenta en la siguiente consulta; mientras, vale lo último descargado
        finally:
            _nvd_refresh["running"] = False
    threading.Thread(target=run, name="tamandua-nvd", daemon=True).start()


def load_recent_cves(data_dir: Path, days: int = 7) -> dict:
    """Lo último descargado de NVD. Si caducó, se refresca en segundo plano: el panel nunca espera a NVD."""
    folder = data_dir / "feeds"
    path, counts_path = folder / "nvd-recent.json", folder / "nvd-counts.json"
    stale = not counts_path.is_file() or time.time() - counts_path.stat().st_mtime >= NVD_TTL
    if stale:
        _refresh_in_background(data_dir)
    cached = _feed_cache.get("nvd-recent")
    if cached and time.time() - cached[0] < 300 and not stale:
        return cached[1]
    try:
        parsed = _parse_nvd(path.read_bytes())
    except (FileNotFoundError, ValueError, OSError, UnicodeDecodeError, KeyError, TypeError):
        return {"__meta__": {"refreshing": _nvd_refresh["running"]}, "items": []}
    try:
        counts = json.loads(counts_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError, OSError):
        counts = {}
    parsed["__meta__"].update(total_7d=counts.get("total_7d") or parsed["__meta__"].get("total"),
                              total_30d=counts.get("total_30d"), per_day=counts.get("per_day") or [],
                              fetched_at=counts.get("fetched_at"), refreshing=_nvd_refresh["running"])
    _feed_cache["nvd-recent"] = (time.time(), parsed)
    return parsed


# --- prioridad explicable ------------------------------------------------------------

SEVERITY = {"critical": msg("intel.severity.critical"), "high": msg("intel.severity.high"), "medium": msg("intel.severity.medium"),
            "low": msg("intel.severity.low"), "info": msg("intel.severity.info")}


def prioritize(severity: str, cvss_score: float | None, kev: dict | None, epss: tuple | None, fixed: str | None) -> dict:
    """Acción SSVC-like con factores visibles: no es una nota mágica."""
    factors = []
    score = cvss_score or 0.0
    probability = epss[0] if epss else None
    if kev:
        factors.append(msg("intel.priority.kev_ransomware") if kev.get("ransomware") else msg("intel.priority.kev"))
    if probability is not None:
        factors.append(msg("intel.priority.epss", probability=f"{probability:.1%}", percentile=f"{epss[1]:.0%}"))
    if cvss_score is not None:
        factors.append(msg("intel.priority.cvss", score=cvss_score, severity=SEVERITY.get(severity, severity)))
    if fixed:
        factors.append(msg("intel.priority.fixed", version=fixed))
    else:
        factors.append(msg("intel.priority.no_fix"))
    if kev or (score >= 9 and (probability or 0) >= 0.1):
        action = "act"
    elif score >= 7 or (probability or 0) >= 0.1 or (score >= 4 and (probability or 0) >= 0.05):
        action = "attend"
    else:
        action = "track"
    return {"action": action, "factors": factors}


# --- hallazgo enriquecido -----------------------------------------------------------

def is_malicious(summary: dict) -> bool:
    """Avisos MAL-* (OpenSSF Malicious Packages, vía OSV): el paquete es código hostil, no un fallo."""
    return any(str(identifier).upper().startswith("MAL-") for identifier in [summary.get("id"), *(summary.get("aliases") or [])])


def malicious_finding(dependency: dict, summary: dict) -> dict:
    """Un paquete malicioso no se «actualiza»: se elimina y se da por comprometido lo que lo instaló."""
    name, installed, path = dependency["name"], dependency["version"], dependency["path"]
    digest = fingerprint("sca", summary["id"], dependency["ecosystem"], name, installed)
    return {"finding_id": digest[:16], "fingerprint": digest, "scanner": "sca", "rule_id": summary["id"],
            "title": msg("intel.malicious.title", package=name[:150], version=installed[:40]), "path": path, "line": 1, "severity": "critical",
            "confidence": 9, "verdict": "candidate", "malicious": True, "cwe": [506], "owasp": ["A03:2025"],
            "cve": [], "ghsa": sorted({alias for alias in summary["aliases"] if alias.startswith("GHSA-")}),
            "package": {"ecosystem": dependency["ecosystem"], "name": name, "version": installed, "fixed_version": None, "introduced": None},
            "advisory": {key: summary[key] for key in ("id", "aliases", "summary", "details", "cvss_vector", "cvss_score", "published",
                                                        "modified", "references")},
            "kev": None, "epss": None, "source": data_sources.from_osv(summary["id"]),
            "priority": {"action": "act", "factors": [msg("intel.priority.malicious")]},
            "reason": summary["summary"] or msg("intel.malicious.reason", id=summary["id"], package=name, version=installed),
            "remediation": msg("intel.malicious.remediation", package=name, version=installed, path=path)}

def fingerprint(scanner: str, rule: str, ecosystem: str, name: str, version: str) -> str:
    """Estable entre ejecuciones e independiente de la ruta: la clave para no duplicar tickets."""
    return hashlib.sha256(f"{scanner}|{rule}|{ecosystem}|{name}|{version}".encode()).hexdigest()


def dependency_finding(dependency: dict, advisory: dict, feeds: dict) -> dict:
    summary = summarize_advisory(advisory)
    version_range = affected_range(advisory, dependency["ecosystem"], dependency["name"], dependency["version"])
    cves = [alias for alias in summary["aliases"] if alias.startswith("CVE-")] + ([summary["id"]] if summary["id"].startswith("CVE-") else [])
    ghsas = [alias for alias in summary["aliases"] if alias.startswith("GHSA-")] + ([summary["id"]] if summary["id"].startswith("GHSA-") else [])
    kev = next((feeds.get("kev", {}).get(cve) for cve in cves if feeds.get("kev", {}).get(cve)), None)
    epss = next((feeds.get("epss", {}).get(cve) for cve in cves if feeds.get("epss", {}).get(cve)), None)
    fixed = version_range["fixed"]
    priority = prioritize(summary["severity"], summary["cvss_score"], kev, epss, fixed)
    name, installed, path = dependency["name"], dependency["version"], dependency["path"]
    if is_malicious(summary):
        return malicious_finding(dependency, summary)
    if fixed:
        remediation = msg("intel.dependency.update", package=name, installed=installed, version=fixed, path=path)
    else:
        remediation = msg("intel.dependency.no_fix", package=name)
    digest = fingerprint("sca", summary["id"], dependency["ecosystem"], name, installed)
    title = f"{name} {installed}: {summary['summary']}" if summary["summary"] else f"{name} {installed}: {summary['id']}"
    return {"finding_id": digest[:16], "fingerprint": digest, "scanner": "sca", "rule_id": summary["id"],
            "title": title[:200], "path": path, "line": 1, "severity": summary["severity"],
            "confidence": 8 if summary["cvss_score"] is not None else 6, "verdict": "candidate",
            "cwe": summary["cwe"], "owasp": ["A03:2025"], "cve": sorted(set(cves)), "ghsa": sorted(set(ghsas)),
            "package": {"ecosystem": dependency["ecosystem"], "name": name, "version": installed,
                        "fixed_version": fixed, "introduced": version_range["introduced"]},
            "advisory": {key: summary[key] for key in ("id", "aliases", "summary", "details", "cvss_vector",
                                                        "cvss_score", "published", "modified", "references")},
            "kev": kev, "epss": {"score": epss[0], "percentile": epss[1]} if epss else None,
            "source": data_sources.from_osv(summary["id"]),
            "priority": priority,
            "reason": summary["summary"] or msg("intel.dependency.reason", id=summary["id"], package=name, version=installed),
            "remediation": remediation}
