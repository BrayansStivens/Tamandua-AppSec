"""EUVD (European Vulnerability Database, ENISA) como segunda fuente cuando NVD no puntúa un CVE.

Desde abril de 2026 NVD solo enriquece una parte de los CVE (KEV, software federal y crítico): muchos quedan sin
CVSS. EUVD, mantenida por ENISA por mandato de NIS2, publica puntuación, vector y si la vulnerabilidad se explota
activamente. Se consulta bajo demanda, solo para el CVE que se está mirando (el identificador es público; no sale
nada del código ni de los hallazgos), con caché en `data/feeds/euvd-cache.json`. `TAMANDUA_EUVD=off` lo apaga.
"""

from __future__ import annotations

import json
import os
import re
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote
from urllib.request import Request, urlopen

API = "https://euvdservices.enisa.europa.eu/api/search?text={cve}&size=5"
PAGE = "https://euvd.enisa.europa.eu/vulnerability/{id}"
CVE = re.compile(r"CVE-\d{4}-\d{4,7}")
FOUND_TTL, MISSING_TTL = timedelta(days=7), timedelta(days=1)
MAX_CACHE = 5000
_lock = threading.Lock()


def enabled() -> bool:
    return os.environ.get("TAMANDUA_EUVD", "on").lower() not in ("off", "0", "false", "no")


def _cache_path(data_dir: Path) -> Path:
    return data_dir / "feeds" / "euvd-cache.json"


def _date(value) -> str | None:
    try:
        return datetime.strptime(str(value), "%b %d, %Y, %I:%M:%S %p").date().isoformat()
    except (TypeError, ValueError):
        return None


def severity(score: float | None) -> str | None:
    if score is None:
        return None
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low" if score > 0 else "none"


def parse(payload: dict, cve: str) -> dict | None:
    """El aviso de EUVD que corresponde a este CVE (por alias), con lo que nos sirve."""
    for item in (payload or {}).get("items") or []:
        aliases = {alias.strip() for alias in str(item.get("aliases") or "").split("\n") if alias.strip()}
        if cve not in aliases:
            continue
        try:
            score = float(item["baseScore"]) if item.get("baseScore") not in (None, "") else None
        except (TypeError, ValueError):
            score = None
        identifier = str(item.get("id") or "")
        return {"id": identifier, "url": PAGE.format(id=quote(identifier, safe="-")) if identifier else None,
                "score": score, "version": str(item.get("baseScoreVersion") or "") or None,
                "vector": str(item.get("baseScoreVector") or "") or None, "severity": severity(score),
                "exploited_since": _date(item.get("exploitedSince")), "published": _date(item.get("datePublished"))}
    return None


def _fetch(cve: str) -> dict | None:
    request = Request(API.format(cve=cve), headers={"User-Agent": "Tamandua", "Accept": "application/json"})
    with urlopen(request, timeout=5) as response:  # nosemgrep: URL fija de ENISA; solo el CVE validado va en la consulta
        return parse(json.loads(response.read(2_000_000)), cve)


def lookup(data_dir: Path, cve: str, *, fetch=None, now: datetime | None = None) -> dict | None:
    """El dato de EUVD para un CVE, de la caché o de la API. None si no existe, está apagado o no responde."""
    if not CVE.fullmatch(cve or "") or not enabled():
        return None
    now = now or datetime.now(timezone.utc)
    path = _cache_path(data_dir)
    with _lock:
        try:
            cache = json.loads(path.read_text(encoding="utf-8"))
            cache = cache if isinstance(cache, dict) else {}
        except (FileNotFoundError, ValueError, OSError):
            cache = {}
    entry = cache.get(cve) if isinstance(cache.get(cve), dict) else None
    if entry:
        try:
            fresh = now - datetime.fromisoformat(entry["at"]) < (FOUND_TTL if entry.get("item") else MISSING_TTL)
        except (KeyError, TypeError, ValueError):
            fresh = False
        if fresh:
            return entry.get("item")
    try:
        item = (fetch or _fetch)(cve)
    except (OSError, ValueError):
        return entry.get("item") if entry else None  # sin red: lo último que se supo
    with _lock:
        try:  # se relee: otra consulta pudo guardar mientras se esperaba a la red
            cache = json.loads(path.read_text(encoding="utf-8"))
            cache = cache if isinstance(cache, dict) else {}
        except (FileNotFoundError, ValueError, OSError):
            cache = {}
        cache[cve] = {"at": now.isoformat(), "item": item}
        if len(cache) > MAX_CACHE:
            for stale in sorted(cache, key=lambda key: str((cache[key] or {}).get("at")))[: len(cache) - MAX_CACHE]:
                cache.pop(stale, None)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(cache, ensure_ascii=False), encoding="utf-8")
        os.replace(temporary, path)
    return item
