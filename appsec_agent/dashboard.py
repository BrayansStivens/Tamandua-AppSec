"""Agregados del panel: qué está abierto, qué se corrigió, qué se explota y dónde.

"Abierto" es lo que hay en la última ejecución de cada activo menos lo que el
triage descartó (falso positivo o riesgo aceptado vigente); "corregido" es una
huella que estaba en una ejecución anterior de ese activo y ya no aparece en la
última. Lo descartado se cuenta aparte para que no desaparezca sin rastro.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .kinds import FULL_SCANS
from .advisories import load_feeds, load_recent_cves
from .assets import asset_key
from .store import list_runs, load_run
from .triage import annotate, is_active, load as load_triage

SEVERITIES = ("critical", "high", "medium", "low")
CWE_NAMES = {
    79: "Cross-site scripting", 89: "Inyección SQL", 78: "Inyección de comandos", 22: "Path traversal",
    502: "Deserialización insegura", 798: "Credenciales embebidas", 295: "Validación de certificado",
    918: "SSRF", 601: "Redirección abierta", 347: "Verificación de firma", 327: "Criptografía débil",
    328: "Hash débil", 916: "Hash de contraseña débil", 95: "Eval de código", 1333: "ReDoS", 1321: "Prototype pollution",
    400: "Consumo de recursos sin límite", 770: "Asignación sin límites", 20: "Validación de entrada", 200: "Exposición de información",
    287: "Autenticación incorrecta", 352: "CSRF", 611: "XXE", 94: "Inyección de código", 1104: "Componente vulnerable",
    285: "Autorización incorrecta", 306: "Sin autenticación", 74: "Inyección", 1336: "Inyección de plantilla", 915: "Asignación masiva",
}


def _day(stamp: str) -> str:
    return stamp[:10]


def _score(open_by_severity: dict, kev: int = 0, high_epss: int = 0) -> dict:
    """Curva explícita: nunca cae a 0 de golpe y pesa más lo explotable que lo grave.

    Es un resumen, no una medida: la fórmula se muestra al lado para que nadie la
    confunda con una certificación.
    """
    import math
    risk = (8 * open_by_severity.get("critical", 0) + 3 * open_by_severity.get("high", 0)
            + 0.8 * open_by_severity.get("medium", 0) + 0.1 * open_by_severity.get("low", 0) + 15 * kev + 5 * high_epss)
    return {"value": round(100 * math.exp(-risk / 150), 1), "risk": round(risk, 1),
            "formula": "100·e^(−riesgo/150); riesgo = 8·críticos + 3·altos + 0,8·medios + 0,1·bajos + 15·en KEV + 5·EPSS ≥ 10 %"}


def compute(data_dir: Path, days: int = 30) -> dict:
    now = datetime.now(timezone.utc)
    since = now - timedelta(days=days)
    rows = list_runs(data_dir)
    records = []
    decisions = load_triage(data_dir)
    triage_totals: Counter = Counter()
    advisories: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        if row["type"] == "advisory_watch" and row["status"] == "completed":
            # Avisos publicados después de un análisis: cuentan hasta que el siguiente análisis completo manda.
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
        # Por identidad estable: un repositorio renombrado sigue siendo el mismo activo.
        by_asset[asset_key(record)].append(record)

    first_seen: dict[str, tuple[str, dict, str]] = {}
    fixed: dict[str, tuple[str, str]] = {}
    open_findings: list[tuple[str, dict]] = []
    top_assets = []
    for key, runs in by_asset.items():
        asset = runs[-1]["source"]["name"]  # el nombre más reciente
        # Un escaneo incompleto no demuestra que algo se corrigió ni representa el estado del repositorio:
        # cuentan los completos (y solo si no hay ninguno, el más reciente, para no esconder el activo).
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
            for offset in range(364, -1, -1)]

    # Los feeds solo se leen si alguna ejecución ya los descargó: abrir el panel no sale a la red.
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
    # NVD entrega como mucho 2000 por página; el total real viene en la cabecera del feed.
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
        -((pair[1].get("epss") or {}).get("score") or 0)))[:8]
    latest = records[-1] if records else None
    return {
        "window_days": days, "generated_at": now.isoformat(),
        "kpis": {"security_score": _score(open_by_severity, len(kev_items), len(epss_items)), "open": {"total": open_total, **{level: open_by_severity.get(level, 0) for level in SEVERITIES}},
                 "found_in_window": len(in_window), "fixed_in_window": len(fixed_in_window), "fix_rate": fix_rate,
                 "mttr_days": round(sum(mttr) / len(mttr), 1) if mttr else None,
                 "runs_in_window": sum(1 for row in rows if row["created_at"] >= since.isoformat()),
                 "assets": len(by_asset), "kev_open": len(kev_items),
                 "triage": {status: triage_totals.get(status, 0) for status in ("open", "in_progress", "false_positive", "accepted")}},
        "issues_over_time": [{"day": _day((now - timedelta(days=offset)).isoformat()),
                              **{level: over_time.get(_day((now - timedelta(days=offset)).isoformat()), Counter()).get(level, 0) for level in SEVERITIES}}
                             for offset in range(days, -1, -1)],
        "open_vs_fixed": open_vs_fixed,
        "top_assets": top_assets[:10],
        "by_cwe": [{"cwe": cwe, "name": CWE_NAMES.get(cwe, f"CWE-{cwe}"), "count": count} for cwe, count in cwe_counter.most_common(8)],
        "exploitability": {"kev": kev_items[:10], "high_epss": epss_items[:10]},
        "activity": year,
        "recent_runs": rows[:8],
        "top_issues": [{"title": finding["title"], "severity": finding["severity"], "asset": asset,
                        "action": (finding.get("priority") or {}).get("action"), "run_id": next((r["last_run"] for r in top_assets if r["name"] == asset), None),
                        "epss": (finding.get("epss") or {}).get("score"), "kev": bool(finding.get("kev")), "fingerprint": finding["fingerprint"]}
                       for asset, finding in top_issues],
        "kev_news": kev_news, "cve_news": cve_news,
        "tools": (latest or {}).get("summary", {}).get("tools", []),
    }
