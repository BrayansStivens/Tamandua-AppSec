"""Ejecuciones y sus artefactos, triage, escaneos, panel, CVEs, salud y ficheros estáticos."""

from __future__ import annotations

import json
import os
import mimetypes
import re
from pathlib import Path

from tamandua.modules.runs.kinds import FINDING_RUNS
from tamandua.modules.runs import batches
from tamandua.modules.findings import exclusions
from tamandua.modules.findings import registry as findings_registry
from tamandua.modules.integrations import jira
from tamandua.modules.compliance import cra, evidence, sbom
from tamandua.modules.findings import sla
from tamandua.modules.findings import triage
from tamandua.modules.compliance import vex
from tamandua.modules.sources.assets import overview as assets_overview
from tamandua.modules.intel.advisories import load_feeds, load_recent_cves
from tamandua.modules.integrations.installations import github_installations
from tamandua.modules.sources.repositories import find_source
from tamandua.modules.scanning.plan import plan as scan_plan
from tamandua.modules.integrations.github import GitHubAppError
from tamandua.modules.reporting.pdf import render_pdf
from tamandua.modules.reporting.technical import render_technical_pdf
from tamandua.modules.reporting.audit import ReportError, render_audit_pdf, render_portfolio_pdf, validate_options
from tamandua.modules.runs.kinds import FULL_SCANS
from tamandua.modules.runs.store import artifact as store_artifact, list_runs, load_run, page_runs, render_asset_report, render_profile_report, render_repository_report
from tamandua.modules.runs.store import profile_pdf_titles, render_repository_sarif, render_tickets
from tamandua.app.api.routing import Request, problem, route
from tamandua.shared.i18n import msg, text
from tamandua.version import VERSION

STATIC_DIR = Path(__file__).resolve().parents[2] / "static"  # tamandua/app/static
PROFILE_REPORTS = ("report-soc2.md", "report-iso27001.md", "report-custom.md",
                   "report-soc2.pdf", "report-iso27001.pdf", "report-custom.pdf")


SBOM_FILE, VEX_FILE = "sbom.cdx.json", "vex.openvex.json"


def _json_file(request: Request, payload: dict, content_type: str):
    return request.send(200, json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8"), content_type)


def _artifact(request: Request, record: dict, artifact: str):
    repository = record.get("type") in FINDING_RUNS or record.get("type") == "asset_state"
    if artifact == "tickets.json" and repository:
        return request.json(200, render_tickets(record, locale=request.locale))
    if artifact in ("report.md", "report.pdf") and repository:
        if artifact.endswith(".pdf"):
            return request.send(200, render_technical_pdf(record, version=VERSION, locale=request.locale), "application/pdf")
        report = (render_asset_report(record, locale=request.locale) if record["type"] == "asset_state"
                  else render_repository_report(record, locale=request.locale))
        return request.send(200, report.encode("utf-8"), "text/markdown; charset=utf-8")
    if artifact == "findings.sarif" and repository:
        return request.send(200, json.dumps(render_repository_sarif(record, locale=request.locale), ensure_ascii=False, indent=2).encode("utf-8"),
                            "application/sarif+json")
    if artifact == SBOM_FILE and repository:
        scan = sbom.latest_scan(request.data_dir, record["source"]["id"]) if record["type"] == "asset_state" else record
        if scan is None or scan.get("type") not in FULL_SCANS or scan.get("status") != "completed":
            return request.json(404, {"error": msg("compliance.sbom.needs_full_scan")})
        return _json_file(request, sbom.cyclonedx(scan, version=VERSION, locale=request.locale), "application/vnd.cyclonedx+json")
    if artifact == VEX_FILE and repository:
        return _json_file(request, vex.openvex(record, version=VERSION, locale=request.locale), "application/json")
    if artifact in PROFILE_REPORTS:
        profile = artifact.removeprefix("report-").rsplit(".", 1)[0]
        report = render_profile_report(record, profile, request.arg("title", ""), locale=request.locale)
        if artifact.endswith(".pdf"):
            return request.send(200, render_pdf(report, **profile_pdf_titles(profile, locale=request.locale), reference=record["id"],
                                                 locale=request.locale), "application/pdf")
        return request.send(200, report.encode("utf-8"), "text/markdown; charset=utf-8")
    if artifact in ("report.md", "findings.sarif"):
        content_type = "text/markdown; charset=utf-8" if artifact == "report.md" else "application/sarif+json"
        return request.send(200, store_artifact(request.data_dir, record["id"], artifact), content_type)
    return request.json(404, {"error": msg("api.format_unavailable_run")})


@route("GET", "/", public=True, enrolment=True)
def index(request: Request):
    return _static(request, "index.html")


@route("GET", "/assets/", public=True, enrolment=True, prefix=True)
def asset(request: Request):
    if len(request.path) >= 160 or request.path.count("/") != 2:
        return request.json(404, {"error": msg("api.not_found")})
    return _static(request, request.path.lstrip("/"))


def _static(request: Request, name: str):
    target = STATIC_DIR / name
    if target.is_symlink() or not target.is_file():
        return request.json(404, {"error": msg("api.file_not_found")})
    return request.send(200, target.read_bytes(), mimetypes.guess_type(name)[0] or "application/octet-stream")


@route("GET", "/api/runs")
def runs(request: Request):
    return request.json(200, list_runs(request.data_dir))


@route("GET", "/api/runs/page")
def runs_page(request: Request):
    try:
        limit, offset = int(request.arg("limit", "25")), int(request.arg("offset", "0"))
    except ValueError:
        return request.json(400, {"error": msg("api.invalid_paging")})
    return request.json(200, page_runs(request.data_dir, limit=limit, offset=offset, status=request.arg("status") or None,
                                       kind=request.arg("type") or None, query=(request.arg("q") or "")[:100] or None,
                                       asset=(request.arg("asset") or "")[:200] or None))


@route("GET", "/api/assets/state")
def asset_state(request: Request):
    """Estado actual de un repositorio: su registro de hallazgos (escaneos y PRs), abiertos, remediados o todos."""
    key = (request.arg("key") or "")[:200]
    status = request.arg("status", "open")
    if not key or status not in ("open", "fixed", "excluded", "all"):
        return request.json(400, {"error": msg("api.invalid_repository_status")})
    view = findings_registry.view(request.data_dir, key, status=status)
    return request.json(200, jira.annotate(request.data_dir, view))


@route("GET", "/api/assets/export")
def asset_export(request: Request):
    """Exportación del estado actual; no existe un ID de ejecución para esta vista."""
    key = request.arg("key") or ""
    status = request.arg("status", "open")
    artifact = request.arg("artifact") or ""
    if not key or len(key) > 200 or status not in ("open", "fixed", "excluded", "all"):
        return request.json(400, {"error": msg("api.invalid_asset_status")})
    if artifact not in ("tickets.json", "report.md", "report.pdf", "findings.sarif", *PROFILE_REPORTS, "record.json", SBOM_FILE, VEX_FILE):
        return request.json(404, {"error": msg("api.format_unavailable")})
    if not any(row["key"] == key for row in assets_overview(request.data_dir)):
        return request.json(404, {"error": msg("api.asset_not_found")})
    # El VEX describe todas las decisiones (también lo remediado y lo descartado), sea cual sea la pestaña.
    record = jira.annotate(request.data_dir, findings_registry.view(request.data_dir, key, status="all" if artifact == VEX_FILE else status))
    if artifact == "record.json":
        return request.json(200, record)
    try:
        return _artifact(request, record, artifact)
    except ValueError as exc:
        return request.json(400, {"error": problem(exc)})


@route("POST", "/api/reports/audit", action="audit-report", body=400_000)
def audit_report(request: Request):
    """Informe de evidencia para auditoría de una ejecución o del estado de un activo, con los hallazgos elegidos.

    Mismo acceso que ver esa ejecución o ese activo. `fingerprints` acota el informe (uno, varios o los filtrados);
    sin él entran todos los del alcance."""
    payload = request.payload
    if not isinstance(payload, dict) or not set(payload) <= {"run_id", "asset", "account", "assets", "status", "fingerprints", "options"} \
            or sum(key in payload for key in ("run_id", "asset", "account", "assets")) != 1:
        return request.json(400, {"error": msg("api.audit_scope")})
    if "account" in payload or "assets" in payload:
        return _portfolio_report(request, payload)
    chosen = payload.get("fingerprints")
    if chosen is not None and (not isinstance(chosen, list) or len(chosen) > 5000
                               or not all(isinstance(item, str) and 0 < len(item) <= 128 for item in chosen)):
        return request.json(400, {"error": msg("api.invalid_selection", max=5000)})
    try:
        if "run_id" in payload:
            run_id = payload["run_id"]
            if not isinstance(run_id, str) or not re.fullmatch(r"[0-9a-f]{32}", run_id):
                return request.json(400, {"error": msg("api.invalid_run")})
            record = triage.annotate(request.data_dir, load_run(request.data_dir, run_id))
            if record.get("type") not in FINDING_RUNS:
                return request.json(400, {"error": msg("api.run_without_findings")})
        else:
            key, status = payload["asset"], payload.get("status", "open")
            if not isinstance(key, str) or not key or len(key) > 200 or status not in ("open", "fixed", "all"):
                return request.json(400, {"error": msg("api.invalid_asset_status")})
            if not any(row["key"] == key for row in assets_overview(request.data_dir)):
                return request.json(404, {"error": msg("api.asset_not_found")})
            record = findings_registry.view(request.data_dir, key, status=status)
    except (FileNotFoundError, ValueError):
        return request.json(404, {"error": msg("api.run_not_found")})
    findings = record.get("findings") or []
    if chosen is not None:
        wanted = set(chosen)
        findings = [item for item in findings if item.get("fingerprint") in wanted]
    try:
        options = validate_options(payload.get("options"), default_by=request.user.get("display_name") or request.user["username"])
        cra.check_framework(request.data_dir, options["framework"])
        pdf = render_audit_pdf(record, findings, options, version=VERSION, locale=request.locale)
    except (ReportError, cra.CraError) as exc:
        return request.json(400, {"error": problem(exc)})
    request.log.info("audit_report", extra={"user": request.user["username"], "reason": f"{record['id']}: {len(findings)} hallazgos, {options['framework']}"})
    return request.send(200, pdf, "application/pdf")


def _portfolio_report(request: Request, payload: dict):
    """Informe consolidado: una organización (con su cobertura frente a GitHub) o una selección de repositorios."""
    rows = assets_overview(request.data_dir)
    coverage: dict = {"total": None, "missing": []}
    if "account" in payload:
        account = payload["account"]
        if not isinstance(account, str) or not account or len(account) > 100:
            return request.json(400, {"error": msg("api.invalid_organization")})
        prefix = f"{account.casefold()}/"
        chosen = [row for row in rows if (row.get("name") or "").casefold().startswith(prefix)]
        scope = text(msg("api.scope.organization", account=account), request.locale)
        # ¿Se analiza todo? Se contrasta con la lista real de la organización en la GitHub App.
        from tamandua.modules.integrations.github import installation_info, installation_repositories
        for installation in github_installations(request.data_dir):
            try:
                if (installation_info(installation).get("account") or "").casefold() != account.casefold():
                    continue
                names = [repo["name"] for repo in installation_repositories(installation) if not repo.get("archived")]
            except GitHubAppError:
                break
            analysed = {(row.get("name") or "").casefold() for row in chosen}
            coverage = {"total": len(names), "missing": sorted(name for name in names if name.casefold() not in analysed)}
            break
    else:
        keys = payload["assets"]
        if not isinstance(keys, list) or not 1 <= len(keys) <= 500 or not all(isinstance(key, str) and len(key) <= 200 for key in keys):
            return request.json(400, {"error": msg("api.choose_repositories", max=500)})
        wanted = set(keys)
        chosen = [row for row in rows if row["key"] in wanted]
        scope = text(msg("api.scope.repositories", count=len(chosen)), request.locale)
    if not chosen:
        return request.json(404, {"error": msg("api.no_analyzed_in_scope")})
    status = payload.get("status", "all")
    if status not in ("open", "all"):
        return request.json(400, {"error": msg("api.invalid_status")})
    items = evidence.portfolio(request.data_dir, chosen, status=status)
    try:
        options = validate_options(payload.get("options"), default_by=request.user.get("display_name") or request.user["username"])
        cra.check_framework(request.data_dir, options["framework"])
        pdf = render_portfolio_pdf(items, options, version=VERSION, scope_label=scope, coverage=coverage, locale=request.locale)
    except (ReportError, cra.CraError) as exc:
        return request.json(400, {"error": problem(exc)})
    request.log.info("audit_report", extra={"user": request.user["username"], "reason": f"{scope}: {len(items)} repositorios, {options['framework']}"})
    return request.send(200, pdf, "application/pdf")


@route("GET", "/api/assets/exclusions")
def asset_exclusions(request: Request):
    """Rutas excluidas de un repositorio: cualquiera las ve; solo un administrador las cambia."""
    key = request.arg("key") or ""
    if not exclusions.ASSET_KEY.fullmatch(key):
        return request.json(400, {"error": msg("api.invalid_repository")})
    return request.json(200, exclusions.get(request.data_dir, key))


EXCLUSION_FIELDS = {"key", "patterns", "reason"}


@route("POST", "/api/assets/exclusions", admin=True, action="save-exclusions", body=20_000)
def save_asset_exclusions(request: Request):
    payload = request.payload
    if (not isinstance(payload, dict) or not {"key", "patterns"} <= set(payload) or not set(payload) <= EXCLUSION_FIELDS
            or not isinstance(payload["key"], str) or not exclusions.ASSET_KEY.fullmatch(payload["key"])
            or not isinstance(payload.get("reason") or "", str)):
        return request.json(400, {"error": msg("api.invalid_request")})
    key = payload["key"]
    # Solo repositorios o imágenes que ya existen: nada de claves inventadas en el fichero.
    if not findings_registry.load(request.data_dir, key)["findings"] and not any(row["key"] == key for row in assets_overview(request.data_dir)):
        return request.json(404, {"error": msg("api.repository_not_found")})
    try:
        saved = exclusions.save(request.data_dir, key, payload["patterns"], reason=payload.get("reason"), user=request.user)
    except exclusions.ExclusionError as exc:
        return request.json(400, {"error": problem(exc)})
    moved = findings_registry.apply_exclusions(request.data_dir, key, saved["patterns"], when=saved["at"])
    request.log.info("exclusions", extra={"user": request.user["username"], "reason":
                                          f"{key}: {len(saved['patterns'])} rutas, {moved['excluded']} excluidos, {moved['reopened']} reabiertos"})
    return request.json(200, {**saved, "moved": moved})


@route("GET", "/api/assets")
def assets(request: Request):
    """Repositorios analizados, agrupados por identidad estable, con su estado actual."""
    rows = assets_overview(request.data_dir, query=(request.arg("q") or "")[:100] or None)
    if request.arg("key"):
        rows = [row for row in rows if row["key"] == request.arg("key")]
    try:
        limit, offset = max(1, min(int(request.arg("limit", "50")), 200)), max(0, int(request.arg("offset", "0")))
    except ValueError:
        return request.json(400, {"error": msg("api.invalid_paging")})
    return request.json(200, {"items": rows[offset:offset + limit], "total": len(rows), "limit": limit, "offset": offset})


@route("GET", "/api/runs/", prefix=True)
def run_detail(request: Request):
    run_id, separator, artifact = request.path.removeprefix("/api/runs/").partition("/")
    try:
        # Las vistas de una revisión de código reflejan el triage actual, no el del día del escaneo.
        record = jira.annotate(request.data_dir, triage.annotate(request.data_dir, load_run(request.data_dir, run_id)))
        if not separator:
            return request.json(200, record)
        return _artifact(request, record, artifact)
    except (ValueError, OSError, json.JSONDecodeError):
        pass
    return request.json(404, {"error": msg("api.run_not_found")})


@route("GET", "/api/cves")
def cves(request: Request):
    """Búsqueda en lo que hay en local: KEV, EPSS y los CVE de la última semana según NVD."""
    needle = (request.arg("q", "") or "").strip()[:80]
    if not re.fullmatch(r"[A-Za-z0-9 .:_\-]{0,80}", needle):
        return request.json(400, {"error": msg("api.invalid_query")})
    feeds = load_feeds(request.data_dir)
    recent = load_recent_cves(request.data_dir, 7)
    lowered = needle.lower()
    results = [{**item, "source": "nvd", "kev": item["cve"] in feeds["kev"], "epss": (feeds["epss"].get(item["cve"]) or (None, None))[0]}
               for item in recent["items"]
               if not lowered or lowered in item["cve"].lower() or lowered in item["description"].lower()]
    if re.fullmatch(r"(?i)cve-\d{4}-\d{4,}", needle):
        upper = needle.upper()
        entry, epss = feeds["kev"].get(upper), feeds["epss"].get(upper)
        if all(result["cve"] != upper for result in results) and (entry or epss):
            results.insert(0, {"cve": upper, "published": None, "score": None, "severity": None,
                               "description": (entry or {}).get("name") or msg("api.no_local_description"),
                               "source": "kev" if entry else "epss", "kev": bool(entry), "epss": epss[0] if epss else None})
    return request.json(200, {"query": needle, "items": results[:50], "total": len(results),
                              "sources": {"kev": (feeds["kev"].get("__meta__") or {}).get("version"),
                                          "epss": bool(feeds["epss"]), "nvd_recent": (recent.get("__meta__") or {}).get("total")}})


TRIAGE_FIELDS = {"run_id", "fingerprints", "status", "reason", "note", "expires_at"}


@route("POST", "/api/findings/triage", action="triage", body=40_000)
def triage_findings(request: Request):
    payload = request.payload
    if (not isinstance(payload, dict) or not {"run_id", "fingerprints", "status"} <= set(payload)
            or not set(payload) <= TRIAGE_FIELDS or not isinstance(payload["run_id"], str)):
        return request.json(400, {"error": msg("api.invalid_triage")})
    try:
        # Una ejecución concreta o el estado del repositorio (asset:<clave>): el triage es el mismo.
        record = findings_registry.resolve(request.data_dir, payload["run_id"])
    except (ValueError, OSError, json.JSONDecodeError):
        return request.json(404, {"error": msg("api.run_not_found")})
    if record.get("type") not in (*FINDING_RUNS, "asset_state"):
        return request.json(400, {"error": msg("api.triage_scope")})
    try:
        updated = triage.decide(request.data_dir, record, payload["fingerprints"], payload["status"],
                                reason=payload.get("reason"), note=payload.get("note"),
                                expires_at=payload.get("expires_at"), user=request.user)
    except PermissionError as exc:
        return request.json(403, {"error": problem(exc)})
    except triage.TriageError as exc:
        return request.json(400, {"error": problem(exc)})
    request.log.info("triage", extra={"user": request.user["username"], "run_id": record["id"], "reason":
                                      f"{payload['status']}: {len(payload['fingerprints'])} hallazgos"})
    return request.json(200, {"summary": updated["summary"]})


@route("GET", "/api/repositories/plan")
def repository_plan(request: Request):
    """Lo que hará el escaneo, calculado con el árbol real del repositorio y los motores disponibles."""
    source_id = request.arg("source_id")
    with request.state.code_lock:
        tokens = request.state.code_tokens.copy()
    source = find_source(tokens, github_installations(request.data_dir), source_id)
    if source is None:
        return request.json(400, {"error": msg("sources.errors.not_available")})
    try:
        return request.json(200, scan_plan(source["id"], installation_id=source.get("installation_id")))
    except GitHubAppError as exc:
        return request.json(502, {"error": problem(exc)})


@route("POST", "/api/repositories/batches", action="scan-batch", body=64_000)
def create_batch(request: Request):
    """Varios repositorios de una vez: una selección (hasta 100) o una organización entera (administración)."""
    payload = request.payload
    if (not isinstance(payload, dict) or not set(payload) <= {"source_ids", "account", "allow_osv_upload", "context"}
            or ("source_ids" in payload) == ("account" in payload)
            or not isinstance(payload.get("allow_osv_upload", False), bool) or not isinstance(payload.get("context", ""), str)):
        return request.json(400, {"error": msg("api.batch_scope")})
    installations = github_installations(request.data_dir)
    if not installations:
        return request.json(400, {"error": msg("api.batch_needs_app")})
    if "account" in payload:
        # Una organización entera ocupa el servidor durante horas: es una decisión de administración.
        if request.user.get("role") != "admin":
            return request.json(403, {"error": msg("api.org_admin_only")})
        from tamandua.modules.integrations.github import installation_info, installation_repositories
        account = payload["account"]
        if not isinstance(account, str) or not account or len(account) > 100:
            return request.json(400, {"error": msg("api.invalid_organization")})
        items = []
        for installation in installations:
            try:
                if (installation_info(installation).get("account") or "").casefold() != account.casefold():
                    continue
                items = [{**row, "source_id": row["id"], "installation_id": installation}
                         for row in installation_repositories(installation) if not row.get("archived")]
            except GitHubAppError as exc:
                return request.json(502, {"error": problem(exc)})
            break
        if not items:
            return request.json(404, {"error": msg("api.org_empty")})
        # Batches store their label as text (in the language of whoever started them).
        label = text(msg("api.scope.organization", account=account), request.locale)
    else:
        chosen = payload["source_ids"]
        if not isinstance(chosen, list) or not 1 <= len(chosen) <= batches.MAX_SELECTED or not all(isinstance(item, str) for item in chosen):
            return request.json(400, {"error": msg("api.choose_batch", max=batches.MAX_SELECTED)})
        items = []
        for source_id in dict.fromkeys(chosen):
            source = find_source(None, installations, source_id)
            if source is None or source.get("installation_id") is None:
                return request.json(400, {"error": msg("api.repo_not_in_app", repository=source_id[:120])})
            items.append({**source, "source_id": source["id"]})
        label = text(msg("api.scope.selected", count=len(items)), request.locale)
    try:
        batch = batches.create(request.data_dir, items, by=request.user["username"], label=label,
                               allow_osv_upload=payload.get("allow_osv_upload", False), context=payload.get("context", ""))
    except batches.BatchError as exc:
        return request.json(409, {"error": problem(exc)})
    request.log.info("scan_batch", extra={"user": request.user["username"], "reason": f"{label}: {len(batch['items'])}"})
    return request.json(202, batches.summary(request.data_dir, batch))


@route("GET", "/api/repositories/batches")
def list_batches(request: Request):
    rows = batches.all_batches(request.data_dir)
    current = next((row for row in rows if row["status"] == "running"), None)
    return request.json(200, {"active": batches.summary(request.data_dir, current) if current else None,
                              "recent": [batches.summary(request.data_dir, row) for row in rows if row["status"] != "running"][:5]})


@route("POST", "/api/repositories/batches/cancel", action="cancel-batch", body=256)
def cancel_batch(request: Request):
    payload = request.payload
    if not isinstance(payload, dict) or set(payload) != {"id"} or not isinstance(payload["id"], str):
        return request.json(400, {"error": msg("api.invalid_batch")})
    try:
        batch = batches.load(request.data_dir, payload["id"])
        if batch.get("by") != request.user["username"] and request.user.get("role") != "admin":
            return request.json(403, {"error": msg("api.cancel_forbidden")})
        batch = batches.cancel(request.data_dir, payload["id"], by=request.user["username"])
    except batches.BatchError as exc:
        return request.json(404, {"error": problem(exc)})
    return request.json(200, batches.summary(request.data_dir, batch))


REPOSITORY_SCAN_FIELDS = {"source_id", "allow_osv_upload", "context"}


@route("POST", "/api/repositories/scans", action="scan-repository", body=1024)
def repository_scan(request: Request):
    payload, state = request.payload, request.state
    if (not isinstance(payload, dict) or not {"source_id", "allow_osv_upload"} <= set(payload)
            or not set(payload) <= REPOSITORY_SCAN_FIELDS
            or not isinstance(payload["source_id"], str) or not isinstance(payload["allow_osv_upload"], bool)
            or not isinstance(payload.get("context", ""), str)):
        return request.json(400, {"error": msg("api.invalid_repository")})
    with state.code_lock:
        tokens = state.code_tokens.copy()
    # Se valida que el repositorio exista para esta credencial antes de encolar nada.
    source = find_source(tokens, github_installations(request.data_dir), payload["source_id"])
    if source is None or source["id"] != payload["source_id"]:
        return request.json(400, {"error": msg("sources.errors.not_available")})
    if state.jobs.pending() >= 20:
        return request.json(429, {"error": msg("api.queue_full")})
    queued = state.jobs.enqueue_repository_scan(source_id=payload["source_id"], source_name=source["name"],
                                                allow_osv_upload=payload["allow_osv_upload"],
                                                context=payload.get("context", ""), tokens=tokens,
                                                installation_id=source.get("installation_id"), uid=source.get("uid"))
    return request.json(202, {"run": queued})


@route("POST", "/api/findings/reverify", action="reverify-finding", body=512)
def reverify_finding(request: Request):
    """Vuelve a analizar el activo de un hallazgo (o se engancha al análisis en curso) para ver si sigue ahí."""
    from tamandua.modules.findings import verifications
    from tamandua.modules.sources.assets import asset_key
    from tamandua.modules.findings.registry import VIEW_PREFIX, load as registry
    from tamandua.modules.scanning.image import ImageError, parse_reference
    payload, state = request.payload, request.state
    if (not isinstance(payload, dict) or set(payload) != {"run_id", "fingerprint"} or not isinstance(payload["run_id"], str)
            or not isinstance(payload["fingerprint"], str) or not re.fullmatch(r"[0-9a-f]{16,64}", payload["fingerprint"])):
        return request.json(400, {"error": msg("api.invalid_finding")})
    run_id = payload["run_id"]
    if run_id.startswith(VIEW_PREFIX):
        key = run_id.removeprefix(VIEW_PREFIX)
    else:
        try:
            key = asset_key(load_run(request.data_dir, run_id))
        except (ValueError, OSError):
            return request.json(404, {"error": msg("api.run_not_found")})
    entry = registry(request.data_dir, key).get("findings", {}).get(payload["fingerprint"])
    if entry is None:
        return request.json(404, {"error": msg("api.finding_not_in_asset")})
    origin = entry.get("origin") or {}
    if origin.get("kind") == "pr" and not origin.get("merged"):
        return request.json(409, {"error": msg("api.finding_from_open_pr")})
    by = request.user["username"]
    current = verifications.in_flight(request.data_dir, key)
    if current:
        verifications.record(request.data_dir, key, payload["fingerprint"], current["id"], by=by)
        return request.json(202, {"run": {"id": current["id"], "status": current["status"]}, "joined": True})
    base = verifications.latest_scan(request.data_dir, key)
    if base is None:
        return request.json(409, {"error": msg("api.no_full_scan")})
    if state.jobs.pending() >= 20:
        return request.json(429, {"error": msg("api.queue_full")})
    source = base.get("source") or {}
    if source.get("id") == "local:demo-ejemplos":
        return request.json(409, {"error": msg("api.demo_reverify")})
    if base["type"] == "image_scan":
        try:
            image = parse_reference(str((source.get("image") or {}).get("reference") or base.get("target") or ""))
        except ImageError as exc:
            return request.json(409, {"error": msg("api.image_rescan_failed", detail=problem(exc))})
        queued = state.jobs.enqueue_image_scan(image=image, context="", requested_by=by)
    else:
        with state.code_lock:
            tokens = state.code_tokens.copy()
        found = find_source(tokens, github_installations(request.data_dir), source.get("id") or "")
        if found is None:
            return request.json(409, {"error": msg("api.repository_gone")})
        queued = state.jobs.enqueue_repository_scan(source_id=found["id"], source_name=found["name"], allow_osv_upload=False, context="",
                                                    tokens=tokens, installation_id=found.get("installation_id"), uid=found.get("uid"),
                                                    requested_by=by, trigger={"kind": "reverify"})
    verifications.record(request.data_dir, key, payload["fingerprint"], queued["id"], by=by)
    request.log.info("reverify", extra={"user": by, "reason": f"{key} {payload['fingerprint'][:12]}"})
    return request.json(202, {"run": queued, "joined": False})


IMAGE_SCAN_FIELDS = {"reference", "context"}


@route("POST", "/api/images/scans", action="scan-image", body=1024)
def image_scan(request: Request):
    """Encola el análisis de una imagen de contenedor desde su registro."""
    from tamandua.modules.scanning.image import ImageError, check_registry_address, parse_reference
    payload, state = request.payload, request.state
    if (not isinstance(payload, dict) or "reference" not in payload or not set(payload) <= IMAGE_SCAN_FIELDS
            or not isinstance(payload["reference"], str) or not isinstance(payload.get("context", ""), str)):
        return request.json(400, {"error": msg("api.invalid_image")})
    try:
        image = parse_reference(payload["reference"])
        check_registry_address(image["registry"])
    except ImageError as exc:
        return request.json(400, {"error": problem(exc)})
    if state.jobs.pending() >= 20:
        return request.json(429, {"error": msg("api.queue_full")})
    queued = state.jobs.enqueue_image_scan(image=image, context=payload.get("context", ""), requested_by=request.user["username"])
    return request.json(202, {"run": queued, "image": image})


@route("POST", "/api/images/batches", action="scan-image-batch", body=64_000)
def image_batch(request: Request):
    """Varias imágenes de una vez (hasta 100), en un lote que avanza cuando el servidor está libre."""
    from tamandua.modules.scanning.image import ImageError, check_registry_address, parse_reference
    payload = request.payload
    if (not isinstance(payload, dict) or not set(payload) <= {"references", "context"} or not isinstance(payload.get("references"), list)
            or not isinstance(payload.get("context", ""), str)):
        return request.json(400, {"error": msg("api.images_required")})
    if any(not isinstance(item, str) for item in payload["references"]):
        return request.json(400, {"error": msg("api.invalid_image_reference")})
    references = list(dict.fromkeys(item.strip() for item in payload["references"] if item.strip()))
    if not 1 <= len(references) <= batches.MAX_SELECTED:
        return request.json(400, {"error": msg("api.choose_images", max=batches.MAX_SELECTED)})
    items = []
    for reference in references:
        try:
            image = parse_reference(reference)
            check_registry_address(image["registry"])
        except ImageError as exc:
            return request.json(400, {"error": msg("api.image_error", reference=reference[:120], detail=problem(exc))})
        items.append({"kind": "image", "image": image})
    label = text(msg("api.scope.images", count=len(items)), request.locale)
    try:
        batch = batches.create(request.data_dir, items, by=request.user["username"], label=label, context=payload.get("context", ""))
    except batches.BatchError as exc:
        return request.json(409, {"error": problem(exc)})
    request.log.info("scan_image_batch", extra={"user": request.user["username"], "reason": label})
    return request.json(202, batches.summary(request.data_dir, batch))


@route("GET", "/api/onboarding")
def onboarding(request: Request):
    """Primeros pasos, deducidos del estado real (nada se marca a mano): el Resumen los muestra hasta completarlos."""
    from tamandua.modules.integrations import notifications
    from tamandua.modules.pullrequests import watch as pr_watch
    from tamandua.modules.runs.kinds import FULL_SCANS
    runs = list_runs(request.data_dir)
    try:
        alerts = bool(notifications.channels())
    except Exception:  # noqa: BLE001 — sin bóveda legible, el paso simplemente queda pendiente
        alerts = False
    return request.json(200, {
        "mfa": bool((request.user.get("totp") or {}).get("enabled")),
        "github": bool(github_installations(request.data_dir)),
        # La demo no cuenta como «tu primer análisis»: es para ver la herramienta, no tu código.
        "analyzed": any(row["type"] in FULL_SCANS and row["status"] == "completed"
                        and (row.get("source") or {}).get("id") != "local:demo-ejemplos" for row in runs),
        "demo": any((row.get("source") or {}).get("id") == "local:demo-ejemplos" for row in runs),
        "watching": any(config.get("enabled") for config in pr_watch.load(request.data_dir)["repositories"].values()),
        "alerts": alerts, "admin": request.user.get("role") == "admin"})


@route("POST", "/api/sla", admin=True, action="sla", body=1024)
def sla_change(request: Request):
    payload = request.payload
    if not isinstance(payload, dict) or set(payload) != {"days"}:
        return request.json(400, {"error": msg("api.invalid_request")})
    try:
        return request.json(200, sla.save(request.data_dir, payload["days"], user=request.user))
    except sla.SlaError as exc:
        return request.json(400, {"error": problem(exc)})


@route("GET", "/api/notifications", admin=True)
def notification_list(request: Request):
    """Canales de aviso (Slack, Teams, webhook): nunca devuelve la URL ni el secreto de firma."""
    from tamandua.modules.integrations import notifications
    return request.json(200, {"channels": notifications.channels(), "kinds": notifications.KINDS, "events": notifications.EVENTS,
                              "thresholds": list(notifications.THRESHOLDS), "links": bool(notifications.panel_link())})


@route("POST", "/api/notifications", admin=True, action="notifications", body=4096)
def notification_change(request: Request):
    from tamandua.modules.integrations import notifications
    payload = request.payload
    if not isinstance(payload, dict) or payload.get("op") not in ("save", "remove", "test"):
        return request.json(400, {"error": msg("api.invalid_request")})
    try:
        if payload["op"] == "save":
            if set(payload) != {"op", "kind", "name", "url", "events", "threshold"}:
                return request.json(400, {"error": msg("api.invalid_request")})
            row, secret = notifications.save(payload["kind"], payload["name"], payload["url"], payload["events"], payload["threshold"],
                                             by=request.user["username"])
            return request.json(200, {"channel": row, "secret": secret})
        if set(payload) != {"op", "id"} or not isinstance(payload["id"], str):
            return request.json(400, {"error": msg("api.invalid_request")})
        if payload["op"] == "remove":
            notifications.remove(payload["id"], by=request.user["username"])
            return request.json(200, {"channels": notifications.channels()})
        ok, detail = notifications.test(payload["id"])
        # 200 también si falla: el panel muestra el detalle (p. ej. HTTP 404) y el estado actualizado del canal.
        return request.json(200, {"ok": ok, "detail": detail, "channels": notifications.channels()})
    except notifications.NotificationError as exc:
        return request.json(400, {"error": problem(exc)})


@route("GET", "/api/registries")
def registry_list(request: Request):
    from tamandua.modules.scanning.image import registries
    return request.json(200, {"registries": registries(), "allow_private": os.environ.get("TAMANDUA_ALLOW_PRIVATE_REGISTRIES", "").strip() == "1"})


@route("POST", "/api/registries", admin=True, action="save-registry", body=6000)
def registry_save(request: Request):
    """Credenciales de solo lectura de un registro privado: se guardan cifradas y nunca vuelven al navegador."""
    from tamandua.modules.scanning.image import ImageError, forget_registry, save_registry
    payload = request.payload
    if not isinstance(payload, dict) or payload.get("action") not in ("save", "remove") or not isinstance(payload.get("registry"), str):
        return request.json(400, {"error": msg("api.invalid_request")})
    try:
        if payload["action"] == "remove":
            return request.json(200, {"registries": forget_registry(payload["registry"])})
        if set(payload) != {"action", "registry", "username", "token"}:
            return request.json(400, {"error": msg("api.invalid_request")})
        return request.json(200, {"registries": save_registry(payload["registry"], payload["username"], payload["token"],
                                                              by=request.user["username"])})
    except ImageError as exc:
        return request.json(400, {"error": problem(exc)})
