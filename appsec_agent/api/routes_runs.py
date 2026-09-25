"""Ejecuciones y sus artefactos, triage, escaneos, panel, CVEs, salud y ficheros estáticos."""

from __future__ import annotations

import json
import os
import mimetypes
import re
from pathlib import Path

from ..kinds import FINDING_RUNS
from .. import batches, exclusions, findings_registry, jira, triage
from ..assets import overview as assets_overview
from ..advisories import load_feeds, load_recent_cves
from ..dashboard import compute as compute_dashboard
from ..integrations import github_installations
from ..repository_sources import find_source
from ..scanners import docker_available
from ..scan_plan import plan as scan_plan
from ..github_app import GitHubAppError
from ..pdf_reports import render_pdf
from ..audit_report import ReportError, render_audit_pdf, validate_options
from ..store import _run_dir, list_runs, load_run, page_runs, render_asset_report, render_profile_report, render_repository_report
from ..store import render_repository_sarif, render_tickets
from .core import VERSION, Request, route

STATIC_DIR = Path(__file__).resolve().parents[1] / "static"
PROFILE_REPORTS = ("report-soc2.md", "report-iso27001.md", "report-custom.md",
                   "report-soc2.pdf", "report-iso27001.pdf", "report-custom.pdf")


def _artifact(request: Request, record: dict, artifact: str):
    repository = record.get("type") in FINDING_RUNS or record.get("type") == "asset_state"
    if artifact == "tickets.json" and repository:
        return request.json(200, render_tickets(record))
    if artifact in ("report.md", "report.pdf") and repository:
        report = render_asset_report(record) if record["type"] == "asset_state" else render_repository_report(record)
        if artifact.endswith(".pdf"):
            return request.send(200, render_pdf(report, title="Informe de hallazgos", kind="Registro técnico",
                                                 reference=record["id"]), "application/pdf")
        return request.send(200, report.encode("utf-8"), "text/markdown; charset=utf-8")
    if artifact == "findings.sarif" and repository:
        return request.send(200, json.dumps(render_repository_sarif(record), ensure_ascii=False, indent=2).encode("utf-8"),
                            "application/sarif+json")
    if artifact in PROFILE_REPORTS:
        profile = artifact.removeprefix("report-").rsplit(".", 1)[0]
        report = render_profile_report(record, profile, request.arg("title", ""))
        if artifact.endswith(".pdf"):
            label = {"soc2": "SOC 2 Tipo II", "iso27001": "ISO/IEC 27001:2022", "custom": "Personalizado"}[profile]
            return request.send(200, render_pdf(report, title=f"Evidencia técnica para {label}",
                                                 kind="Dossier para revisión", reference=record["id"]), "application/pdf")
        return request.send(200, report.encode("utf-8"), "text/markdown; charset=utf-8")
    if artifact in ("report.md", "findings.sarif"):
        content_type = "text/markdown; charset=utf-8" if artifact == "report.md" else "application/sarif+json"
        return request.send(200, (_run_dir(request.data_dir, record["id"]) / artifact).read_bytes(), content_type)
    return request.json(404, {"error": "Formato no disponible para esta ejecución"})


@route("GET", "/api/health", public=True, enrolment=True)
def health(request: Request):
    # Sin sesión la salud solo confirma que el proceso responde: nada del estado interno.
    if request.user is None:
        return request.json(200, {"status": "ok", "version": VERSION})
    return request.json(200, {"status": "ok", "docker": docker_available(), "queued": request.state.jobs.pending(),
                              "version": VERSION})


@route("GET", "/", public=True, enrolment=True)
def index(request: Request):
    return _static(request, "index.html")


@route("GET", "/assets/", public=True, enrolment=True, prefix=True)
def asset(request: Request):
    if len(request.path) >= 160 or request.path.count("/") != 2:
        return request.json(404, {"error": "Ruta no encontrada"})
    return _static(request, request.path.lstrip("/"))


def _static(request: Request, name: str):
    target = STATIC_DIR / name
    if target.is_symlink() or not target.is_file():
        return request.json(404, {"error": "Archivo no encontrado"})
    return request.send(200, target.read_bytes(), mimetypes.guess_type(name)[0] or "application/octet-stream")


@route("GET", "/api/runs")
def runs(request: Request):
    return request.json(200, list_runs(request.data_dir))


@route("GET", "/api/runs/page")
def runs_page(request: Request):
    try:
        limit, offset = int(request.arg("limit", "25")), int(request.arg("offset", "0"))
    except ValueError:
        return request.json(400, {"error": "Paginación inválida"})
    return request.json(200, page_runs(request.data_dir, limit=limit, offset=offset, status=request.arg("status") or None,
                                       kind=request.arg("type") or None, query=(request.arg("q") or "")[:100] or None,
                                       asset=(request.arg("asset") or "")[:200] or None))


@route("GET", "/api/assets/state")
def asset_state(request: Request):
    """Estado actual de un repositorio: su registro de hallazgos (escaneos y PRs), abiertos, remediados o todos."""
    key = (request.arg("key") or "")[:200]
    status = request.arg("status", "open")
    if not key or status not in ("open", "fixed", "excluded", "all"):
        return request.json(400, {"error": "Repositorio o estado inválido"})
    view = findings_registry.view(request.data_dir, key, status=status)
    return request.json(200, jira.annotate(request.data_dir, view))


@route("GET", "/api/assets/export")
def asset_export(request: Request):
    """Exportación del estado actual; no existe un ID de ejecución para esta vista."""
    key = request.arg("key") or ""
    status = request.arg("status", "open")
    artifact = request.arg("artifact") or ""
    if not key or len(key) > 200 or status not in ("open", "fixed", "excluded", "all"):
        return request.json(400, {"error": "Activo o estado inválido"})
    if artifact not in ("tickets.json", "report.md", "report.pdf", "findings.sarif", *PROFILE_REPORTS, "record.json"):
        return request.json(404, {"error": "Formato no disponible"})
    if not any(row["key"] == key for row in assets_overview(request.data_dir)):
        return request.json(404, {"error": "Activo no encontrado"})
    record = jira.annotate(request.data_dir, findings_registry.view(request.data_dir, key, status=status))
    if artifact == "record.json":
        return request.json(200, record)
    try:
        return _artifact(request, record, artifact)
    except ValueError as exc:
        return request.json(400, {"error": str(exc)})


@route("POST", "/api/reports/audit", action="audit-report", body=400_000)
def audit_report(request: Request):
    """Informe de evidencia para auditoría de una ejecución o del estado de un activo, con los hallazgos elegidos.

    Mismo acceso que ver esa ejecución o ese activo. `fingerprints` acota el informe (uno, varios o los filtrados);
    sin él entran todos los del alcance."""
    payload = request.payload
    if not isinstance(payload, dict) or not set(payload) <= {"run_id", "asset", "status", "fingerprints", "options"} \
            or ("run_id" in payload) == ("asset" in payload):
        return request.json(400, {"error": "Indica una ejecución o un activo"})
    chosen = payload.get("fingerprints")
    if chosen is not None and (not isinstance(chosen, list) or len(chosen) > 5000
                               or not all(isinstance(item, str) and 0 < len(item) <= 128 for item in chosen)):
        return request.json(400, {"error": "Selección de hallazgos inválida (hasta 5000)"})
    try:
        if "run_id" in payload:
            run_id = payload["run_id"]
            if not isinstance(run_id, str) or not re.fullmatch(r"[0-9a-f]{32}", run_id):
                return request.json(400, {"error": "Ejecución inválida"})
            record = triage.annotate(request.data_dir, load_run(request.data_dir, run_id))
            if record.get("type") not in FINDING_RUNS:
                return request.json(400, {"error": "Esta ejecución no tiene hallazgos que informar"})
        else:
            key, status = payload["asset"], payload.get("status", "open")
            if not isinstance(key, str) or not key or len(key) > 200 or status not in ("open", "fixed", "all"):
                return request.json(400, {"error": "Activo o estado inválido"})
            if not any(row["key"] == key for row in assets_overview(request.data_dir)):
                return request.json(404, {"error": "Activo no encontrado"})
            record = findings_registry.view(request.data_dir, key, status=status)
    except (FileNotFoundError, ValueError):
        return request.json(404, {"error": "Ejecución no encontrada"})
    findings = record.get("findings") or []
    if chosen is not None:
        wanted = set(chosen)
        findings = [item for item in findings if item.get("fingerprint") in wanted]
    try:
        options = validate_options(payload.get("options"), default_by=request.user.get("display_name") or request.user["username"])
        pdf = render_audit_pdf(record, findings, options, version=VERSION)
    except ReportError as exc:
        return request.json(400, {"error": str(exc)})
    request.log.info("audit_report", extra={"user": request.user["username"], "reason": f"{record['id']}: {len(findings)} hallazgos, {options['framework']}"})
    return request.send(200, pdf, "application/pdf")


@route("GET", "/api/assets/exclusions")
def asset_exclusions(request: Request):
    """Rutas excluidas de un repositorio: cualquiera las ve; solo un administrador las cambia."""
    key = request.arg("key") or ""
    if not exclusions.ASSET_KEY.fullmatch(key):
        return request.json(400, {"error": "Repositorio inválido"})
    return request.json(200, exclusions.get(request.data_dir, key))


EXCLUSION_FIELDS = {"key", "patterns", "reason"}


@route("POST", "/api/assets/exclusions", admin=True, action="save-exclusions", body=20_000)
def save_asset_exclusions(request: Request):
    payload = request.payload
    if (not isinstance(payload, dict) or not {"key", "patterns"} <= set(payload) or not set(payload) <= EXCLUSION_FIELDS
            or not isinstance(payload["key"], str) or not exclusions.ASSET_KEY.fullmatch(payload["key"])
            or not isinstance(payload.get("reason") or "", str)):
        return request.json(400, {"error": "Solicitud inválida"})
    key = payload["key"]
    # Solo repositorios o imágenes que ya existen: nada de claves inventadas en el fichero.
    if not findings_registry.load(request.data_dir, key)["findings"] and not any(row["key"] == key for row in assets_overview(request.data_dir)):
        return request.json(404, {"error": "Repositorio no encontrado"})
    try:
        saved = exclusions.save(request.data_dir, key, payload["patterns"], reason=payload.get("reason"), user=request.user)
    except exclusions.ExclusionError as exc:
        return request.json(400, {"error": str(exc)})
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
        return request.json(400, {"error": "Paginación inválida"})
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
    return request.json(404, {"error": "Ejecución no encontrada"})


@route("GET", "/api/dashboard")
def dashboard(request: Request):
    try:
        days = int(request.arg("days", "30"))
    except ValueError:
        return request.json(400, {"error": "Ventana inválida"})
    if days not in (7, 30, 90, 365):
        return request.json(400, {"error": "Ventana inválida"})
    return request.json(200, compute_dashboard(request.data_dir, days))


@route("GET", "/api/cves")
def cves(request: Request):
    """Búsqueda en lo que hay en local: KEV, EPSS y los CVE de la última semana según NVD."""
    needle = (request.arg("q", "") or "").strip()[:80]
    if not re.fullmatch(r"[A-Za-z0-9 .:_\-]{0,80}", needle):
        return request.json(400, {"error": "Búsqueda inválida"})
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
                               "description": (entry or {}).get("name") or "Sin descripción local; consulta la referencia.",
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
        return request.json(400, {"error": "Solicitud de triage inválida"})
    try:
        # Una ejecución concreta o el estado del repositorio (asset:<clave>): el triage es el mismo.
        record = findings_registry.resolve(request.data_dir, payload["run_id"])
    except (ValueError, OSError, json.JSONDecodeError):
        return request.json(404, {"error": "Ejecución no encontrada"})
    if record.get("type") not in (*FINDING_RUNS, "asset_state"):
        return request.json(400, {"error": "El triage aplica a revisiones de código e imágenes"})
    try:
        updated = triage.decide(request.data_dir, record, payload["fingerprints"], payload["status"],
                                reason=payload.get("reason"), note=payload.get("note"),
                                expires_at=payload.get("expires_at"), user=request.user)
    except PermissionError as exc:
        return request.json(403, {"error": str(exc)})
    except triage.TriageError as exc:
        return request.json(400, {"error": str(exc)})
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
        return request.json(400, {"error": "Repositorio no disponible para la credencial configurada"})
    try:
        return request.json(200, scan_plan(source["id"], installation_id=source.get("installation_id")))
    except GitHubAppError as exc:
        return request.json(502, {"error": str(exc)})


@route("POST", "/api/repositories/batches", action="scan-batch", body=64_000)
def create_batch(request: Request):
    """Varios repositorios de una vez: una selección (hasta 100) o una organización entera (administración)."""
    payload = request.payload
    if (not isinstance(payload, dict) or not set(payload) <= {"source_ids", "account", "allow_osv_upload", "context"}
            or ("source_ids" in payload) == ("account" in payload)
            or not isinstance(payload.get("allow_osv_upload", False), bool) or not isinstance(payload.get("context", ""), str)):
        return request.json(400, {"error": "Indica los repositorios o una organización"})
    installations = github_installations(request.data_dir)
    if not installations:
        return request.json(400, {"error": "Los lotes usan la GitHub App: conéctala en Integraciones"})
    if "account" in payload:
        # Una organización entera ocupa el servidor durante horas: es una decisión de administración.
        if request.user.get("role") != "admin":
            return request.json(403, {"error": "Analizar una organización entera es cosa de un administrador"})
        from ..github_app import installation_info, installation_repositories
        account = payload["account"]
        if not isinstance(account, str) or not account or len(account) > 100:
            return request.json(400, {"error": "Organización inválida"})
        items = []
        for installation in installations:
            try:
                if (installation_info(installation).get("account") or "").casefold() != account.casefold():
                    continue
                items = [{**row, "source_id": row["id"], "installation_id": installation}
                         for row in installation_repositories(installation) if not row.get("archived")]
            except GitHubAppError as exc:
                return request.json(502, {"error": str(exc)})
            break
        if not items:
            return request.json(404, {"error": "No hay repositorios de esa organización en la GitHub App"})
        label = f"Organización {account}"
    else:
        chosen = payload["source_ids"]
        if not isinstance(chosen, list) or not 1 <= len(chosen) <= batches.MAX_SELECTED or not all(isinstance(item, str) for item in chosen):
            return request.json(400, {"error": f"Elige entre 1 y {batches.MAX_SELECTED} repositorios (para más, analiza la organización)"})
        items = []
        for source_id in dict.fromkeys(chosen):
            source = find_source(None, installations, source_id)
            if source is None or source.get("installation_id") is None:
                return request.json(400, {"error": f"Repositorio no disponible en la GitHub App: {source_id[:120]}"})
            items.append({**source, "source_id": source["id"]})
        label = f"{len(items)} repositorios seleccionados"
    try:
        batch = batches.create(request.data_dir, items, by=request.user["username"], label=label,
                               allow_osv_upload=payload.get("allow_osv_upload", False), context=payload.get("context", ""))
    except batches.BatchError as exc:
        return request.json(409, {"error": str(exc)})
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
        return request.json(400, {"error": "Lote inválido"})
    try:
        batch = batches.load(request.data_dir, payload["id"])
        if batch.get("by") != request.user["username"] and request.user.get("role") != "admin":
            return request.json(403, {"error": "Solo quien lo lanzó o un administrador puede cancelarlo"})
        batch = batches.cancel(request.data_dir, payload["id"], by=request.user["username"])
    except batches.BatchError as exc:
        return request.json(404, {"error": str(exc)})
    return request.json(200, batches.summary(request.data_dir, batch))


REPOSITORY_SCAN_FIELDS = {"source_id", "allow_osv_upload", "context"}


@route("POST", "/api/repositories/scans", action="scan-repository", body=1024)
def repository_scan(request: Request):
    payload, state = request.payload, request.state
    if (not isinstance(payload, dict) or not {"source_id", "allow_osv_upload"} <= set(payload)
            or not set(payload) <= REPOSITORY_SCAN_FIELDS
            or not isinstance(payload["source_id"], str) or not isinstance(payload["allow_osv_upload"], bool)
            or not isinstance(payload.get("context", ""), str)):
        return request.json(400, {"error": "Repositorio inválido"})
    with state.code_lock:
        tokens = state.code_tokens.copy()
    # Se valida que el repositorio exista para esta credencial antes de encolar nada.
    source = find_source(tokens, github_installations(request.data_dir), payload["source_id"])
    if source is None or source["id"] != payload["source_id"]:
        return request.json(400, {"error": "Repositorio no disponible para la credencial configurada"})
    if state.jobs.pending() >= 20:
        return request.json(429, {"error": "Demasiados escaneos en cola"})
    queued = state.jobs.enqueue_repository_scan(source_id=payload["source_id"], source_name=source["name"],
                                                allow_osv_upload=payload["allow_osv_upload"],
                                                context=payload.get("context", ""), tokens=tokens,
                                                installation_id=source.get("installation_id"), uid=source.get("uid"))
    return request.json(202, {"run": queued})


IMAGE_SCAN_FIELDS = {"reference", "context"}


@route("POST", "/api/images/scans", action="scan-image", body=1024)
def image_scan(request: Request):
    """Encola el análisis de una imagen de contenedor desde su registro."""
    from ..image_scan import ImageError, check_registry_address, parse_reference
    payload, state = request.payload, request.state
    if (not isinstance(payload, dict) or "reference" not in payload or not set(payload) <= IMAGE_SCAN_FIELDS
            or not isinstance(payload["reference"], str) or not isinstance(payload.get("context", ""), str)):
        return request.json(400, {"error": "Imagen inválida"})
    try:
        image = parse_reference(payload["reference"])
        check_registry_address(image["registry"])
    except ImageError as exc:
        return request.json(400, {"error": str(exc)})
    if state.jobs.pending() >= 20:
        return request.json(429, {"error": "Demasiados escaneos en cola"})
    queued = state.jobs.enqueue_image_scan(image=image, context=payload.get("context", ""), requested_by=request.user["username"])
    return request.json(202, {"run": queued, "image": image})


@route("GET", "/api/registries")
def registry_list(request: Request):
    from ..image_scan import registries
    return request.json(200, {"registries": registries(), "allow_private": os.environ.get("APPSEC_AGENT_ALLOW_PRIVATE_REGISTRIES", "").strip() == "1"})


@route("POST", "/api/registries", admin=True, action="save-registry", body=6000)
def registry_save(request: Request):
    """Credenciales de solo lectura de un registro privado: se guardan cifradas y nunca vuelven al navegador."""
    from ..image_scan import ImageError, forget_registry, save_registry
    payload = request.payload
    if not isinstance(payload, dict) or payload.get("action") not in ("save", "remove") or not isinstance(payload.get("registry"), str):
        return request.json(400, {"error": "Solicitud inválida"})
    try:
        if payload["action"] == "remove":
            return request.json(200, {"registries": forget_registry(payload["registry"])})
        if set(payload) != {"action", "registry", "username", "token"}:
            return request.json(400, {"error": "Solicitud inválida"})
        return request.json(200, {"registries": save_registry(payload["registry"], payload["username"], payload["token"],
                                                              by=request.user["username"])})
    except ImageError as exc:
        return request.json(400, {"error": str(exc)})
