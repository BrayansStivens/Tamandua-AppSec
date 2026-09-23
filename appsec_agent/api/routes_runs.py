"""Ejecuciones y sus artefactos, triage, escaneos, panel, CVEs, salud y ficheros estáticos."""

from __future__ import annotations

import json
import os
import mimetypes
import re
from pathlib import Path

from ..kinds import FINDING_RUNS
from .. import findings_registry, jira, triage
from ..assets import overview as assets_overview
from ..advisories import load_feeds, load_recent_cves
from ..dashboard import compute as compute_dashboard
from ..engine import scan_fixture
from ..fixture import FixtureError
from ..integrations import github_installation
from ..repository_sources import available_sources
from ..scanners import docker_available
from ..scan_plan import plan as scan_plan
from ..github_app import GitHubAppError
from ..repository_sources import SourceError
from ..store import _run_dir, list_runs, load_run, page_runs, render_profile_report, render_repository_report
from ..store import render_repository_sarif, render_tickets, save_scan
from .core import VERSION, Request, route

STATIC_DIR = Path(__file__).resolve().parents[1] / "static"
FIXTURE_DIR = Path(__file__).resolve().parents[2] / "fixtures" / "tenant-api-lab"
PROFILE_REPORTS = ("report-soc2.md", "report-iso27001.md", "report-custom.md")


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
    if not key or status not in ("open", "fixed", "all"):
        return request.json(400, {"error": "Repositorio o estado inválido"})
    view = findings_registry.view(request.data_dir, key, status=status)
    return request.json(200, jira.annotate(request.data_dir, view))


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
        repository = record.get("type") in FINDING_RUNS
        if not separator:
            return request.json(200, record)
        if artifact == "tickets.json":
            return request.json(200, render_tickets(record))
        if artifact == "report.md" and repository:
            return request.send(200, render_repository_report(record).encode("utf-8"), "text/markdown; charset=utf-8")
        if artifact == "findings.sarif" and repository:
            return request.send(200, json.dumps(render_repository_sarif(record), ensure_ascii=False, indent=2).encode("utf-8"),
                                "application/sarif+json")
        if artifact in ("report.md", "findings.sarif"):
            content_type = "text/markdown; charset=utf-8" if artifact == "report.md" else "application/sarif+json"
            return request.send(200, (_run_dir(request.data_dir, run_id) / artifact).read_bytes(), content_type)
        if artifact in PROFILE_REPORTS:
            profile = artifact.removeprefix("report-").removesuffix(".md")
            report = render_profile_report(record, profile, request.arg("title", ""))
            return request.send(200, report.encode("utf-8"), "text/markdown; charset=utf-8")
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
    installation = github_installation(request.data_dir)
    try:
        listing = available_sources(tokens, installation)
    except (SourceError, GitHubAppError) as exc:
        return request.json(502, {"error": str(exc)})
    if not any(item["id"] == source_id for item in listing["sources"]):
        return request.json(400, {"error": "Repositorio no disponible para la credencial configurada"})
    try:
        return request.json(200, scan_plan(source_id, installation_id=installation))
    except GitHubAppError as exc:
        return request.json(502, {"error": str(exc)})


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
    installation = github_installation(request.data_dir)
    # Se valida que el repositorio exista para esta credencial antes de encolar nada.
    listing = available_sources(tokens, installation)
    source = next((item for item in listing["sources"] if item["id"] == payload["source_id"]), None)
    if source is None:
        return request.json(400, {"error": "Repositorio no disponible para la credencial configurada"})
    if state.jobs.pending() >= 20:
        return request.json(429, {"error": "Demasiados escaneos en cola"})
    queued = state.jobs.enqueue_repository_scan(source_id=payload["source_id"], source_name=source["name"],
                                                allow_osv_upload=payload["allow_osv_upload"],
                                                context=payload.get("context", ""), tokens=tokens,
                                                installation_id=installation, uid=source.get("uid"))
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


@route("POST", "/api/lab/scans", action="scan-lab")
def lab_scan(request: Request):
    payload, state = request.payload, request.state
    if not isinstance(payload, dict) or set(payload) != {"variant"} or payload["variant"] not in ("both", "vulnerable", "fixed"):
        return request.json(400, {"error": "Variante inválida"})
    if not state.scan_lock.acquire(blocking=False):
        return request.json(409, {"error": "Ya hay una prueba en curso"})
    try:
        variants = ("vulnerable", "fixed") if payload["variant"] == "both" else (payload["variant"],)
        records = [save_scan(request.data_dir, scan_fixture(FIXTURE_DIR, variant)) for variant in variants]
        return request.json(200, {"runs": [{"id": record["id"], "variant": record["variant"], "status": record["status"],
                                            "summary": record["summary"]} for record in records]})
    except (FixtureError, OSError, ValueError):
        return request.json(500, {"error": "No se pudo ejecutar el laboratorio aprobado"})
    finally:
        state.scan_lock.release()
