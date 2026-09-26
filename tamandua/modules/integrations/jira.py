"""Conector de Jira Cloud: convierte los tickets de una ejecución en incidencias.

* La credencial (email + API token de Atlassian) la pone un administrador desde
  el panel y se valida contra Jira antes de guardarse. Vive en el directorio de
  configuración con permisos 0600 y nunca vuelve al navegador: solo el email, el
  proyecto y los cuatro últimos caracteres del token.
* Solo se habla con ``https://<sitio>.atlassian.net``: el panel no puede usarse
  para hacer peticiones a otros destinos (SSRF), y no se siguen redirecciones.
* Una incidencia por trabajo de remediación: los avisos de un mismo paquete van
  juntos, con la versión que los cierra todos; el código y los secretos, uno a uno.
* Idempotente: cada incidencia lleva la etiqueta ``appsec-<huella>`` de cada hallazgo que cubre. Antes de
  crear se busca por esa etiqueta, y los vínculos se recuerdan por activo y
  huella en ``data/jira-links.json``; exportar dos veces no duplica.
* Jira Server/Data Center queda fuera a propósito: exigiría aceptar hosts
  arbitrarios de la red del cliente.
"""

from __future__ import annotations

import base64
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from tamandua.shared import documents
from tamandua.modules.runs.kinds import FINDING_RUNS
from tamandua.shared import log as logging_setup
from tamandua.modules.intel.advisories import compare_versions
from tamandua.modules.findings.triage import asset_key
from tamandua.version import USER_AGENT

SITE_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.atlassian\.net")
PROJECT_PATTERN = re.compile(r"[A-Z][A-Z0-9_]{1,9}")
MAX_BATCH = 50
RESPONSE_LIMIT = 2_000_000
_log = logging_setup.get("jira")


class JiraError(ValueError):
    pass


class _NoRedirect(HTTPRedirectHandler):
    """La credencial no viaja a un destino que indique una redirección."""

    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


# ------------------------------------------------------------ credencial

def _load() -> dict | None:
    from tamandua.shared.vault import VaultError, get
    try:
        data = get("jira")
    except VaultError:
        return None
    return data if isinstance(data, dict) and data.get("token") else None


def _write(data: dict) -> None:
    from tamandua.shared.vault import put
    put("jira", data)


def normalize_site(value) -> str:
    if not isinstance(value, str) or len(value) > 120:
        raise JiraError("Sitio de Jira inválido")
    text = value.strip().lower()
    if "://" not in text:
        text = "https://" + text
    try:
        parts = urlsplit(text)
        host, port = (parts.hostname or "").rstrip("."), parts.port
    except ValueError:
        raise JiraError("Usa la dirección de tu Jira Cloud: https://tu-sitio.atlassian.net") from None
    if (parts.scheme != "https" or parts.username or parts.password or port or parts.query or parts.fragment
            or parts.path not in ("", "/") or not SITE_PATTERN.fullmatch(host)):
        raise JiraError("Usa la dirección de tu Jira Cloud: https://tu-sitio.atlassian.net")
    return host


def status() -> dict:
    data = _load()
    if not data:
        return {"configured": False}
    return {"configured": True, "site": data["site"], "email": data["email"], "project": data["project"],
            "project_name": data.get("project_name"), "issue_type": data["issue_type"],
            "last4": data["token"][-4:], "saved_at": data.get("saved_at"), "saved_by": data.get("saved_by")}


def configure(site, email, token, project, issue_type, *, by: str, http=None) -> dict:
    """Valida contra Jira (identidad, proyecto y tipo de incidencia) y solo entonces guarda."""
    host = normalize_site(site)
    if not isinstance(email, str) or not re.fullmatch(r"[^@\s]{1,64}@[^@\s]{1,190}", email.strip()):
        raise JiraError("Email inválido")
    if (not isinstance(token, str) or not 16 <= len(token) <= 400
            or any(character.isspace() or ord(character) < 33 or ord(character) > 126 for character in token)):
        raise JiraError("API token inválido")
    project = (project or "").strip().upper() if isinstance(project, str) else ""
    if not PROJECT_PATTERN.fullmatch(project):
        raise JiraError("Clave de proyecto inválida (p. ej. SEC)")
    issue_type = " ".join(issue_type.split())[:60] if isinstance(issue_type, str) and issue_type.strip() else "Task"
    credentials = {"site": host, "email": email.strip(), "token": token}
    client = http or _http
    me = client(credentials, "GET", "/rest/api/3/myself")
    found = client(credentials, "GET", f"/rest/api/3/project/{quote(project)}")
    types = [item.get("name") for item in found.get("issueTypes", []) if isinstance(item, dict)]
    if types and issue_type not in types:
        raise JiraError(f"El proyecto {project} no tiene el tipo «{issue_type}». Disponibles: {', '.join(types[:8])}")
    _write({**credentials, "project": project, "project_name": found.get("name"), "issue_type": issue_type,
            "account": me.get("accountId"), "saved_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "saved_by": by})
    _log.info("jira_configured", extra={"user": by, "reason": f"{host}/{project}"})
    return status()


def forget() -> None:
    from tamandua.shared.vault import delete
    delete("jira")


# ------------------------------------------------------------------ HTTP

def _http(credentials: dict, method: str, path: str, body: dict | None = None) -> dict:
    """Petición a la API REST v3. Los errores se traducen sin exponer la respuesta cruda."""
    token = base64.b64encode(f"{credentials['email']}:{credentials['token']}".encode()).decode("ascii")
    request = Request(f"https://{credentials['site']}{path}", method=method,
                      data=json.dumps(body).encode("utf-8") if body is not None else None,
                      headers={"Authorization": f"Basic {token}", "Accept": "application/json",
                               "Content-Type": "application/json", "User-Agent": USER_AGENT})
    try:
        with build_opener(_NoRedirect()).open(request, timeout=15) as response:
            raw = response.read(RESPONSE_LIMIT + 1)
    except HTTPError as exc:
        detail = ""
        try:
            payload = json.loads(exc.read(20_000) or b"{}")
            messages = list((payload.get("errors") or {}).items())[:3]
            detail = "; ".join(f"{field}: {text}" for field, text in messages) or "; ".join(payload.get("errorMessages", [])[:2])
        except (ValueError, OSError, AttributeError):
            pass
        finally:
            exc.close()
        if exc.code in (401, 403):
            raise JiraError("Jira rechazó la credencial o no da permiso sobre el proyecto") from None
        if exc.code == 404:
            raise JiraError("Jira no encuentra el recurso (revisa el sitio y la clave del proyecto)") from None
        raise JiraError(f"Jira respondió {exc.code}" + (f": {detail[:300]}" if detail else "")) from None
    except (URLError, TimeoutError, OSError):
        raise JiraError("No se pudo contactar con Jira") from None
    if len(raw) > RESPONSE_LIMIT:
        raise JiraError("Respuesta de Jira demasiado grande")
    try:
        payload = json.loads(raw or b"{}")
    except ValueError:
        raise JiraError("Jira devolvió una respuesta ilegible") from None
    return payload if isinstance(payload, dict) else {}


# ------------------------------------------------------ incidencias

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


def _adf(text: str) -> dict:
    """Atlassian Document Format mínimo: un párrafo por línea, los títulos en negrita."""
    content = []
    for line in text.splitlines()[:200]:
        line = line.rstrip()[:2000]
        if not line:
            continue
        bold = line.startswith("#")
        clean = line.lstrip("#").strip().replace("**", "").replace("`", "")
        node = {"type": "text", "text": clean}
        if bold:
            node["marks"] = [{"type": "strong"}]
        content.append({"type": "paragraph", "content": [node]})
    return {"type": "doc", "version": 1, "content": content or [{"type": "paragraph", "content": [{"type": "text", "text": "—"}]}]}


def label_for(fingerprint: str) -> str:
    return f"appsec-{fingerprint[:16]}"


def export(data_dir: Path, record: dict, tickets: list[dict], fingerprints: list, *, by: str, http=None) -> dict:
    """Crea en Jira las incidencias de los tickets pedidos. Devuelve creadas, existentes y fallos."""
    credentials = _load()
    if not credentials:
        raise JiraError("Configura Jira en Integraciones antes de exportar")
    if (not isinstance(fingerprints, list) or not 1 <= len(fingerprints) <= MAX_BATCH
            or not all(isinstance(item, str) and re.fullmatch(r"[0-9a-f]{64}", item) for item in fingerprints)):
        raise JiraError(f"Indica entre 1 y {MAX_BATCH} hallazgos")
    by_fingerprint = {ticket["fingerprint"]: ticket for ticket in tickets}
    missing = [item for item in fingerprints if item not in by_fingerprint]
    if missing:
        raise JiraError("Hay hallazgos que no están pendientes en esta ejecución (descartados en triage o ajenos)")
    client = http or _http
    asset = asset_key(record)
    known = load_links(data_dir).get(asset, {})
    base = f"https://{credentials['site']}/browse/"
    created, existing, failed = [], [], []
    state = {"priority": True}
    for group in _work_items([by_fingerprint[item] for item in dict.fromkeys(fingerprints)]):
        prints = [ticket["fingerprint"] for ticket in group]
        try:
            link = next((known[item] for item in prints if item in known), None)
            if link is None:
                # Otra instalación o una exportación anterior pudo crearla: se busca por las etiquetas.
                labels = ", ".join(f'"{label_for(item)}"' for item in prints)
                found = client(credentials, "POST", "/rest/api/3/search/jql",
                               {"jql": f'project = "{credentials["project"]}" AND labels in ({labels})', "maxResults": 1, "fields": ["key"]})
                issues = found.get("issues") or []
                if issues:
                    link = {"key": issues[0]["key"], "url": base + issues[0]["key"], "linked_at": _stamp(), "by": by}
            if link is not None:
                for item in prints:
                    if item not in known:
                        _remember(data_dir, asset, item, link)
                existing.extend({"fingerprint": item, **link} for item in prints)
                continue
            result = _create(client, credentials, _issue_fields(credentials, group), state)
            link = {"key": result["key"], "url": base + result["key"], "linked_at": _stamp(), "by": by}
            for item in prints:
                _remember(data_dir, asset, item, link)
            created.extend({"fingerprint": item, **link} for item in prints)
        except (JiraError, KeyError, TypeError) as exc:
            message = str(exc) if isinstance(exc, JiraError) else "Respuesta inesperada de Jira"
            failed.extend({"fingerprint": item, "error": message} for item in prints)
    _log.info("jira_export", extra={"user": by, "run_id": record["id"],
                                    "reason": f"{len(created)} creadas, {len(existing)} ya existían, {len(failed)} fallos"})
    return {"created": created, "existing": existing, "failed": failed}


SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
PRIORITY_ORDER = ("Highest", "High", "Medium", "Low")


def _work_items(tickets: list[dict]) -> list[list[dict]]:
    """Agrupa por paquete instalado; todo lo demás es un trabajo por hallazgo."""
    groups: dict[str, list[dict]] = {}
    for ticket in tickets:
        package = ticket.get("package") or {}
        key = f"pkg:{package.get('ecosystem')}:{package.get('name')}@{package.get('version')}" if package.get("name") else ticket["fingerprint"]
        groups.setdefault(key, []).append(ticket)
    return list(groups.values())


def _issue_fields(credentials: dict, group: list[dict]) -> dict:
    first = group[0]
    severity = min((ticket["severity"] for ticket in group), key=lambda item: SEVERITY_ORDER.index(item) if item in SEVERITY_ORDER else 9)
    priority = min((ticket["priority"] for ticket in group), key=lambda item: PRIORITY_ORDER.index(item) if item in PRIORITY_ORDER else 9)
    package = first.get("package") or {}
    if len(group) > 1 and package.get("name"):
        fixes = [ticket["package"]["fixed_version"] for ticket in group if (ticket.get("package") or {}).get("fixed_version")]
        target = None
        for version in fixes:
            if target is None or compare_versions(version, target) > 0:
                target = version
        summary = (f"[{severity.upper()}] Actualizar {package['name']} {package.get('version')}"
                   + (f" a {target}" if target else " (sin corrección publicada)") + f" · {len(group)} avisos")
        header = [f"Paquete {package['name']} {package.get('version')} ({package.get('ecosystem')}).",
                  f"Actualizar a {target} cierra los {len(fixes)} avisos con corrección publicada." if target else
                  "Ninguno de los avisos tiene todavía versión corregida publicada.", ""]
        description = "\n".join(header) + "\n\n".join(ticket["description"] for ticket in group)
    else:
        summary, description = first["summary"], first["description"]
    labels = {label_for(ticket["fingerprint"]) for ticket in group}
    for ticket in group:
        labels.update(re.sub(r"[^A-Za-z0-9_.-]", "-", item)[:60] for item in ticket["labels"])
    trace = "\n".join(f"Huella: {ticket['fingerprint']}" for ticket in group)
    return {"project": {"key": credentials["project"]}, "issuetype": {"name": credentials["issue_type"]},
            "summary": summary[:255], "priority": {"name": priority},
            "description": _adf(f"{description}\n\nOrigen: {first['source']} · ejecución {first['run_id']}\n{trace}"),
            "labels": sorted(labels)}


def _create(client, credentials: dict, fields: dict, state: dict) -> dict:
    # Muchos proyectos no exponen el campo prioridad en la pantalla de alta: se reintenta sin él.
    if not state["priority"]:
        fields.pop("priority", None)
    try:
        return client(credentials, "POST", "/rest/api/3/issue", {"fields": fields})
    except JiraError as exc:
        if "priority" not in str(exc) or "priority" not in fields:
            raise
        state["priority"] = False
        fields.pop("priority")
        return client(credentials, "POST", "/rest/api/3/issue", {"fields": fields})


def _stamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
