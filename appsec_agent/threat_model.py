"""Modelado de amenazas: un modelo del sistema, STRIDE por elemento y evidencia de los escaneos.

El modelo lo construye el equipo —componentes, flujos de datos y fronteras de
confianza— con ayuda de una **propuesta** que sale del inventario de los
repositorios escaneados (qué frameworks, bases de datos y servicios usa el
código). La propuesta es un punto de partida editable, no una verdad.

Sobre el modelo se aplican reglas STRIDE propias y visibles, como las reglas
SAST: cada amenaza dice qué regla la genera, por qué aplica a ese elemento, qué
la mitiga y con qué CWE se relaciona. Lo que la distingue de una lista genérica
es la **evidencia**: si un repositorio enlazado tiene hallazgos abiertos con uno
de esos CWE, la amenaza aparece como *evidenciada* y enlaza a ellos.

Exporta a OWASP Threat Dragon (JSON v2) y a un script de OWASP pytm, para quien
quiera seguir en esas herramientas.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import threading
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

from . import triage


class ModelError(ValueError):
    pass


KINDS = {
    "actor": "Usuario o actor externo", "web_app": "Aplicación web (cliente)", "api": "API / backend",
    "service": "Servicio interno", "function": "Función o tarea", "database": "Base de datos", "cache": "Caché",
    "queue": "Cola o bus de mensajes", "storage": "Almacenamiento de ficheros", "external": "Servicio de terceros",
    "identity": "Proveedor de identidad",
}
PROCESSES = {"web_app", "api", "service", "function"}
STORES = {"database", "cache", "queue", "storage"}
CLASSIFICATIONS = {"public": 1, "internal": 2, "confidential": 3, "pii": 3, "credentials": 4, "payment": 4}
CLASSIFICATION_LABELS = {"public": "públicos", "internal": "internos", "confidential": "confidenciales",
                         "pii": "datos personales", "credentials": "credenciales", "payment": "datos de pago"}
PROTOCOLS = ("https", "http", "grpc", "websocket", "sql", "amqp", "redis", "smtp", "sftp", "other")
DECISIONS = ("mitigated", "accepted", "not_applicable")
ID = re.compile(r"[a-z0-9][a-z0-9-]{0,39}")
LIMITS = {"components": 60, "flows": 150, "boundaries": 20}
_lock = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _text(value, limit: int, field: str, *, required: bool = False) -> str:
    if value is None or value == "":
        if required:
            raise ModelError(f"Falta {field}")
        return ""
    if not isinstance(value, str) or len(value) > limit:
        raise ModelError(f"{field} admite hasta {limit} caracteres")
    cleaned = " ".join(value.split())
    if any(ord(character) < 32 for character in cleaned):
        raise ModelError(f"{field} contiene caracteres de control")
    return cleaned


# ------------------------------------------------------------ validación

def validate(payload: dict, *, known_assets: set[str]) -> dict:
    """Normaliza un modelo que llega del panel. Todo lo que no se reconoce se rechaza."""
    if not isinstance(payload, dict):
        raise ModelError("Modelo inválido")
    model = {"name": _text(payload.get("name"), 80, "El nombre", required=True),
             "description": _text(payload.get("description"), 1000, "La descripción")}
    components, ids = [], set()
    for raw in payload.get("components") or []:
        if not isinstance(raw, dict):
            raise ModelError("Componente inválido")
        identifier = raw.get("id")
        if not isinstance(identifier, str) or not ID.fullmatch(identifier) or identifier in ids:
            raise ModelError("Cada componente necesita un identificador único (minúsculas, números y guiones)")
        if raw.get("kind") not in KINDS:
            raise ModelError(f"Tipo de componente inválido en {identifier}")
        data = raw.get("data") or []
        if not isinstance(data, list) or any(item not in CLASSIFICATIONS for item in data):
            raise ModelError(f"Clasificación de datos inválida en {identifier}")
        asset = raw.get("asset")
        if asset not in (None, "") and asset not in known_assets:
            raise ModelError(f"El componente {identifier} enlaza un activo que no existe")
        ids.add(identifier)
        components.append({"id": identifier, "name": _text(raw.get("name"), 80, "El nombre del componente", required=True),
                           "kind": raw["kind"], "description": _text(raw.get("description"), 400, "La descripción"),
                           "technology": _text(raw.get("technology"), 80, "La tecnología"),
                           "asset": asset or None, "data": sorted(set(data)),
                           "internet_facing": bool(raw.get("internet_facing")),
                           "authenticates": bool(raw.get("authenticates")),
                           "encrypted_at_rest": bool(raw.get("encrypted_at_rest")),
                           "origin": raw.get("origin") if raw.get("origin") in ("suggested", "manual") else "manual"})
    flows, flow_ids = [], set()
    for raw in payload.get("flows") or []:
        if not isinstance(raw, dict):
            raise ModelError("Flujo inválido")
        identifier = raw.get("id")
        if not isinstance(identifier, str) or not ID.fullmatch(identifier) or identifier in flow_ids:
            raise ModelError("Cada flujo necesita un identificador único")
        if raw.get("source") not in ids or raw.get("target") not in ids or raw["source"] == raw["target"]:
            raise ModelError(f"El flujo {identifier} debe unir dos componentes distintos del modelo")
        if raw.get("protocol") not in PROTOCOLS:
            raise ModelError(f"Protocolo inválido en {identifier}")
        data = raw.get("data") or []
        if not isinstance(data, list) or any(item not in CLASSIFICATIONS for item in data):
            raise ModelError(f"Clasificación de datos inválida en {identifier}")
        flow_ids.add(identifier)
        flows.append({"id": identifier, "source": raw["source"], "target": raw["target"],
                      "name": _text(raw.get("name"), 80, "El nombre del flujo"), "protocol": raw["protocol"],
                      "data": sorted(set(data)), "authenticated": bool(raw.get("authenticated")),
                      "encrypted": bool(raw.get("encrypted")) or raw["protocol"] in ("https", "sftp")})
    boundaries, boundary_ids, placed = [], set(), set()
    for raw in payload.get("boundaries") or []:
        if not isinstance(raw, dict):
            raise ModelError("Frontera inválida")
        identifier = raw.get("id")
        members = raw.get("components") or []
        if not isinstance(identifier, str) or not ID.fullmatch(identifier) or identifier in boundary_ids:
            raise ModelError("Cada frontera necesita un identificador único")
        if not isinstance(members, list) or any(item not in ids for item in members):
            raise ModelError(f"La frontera {identifier} incluye componentes que no existen")
        if placed.intersection(members):
            raise ModelError("Un componente solo puede estar en una frontera de confianza")
        placed.update(members)
        boundary_ids.add(identifier)
        boundaries.append({"id": identifier, "name": _text(raw.get("name"), 80, "El nombre de la frontera", required=True),
                           "components": list(dict.fromkeys(members))})
    for key, items in (("components", components), ("flows", flows), ("boundaries", boundaries)):
        if len(items) > LIMITS[key]:
            raise ModelError(f"Máximo {LIMITS[key]} {key} por modelo")
    return {**model, "components": components, "flows": flows, "boundaries": boundaries}


# ------------------------------------------------------------ almacén

def _dir(data_dir: Path) -> Path:
    return data_dir / "threat-models"


def _path(data_dir: Path, model_id: str) -> Path:
    if not isinstance(model_id, str) or not re.fullmatch(r"[0-9a-f]{24}", model_id):
        raise ModelError("Modelo no encontrado")
    return _dir(data_dir) / f"{model_id}.json"


def load(data_dir: Path, model_id: str) -> dict:
    try:
        return json.loads(_path(data_dir, model_id).read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ModelError("Modelo no encontrado") from None


def _write(data_dir: Path, model: dict) -> None:
    target = _path(data_dir, model["id"])
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(".tmp")
    temporary.write_text(json.dumps(model, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    os.replace(temporary, target)


def list_models(data_dir: Path) -> list[dict]:
    rows = []
    folder = _dir(data_dir)
    if not folder.is_dir():
        return rows
    for path in sorted(folder.glob("*.json")):
        try:
            model = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        rows.append({key: model.get(key) for key in ("id", "name", "description", "updated_at", "updated_by", "created_at")}
                    | {"components": len(model.get("components", [])), "flows": len(model.get("flows", []))})
    return sorted(rows, key=lambda row: row.get("updated_at") or "", reverse=True)


def save(data_dir: Path, model: dict, *, by: str, model_id: str | None = None) -> dict:
    with _lock:
        if model_id is None:
            stored = {"id": secrets.token_hex(12), "created_at": _now(), "created_by": by, "decisions": {}}
        else:
            stored = load(data_dir, model_id)
        stored.update(model, updated_at=_now(), updated_by=by)
        _write(data_dir, stored)
    return stored


def delete(data_dir: Path, model_id: str) -> None:
    try:
        _path(data_dir, model_id).unlink()
    except FileNotFoundError:
        raise ModelError("Modelo no encontrado") from None


def decide(data_dir: Path, model_id: str, threat_id: str, status: str, reason, *, by: str) -> dict:
    if status not in (*DECISIONS, "open"):
        raise ModelError("Decisión inválida")
    if not isinstance(threat_id, str) or not re.fullmatch(r"[0-9a-f]{16}", threat_id):
        raise ModelError("Amenaza inválida")
    reason = _text(reason, 500, "El motivo")
    if status != "open" and len(reason) < 10:
        raise ModelError("Explica el motivo (mínimo 10 caracteres): queda registrado")
    with _lock:
        model = load(data_dir, model_id)
        if threat_id not in {item["id"] for item in threats(model)}:
            raise ModelError("La amenaza no pertenece a este modelo")
        decisions = model.setdefault("decisions", {})
        if status == "open":
            decisions.pop(threat_id, None)
        else:
            decisions[threat_id] = {"status": status, "reason": reason, "by": by, "at": _now()}
        _write(data_dir, model)
    return model


# ------------------------------------------------------------ propuesta

# Firma de dependencia → componente que sugiere. Nombres exactos o prefijos terminados en «/».
SIGNATURES = [
    (("next",), "web_app", "Aplicación Next.js", "Next.js"),
    (("react", "vue", "@angular/core", "svelte", "solid-js"), "web_app", "Aplicación web en el navegador", None),
    (("express", "fastify", "koa", "@nestjs/core", "@hapi/hapi", "hono"), "api", "API Node.js", None),
    (("django", "flask", "fastapi", "starlette", "tornado"), "api", "API Python", None),
    (("github.com/gin-gonic/gin", "github.com/labstack/echo/v4", "github.com/gofiber/fiber/v2"), "api", "API Go", None),
    (("axum", "actix-web", "rocket", "warp", "poem"), "api", "API Rust", None),
    (("clap", "typer", "click", "commander", "yargs", "github.com/spf13/cobra"), "function", "Herramienta de línea de comandos", None),
    (("pg", "postgres", "psycopg2", "psycopg2-binary", "psycopg", "asyncpg", "github.com/lib/pq", "github.com/jackc/pgx/v5"), "database", "PostgreSQL", "PostgreSQL"),
    (("mysql", "mysql2", "pymysql", "mysqlclient"), "database", "MySQL", "MySQL"),
    (("mongoose", "mongodb", "pymongo", "motor"), "database", "MongoDB", "MongoDB"),
    (("sqlx", "diesel", "tokio-postgres", "sea-orm", "rusqlite"), "database", "Base de datos (Rust)", None),
    (("@prisma/client", "prisma", "sequelize", "typeorm", "drizzle-orm", "sqlalchemy", "knex"), "database", "Base de datos (ORM)", None),
    (("redis", "ioredis", "github.com/redis/go-redis/v9"), "cache", "Redis", "Redis"),
    (("bull", "bullmq", "amqplib", "kafkajs", "celery", "pika", "kombu"), "queue", "Cola de trabajos", None),
    (("@aws-sdk/client-s3", "aws-sdk", "boto3", "@google-cloud/storage", "cloudinary", "@azure/storage-blob"), "storage", "Almacenamiento de objetos", None),
    (("stripe",), "external", "Stripe (pagos)", "Stripe"),
    (("@sendgrid/mail", "nodemailer", "resend", "postmark"), "external", "Correo transaccional", None),
    (("twilio",), "external", "Twilio (SMS/voz)", "Twilio"),
    (("openai", "@anthropic-ai/sdk", "anthropic", "@google/generative-ai", "langchain", "ollama-rs", "async-openai", "ollama"), "external", "Proveedor de LLM", None),
    (("@supabase/supabase-js",), "external", "Supabase", "Supabase"),
    (("firebase", "firebase-admin"), "external", "Firebase", "Firebase"),
    (("next-auth", "@auth/core", "@clerk/nextjs", "@auth0/nextjs-auth0", "passport", "keycloak-js", "authlib"), "identity", "Proveedor de identidad", None),
]
SERVICE_IMAGES = {"postgres": ("database", "PostgreSQL"), "mysql": ("database", "MySQL"), "mariadb": ("database", "MariaDB"),
                  "mongo": ("database", "MongoDB"), "redis": ("cache", "Redis"), "rabbitmq": ("queue", "RabbitMQ"),
                  "kafka": ("queue", "Kafka"), "minio": ("storage", "MinIO"), "elasticsearch": ("database", "Elasticsearch")}
PAYMENT = {"stripe"}


def _slug(text: str, used: set[str]) -> str:
    plain = "".join(character for character in unicodedata.normalize("NFKD", text) if not unicodedata.combining(character))
    base = re.sub(r"[^a-z0-9]+", "-", plain.lower()).strip("-")[:30] or "c"
    candidate, index = base, 2
    while candidate in used:
        candidate, index = f"{base}-{index}", index + 1
    used.add(candidate)
    return candidate


def suggest(name: str, repositories: list[dict]) -> dict:
    """Propuesta inicial a partir del inventario de los últimos escaneos. Todo queda marcado como sugerido."""
    used: set[str] = set()
    components = [{"id": _slug("usuario", used), "name": "Usuario", "kind": "actor", "internet_facing": True, "origin": "suggested"}]
    flows, app_ids, backends = [], [], []
    found: dict[tuple[str, str], dict] = {}
    for repository in repositories:
        inventory = repository.get("inventory") or {}
        names = {item for values in (inventory.get("packages") or {}).values() for item in values}
        # Sin inventario (escaneos antiguos) se usan los paquetes de los hallazgos de dependencias.
        names |= {(item.get("package") or {}).get("name") for item in repository.get("findings", []) if item.get("package")}
        names.discard(None)
        found_in = inventory.get("found_in") or {}
        short = repository["name"].split("/")[-1]
        matched = []
        for packages, kind, label, technology in SIGNATURES:
            hit = sorted(names.intersection(packages))
            if hit:
                where = found_in.get(hit[0])
                matched.append((kind, label, technology or hit[0],
                                f"Detectado por «{', '.join(hit[:3])}» en {short}/{where}" if where else f"Detectado por «{', '.join(hit[:3])}» en {short}"))
        for image in inventory.get("services") or []:
            if image in SERVICE_IMAGES:
                kind, label = SERVICE_IMAGES[image]
                where = found_in.get(f"image:{image}")
                matched.append((kind, label, label, f"Imagen «{image}» en {short}/{where}" if where else f"Imagen «{image}» en {short}"))
        has_process = any(kind in PROCESSES for kind, _, _, _ in matched)
        if not has_process:
            read = ", ".join(inventory.get("manifests") or []) or "ningún manifiesto"
            matched.append(("api", f"Servicio {short}", None,
                            f"No se reconoció ningún framework en {short} (leído: {read[:200]}); revisa el tipo."))
        # Un ORM es la forma de hablar con la base de datos, no otra base de datos: si hay motor concreto, se fusionan.
        orm = next((item for item in matched if item[1] == "Base de datos (ORM)"), None)
        engines = [item for item in matched if item[0] == "database" and item[1] != "Base de datos (ORM)"]
        if orm and engines:
            matched = [item for item in matched if item is not orm and item is not engines[0]]
            kind, label, technology, provenance = engines[0]
            matched.append((kind, label, f"{technology} vía {orm[2]}", f"{provenance}; acceso con {orm[3].split('«', 1)[-1].split('»', 1)[0]}"))
        # Next.js ya es la app web: no se duplica con «aplicación en el navegador».
        if any(label == "Aplicación Next.js" for _, label, _, _ in matched):
            matched = [item for item in matched if item[1] != "Aplicación web en el navegador"]
        several = len(repositories) > 1
        for kind, label, technology, provenance in matched:
            key = (kind, label if kind not in PROCESSES else f"{label}:{repository['id']}")
            if key in found:
                # Otra pista del mismo componente: se suma a su procedencia en lugar de perderse.
                existing = found[key]
                if provenance and provenance not in existing["description"]:
                    existing["description"] = f"{existing['description']}; {provenance}"[:400]
                if technology and " vía " in technology and " vía " not in existing["technology"]:
                    existing["technology"] = technology
                continue
            # Con varios repositorios, cada proceso lleva el suyo en el nombre: dos «API Python» no se distinguen.
            shown = f"{label} · {short}" if several and kind in PROCESSES and short not in label else label
            component = {"id": _slug(shown, used), "name": shown, "kind": kind, "technology": technology or "",
                         "description": provenance[:400],
                         "origin": "suggested", "asset": repository["id"] if kind in PROCESSES else None,
                         "internet_facing": kind in ("web_app", "api") and kind != "service",
                         "authenticates": kind in PROCESSES,
                         "data": ["payment"] if technology and technology.lower() in PAYMENT else
                                 ["pii", "credentials"] if kind in ("database", "identity") else
                                 ["internal"] if kind in STORES else []}
            found[key] = component
            components.append(component)
            (app_ids if kind == "web_app" else backends if kind in PROCESSES else []).append(component["id"])
    front = app_ids or backends[:1]
    user = components[0]["id"]
    for target in front:
        flows.append({"source": user, "target": target, "protocol": "https", "data": ["pii", "credentials"], "authenticated": False})
    servers = backends or app_ids
    for app in app_ids:
        for backend in backends:
            flows.append({"source": app, "target": backend, "protocol": "https", "data": ["pii"], "authenticated": True})
    for component in components:
        if component["kind"] in STORES:
            protocol = {"database": "sql", "cache": "redis", "queue": "amqp", "storage": "https"}[component["kind"]]
            for server in servers:
                flows.append({"source": server, "target": component["id"], "protocol": protocol, "data": component["data"], "authenticated": True})
        elif component["kind"] in ("external", "identity"):
            for server in servers[:1]:
                flows.append({"source": server, "target": component["id"], "protocol": "https", "data": component["data"] or ["internal"], "authenticated": True})
    flow_ids: set[str] = set()
    for flow in flows:
        flow["id"] = _slug(f"{flow['source']}-{flow['target']}", flow_ids)
        flow["name"] = ""
    boundaries = [{"id": "internet", "name": "Internet", "components": [c["id"] for c in components if c["kind"] in ("actor", "external", "identity")]},
                  {"id": "aplicacion", "name": "Aplicación", "components": [c["id"] for c in components if c["kind"] in PROCESSES]},
                  {"id": "datos", "name": "Datos", "components": [c["id"] for c in components if c["kind"] in STORES]}]
    sources = "; ".join(f"{item['name']} ({', '.join((item.get('inventory') or {}).get('manifests') or []) or 'sin manifiestos'})"
                        for item in repositories)
    return {"name": name, "description": f"Propuesta a partir de las dependencias de: {sources}"[:1000] + ". Revisa componentes, flujos y datos.",
            "components": components, "flows": flows, "boundaries": [item for item in boundaries if item["components"]]}


# ------------------------------------------------------------ STRIDE

STRIDE = {"S": "Suplantación", "T": "Manipulación", "R": "Repudio", "I": "Divulgación de información",
          "D": "Denegación de servicio", "E": "Elevación de privilegios"}

# Cada regla: id, categoría STRIDE, a qué aplica, título, por qué, mitigaciones y CWE que la evidencian.
RULES = [
    {"id": "TM-S01", "base": "high", "stride": "S", "applies": "internet_process_unauthenticated", "title": "Acceso sin autenticación a un componente expuesto",
     "why": "Recibe tráfico de Internet y no está marcado como autenticado: cualquiera puede invocarlo.",
     "mitigations": ["Exigir autenticación en todas las rutas no públicas", "Inventariar explícitamente las rutas públicas"], "cwe": [306, 287]},
    {"id": "TM-S02", "base": "high", "stride": "S", "applies": "identity", "title": "Tokens o sesiones aceptados sin validar bien",
     "why": "El sistema confía en la identidad que emite este proveedor: firma, emisor, audiencia y caducidad deben comprobarse siempre.",
     "mitigations": ["Validar firma, iss, aud y exp; rechazar alg=none", "Rotar claves y revocar sesiones al cerrar sesión"], "cwe": [287, 345, 347, 384, 613]},
    {"id": "TM-S03", "base": "medium", "stride": "S", "applies": "inbound_from_external", "title": "Webhooks o llamadas de terceros suplantables",
     "why": "Un servicio de terceros envía datos a este componente: sin verificar la firma, cualquiera puede fingir ser él.",
     "mitigations": ["Verificar la firma HMAC del webhook y su marca de tiempo", "Idempotencia por identificador de evento"], "cwe": [345, 347]},
    {"id": "TM-S04", "base": "medium", "stride": "S", "applies": "web_app", "title": "Peticiones en nombre del usuario (CSRF)",
     "why": "Una aplicación web con sesión en el navegador puede recibir peticiones forjadas desde otro origen.",
     "mitigations": ["Cookies SameSite=Strict/Lax y token o cabecera anti-CSRF", "Comprobar Origin en peticiones que cambian estado"], "cwe": [352]},
    {"id": "TM-T01", "base": "high", "stride": "T", "applies": "process", "title": "Inyección a través de la entrada del componente",
     "why": "Procesa entrada que no controla: consultas, comandos, plantillas o HTML construidos con ella pueden alterarse.",
     "mitigations": ["Consultas parametrizadas y APIs sin shell", "Validación por lista blanca y codificación de salida por contexto"],
     "cwe": [74, 77, 78, 79, 89, 94, 95, 611, 643, 917, 943, 1336]},
    {"id": "TM-T02", "base": "medium", "stride": "T", "applies": "process", "title": "Dependencias vulnerables o comprometidas",
     "why": "El componente se construye con código de terceros: una versión vulnerable o un paquete malicioso cambian su comportamiento.",
     "mitigations": ["Actualizar a versiones corregidas y fijar versiones con lockfile", "Revisar KEV/EPSS y vigilar la cadena de suministro"], "cwe": [1104, 1395, 937, 1035],
     "evidence": {"scanners": ("sca",), "any_cwe": True}},
    {"id": "TM-T03", "base": "high", "stride": "T", "applies": "store_written_unauthenticated", "title": "Escritura en el almacén sin autenticación",
     "why": "Algún flujo escribe en este almacén sin estar autenticado: cualquiera con red puede alterar los datos.",
     "mitigations": ["Credenciales por servicio con mínimo privilegio", "Aislar el almacén en red privada"], "cwe": [306, 284]},
    {"id": "TM-T04", "base": "medium", "stride": "T", "applies": "flow_unencrypted_boundary", "title": "Datos alterables en tránsito",
     "why": "El flujo cruza una frontera de confianza sin cifrar: un intermediario puede modificarlo.",
     "mitigations": ["TLS en todos los flujos que cruzan fronteras", "Validar certificados; HSTS en lo expuesto"], "cwe": [319, 295]},
    {"id": "TM-R01", "base": "low", "stride": "R", "applies": "process_sensitive", "title": "Acciones sensibles sin rastro verificable",
     "why": "Maneja datos sensibles: sin registro de quién hizo qué, no se puede investigar un abuso ni atribuirlo.",
     "mitigations": ["Registro de auditoría de accesos y cambios (quién, qué, cuándo)", "Logs fuera del alcance de quien opera la app"], "cwe": [778, 223, 117]},
    {"id": "TM-I01", "base": "medium", "stride": "I", "applies": "process", "title": "Secretos o datos sensibles expuestos por el componente",
     "why": "Un componente puede filtrar información por errores, respuestas demasiado amplias o secretos en el código.",
     "mitigations": ["Errores genéricos hacia fuera y detalle solo en logs", "Secretos en un gestor, nunca en el repositorio", "Respuestas con solo los campos necesarios"],
     "cwe": [200, 209, 213, 532, 538, 540, 798, 312, 359], "evidence": {"scanners": ("sast", "secrets", "iac"), "any_cwe_for": ("secrets",)}},
    {"id": "TM-I02", "base": "medium", "stride": "I", "applies": "store_sensitive_unencrypted", "title": "Datos sensibles sin cifrar en reposo",
     "why": "Guarda datos sensibles y no está marcado como cifrado en reposo: una copia del disco o del backup los expone.",
     "mitigations": ["Cifrado en reposo con claves gestionadas (KMS)", "Minimizar y seudonimizar lo que se guarda"], "cwe": [311, 312]},
    {"id": "TM-I03", "base": "high", "stride": "I", "applies": "store_credentials", "title": "Credenciales guardadas de forma recuperable",
     "why": "Guarda credenciales: con hashes débiles o reversibles, una fuga de la base de datos es una fuga de contraseñas.",
     "mitigations": ["Hash de contraseñas con scrypt, Argon2id o bcrypt", "Tokens de API guardados como hash"], "cwe": [256, 257, 261, 327, 328, 759, 760, 916]},
    {"id": "TM-I04", "base": "medium", "stride": "I", "applies": "flow_unencrypted_boundary", "title": "Datos legibles en tránsito",
     "why": "El flujo cruza una frontera de confianza sin cifrar y lleva datos que no son públicos.",
     "mitigations": ["TLS obligatorio", "No enviar credenciales ni datos personales por canales en claro"], "cwe": [319]},
    {"id": "TM-I05", "base": "medium", "stride": "I", "applies": "flow_to_external_sensitive", "title": "Datos sensibles enviados a un tercero",
     "why": "El flujo lleva datos personales, de pago o credenciales a un servicio externo: quedan fuera de tu control.",
     "mitigations": ["Enviar solo lo imprescindible y seudonimizar", "Contrato de encargo de tratamiento y revisión del proveedor"], "cwe": [359, 201]},
    {"id": "TM-I06", "base": "medium", "stride": "I", "applies": "storage", "title": "Objetos accesibles sin permiso",
     "why": "Un almacenamiento de ficheros mal configurado sirve objetos a cualquiera que tenga el enlace.",
     "mitigations": ["Buckets privados y URLs firmadas de corta duración", "Bloquear el acceso público a nivel de cuenta"], "cwe": [732, 552]},
    {"id": "TM-D01", "base": "medium", "stride": "D", "applies": "internet_process", "title": "Agotamiento por volumen de peticiones",
     "why": "Está expuesto a Internet: sin límites, unas pocas peticiones caras bastan para dejarlo sin servicio.",
     "mitigations": ["Límites de tasa y de tamaño por cliente", "Timeouts y colas acotadas"], "cwe": [400, 770, 1333, 799]},
    {"id": "TM-D02", "base": "low", "stride": "D", "applies": "external", "title": "Dependencia de un tercero sin plan de fallo",
     "why": "Si el servicio externo cae o responde lento, el componente que lo llama puede bloquearse con él.",
     "mitigations": ["Timeouts, reintentos con retroceso y circuit breaker", "Degradar la funcionalidad en lugar de caer"], "cwe": [400]},
    {"id": "TM-E01", "base": "high", "stride": "E", "applies": "process_authenticated", "title": "Acceso a objetos o funciones de otros usuarios",
     "why": "Distingue usuarios: sin comprobar la propiedad del objeto y el rol en cada petición, uno accede a lo de otro (BOLA/BFLA).",
     "mitigations": ["Autorización por objeto en el servidor, en cada petición", "Denegar por defecto y probar con dos usuarios"], "cwe": [285, 639, 862, 863, 269, 915]},
    {"id": "TM-E02", "base": "high", "stride": "E", "applies": "process_calls_out", "title": "El servidor hace peticiones hacia donde decida el atacante (SSRF)",
     "why": "Este componente llama a otros servicios: si parte del destino viene de la entrada, puede alcanzar la red interna o metadatos cloud.",
     "mitigations": ["Lista blanca de destinos y resolución DNS fijada", "Bloquear direcciones privadas y de metadatos"], "cwe": [918]},
]
SEVERITY_ORDER = ("critical", "high", "medium", "low")


def _index(model: dict) -> tuple[dict, dict]:
    components = {item["id"]: item for item in model.get("components", [])}
    boundary_of = {member: boundary["id"] for boundary in model.get("boundaries", []) for member in boundary["components"]}
    return components, boundary_of


def _targets(model: dict) -> list[tuple[dict, dict | None, dict | None]]:
    """(regla, componente, flujo) para cada regla que aplica. Las condiciones están aquí, a la vista."""
    components, boundary_of = _index(model)
    flows = model.get("flows", [])
    inbound = {cid: [flow for flow in flows if flow["target"] == cid] for cid in components}
    outbound = {cid: [flow for flow in flows if flow["source"] == cid] for cid in components}
    result = []
    for rule in RULES:
        applies = rule["applies"]
        if applies.startswith("flow_"):
            for flow in flows:
                crosses = boundary_of.get(flow["source"]) != boundary_of.get(flow["target"])
                sensitive = any(CLASSIFICATIONS[item] >= 3 for item in flow["data"])
                target = components[flow["target"]]
                if ((applies == "flow_unencrypted_boundary" and crosses and not flow["encrypted"] and set(flow["data"]) - {"public"})
                        or (applies == "flow_to_external_sensitive" and target["kind"] == "external" and sensitive)):
                    result.append((rule, None, flow))
            continue
        for component in components.values():
            kind = component["kind"]
            process = kind in PROCESSES
            sensitive = any(CLASSIFICATIONS[item] >= 3 for item in component["data"]) or any(
                CLASSIFICATIONS[item] >= 3 for flow in inbound[component["id"]] + outbound[component["id"]] for item in flow["data"])
            match = {
                "process": process,
                "web_app": kind == "web_app",
                "identity": kind == "identity",
                "external": kind == "external",
                "storage": kind == "storage",
                "internet_process": process and component["internet_facing"],
                "internet_process_unauthenticated": process and component["internet_facing"] and not component["authenticates"],
                "process_authenticated": process and component["authenticates"],
                "process_sensitive": process and sensitive,
                "process_calls_out": process and any(components[flow["target"]]["kind"] in ("external", "service", "api", "identity") for flow in outbound[component["id"]]),
                "inbound_from_external": process and any(components[flow["source"]]["kind"] == "external" for flow in inbound[component["id"]]),
                "store_written_unauthenticated": kind in STORES and any(not flow["authenticated"] for flow in inbound[component["id"]]),
                "store_sensitive_unencrypted": kind in STORES and not component["encrypted_at_rest"] and any(CLASSIFICATIONS[item] >= 3 for item in component["data"]),
                "store_credentials": kind in STORES and "credentials" in component["data"],
            }.get(applies, False)
            if match:
                result.append((rule, component, None))
    return result


def _severity(model: dict, rule: dict, component: dict | None, flow: dict | None) -> str:
    """Severidad base de la regla, un nivel arriba si está expuesto y lleva datos críticos, uno abajo si es interno y poco sensible."""
    components, _ = _index(model)
    if flow is not None:
        data = flow["data"]
        exposure = 3 if any(components[end]["internet_facing"] or components[end]["kind"] in ("actor", "external") for end in (flow["source"], flow["target"])) else 2
    else:
        related = [f for f in model.get("flows", []) if component["id"] in (f["source"], f["target"])]
        data = component["data"] + [item for f in related for item in f["data"]]
        exposure = 3 if component["internet_facing"] or component["kind"] in ("external", "identity") else 2 if related else 1
    impact = max([CLASSIFICATIONS[item] for item in data] or [2])
    level = SEVERITY_ORDER.index(rule["base"])
    if exposure == 3 and impact >= 4:
        level -= 1
    elif exposure == 1 or impact <= 1:
        level += 1
    return SEVERITY_ORDER[max(0, min(level, len(SEVERITY_ORDER) - 1))]


def _assets_near(model: dict, component: dict | None, flow: dict | None) -> set[str]:
    """Repositorios cuyo código implementa o toca el elemento.

    Un proceso tiene su propio código: su evidencia sale solo de su repositorio, nunca del de quien lo llama.
    Un almacén, un tercero o un flujo no tienen código propio: su evidencia está en los procesos que los usan.
    """
    components, _ = _index(model)
    if component is not None and component["kind"] in PROCESSES:
        return {component["asset"]} if component.get("asset") else set()
    if flow is not None:
        ends = [components[flow["source"]], components[flow["target"]]]
    else:
        ends = [component] + [components[f["source"] if f["target"] == component["id"] else f["target"]]
                              for f in model.get("flows", []) if component["id"] in (f["source"], f["target"])]
    return {item["asset"] for item in ends if item.get("asset")}


def threats(model: dict, findings_by_asset: dict[str, list[dict]] | None = None) -> list[dict]:
    """Amenazas del modelo con su severidad, evidencia de los escaneos y decisión del equipo."""
    decisions = model.get("decisions", {})
    rows = []
    for rule, component, flow in _targets(model):
        element = flow["id"] if flow else component["id"]
        threat_id = hashlib.sha256(f"{rule['id']}|{element}".encode()).hexdigest()[:16]
        evidence = []
        policy = rule.get("evidence") or {}
        # Por defecto evidencia el código propio; una vulnerabilidad de una dependencia se atribuye a TM-T02.
        scanners = policy.get("scanners", ("sast", "secrets", "iac"))
        for asset in sorted(_assets_near(model, component, flow)):
            for finding in (findings_by_asset or {}).get(asset, []):
                scanner = finding.get("scanner")
                if scanner not in scanners:
                    continue
                if (policy.get("any_cwe") or scanner in policy.get("any_cwe_for", ())
                        or set(finding.get("cwe") or []) & set(rule["cwe"])):
                    evidence.append({"asset": asset, "run_id": finding.get("run_id"), "fingerprint": finding["fingerprint"],
                                     "title": finding["title"], "severity": finding["severity"],
                                     "location": f"{finding.get('path')}:{finding.get('line')}", "cwe": finding.get("cwe")})
        decision = decisions.get(threat_id)
        status = decision["status"] if decision else "evidenced" if evidence else "open"
        severity = _severity(model, rule, component, flow)
        if evidence:
            worst = min((SEVERITY_ORDER.index(item["severity"]) for item in evidence if item["severity"] in SEVERITY_ORDER), default=3)
            severity = SEVERITY_ORDER[min(SEVERITY_ORDER.index(severity), worst)]
        components, _ = _index(model)
        label = (f"{components[flow['source']]['name']} → {components[flow['target']]['name']}" if flow else component["name"])
        rows.append({"id": threat_id, "rule": rule["id"], "stride": rule["stride"], "category": STRIDE[rule["stride"]],
                     "title": rule["title"], "why": rule["why"], "mitigations": rule["mitigations"], "cwe": rule["cwe"],
                     "element": element, "element_type": "flow" if flow else "component", "element_name": label,
                     "severity": severity, "status": status, "decision": decision,
                     "evidence": evidence[:20], "evidence_count": len(evidence)})
    order = {"evidenced": 0, "open": 1, "accepted": 2, "mitigated": 3, "not_applicable": 4}
    return sorted(rows, key=lambda row: (order[row["status"]], SEVERITY_ORDER.index(row["severity"]), row["stride"], row["element_name"]))


def evidence_index(data_dir: Path, assets: set[str]) -> dict[str, list[dict]]:
    """Hallazgos activos del último escaneo completo de cada repositorio enlazado."""
    from .store import list_runs, load_run
    latest: dict[str, dict] = {}
    from .assets import asset_key
    for row in list_runs(data_dir):
        key = asset_key(row)
        source = (row.get("source") or {}).get("id")
        match = key if key in assets else source if source in assets else None
        if row["type"] == "repository_scan" and row["status"] in ("completed", "incomplete") and match and match not in latest:
            latest[match] = row
    result = {}
    for asset, row in latest.items():
        try:
            record = triage.annotate(data_dir, load_run(data_dir, row["id"]))
        except (ValueError, OSError):
            continue
        result[asset] = [{**item, "run_id": record["id"]} for item in record["findings"] if triage.is_active(item)]
    return result


def summary(rows: list[dict]) -> dict:
    return {"total": len(rows),
            "by_status": {status: sum(1 for row in rows if row["status"] == status)
                          for status in ("evidenced", "open", "accepted", "mitigated", "not_applicable")},
            "by_stride": {letter: sum(1 for row in rows if row["stride"] == letter) for letter in STRIDE},
            "by_severity": {level: sum(1 for row in rows if row["severity"] == level and row["status"] in ("evidenced", "open"))
                            for level in SEVERITY_ORDER}}


# ------------------------------------------------------------ exportaciones

def to_threat_dragon(model: dict, rows: list[dict]) -> dict:
    """OWASP Threat Dragon v2: un diagrama STRIDE con actores, procesos, almacenes, flujos y fronteras."""
    shapes = {"actor": ("actor", "tm.Actor"), "external": ("actor", "tm.Actor"), "identity": ("actor", "tm.Actor"),
              **{kind: ("store", "tm.Store") for kind in STORES}, **{kind: ("process", "tm.Process") for kind in PROCESSES}}
    status = {"evidenced": "Open", "open": "Open", "accepted": "Open", "mitigated": "Mitigated", "not_applicable": "NA"}
    by_element: dict[str, list[dict]] = {}
    for number, row in enumerate(rows, 1):
        by_element.setdefault(row["element"], []).append({
            "id": row["id"], "number": number, "title": row["title"], "type": STRIDE_EN[row["stride"]],
            "status": status[row["status"]], "severity": {"critical": "High", "high": "High", "medium": "Medium", "low": "Low"}[row["severity"]],
            "description": row["why"] + (f" Evidencia: {row['evidence_count']} hallazgos abiertos." if row["evidence_count"] else ""),
            "mitigation": "; ".join(row["mitigations"]), "modelType": "STRIDE", "score": ""})
    layout = _layout(model)
    cells = []
    for index, boundary in enumerate(model.get("boundaries", [])):
        box = layout["boundaries"].get(boundary["id"])
        if box:
            cells.append({"id": f"b-{boundary['id']}", "shape": "trust-boundary-box", "zIndex": -1,
                          "position": {"x": box["x"], "y": box["y"]}, "size": {"width": box["width"], "height": box["height"]},
                          "attrs": {"label": {"text": boundary["name"]}},
                          "data": {"type": "tm.BoundaryBox", "name": boundary["name"], "isTrustBoundary": True, "hasOpenThreats": False}})
    for component in model.get("components", []):
        shape, kind = shapes[component["kind"]]
        position = layout["nodes"][component["id"]]
        items = by_element.get(component["id"], [])
        cells.append({"id": component["id"], "shape": shape, "zIndex": 1,
                      "position": {"x": position["x"], "y": position["y"]}, "size": {"width": 160, "height": 80},
                      "attrs": {"text": {"text": component["name"]}},
                      "data": {"type": kind, "name": component["name"], "description": component.get("description", ""),
                               "outOfScope": False, "reasonOutOfScope": "", "threats": items,
                               "hasOpenThreats": any(item["status"] == "Open" for item in items),
                               "isEncrypted": component.get("encrypted_at_rest", False), "isWebApplication": component["kind"] == "web_app",
                               "providesAuthentication": component["kind"] == "identity"}})
    for flow in model.get("flows", []):
        items = by_element.get(flow["id"], [])
        cells.append({"id": flow["id"], "shape": "flow", "zIndex": 2, "source": {"cell": flow["source"]}, "target": {"cell": flow["target"]},
                      "labels": [flow["name"] or flow["protocol"].upper()],
                      "data": {"type": "tm.Flow", "name": flow["name"] or flow["protocol"].upper(), "protocol": flow["protocol"],
                               "isEncrypted": flow["encrypted"], "isPublicNetwork": False, "outOfScope": False,
                               "reasonOutOfScope": "", "threats": items, "hasOpenThreats": any(item["status"] == "Open" for item in items)}})
    return {"version": "2.2.0", "summary": {"title": model["name"], "owner": model.get("updated_by", ""),
                                            "description": model.get("description", ""), "id": 0},
            "detail": {"contributors": [], "reviewer": "", "threatTop": len(rows), "threatMax": len(rows),
                       "diagrams": [{"id": 0, "title": model["name"], "diagramType": "STRIDE", "placeholder": "", "thumbnail": "",
                                     "version": "2.2.0", "cells": cells}]}}


STRIDE_EN = {"S": "Spoofing", "T": "Tampering", "R": "Repudiation", "I": "Information disclosure",
             "D": "Denial of service", "E": "Elevation of privilege"}


def _layout(model: dict) -> dict:
    """Columnas por frontera en el orden declarado; lo que no está en ninguna, al final."""
    columns = [boundary["components"] for boundary in model.get("boundaries", [])]
    placed = {member for column in columns for member in column}
    loose = [item["id"] for item in model.get("components", []) if item["id"] not in placed]
    if loose:
        columns.append(loose)
    nodes, boundaries = {}, {}
    for index, column in enumerate(columns):
        x = 40 + index * 260
        for row, member in enumerate(column):
            nodes[member] = {"x": x + 20, "y": 60 + row * 120}
        if index < len(model.get("boundaries", [])):
            boundaries[model["boundaries"][index]["id"]] = {"x": x, "y": 20, "width": 200, "height": 60 + max(1, len(column)) * 120}
    return {"nodes": nodes, "boundaries": boundaries}


def to_pytm(model: dict) -> str:
    """Script de OWASP pytm equivalente, para quien quiera seguir modelando como código."""
    def name(value: str) -> str:
        return json.dumps(value, ensure_ascii=False)
    variables = {item["id"]: "c_" + item["id"].replace("-", "_") for item in model.get("components", [])}
    boundary_vars = {item["id"]: "b_" + item["id"].replace("-", "_") for item in model.get("boundaries", [])}
    member_of = {member: boundary["id"] for boundary in model.get("boundaries", []) for member in boundary["components"]}
    classes = {"actor": "Actor", "external": "ExternalEntity", "identity": "ExternalEntity", "web_app": "Server",
               "api": "Server", "service": "Process", "function": "Lambda", **{kind: "Datastore" for kind in STORES}}
    lines = ["#!/usr/bin/env python3", f"# Generado por AppSec Agent a partir del modelo {name(model['name'])}.",
             "# Requiere OWASP pytm: pip install pytm · uso: python3 tm.py --report docs/basic_template.md",
             "from pytm import TM, Actor, Boundary, Dataflow, Datastore, ExternalEntity, Lambda, Process, Server", "",
             f"tm = TM({name(model['name'])})", f"tm.description = {name(model.get('description') or model['name'])}",
             "tm.isOrdered = True", ""]
    for boundary in model.get("boundaries", []):
        lines.append(f"{boundary_vars[boundary['id']]} = Boundary({name(boundary['name'])})")
    lines.append("")
    for component in model.get("components", []):
        variable = variables[component["id"]]
        lines.append(f"{variable} = {classes[component['kind']]}({name(component['name'])})")
        if component["id"] in member_of:
            lines.append(f"{variable}.inBoundary = {boundary_vars[member_of[component['id']]]}")
        if component["kind"] in STORES:
            lines.append(f"{variable}.isEncrypted = {component.get('encrypted_at_rest', False)}")
        if component["kind"] in PROCESSES:
            lines.append(f"{variable}.authenticatesSource = {component.get('authenticates', False)}")
    lines.append("")
    for flow in model.get("flows", []):
        label = flow["name"] or flow["protocol"].upper()
        variable = "f_" + flow["id"].replace("-", "_")
        lines += [f"{variable} = Dataflow({variables[flow['source']]}, {variables[flow['target']]}, {name(label)})",
                  f"{variable}.protocol = {name(flow['protocol'].upper())}",
                  f"{variable}.isEncrypted = {flow['encrypted']}"]
    lines += ["", 'if __name__ == "__main__":', "    tm.process()", ""]
    return "\n".join(lines)


def to_markdown(model: dict, rows: list[dict]) -> str:
    components, _ = _index(model)
    counts = summary(rows)
    lines = [f"# Modelo de amenazas · {model['name']}", "", model.get("description") or "", "",
             f"Actualizado {model.get('updated_at', '')[:16].replace('T', ' ')} por {model.get('updated_by', '—')}.", "",
             "## Resumen", "",
             f"- {counts['total']} amenazas STRIDE sobre {len(components)} componentes y {len(model.get('flows', []))} flujos.",
             f"- **{counts['by_status']['evidenced']} evidenciadas** por hallazgos abiertos de los escaneos; "
             f"{counts['by_status']['open']} abiertas sin evidencia (revisar); {counts['by_status']['mitigated']} mitigadas; "
             f"{counts['by_status']['accepted']} aceptadas; {counts['by_status']['not_applicable']} no aplican.", "",
             "## Componentes", "", "| Componente | Tipo | Datos | Expuesto | Repositorio |", "|---|---|---|---|---|"]
    for item in model.get("components", []):
        lines.append(f"| {item['name']} | {KINDS[item['kind']]} | {', '.join(CLASSIFICATION_LABELS[d] for d in item['data']) or '—'} | "
                     f"{'sí' if item['internet_facing'] else 'no'} | {item.get('asset') or '—'} |")
    lines += ["", "## Amenazas", ""]
    labels = {"evidenced": "EVIDENCIADA", "open": "abierta", "mitigated": "mitigada", "accepted": "aceptada", "not_applicable": "no aplica"}
    for row in rows:
        lines += [f"### [{row['severity'].upper()}] {row['title']} · {row['element_name']}", "",
                  f"STRIDE: {row['category']} · regla `{row['rule']}` · estado: **{labels[row['status']]}**"
                  + (f" ({row['decision']['by']}: {row['decision']['reason']})" if row.get("decision") else ""), "",
                  row["why"], "", "Mitigaciones: " + "; ".join(row["mitigations"]),
                  "CWE: " + ", ".join(f"CWE-{item}" for item in row["cwe"])]
        for item in row["evidence"][:5]:
            lines.append(f"- Evidencia: {item['title']} ({item['severity']}) en `{item['location']}` · {item['asset']}")
        lines.append("")
    lines += ["> Las amenazas salen de reglas sobre el modelo declarado: si el modelo no refleja el sistema, tampoco lo harán las amenazas.", ""]
    return "\n".join(lines)
