"""Modelado de amenazas: un modelo del sistema, STRIDE por elemento y evidencia de los escaneos.

El modelo lo construye el equipo —componentes, flujos de datos y fronteras de
confianza— con ayuda de una **propuesta** que sale del inventario de los
repositorios escaneados (qué frameworks, bases de datos y servicios usa el
código). La propuesta es un punto de partida editable, no una verdad.

Sobre el modelo se aplican reglas STRIDE propias y visibles, como las reglas
SAST: cada amenaza dice qué regla la genera, por qué aplica a ese elemento, qué
la mitiga y con qué CWE se relaciona. Lo que la distingue de una lista genérica
es la **evidencia**: si un repositorio enlazado tiene hallazgos abiertos con uno
de esos CWE —en la carpeta del componente, si se indicó—, la amenaza aparece *con indicios* y
enlaza a ellos: una señal para revisar, no una confirmación.

Exporta a OWASP Threat Dragon (JSON v2) y a un script de OWASP pytm, para quien
quiera seguir en esas herramientas.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

from tamandua.modules.threats import diagram as threat_diagram
from tamandua.modules.threats import methods as threat_methods
from tamandua.modules.threats import report as threat_report
from tamandua.modules.findings import triage
from tamandua.shared import documents
from tamandua.shared.i18n import default_locale, localize, msg, t, text


class ModelError(ValueError):
    """A validation error; `message` is a language-neutral message, str() renders it in the default locale."""

    def __init__(self, message):
        super().__init__(message)
        self.message = message

    def __str__(self) -> str:
        return text(self.message)


KINDS = {
    "actor": msg("threats.kinds.actor"), "web_app": msg("threats.kinds.web_app"), "api": msg("threats.kinds.api"),
    "service": msg("threats.kinds.service"), "function": msg("threats.kinds.function"), "database": msg("threats.kinds.database"),
    "cache": msg("threats.kinds.cache"), "queue": msg("threats.kinds.queue"), "storage": msg("threats.kinds.storage"),
    "external": msg("threats.kinds.external"), "identity": msg("threats.kinds.identity"), "custom": msg("threats.kinds.custom"),
}
PROCESSES = {"web_app", "api", "service", "function"}
STORES = {"database", "cache", "queue", "storage"}
CLASSIFICATIONS = {"public": 1, "internal": 2, "confidential": 3, "pii": 3, "credentials": 4, "payment": 4}
CLASSIFICATION_LABELS = {"public": msg("threats.classifications.public"), "internal": msg("threats.classifications.internal"),
                         "confidential": msg("threats.classifications.confidential"), "pii": msg("threats.classifications.pii"),
                         "credentials": msg("threats.classifications.credentials"), "payment": msg("threats.classifications.payment")}
PROTOCOLS = ("https", "http", "grpc", "websocket", "sql", "amqp", "redis", "smtp", "sftp", "other")
DECISIONS = ("mitigated", "accepted", "not_applicable")
ID = re.compile(r"[a-z0-9][a-z0-9-]{0,39}")
FOLDER = re.compile(r"[A-Za-z0-9_.\- /@+]{0,200}")
CANVAS = 100_000  # coordenadas del lienzo: de sobra para cualquier diagrama
LIMITS = {"components": 60, "flows": 150, "boundaries": 20}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _text(value, limit: int, field, *, required: bool = False) -> str:
    if value is None or value == "":
        if required:
            raise ModelError(msg("threats.errors.field_required", field=field))
        return ""
    if not isinstance(value, str) or len(value) > limit:
        raise ModelError(msg("threats.errors.field_too_long", field=field, limit=limit))
    cleaned = " ".join(value.split())
    if any(ord(character) < 32 for character in cleaned):
        raise ModelError(msg("threats.errors.control_characters", field=field))
    return cleaned


def _folder(value, field) -> str:
    """Carpeta del repositorio que es el código de un componente: relativa, sin «..», terminada en «/»."""
    if value in (None, ""):
        return ""
    if not isinstance(value, str) or not FOLDER.fullmatch(value):
        raise ModelError(msg("threats.errors.folder_relative", field=field))
    clean = value.strip().removeprefix("./").strip("/")
    if any(part in ("", ".", "..") for part in clean.split("/")) and clean:
        raise ModelError(msg("threats.errors.folder_segments", field=field))
    return f"{clean}/" if clean else ""


def _number(value, low: float, high: float):
    return round(float(value), 1) if isinstance(value, (int, float)) and not isinstance(value, bool) and low <= value <= high else None


def _position(raw) -> dict | None:
    """Dónde está un componente en el lienzo del editor. Opcional: sin ella se reparte en columnas."""
    if not isinstance(raw, dict):
        return None
    x, y = _number(raw.get("x"), -CANVAS, CANVAS), _number(raw.get("y"), -CANVAS, CANVAS)
    return {"x": x, "y": y} if x is not None and y is not None else None


def _size(raw) -> dict | None:
    """Tamaño de un componente redimensionado en el editor; sin él, el panel usa el tamaño estándar."""
    if not isinstance(raw, dict):
        return None
    width, height = _number(raw.get("width"), 120, 800), _number(raw.get("height"), 50, 600)
    return {"width": width, "height": height} if width and height else None


def _box(raw) -> dict | None:
    if not isinstance(raw, dict):
        return None
    position = _position(raw)
    width, height = _number(raw.get("width"), 80, 20_000), _number(raw.get("height"), 60, 20_000)
    return {**position, "width": width, "height": height} if position and width and height else None


# ------------------------------------------------------------ validación

def _color(value, identifier: str) -> str:
    """Color elegido en el editor: un token de la paleta o nada (automático, según el tipo)."""
    if value in (None, ""):
        return ""
    if value not in threat_diagram.COLORS:
        raise ModelError(msg("threats.errors.invalid_color", id=identifier))
    return value


def _legend(raw, components: list[dict]) -> dict:
    """Team labels for manual colors ({tone: label}); labels of colors no component uses are dropped."""
    if raw in (None, {}):
        return {}
    if not isinstance(raw, dict) or any(tone not in threat_diagram.COLORS for tone in raw):
        raise ModelError(msg("threats.errors.invalid_legend"))
    used = set(threat_diagram.legend_tones({"components": components})[1])
    labels = {tone: _text(raw[tone], 40, msg("threats.fields.legend_label", color=threat_diagram.COLOR_NAMES[tone]))
              for tone in threat_diagram.COLORS if tone in raw}
    return {tone: label for tone, label in labels.items() if label and tone in used}


def validate(payload: dict, *, known_assets: set[str]) -> dict:
    """Normaliza un modelo que llega del panel. Todo lo que no se reconoce se rechaza."""
    if not isinstance(payload, dict):
        raise ModelError(msg("threats.errors.invalid_model"))
    model = {"name": _text(payload.get("name"), 80, msg("threats.fields.name"), required=True),
             "description": _text(payload.get("description"), 1000, msg("threats.fields.description"))}
    components, ids = [], set()
    for raw in payload.get("components") or []:
        if not isinstance(raw, dict):
            raise ModelError(msg("threats.errors.invalid_component"))
        identifier = raw.get("id")
        if not isinstance(identifier, str) or not ID.fullmatch(identifier) or identifier in ids:
            raise ModelError(msg("threats.errors.component_id"))
        if raw.get("kind") not in KINDS:
            raise ModelError(msg("threats.errors.invalid_kind", id=identifier))
        if raw.get("kind") == "custom" and raw.get("custom_base", "service") not in KINDS.keys() - {"custom"}:
            raise ModelError(msg("threats.errors.invalid_base", id=identifier))
        data = raw.get("data") or []
        if not isinstance(data, list) or any(item not in CLASSIFICATIONS for item in data):
            raise ModelError(msg("threats.errors.invalid_data", id=identifier))
        asset = raw.get("asset")
        if asset not in (None, "") and asset not in known_assets:
            raise ModelError(msg("threats.errors.unknown_asset", id=identifier))
        ids.add(identifier)
        components.append({"id": identifier, "name": _text(raw.get("name"), 80, msg("threats.fields.component_name"), required=True),
                           "kind": raw["kind"], "custom_kind": _text(raw.get("custom_kind"), 80, msg("threats.fields.custom_kind"), required=raw["kind"] == "custom") if raw["kind"] == "custom" else "",
                           "custom_base": raw.get("custom_base", "service") if raw["kind"] == "custom" else "",
                           "description": _text(raw.get("description"), 400, msg("threats.fields.description")),
                           "technology": _text(raw.get("technology"), 80, msg("threats.fields.technology")),
                           "asset": asset or None, "asset_ref": _text(raw.get("asset_ref"), 200, msg("threats.fields.asset_ref")),
                           "path": _folder(raw.get("path"), msg("threats.fields.folder", id=identifier)),
                           "position": _position(raw.get("position")), "size": _size(raw.get("size")), "data": sorted(set(data)),
                           "internet_facing": bool(raw.get("internet_facing")),
                           "authenticates": bool(raw.get("authenticates")),
                           "encrypted_at_rest": bool(raw.get("encrypted_at_rest")),
                           "color": _color(raw.get("color"), identifier),
                           "origin": raw.get("origin") if raw.get("origin") in ("suggested", "manual") else "manual"})
    flows, flow_ids = [], set()
    for raw in payload.get("flows") or []:
        if not isinstance(raw, dict):
            raise ModelError(msg("threats.errors.invalid_flow"))
        identifier = raw.get("id")
        if not isinstance(identifier, str) or not ID.fullmatch(identifier) or identifier in flow_ids:
            raise ModelError(msg("threats.errors.flow_id"))
        if raw.get("source") not in ids or raw.get("target") not in ids or raw["source"] == raw["target"]:
            raise ModelError(msg("threats.errors.flow_ends", id=identifier))
        if raw.get("protocol") not in PROTOCOLS:
            raise ModelError(msg("threats.errors.invalid_protocol", id=identifier))
        data = raw.get("data") or []
        if not isinstance(data, list) or any(item not in CLASSIFICATIONS for item in data):
            raise ModelError(msg("threats.errors.invalid_data", id=identifier))
        flow_ids.add(identifier)
        flows.append({"id": identifier, "source": raw["source"], "target": raw["target"],
                      "name": _text(raw.get("name"), 80, msg("threats.fields.flow_name")), "protocol": raw["protocol"],
                      "data": sorted(set(data)), "authenticated": bool(raw.get("authenticated")),
                      "encrypted": bool(raw.get("encrypted")) or raw["protocol"] in ("https", "sftp")})
    boundaries, boundary_ids, placed = [], set(), set()
    for raw in payload.get("boundaries") or []:
        if not isinstance(raw, dict):
            raise ModelError(msg("threats.errors.invalid_boundary"))
        identifier = raw.get("id")
        members = raw.get("components") or []
        if not isinstance(identifier, str) or not ID.fullmatch(identifier) or identifier in boundary_ids:
            raise ModelError(msg("threats.errors.boundary_id"))
        if not isinstance(members, list) or any(item not in ids for item in members):
            raise ModelError(msg("threats.errors.boundary_members", id=identifier))
        if placed.intersection(members):
            raise ModelError(msg("threats.errors.one_boundary"))
        placed.update(members)
        boundary_ids.add(identifier)
        boundaries.append({"id": identifier, "name": _text(raw.get("name"), 80, msg("threats.fields.boundary_name"), required=True),
                           "components": list(dict.fromkeys(members)), "box": _box(raw.get("box")),
                           "color": _color(raw.get("color"), identifier)})
    too_many = {"components": msg("threats.errors.too_many_components", limit=LIMITS["components"]),
                "flows": msg("threats.errors.too_many_flows", limit=LIMITS["flows"]),
                "boundaries": msg("threats.errors.too_many_boundaries", limit=LIMITS["boundaries"])}
    for key, items in (("components", components), ("flows", flows), ("boundaries", boundaries)):
        if len(items) > LIMITS[key]:
            raise ModelError(too_many[key])
    repositories = payload.get("repositories") or []
    if not isinstance(repositories, list) or len(repositories) > 50 or any(not isinstance(item, str) for item in repositories):
        raise ModelError(msg("threats.errors.invalid_repositories"))
    if any(item not in known_assets for item in repositories):
        raise ModelError(msg("threats.errors.unknown_repository"))
    # Los repositorios que usan los componentes forman parte del proyecto aunque no se hayan añadido a mano.
    model["repositories"] = list(dict.fromkeys([*repositories, *(item["asset"] for item in components if item.get("asset") and not item["asset"].startswith("domain:"))]))
    references = payload.get("repository_refs") or []
    if not isinstance(references, list) or len(references) > 50:
        raise ModelError(msg("threats.errors.invalid_repository_refs"))
    model["repository_refs"] = list(dict.fromkeys(_text(item, 200, msg("threats.fields.repository_ref"), required=True) for item in references))
    try:
        # Lo propio del enfoque elegido: amenazas escritas a mano, árboles, técnicas ATT&CK, etapas PASTA.
        extras = threat_methods.validate(payload, elements=ids | flow_ids)
    except threat_methods.MethodError as exc:
        raise ModelError(exc.message) from exc
    model["legend"] = _legend(payload.get("legend"), components)
    return {**model, "components": components, "flows": flows, "boundaries": boundaries, **extras}


def to_portable(model: dict, assets: dict[str, dict] | None = None) -> dict:
    """Formato editable: no contiene IDs locales, decisiones ni evidencia de escaneos."""
    assets = assets or {}
    def label(identifier: str) -> str:
        return assets.get(identifier, {}).get("name") or identifier

    fields = ("name", "description", "methodology", "components", "flows", "boundaries")
    portable = {key: model[key] for key in fields if key in model}
    if model.get("legend"):
        portable["legend"] = model["legend"]
    if model.get("methodology") == "custom":
        portable["custom_modules"] = model.get("custom_modules", ["manual", "elements"])
    allowed = _portable_sections(model)
    for section in ("manual_threats", "pasta", "attack_trees", "attack_mappings"):
        if section in allowed:
            portable[section] = model.get(section) or ({} if section == "pasta" else [])
    portable["repository_refs"] = list(dict.fromkeys([*(model.get("repository_refs") or []),
                                                        *(label(item) for item in model.get("repositories") or [])]))
    portable["components"] = []
    for component in model.get("components") or []:
        entry = {key: value for key, value in component.items() if key != "asset"}
        entry["asset_ref"] = label(component["asset"]) if component.get("asset") else component.get("asset_ref") or ""
        portable["components"].append(entry)
    return {"format": "tamandua-threat-model", "version": 1, "model": portable}


def from_portable(document: dict) -> dict:
    """Importa un modelo sin confiar en IDs de activos ni enlazarlos automáticamente."""
    if not isinstance(document, dict):
        raise ModelError(msg("threats.errors.not_an_object"))
    if "format" in document or "version" in document:
        if document.get("format") != "tamandua-threat-model" or document.get("version") != 1:
            raise ModelError(msg("threats.errors.unsupported_format"))
        raw = document.get("model")
    else:
        raw = document
    if not isinstance(raw, dict):
        raise ModelError(msg("threats.errors.model_not_an_object"))
    repositories = raw.get("repositories") or []
    references = raw.get("repository_refs") or []
    if not isinstance(repositories, list) or not isinstance(references, list):
        raise ModelError(msg("threats.errors.refs_not_a_list"))
    components = raw.get("components") or []
    if not isinstance(components, list):
        raise ModelError(msg("threats.errors.components_not_a_list"))
    detached = []
    for item in components:
        if not isinstance(item, dict):
            raise ModelError(msg("threats.errors.invalid_component"))
        reference = item.get("asset_ref") or item.get("asset") or ""
        detached.append({**item, "asset": None, "asset_ref": reference})
    clean = {**raw, "components": detached, "repositories": [], "repository_refs": [*references, *repositories]}
    imported = validate(clean, known_assets=set())
    # Posiciones que no encajan con sus fronteras (cajas pequeñas o solapadas): mejor recolocar que dibujarlas mal.
    if not geometry_fits(imported):
        imported = {**imported, "components": [{**item, "position": None} for item in imported["components"]],
                    "boundaries": [{**item, "box": None} for item in imported["boundaries"]]}
        imported["relayout"] = True
    allowed = _portable_sections(imported)
    labels = {"manual_threats": msg("threats.sections.manual_threats"), "attack_trees": msg("threats.sections.attack_trees"),
              "attack_mappings": msg("threats.sections.attack_mappings"), "pasta": msg("threats.sections.pasta")}
    for section, label in labels.items():
        if imported[section] and section not in allowed:
            method = threat_methods.METHODOLOGIES[imported["methodology"]]
            raise ModelError(msg("threats.errors.section_not_allowed", method=method, section=label))
    if imported["methodology"] != "custom" and raw.get("custom_modules") not in (None, [], ["manual", "elements"]):
        raise ModelError(msg("threats.errors.custom_modules_only"))
    return imported


def geometry_fits(model: dict) -> bool:
    """¿Las posiciones y cajas de un modelo son coherentes? Cada componente colocado dentro de la caja de su
    frontera y ninguna caja pisa a otra (salvo si la contiene entera). Sin posiciones, no hay nada que comprobar."""
    components = {item["id"]: item for item in model.get("components", [])}
    if not any(item.get("position") for item in components.values()):
        return True
    if not all(item.get("position") for item in components.values()):
        return False
    boxes = {item["id"]: item["box"] for item in model.get("boundaries", []) if item.get("box")}
    for boundary in model.get("boundaries", []):
        box = boxes.get(boundary["id"])
        if box is None and boundary["components"]:
            return False
        for member in boundary["components"]:
            point, (width, height) = components[member]["position"], _node_size(components[member])
            if not (box["x"] <= point["x"] and point["x"] + width <= box["x"] + box["width"]
                    and box["y"] <= point["y"] and point["y"] + height - 16 <= box["y"] + box["height"]):
                return False
    ids = list(boxes)
    for index, first in enumerate(ids):
        for second in ids[index + 1:]:
            a, b = boxes[first], boxes[second]
            overlap = a["x"] < b["x"] + b["width"] and b["x"] < a["x"] + a["width"] and a["y"] < b["y"] + b["height"] and b["y"] < a["y"] + a["height"]
            inside = lambda outer, inner: (outer["x"] <= inner["x"] and outer["y"] <= inner["y"] and inner["x"] + inner["width"] <= outer["x"] + outer["width"]
                                           and inner["y"] + inner["height"] <= outer["y"] + outer["height"])
            if overlap and not inside(a, b) and not inside(b, a):
                return False
    return True


def _portable_sections(model: dict) -> set[str]:
    """Las secciones propias de un método; el diagrama es común a todos."""
    method = model.get("methodology") or "stride"
    if method == "custom":
        modules = set(model.get("custom_modules", ["manual", "elements"]))
        return {section for module, section in (("manual", "manual_threats"), ("trees", "attack_trees"),
                                                ("attack", "attack_mappings"), ("pasta", "pasta")) if module in modules}
    return {
        "stride": {"manual_threats"},
        "linddun": {"manual_threats"},
        "pasta": {"manual_threats", "pasta", "attack_trees"},
        "attack_trees": {"manual_threats", "attack_trees"},
        "attack": {"manual_threats", "attack_mappings"},
    }.get(method, set())


# ------------------------------------------------------------ almacén

def _name(model_id: str) -> str:
    if not isinstance(model_id, str) or not re.fullmatch(r"[0-9a-f]{24}", model_id):
        raise ModelError(msg("threats.errors.not_found"))
    return f"threat-models/{model_id}"


def load(data_dir: Path, model_id: str) -> dict:
    model = documents.load(data_dir, _name(model_id))
    if model is None:
        raise ModelError(msg("threats.errors.not_found"))
    return model


def _write(data_dir: Path, model: dict) -> None:
    documents.save(data_dir, _name(model["id"]), model)


def list_models(data_dir: Path) -> list[dict]:
    rows = []
    for name in documents.names(data_dir, "threat-models/"):
        model = documents.load(data_dir, name)
        if not isinstance(model, dict):
            continue
        rows.append({key: model.get(key) for key in ("id", "name", "description", "updated_at", "updated_by", "created_at")}
                    | {"components": len(model.get("components", [])), "flows": len(model.get("flows", [])),
                       "repositories": len(model.get("repositories") or []),
                       "methodology": model.get("methodology") or "stride"})
    return sorted(rows, key=lambda row: row.get("updated_at") or "", reverse=True)


def save(data_dir: Path, model: dict, *, by: str, model_id: str | None = None) -> dict:
    with documents.lock(data_dir, "threat-models"):
        if model_id is None:
            stored = {"id": secrets.token_hex(12), "created_at": _now(), "created_by": by, "decisions": {}}
        else:
            stored = load(data_dir, model_id)
        stored.update(model, updated_at=_now(), updated_by=by)
        _write(data_dir, stored)
    return stored


def delete(data_dir: Path, model_id: str) -> None:
    load(data_dir, model_id)  # 404 si no existe
    documents.delete(data_dir, _name(model_id))


def decide(data_dir: Path, model_id: str, threat_id: str, status: str, reason, *, by: str) -> dict:
    if status not in (*DECISIONS, "open"):
        raise ModelError(msg("threats.errors.invalid_decision"))
    if not isinstance(threat_id, str) or not re.fullmatch(r"[0-9a-f]{16}", threat_id):
        raise ModelError(msg("threats.errors.invalid_threat"))
    reason = _text(reason, 500, msg("threats.fields.reason"))
    if status != "open" and len(reason) < 10:
        raise ModelError(msg("threats.errors.reason_required"))
    with documents.lock(data_dir, "threat-models"):
        model = load(data_dir, model_id)
        if threat_id not in {item["id"] for item in threats(model)}:
            raise ModelError(msg("threats.errors.threat_not_in_model"))
        decisions = model.setdefault("decisions", {})
        if status == "open":
            decisions.pop(threat_id, None)
        else:
            decisions[threat_id] = {"status": status, "reason": reason, "by": by, "at": _now()}
        _write(data_dir, model)
    return model


# ------------------------------------------------------------ propuesta

# Firma de dependencia → componente que sugiere. Nombres exactos o prefijos terminados en «/».
NEXT_APP, BROWSER_APP, ORM_DATABASE = msg("threats.suggest.nextjs_app"), msg("threats.suggest.browser_app"), msg("threats.suggest.orm_database")
SIGNATURES = [
    (("next",), "web_app", NEXT_APP, "Next.js"),
    (("react", "vue", "@angular/core", "svelte", "solid-js"), "web_app", BROWSER_APP, None),
    (("express", "fastify", "koa", "@nestjs/core", "@hapi/hapi", "hono"), "api", msg("threats.suggest.node_api"), None),
    (("django", "flask", "fastapi", "starlette", "tornado"), "api", msg("threats.suggest.python_api"), None),
    (("github.com/gin-gonic/gin", "github.com/labstack/echo/v4", "github.com/gofiber/fiber/v2"), "api", msg("threats.suggest.go_api"), None),
    (("axum", "actix-web", "rocket", "warp", "poem"), "api", msg("threats.suggest.rust_api"), None),
    (("clap", "typer", "click", "commander", "yargs", "github.com/spf13/cobra"), "function", msg("threats.suggest.cli"), None),
    (("pg", "postgres", "psycopg2", "psycopg2-binary", "psycopg", "asyncpg", "github.com/lib/pq", "github.com/jackc/pgx/v5"), "database", "PostgreSQL", "PostgreSQL"),
    (("mysql", "mysql2", "pymysql", "mysqlclient"), "database", "MySQL", "MySQL"),
    (("mongoose", "mongodb", "pymongo", "motor"), "database", "MongoDB", "MongoDB"),
    (("sqlx", "diesel", "tokio-postgres", "sea-orm", "rusqlite"), "database", msg("threats.suggest.rust_database"), None),
    (("@prisma/client", "prisma", "sequelize", "typeorm", "drizzle-orm", "sqlalchemy", "knex"), "database", ORM_DATABASE, None),
    (("redis", "ioredis", "github.com/redis/go-redis/v9"), "cache", "Redis", "Redis"),
    (("bull", "bullmq", "amqplib", "kafkajs", "celery", "pika", "kombu"), "queue", msg("threats.suggest.job_queue"), None),
    (("@aws-sdk/client-s3", "aws-sdk", "boto3", "@google-cloud/storage", "cloudinary", "@azure/storage-blob"), "storage", msg("threats.suggest.object_storage"), None),
    (("stripe",), "external", msg("threats.suggest.stripe"), "Stripe"),
    (("@sendgrid/mail", "nodemailer", "resend", "postmark"), "external", msg("threats.suggest.email"), None),
    (("twilio",), "external", msg("threats.suggest.twilio"), "Twilio"),
    (("openai", "@anthropic-ai/sdk", "anthropic", "@google/generative-ai", "langchain", "ollama-rs", "async-openai", "ollama"), "external", msg("threats.suggest.llm"), None),
    (("@supabase/supabase-js",), "external", "Supabase", "Supabase"),
    (("firebase", "firebase-admin"), "external", "Firebase", "Firebase"),
    (("next-auth", "@auth/core", "@clerk/nextjs", "@auth0/nextjs-auth0", "passport", "keycloak-js", "authlib"), "identity", msg("threats.suggest.identity"), None),
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


def suggest(name: str, repositories: list[dict], *, locale: str | None = None) -> dict:
    """Propuesta inicial a partir del inventario de los últimos escaneos. Todo queda marcado como sugerido.

    The proposal becomes the team's own editable content, so it is written in the requester's language."""
    locale = locale or default_locale()
    say = lambda value: text(value, locale)  # noqa: E731
    next_app, browser_app, orm_database = say(NEXT_APP), say(BROWSER_APP), say(ORM_DATABASE)
    used: set[str] = set()
    user = t("threats.suggest.user", locale)
    components = [{"id": _slug(user, used), "name": user, "kind": "actor", "internet_facing": True, "origin": "suggested"}]
    flows, app_ids, backends = [], [], []
    found: dict[tuple[str, str], dict] = {}
    via: set[tuple[str, str]] = set()
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
                matched.append((kind, say(label), technology or hit[0],
                                t("threats.suggest.detected_by", locale, packages=", ".join(hit[:3]), where=f"{short}/{where}" if where else short),
                                where.rsplit("/", 1)[0] + "/" if where and "/" in where else "", ", ".join(hit[:3])))
        for image in inventory.get("services") or []:
            if image in SERVICE_IMAGES:
                kind, label = SERVICE_IMAGES[image]
                where = found_in.get(f"image:{image}")
                matched.append((kind, label, label, t("threats.suggest.image_in", locale, image=image, where=f"{short}/{where}" if where else short),
                                "", image))
        has_process = any(item[0] in PROCESSES for item in matched)
        if not has_process:
            read = ", ".join(inventory.get("manifests") or []) or t("threats.suggest.no_manifest", locale)
            matched.append(("api", t("threats.suggest.service", locale, name=short), None,
                            t("threats.suggest.no_framework", locale, name=short, read=read[:200]), "", ""))
        # Un ORM es la forma de hablar con la base de datos, no otra base de datos: si hay motor concreto, se fusionan.
        orm = next((item for item in matched if item[1] == orm_database), None)
        engines = [item for item in matched if item[0] == "database" and item[1] != orm_database]
        merged_orm = None
        if orm and engines:
            matched = [item for item in matched if item is not orm and item is not engines[0]]
            kind, label, technology, provenance, folder, _ = engines[0]
            merged_orm = (kind, label, t("threats.suggest.via", locale, technology=technology, orm=orm[2]),
                          t("threats.suggest.accessed_with", locale, provenance=provenance, packages=orm[5]), folder, "")
            matched.append(merged_orm)
        # Next.js ya es la app web: no se duplica con «aplicación en el navegador».
        if any(item[1] == next_app for item in matched):
            matched = [item for item in matched if item[1] != browser_app]
        several = len(repositories) > 1
        for entry in matched:
            kind, label, technology, provenance, folder, _ = entry
            key = (kind, label if kind not in PROCESSES else f"{label}:{repository['id']}")
            if key in found:
                # Otra pista del mismo componente: se suma a su procedencia en lugar de perderse.
                existing = found[key]
                if provenance and provenance not in existing["description"]:
                    existing["description"] = f"{existing['description']}; {provenance}"[:400]
                if entry is merged_orm and key not in via:
                    existing["technology"] = technology
                    via.add(key)
                continue
            if entry is merged_orm:
                via.add(key)
            # Con varios repositorios, cada proceso lleva el suyo en el nombre: dos «API Python» no se distinguen.
            shown = f"{label} · {short}" if several and kind in PROCESSES and short not in label else label
            component = {"id": _slug(shown, used), "name": shown, "kind": kind, "technology": technology or "",
                         "description": provenance[:400],
                         "origin": "suggested", "asset": repository["id"] if kind in PROCESSES else None,
                         "path": folder if kind in PROCESSES else "",
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
    boundaries = [{"id": "internet", "name": t("threats.suggest.boundary_internet", locale), "components": [c["id"] for c in components if c["kind"] in ("actor", "external", "identity")]},
                  {"id": "aplicacion", "name": t("threats.suggest.boundary_application", locale), "components": [c["id"] for c in components if c["kind"] in PROCESSES]},
                  {"id": "datos", "name": t("threats.suggest.boundary_data", locale), "components": [c["id"] for c in components if c["kind"] in STORES]}]
    sources = "; ".join(f"{item['name']} ({', '.join((item.get('inventory') or {}).get('manifests') or []) or t('threats.suggest.no_manifests', locale)})"
                        for item in repositories)
    return {"name": name, "description": t("threats.suggest.description", locale, sources=sources[:880]),
            "components": components, "flows": flows, "boundaries": [item for item in boundaries if item["components"]]}


NODE_W, ROW, PAD = 184, 124, 36  # mismas medidas que el editor del panel


def merge_proposal(model: dict, proposal: dict) -> tuple[dict, dict]:
    """Añade a un modelo lo que se propone desde nuevos repositorios, sin duplicar lo que ya hay.

    Un componente propuesto es el mismo que uno existente si coinciden tipo y repositorio (procesos) o
    tipo y nombre (actores, almacenes, terceros). Los nuevos se colocan dentro de su frontera si ya
    está dibujada, o a la derecha de lo dibujado: no se pierde la disposición que hizo el equipo.
    """
    merged = json.loads(json.dumps(model))
    components = merged.setdefault("components", [])
    flows = merged.setdefault("flows", [])
    boundaries = merged.setdefault("boundaries", [])
    used = {item["id"] for item in components}
    same: dict[str, str] = {}
    added = []

    def key(item: dict) -> tuple:
        return (item["kind"], item.get("asset")) if item["kind"] in PROCESSES and item.get("asset") else (item["kind"], item["name"].lower())
    existing = {key(item): item["id"] for item in components}
    for item in proposal.get("components", []):
        if key(item) in existing:
            same[item["id"]] = existing[key(item)]
            continue
        new = {**item, "id": _slug(item["name"], used)}
        same[item["id"]] = new["id"]
        existing[key(new)] = new["id"]
        components.append(new)
        added.append(new["id"])
    pairs = {(flow["source"], flow["target"]) for flow in flows}
    flow_ids = {flow["id"] for flow in flows}
    new_flows = 0
    for flow in proposal.get("flows", []):
        source, target = same.get(flow["source"]), same.get(flow["target"])
        if not source or not target or source == target or (source, target) in pairs:
            continue
        pairs.add((source, target))
        flows.append({**flow, "id": _slug(f"{source}-{target}", flow_ids), "source": source, "target": target})
        new_flows += 1
    placed = {member for boundary in boundaries for member in boundary["components"]}
    by_name = {boundary["name"].lower(): boundary for boundary in boundaries}
    boundary_ids = {boundary["id"] for boundary in boundaries}
    drawn = any(item.get("position") for item in components)
    right = max([item["position"]["x"] + NODE_W for item in components if item.get("position")]
                + [boundary["box"]["x"] + boundary["box"]["width"] for boundary in boundaries if boundary.get("box")] or [0]) + 80
    for proposed in proposal.get("boundaries", []):
        members = [same[member] for member in proposed["components"] if same.get(member) in added and same[member] not in placed]
        if not members:
            continue
        # A proposal may come in another language than the model: its boundary id is stable.
        target = by_name.get(proposed["name"].lower()) or next((item for item in boundaries if item["id"] == proposed["id"]), None)
        if target is None:
            target = {"id": _slug(proposed["id"], boundary_ids), "name": proposed["name"], "components": []}
            if drawn:
                target["box"] = {"x": right - PAD, "y": 40, "width": NODE_W + PAD * 2, "height": 70}
                right += NODE_W + PAD * 2 + 60
            boundaries.append(target)
            by_name[target["name"].lower()] = target
        for member in members:
            target["components"].append(member)
            placed.add(member)
            if drawn:
                component = next(item for item in components if item["id"] == member)
                box = target.get("box")
                if box:
                    inside = [item["position"]["y"] for item in components if item["id"] in target["components"] and item.get("position")]
                    component["position"] = {"x": box["x"] + PAD, "y": (max(inside) + ROW) if inside else box["y"] + 50}
                    box["height"] = max(box["height"], component["position"]["y"] - box["y"] + ROW)
    for member in added:  # sin frontera: a la derecha de lo dibujado
        component = next(item for item in components if item["id"] == member)
        if drawn and not component.get("position"):
            component["position"] = {"x": right, "y": 90}
            right += NODE_W + 60
    return merged, {"components": len(added), "flows": new_flows}


# ------------------------------------------------------------ STRIDE

STRIDE = {"S": msg("threats.stride.s"), "T": msg("threats.stride.t"), "R": msg("threats.stride.r"), "I": msg("threats.stride.i"),
          "D": msg("threats.stride.d"), "E": msg("threats.stride.e")}

# Each rule: id, base severity, STRIDE category, what it applies to and the CWEs that evidence it (texts: threats.rules.*).
RULES = [
    threat_methods.rule("TM-S01", "high", "S", "internet_process_unauthenticated", [306, 287]),
    threat_methods.rule("TM-S02", "high", "S", "identity", [287, 345, 347, 384, 613]),
    threat_methods.rule("TM-S03", "medium", "S", "inbound_from_external", [345, 347]),
    threat_methods.rule("TM-S04", "medium", "S", "web_app", [352]),
    threat_methods.rule("TM-T01", "high", "T", "process", [74, 77, 78, 79, 89, 94, 95, 611, 643, 917, 943, 1336]),
    threat_methods.rule("TM-T02", "medium", "T", "process", [1104, 1395, 937, 1035], evidence={"scanners": ("sca",), "any_cwe": True}),
    threat_methods.rule("TM-T03", "high", "T", "store_written_unauthenticated", [306, 284]),
    threat_methods.rule("TM-T04", "medium", "T", "flow_unencrypted_boundary", [319, 295]),
    threat_methods.rule("TM-R01", "low", "R", "process_sensitive", [778, 223, 117]),
    threat_methods.rule("TM-I01", "medium", "I", "process", [200, 209, 213, 532, 538, 540, 798, 312, 359],
                         mitigations=3, evidence={"scanners": ("sast", "secrets", "iac"), "any_cwe_for": ("secrets",)}),
    threat_methods.rule("TM-I02", "medium", "I", "store_sensitive_unencrypted", [311, 312]),
    threat_methods.rule("TM-I03", "high", "I", "store_credentials", [256, 257, 261, 327, 328, 759, 760, 916]),
    threat_methods.rule("TM-I04", "medium", "I", "flow_unencrypted_boundary", [319]),
    threat_methods.rule("TM-I05", "medium", "I", "flow_to_external_sensitive", [359, 201]),
    threat_methods.rule("TM-I06", "medium", "I", "storage", [732, 552]),
    threat_methods.rule("TM-D01", "medium", "D", "internet_process", [400, 770, 1333, 799]),
    threat_methods.rule("TM-D02", "low", "D", "external", [400]),
    threat_methods.rule("TM-E01", "high", "E", "process_authenticated", [285, 639, 862, 863, 269, 915]),
    threat_methods.rule("TM-E02", "high", "E", "process_calls_out", [918]),
]
SEVERITY_ORDER = ("critical", "high", "medium", "low")


def _index(model: dict) -> tuple[dict, dict]:
    components = {item["id"]: item for item in model.get("components", [])}
    boundary_of = {member: boundary["id"] for boundary in model.get("boundaries", []) for member in boundary["components"]}
    return components, boundary_of


def _kind(component: dict) -> str:
    """Los tipos propios conservan un rol base para las reglas y los formatos externos."""
    return (component.get("custom_base") or "service") if component["kind"] == "custom" else component["kind"]


def _targets(model: dict, rules: list[dict] | None = None) -> list[tuple[dict, dict | None, dict | None]]:
    """(regla, componente, flujo) para cada regla que aplica. Las condiciones están aquí, a la vista."""
    components, boundary_of = _index(model)
    flows = model.get("flows", [])
    inbound = {cid: [flow for flow in flows if flow["target"] == cid] for cid in components}
    outbound = {cid: [flow for flow in flows if flow["source"] == cid] for cid in components}
    result = []
    for rule in RULES if rules is None else rules:
        applies = rule["applies"]
        if applies.startswith("flow_"):
            for flow in flows:
                crosses = boundary_of.get(flow["source"]) != boundary_of.get(flow["target"])
                sensitive = any(CLASSIFICATIONS[item] >= 3 for item in flow["data"])
                target = components[flow["target"]]
                if ((applies == "flow_unencrypted_boundary" and crosses and not flow["encrypted"] and set(flow["data"]) - {"public"})
                        or (applies == "flow_to_external_sensitive" and _kind(target) == "external" and sensitive)
                        or (applies == "flow_personal_to_external" and _kind(target) == "external" and "pii" in flow["data"])):
                    result.append((rule, None, flow))
            continue
        for component in components.values():
            kind = _kind(component)
            process = kind in PROCESSES
            sensitive = any(CLASSIFICATIONS[item] >= 3 for item in component["data"]) or any(
                CLASSIFICATIONS[item] >= 3 for flow in inbound[component["id"]] + outbound[component["id"]] for item in flow["data"])
            # Datos personales (LINDDUN): los guarda o le llegan o salen por algún flujo.
            personal = "pii" in component["data"] or any("pii" in flow["data"] for flow in inbound[component["id"]] + outbound[component["id"]])
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
                "process_calls_out": process and any(_kind(components[flow["target"]]) in ("external", "service", "api", "identity") for flow in outbound[component["id"]]),
                "inbound_from_external": process and any(_kind(components[flow["source"]]) == "external" for flow in inbound[component["id"]]),
                "store_written_unauthenticated": kind in STORES and any(not flow["authenticated"] for flow in inbound[component["id"]]),
                "store_sensitive_unencrypted": kind in STORES and not component["encrypted_at_rest"] and any(CLASSIFICATIONS[item] >= 3 for item in component["data"]),
                "store_credentials": kind in STORES and "credentials" in component["data"],
                "store_personal": kind in STORES and "pii" in component["data"],
                "store_personal_unencrypted": kind in STORES and "pii" in component["data"] and not component["encrypted_at_rest"],
                "process_personal": process and personal,
                "process_personal_facing_actor": process and personal and any(_kind(components[flow["source"]]) == "actor" for flow in inbound[component["id"]]),
            }.get(applies, False)
            if match:
                result.append((rule, component, None))
    return result


def _severity(model: dict, rule: dict, component: dict | None, flow: dict | None) -> str:
    """Severidad base de la regla, un nivel arriba si está expuesto y lleva datos críticos, uno abajo si es interno y poco sensible."""
    components, _ = _index(model)
    if flow is not None:
        data = flow["data"]
        exposure = 3 if any(components[end]["internet_facing"] or _kind(components[end]) in ("actor", "external") for end in (flow["source"], flow["target"])) else 2
    else:
        related = [f for f in model.get("flows", []) if component["id"] in (f["source"], f["target"])]
        data = component["data"] + [item for f in related for item in f["data"]]
        exposure = 3 if component["internet_facing"] or _kind(component) in ("external", "identity") else 2 if related else 1
    impact = max([CLASSIFICATIONS[item] for item in data] or [2])
    level = SEVERITY_ORDER.index(rule["base"])
    if exposure == 3 and impact >= 4:
        level -= 1
    elif exposure == 1 or impact <= 1:
        level += 1
    return SEVERITY_ORDER[max(0, min(level, len(SEVERITY_ORDER) - 1))]


def _scopes_near(model: dict, component: dict | None, flow: dict | None) -> set[tuple[str, str]]:
    """(repositorio, carpeta) cuyo código implementa o toca el elemento; carpeta vacía = repositorio entero."""
    components, _ = _index(model)
    if component is not None and _kind(component) in PROCESSES:
        return {(component["asset"], component.get("path") or "")} if component.get("asset") else set()
    if flow is not None:
        ends = [components[flow["source"]], components[flow["target"]]]
    else:
        ends = [component] + [components[f["source"] if f["target"] == component["id"] else f["target"]]
                              for f in model.get("flows", []) if component["id"] in (f["source"], f["target"])]
    return {(item["asset"], item.get("path") or "") for item in ends if item.get("asset")}


def threats(model: dict, findings_by_asset: dict[str, list[dict]] | None = None, *, locale: str | None = None) -> list[dict]:
    """Amenazas del modelo con su severidad, evidencia de los escaneos y decisión del equipo, rendered for `locale`."""
    decisions = model.get("decisions", {})
    rows = []
    method = model.get("methodology") or "stride"
    families = ([threat_methods.RULE_BASED[method]] if method in threat_methods.RULE_BASED else
                [item for item in ("stride", "linddun") if item in model.get("custom_modules", [])] if method == "custom" else [])
    for family in families:
      rules = RULES if family == "stride" else threat_methods.LINDDUN_RULES
      categories = STRIDE if family == "stride" else threat_methods.LINDDUN
      for rule, component, flow in _targets(model, rules):
        element = flow["id"] if flow else component["id"]
        threat_id = hashlib.sha256(f"{rule['id']}|{element}".encode()).hexdigest()[:16]
        evidence = []
        policy = rule.get("evidence") or {}
        # Por defecto evidencia el código propio; una vulnerabilidad de una dependencia se atribuye a TM-T02.
        scanners = policy.get("scanners", ("sast", "secrets", "iac"))
        scopes = sorted(_scopes_near(model, component, flow))
        for asset, folder in scopes:
            for finding in (findings_by_asset or {}).get(asset, []):
                scanner = finding.get("scanner")
                if scanner not in scanners:
                    continue
                # Solo el código del componente: en un monorepo, el backend no evidencia amenazas del frontend.
                if folder and not str(finding.get("path") or "").startswith(folder):
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
        rows.append({"id": threat_id, "rule": rule["id"], "stride": rule["stride"], "category": categories[rule["stride"]], "framework": family,
                     "title": rule["title"], "why": rule["why"], "mitigations": rule["mitigations"], "cwe": rule["cwe"],
                     "element": element, "element_type": "flow" if flow else "component", "element_name": label,
                     "severity": severity, "status": status, "decision": decision,
                     "evidence": evidence[:20], "evidence_count": len(evidence),
                     "evidence_scope": [{"asset": asset, "path": folder or None} for asset, folder in scopes]})
    if method != "custom" or "manual" in model.get("custom_modules", ["manual", "elements"]):
        rows += _manual_rows(model, decisions)
    rows = localize(rows, locale or default_locale())
    order = {"evidenced": 0, "open": 1, "accepted": 2, "mitigated": 3, "not_applicable": 4}
    return sorted(rows, key=lambda row: (order[row["status"]], SEVERITY_ORDER.index(row["severity"]), row["stride"], row["element_name"]))


def _manual_rows(model: dict, decisions: dict) -> list[dict]:
    """Amenazas escritas por el equipo: mismo ciclo de decisiones que las de las reglas."""
    components, _ = _index(model)
    flows = {flow["id"]: flow for flow in model.get("flows", [])}
    # Un código de la categoría del enfoque («S», «Dd») se muestra con su nombre; lo demás, tal cual.
    names = threat_methods.LINDDUN if model.get("methodology") == "linddun" else STRIDE
    rows = []
    for item in model.get("manual_threats", []):
        threat_id = hashlib.sha256(f"manual|{item['id']}".encode()).hexdigest()[:16]
        element = item.get("element") or ""
        flow = flows.get(element)
        name = (f"{components[flow['source']]['name']} → {components[flow['target']]['name']}" if flow
                else components[element]["name"] if element in components else msg("threats.threat.whole_system"))
        decision = decisions.get(threat_id)
        rows.append({"id": threat_id, "rule": "PROPIA", "stride": item.get("category") or "", "category": names.get(item.get("category") or "", item.get("category") or msg("threats.threat.no_category")),
                     "framework": "manual", "manual_id": item["id"], "title": item["title"], "why": item.get("scenario") or "",
                     "mitigations": [item["mitigation"]] if item.get("mitigation") else [], "cwe": [],
                     "element": element, "element_type": "flow" if flow else "component" if element in components else "system",
                     "element_name": name, "severity": item["severity"], "status": decision["status"] if decision else "open",
                     "decision": decision, "evidence": [], "evidence_count": 0, "evidence_scope": [],
                     "likelihood": item.get("likelihood"), "impact": item.get("impact"), "owner": item.get("owner") or ""})
    return rows


def evidence_index(data_dir: Path, assets: set[str]) -> dict[str, list[dict]]:
    """Hallazgos activos del último escaneo completo de cada repositorio enlazado."""
    from tamandua.modules.runs.store import list_runs, load_run
    latest: dict[str, dict] = {}
    from tamandua.modules.sources.assets import asset_key
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
            "by_stride": {code: sum(1 for row in rows if row["stride"] == code) for code in dict.fromkeys(row["stride"] for row in rows)},
            "by_severity": {level: sum(1 for row in rows if row["severity"] == level and row["status"] in ("evidenced", "open"))
                            for level in SEVERITY_ORDER}}


# ------------------------------------------------------------ exportaciones

def to_threat_dragon(model: dict, rows: list[dict], *, locale: str | None = None) -> dict:
    """OWASP Threat Dragon v2: un diagrama STRIDE con actores, procesos, almacenes, flujos y fronteras."""
    locale = locale or default_locale()
    rows = localize(rows, locale)
    shapes = {"actor": ("actor", "tm.Actor"), "external": ("actor", "tm.Actor"), "identity": ("actor", "tm.Actor"),
              **{kind: ("store", "tm.Store") for kind in STORES}, **{kind: ("process", "tm.Process") for kind in PROCESSES}}
    status = {"evidenced": "Open", "open": "Open", "accepted": "Open", "mitigated": "Mitigated", "not_applicable": "NA"}
    by_element: dict[str, list[dict]] = {}
    for number, row in enumerate(rows, 1):
        by_element.setdefault(row["element"], []).append({
            "id": row["id"], "number": number, "title": row["title"], "type": STRIDE_EN.get(row["stride"], row["category"]),
            "status": status[row["status"]], "severity": {"critical": "High", "high": "High", "medium": "Medium", "low": "Low"}[row["severity"]],
            "description": row["why"] + (" " + t("threats.exports.evidence", locale, count=row["evidence_count"]) if row["evidence_count"] else ""),
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
        shape, kind = shapes[_kind(component)]
        position = layout["nodes"][component["id"]]
        items = by_element.get(component["id"], [])
        cells.append({"id": component["id"], "shape": shape, "zIndex": 1,
                      "position": {"x": position["x"], "y": position["y"]}, "size": {"width": 160, "height": 80},
                      "attrs": {"text": {"text": component["name"]}},
                      "data": {"type": kind, "name": component["name"], "description": component.get("description", ""),
                               "outOfScope": False, "reasonOutOfScope": "", "threats": items,
                               "hasOpenThreats": any(item["status"] == "Open" for item in items),
                               "isEncrypted": component.get("encrypted_at_rest", False), "isWebApplication": _kind(component) == "web_app",
                               "providesAuthentication": _kind(component) == "identity"}})
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
    return threat_diagram.layout(model)


def _node_size(component: dict) -> tuple[float, float]:
    return threat_diagram.node_size(component)


def to_svg(model: dict, *, locale: str | None = None) -> str:
    """Exporta solamente el diagrama actual como SVG autónomo, sin código ni scripts."""
    locale = locale or default_locale()
    return threat_diagram.to_svg(model, localize(KINDS, locale), locale=locale)


def to_pytm(model: dict, *, locale: str | None = None) -> str:
    """Script de OWASP pytm equivalente, para quien quiera seguir modelando como código."""
    locale = locale or default_locale()
    def name(value: str) -> str:
        return json.dumps(value, ensure_ascii=False)
    variables = {item["id"]: "c_" + item["id"].replace("-", "_") for item in model.get("components", [])}
    boundary_vars = {item["id"]: "b_" + item["id"].replace("-", "_") for item in model.get("boundaries", [])}
    member_of = {member: boundary["id"] for boundary in model.get("boundaries", []) for member in boundary["components"]}
    classes = {"actor": "Actor", "external": "ExternalEntity", "identity": "ExternalEntity", "web_app": "Server",
               "api": "Server", "service": "Process", "function": "Lambda", **{kind: "Datastore" for kind in STORES}}
    comment = lambda value: "# " + " ".join(value.split())  # noqa: E731
    lines = ["#!/usr/bin/env python3", comment(t("threats.exports.pytm_generated", locale, name=name(model["name"]))),
             comment(t("threats.exports.pytm_requires", locale)),
             "from pytm import TM, Actor, Boundary, Dataflow, Datastore, ExternalEntity, Lambda, Process, Server", "",
             f"tm = TM({name(model['name'])})", f"tm.description = {name(model.get('description') or model['name'])}",
             "tm.isOrdered = True", ""]
    for boundary in model.get("boundaries", []):
        lines.append(f"{boundary_vars[boundary['id']]} = Boundary({name(boundary['name'])})")
    lines.append("")
    for component in model.get("components", []):
        variable = variables[component["id"]]
        lines.append(f"{variable} = {classes[_kind(component)]}({name(component['name'])})")
        if component["id"] in member_of:
            lines.append(f"{variable}.inBoundary = {boundary_vars[member_of[component['id']]]}")
        if _kind(component) in STORES:
            lines.append(f"{variable}.isEncrypted = {component.get('encrypted_at_rest', False)}")
        if _kind(component) in PROCESSES:
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


def to_markdown(model: dict, rows: list[dict], *, locale: str | None = None) -> str:
    return threat_report.to_markdown(model, rows, locale=locale)
