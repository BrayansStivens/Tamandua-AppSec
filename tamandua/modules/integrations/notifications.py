"""Avisos a Slack, Teams o un webhook cuando pasa algo que importa, para no depender de abrir el panel.

Eventos:
- `findings`: hallazgos nuevos desde un umbral de severidad, al terminar un análisis completo (manual, en lote o
  por la vigilancia de la rama principal) o al detectar avisos nuevos a diario. Uno por análisis, agrupado: los
  cinco más graves y el recuento. Las revisiones de PR no avisan aquí: ya comentan en el propio PR.
- `batches`: un lote (varios repositorios, una organización, varias imágenes) terminó.

Las URL de los webhooks son secretos (quien la tiene publica en tu canal): se guardan cifradas en la bóveda y
nunca vuelven al navegador. Solo https y, salvo permiso expreso, a direcciones públicas (SSRF). El envío va en
un hilo aparte con tiempo máximo: un canal caído nunca retrasa ni rompe un análisis. Los mensajes llevan título,
severidad y ubicación de cada hallazgo, nunca el valor de un secreto.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets as token_source
import socket
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert

from tamandua.modules.integrations.tables import outbox
from tamandua.shared import db
from tamandua.shared import log as logging_setup

_log = logging_setup.get("notifications")
_lock = threading.Lock()
VAULT_NAME = "notification-channels"
KINDS = {"slack": "Slack", "teams": "Microsoft Teams", "webhook": "Webhook"}
EVENTS = {"findings": "Hallazgos nuevos", "batches": "Lotes terminados"}
THRESHOLDS = ("critical", "high", "medium")
ORDER = ("critical", "high", "medium", "low", "info")
LABEL = {"critical": "crítico", "high": "alto", "medium": "medio", "low": "bajo", "info": "informativo"}
LABELS = {"critical": "críticos", "high": "altos", "medium": "medios", "low": "bajos", "info": "informativos"}
MAX_CHANNELS = 10
HOSTS = {"slack": re.compile(r"hooks\.slack\.com"),
         # Teams: los flujos de Workflows/Power Automate (los conectores clásicos de Office 365 se retiran).
         "teams": re.compile(r"(?:[a-z0-9-]+\.)*(?:logic\.azure\.com|webhook\.office\.com|environment\.api\.powerplatform\.com)")}


class NotificationError(ValueError):
    pass


def _vault() -> dict:
    from tamandua.shared.vault import get
    stored = get(VAULT_NAME)
    return stored if isinstance(stored, dict) else {}


def channels() -> list[dict]:
    """Lo que ve el panel: sin URL ni secreto, solo el host y los últimos caracteres."""
    rows = []
    for identifier, item in _vault().items():
        # Solo el host: el final de la URL de Slack o Teams es parte de su token.
        rows.append({"id": identifier, "kind": item["kind"], "name": item["name"], "host": urlsplit(item["url"]).hostname,
                     "events": item["events"], "threshold": item["threshold"],
                     "signed": bool(item.get("secret")), "created_by": item.get("created_by"), "created_at": item.get("created_at"),
                     "last": item.get("last")})
    return sorted(rows, key=lambda row: row.get("created_at") or "")


def check_url(kind: str, url: str) -> str:
    if not isinstance(url, str) or len(url) > 2048 or any(ord(char) < 33 for char in url):
        raise NotificationError("URL inválida")
    parts = urlsplit(url.strip())
    host = (parts.hostname or "").lower()
    if parts.scheme != "https" or not host or parts.username or parts.password:
        raise NotificationError("La URL debe ser https y sin usuario ni contraseña")
    if kind in HOSTS and not HOSTS[kind].fullmatch(host):
        raise NotificationError(f"No parece una URL de {KINDS[kind]}: {host}")
    if os.environ.get("TAMANDUA_ALLOW_PRIVATE_WEBHOOKS", "").strip() != "1":
        # El servidor hará la petición: una dirección interna convertiría el formulario en un SSRF.
        try:
            addresses = {info[4][0] for info in socket.getaddrinfo(host, parts.port or 443, proto=socket.IPPROTO_TCP)}
        except OSError as exc:
            raise NotificationError(f"No se pudo resolver {host}") from exc
        if not addresses or not all(ipaddress.ip_address(address.split("%")[0]).is_global for address in addresses):
            raise NotificationError(f"{host} resuelve a una dirección privada. Para un receptor de tu red, arranca con "
                                    "TAMANDUA_ALLOW_PRIVATE_WEBHOOKS=1.")
    return url.strip()


def save(kind: str, name: str, url: str, events: list[str], threshold: str, *, by: str) -> tuple[dict, str | None]:
    """Crea un canal. Devuelve la fila y, en un webhook, el secreto de firma (se muestra una sola vez)."""
    from tamandua.shared.vault import put
    if kind not in KINDS:
        raise NotificationError("Tipo de canal inválido")
    if not isinstance(name, str) or not 1 <= len(name.strip()) <= 60 or any(not char.isprintable() for char in name):
        raise NotificationError("Nombre inválido (hasta 60 caracteres)")
    if not isinstance(events, list) or not events or any(item not in EVENTS for item in events):
        raise NotificationError("Elige al menos un evento")
    if threshold not in THRESHOLDS:
        raise NotificationError("Umbral inválido")
    url = check_url(kind, url)
    with _lock:
        stored = _vault()
        if len(stored) >= MAX_CHANNELS:
            raise NotificationError(f"Como mucho {MAX_CHANNELS} canales")
        identifier = uuid.uuid4().hex[:12]
        secret = token_source.token_urlsafe(32) if kind == "webhook" else None
        stored[identifier] = {"kind": kind, "name": " ".join(name.split()), "url": url, "events": sorted(set(events)), "threshold": threshold,
                              "secret": secret, "created_by": by, "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        put(VAULT_NAME, stored)
    _log.info("channel_saved", extra={"user": by, "reason": f"{kind} {urlsplit(url).hostname}"})
    return next(row for row in channels() if row["id"] == identifier), secret


def remove(identifier: str, *, by: str) -> None:
    from tamandua.shared.vault import put
    with _lock:
        stored = _vault()
        if stored.pop(identifier, None) is None:
            raise NotificationError("Canal no encontrado")
        put(VAULT_NAME, stored)
    _log.info("channel_removed", extra={"user": by, "reason": identifier})


def _record_delivery(identifier: str, ok: bool, detail: str) -> None:
    from tamandua.shared.vault import put
    with _lock:
        stored = _vault()
        if identifier in stored:
            stored[identifier]["last"] = {"at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "ok": ok, "detail": detail[:160]}
            put(VAULT_NAME, stored)


# ------------------------------------------------------------------ mensajes

def panel_link(run_id: str | None = None) -> str | None:
    base = os.environ.get("TAMANDUA_PUBLIC_URL", "").strip().rstrip("/")
    if not base.startswith(("https://", "http://")):
        return None
    return f"{base}/#/hallazgos?run={run_id}" if run_id else base


def _where(finding: dict) -> str:
    package = finding.get("package") or {}
    if package.get("name"):
        return f"{package['name']} {package.get('version') or ''}".strip()
    return f"{finding.get('path')}:{finding.get('line')}"


def findings_message(record: dict, opened: list[dict]) -> dict:
    """El contenido común de un aviso de hallazgos; cada canal lo pinta a su manera."""
    counts = {level: sum(1 for item in opened if item.get("severity") == level) for level in ORDER}
    top = sorted(opened, key=lambda item: (ORDER.index(item.get("severity", "info")) if item.get("severity") in ORDER else 9, not item.get("kev")))[:5]
    name = (record.get("source") or {}).get("name") or record.get("fixture") or "activo"
    origin = {"advisory_watch": "avisos publicados después del último análisis",
              "image_scan": "análisis de la imagen"}.get(record.get("type"), "análisis completo del repositorio")
    if (record.get("trigger") or {}).get("kind") == "branch":
        origin = "reanálisis automático tras un cambio en la rama principal"
    summary = ", ".join(f"{counts[level]} {LABELS[level] if counts[level] != 1 else LABEL[level]}" for level in ORDER if counts[level])
    kev = sum(1 for item in opened if item.get("kev"))
    return {"event": "findings", "title": f"{len(opened)} {'hallazgo nuevo' if len(opened) == 1 else 'hallazgos nuevos'} en {name}",
            "text": f"{summary} · {origin}" + (f" · {kev} con explotación activa (CISA KEV)" if kev else ""),
            "asset": name, "run_id": record.get("id"), "link": panel_link(record.get("id")), "counts": counts,
            "items": [{"severity": item.get("severity"), "title": str(item.get("title") or "")[:140], "where": _where(item)[:120],
                       "kev": bool(item.get("kev")), "fingerprint": item.get("fingerprint")} for item in top],
            "more": max(0, len(opened) - len(top))}


def batch_message(summary: dict) -> dict:
    return {"event": "batches", "title": f"Lote terminado · {summary.get('label')}",
            "text": " · ".join(part for part in (f"{summary.get('done', 0)} analizados" + (f", {summary['failed']} fallidos" if summary.get("failed") else ""),
                                                 ", ".join(value for value in (f"{summary['critical']} críticos" if summary.get("critical") else "",
                                                                               f"{summary['high']} altos" if summary.get("high") else "") if value)) if part),
            "asset": summary.get("label"), "run_id": None, "link": panel_link(), "counts": {"critical": summary.get("critical", 0),
            "high": summary.get("high", 0)}, "items": [], "more": 0}


def _slack_escape(value: str) -> str:
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _teams_escape(value: str) -> str:
    """Las tarjetas de Teams interpretan Markdown: un nombre con [texto](url) no debe convertirse en enlace."""
    return re.sub(r"([\\`*_\[\]()#>])", r"\\\1", str(value))


def render(kind: str, message: dict) -> dict:
    icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
    lines = [f"{icon.get(item['severity'], '•')} *{_slack_escape(LABEL.get(item['severity'], item['severity']))}* "
             f"{_slack_escape(item['title'])} · `{_slack_escape(item['where'])}`" + (" · KEV" if item["kev"] else "") for item in message["items"]]
    if message["more"]:
        lines.append(f"… y {message['more']} más")
    if kind == "slack":
        blocks = [{"type": "header", "text": {"type": "plain_text", "text": message["title"][:150]}},
                  {"type": "section", "text": {"type": "mrkdwn", "text": _slack_escape(message["text"])}}]
        if lines:
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(lines)[:2900]}})
        if message["link"]:
            blocks.append({"type": "actions", "elements": [{"type": "button", "text": {"type": "plain_text", "text": "Abrir en Tamandua"},
                                                            "url": message["link"]}]})
        return {"text": f"{message['title']}: {message['text']}", "blocks": blocks}
    if kind == "teams":
        body = [{"type": "TextBlock", "text": _teams_escape(message["title"]), "weight": "Bolder", "size": "Medium", "wrap": True},
                {"type": "TextBlock", "text": _teams_escape(message["text"]), "wrap": True, "isSubtle": True}]
        body += [{"type": "TextBlock", "wrap": True, "text": f"**{LABEL.get(item['severity'], item['severity'])}** · {_teams_escape(item['title'])} · {_teams_escape(item['where'])}"
                                                             + (" · KEV" if item["kev"] else "")} for item in message["items"]]
        if message["more"]:
            body.append({"type": "TextBlock", "text": f"… y {message['more']} más", "isSubtle": True})
        card = {"type": "AdaptiveCard", "$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "version": "1.4", "body": body}
        if message["link"]:
            card["actions"] = [{"type": "Action.OpenUrl", "title": "Abrir en Tamandua", "url": message["link"]}]
        return {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}]}
    return {"source": "tamandua", **message, "sent_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}


def _post(channel: dict, payload: dict, *, sender=None) -> tuple[bool, str]:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    headers = {"Content-Type": "application/json", "User-Agent": "Tamandua"}
    if channel.get("secret"):
        # El receptor comprueba que el aviso viene de este Tamandua: HMAC-SHA256 del cuerpo con el secreto del canal.
        headers["X-Tamandua-Signature"] = "sha256=" + hmac.new(channel["secret"].encode(), body, hashlib.sha256).hexdigest()
    try:
        if sender:
            return sender(channel["url"], body, headers)
        check_url(channel["kind"], channel["url"])  # el DNS puede haber cambiado desde que se guardó
        with urlopen(Request(channel["url"], data=body, headers=headers, method="POST"), timeout=10) as response:
            return 200 <= response.status < 300, f"HTTP {response.status}"
    except HTTPError as exc:  # 404: la URL ya no existe; 401/403: sin permiso. Nunca se incluye la URL.
        return False, f"HTTP {exc.code}"
    except URLError as exc:
        return False, f"sin conexión ({str(exc.reason)[:80]})"
    except Exception as exc:  # noqa: BLE001 — un canal caído se anota, no rompe nada
        return False, str(exc)[:120] if isinstance(exc, NotificationError) else type(exc).__name__


def _send(identifier: str, channel: dict, payload: dict, sender=None) -> threading.Thread:
    def send():
        ok, detail = _post(channel, payload, sender=sender)
        _record_delivery(identifier, ok, detail)
        (_log.info if ok else _log.warning)("notification_sent" if ok else "notification_failed",
                                           extra={"reason": f"{channel['kind']} {channel['name']}: {detail}"})
    thread = threading.Thread(target=send, name="tamandua-notify", daemon=True)
    thread.start()
    return thread


RETRY_MINUTES = (1, 5, 30, 120, 360)  # espera creciente entre intentos; tras el último, el mensaje queda como fallido


def deliver(event: str, build, *, sender=None, wait: bool = False, data_dir: Path | None = None) -> list[threading.Thread]:
    """Cada canal suscrito al evento recibe su mensaje (`build(channel)`, o None si no le toca nada).

    Con `data_dir`, el mensaje va al buzón de salida (tabla outbox) y lo entrega el worker con reintentos: si el proceso
    cae o el canal falla, no se pierde. Sin él (o con `sender`, en pruebas), se envía al momento en un hilo."""
    threads = []
    queued = []
    for identifier, channel in _vault().items():
        if event not in channel["events"]:
            continue
        message = build(channel)
        if not message:
            continue
        if data_dir is not None and sender is None:
            queued.append({"tenant_id": db.TENANT, "id": uuid.uuid4().hex, "channel_id": identifier, "payload": render(channel["kind"], message)})
        else:
            threads.append(_send(identifier, channel, render(channel["kind"], message), sender))
    if queued:
        with db.transaction(data_dir) as connection:
            connection.execute(insert(outbox), queued)
    if wait:
        for thread in threads:
            thread.join(15)
    return threads


def on_run(record: dict, opened: list[dict], *, sender=None, wait: bool = False, data_dir: Path | None = None) -> None:
    """Tras incorporar un análisis al registro: avisa de lo nuevo (no de las revisiones de PR).
    Cada canal recibe solo lo que alcanza su umbral: título, recuento y lista salen de lo mismo."""
    if record.get("type") == "pr_review" or not opened:
        return

    def build(channel: dict) -> dict | None:
        limit = ORDER.index(channel["threshold"])
        relevant = [item for item in opened if item.get("severity") in ORDER and ORDER.index(item["severity"]) <= limit]
        return findings_message(record, relevant) if relevant else None
    try:
        if _vault():
            deliver("findings", build, sender=sender, wait=wait, data_dir=data_dir)
    except Exception:  # noqa: BLE001 — avisar nunca rompe un análisis
        _log.exception("notification_dispatch_failed")


def on_batch(summary: dict, *, sender=None, wait: bool = False, data_dir: Path | None = None) -> None:
    try:
        if _vault():
            message = batch_message(summary)
            deliver("batches", lambda channel: message, sender=sender, wait=wait, data_dir=data_dir)
    except Exception:  # noqa: BLE001
        _log.exception("notification_dispatch_failed")


def drain(data_dir: Path, *, sender=None, limit: int = 20) -> int:
    """Entrega lo que toca del buzón de salida (lo llama el worker cada pocos segundos). Devuelve cuántos intentó."""
    channels = _vault()
    with db.transaction(data_dir) as connection:
        rows = connection.execute(select(outbox.c.id, outbox.c.channel_id, outbox.c.payload, outbox.c.attempts)
                                  .where(outbox.c.tenant_id == db.TENANT, outbox.c.status == "pending", outbox.c.next_attempt_at <= func.now())
                                  .order_by(outbox.c.created_at).limit(limit).with_for_update(skip_locked=True)).all()
        for row in rows:
            channel = channels.get(row.channel_id)
            if channel is None:  # el canal se borró mientras esperaba
                connection.execute(update(outbox).where(outbox.c.tenant_id == db.TENANT, outbox.c.id == row.id)
                                   .values(status="failed", last_error="Canal eliminado"))
                continue
            ok, detail = _post(channel, row.payload, sender=sender)
            _record_delivery(row.channel_id, ok, detail)
            attempts = row.attempts + 1
            if ok:
                values = {"status": "sent", "attempts": attempts, "last_error": None}
            elif attempts >= len(RETRY_MINUTES):
                values = {"status": "failed", "attempts": attempts, "last_error": detail}
            else:
                values = {"attempts": attempts, "last_error": detail,
                          "next_attempt_at": func.now() + timedelta(minutes=RETRY_MINUTES[attempts - 1])}
            connection.execute(update(outbox).where(outbox.c.tenant_id == db.TENANT, outbox.c.id == row.id).values(**values))
            (_log.info if ok else _log.warning)("notification_sent" if ok else "notification_failed",
                                               extra={"reason": f"{channel['kind']} {channel['name']}: {detail} (intento {attempts})"})
    return len(rows)


def test(identifier: str, *, sender=None) -> tuple[bool, str]:
    channel = _vault().get(identifier)
    if channel is None:
        raise NotificationError("Canal no encontrado")
    message = {"event": "test", "title": "Prueba de Tamandua", "text": "Si ves esto, el canal está bien configurado.", "asset": None,
               "run_id": None, "link": panel_link(), "counts": {}, "items": [], "more": 0}
    ok, detail = _post(channel, render(channel["kind"], message), sender=sender)
    _record_delivery(identifier, ok, detail)
    return ok, detail


