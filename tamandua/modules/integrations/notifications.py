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
import re
import secrets as token_source
import socket
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit
from urllib.error import HTTPError, URLError
from urllib.request import Request


from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert

from tamandua.modules.integrations.tables import outbox
from tamandua.shared import db, http, settings
from tamandua.shared import log as logging_setup
from tamandua.shared.i18n import default_locale, msg, t, text

_log = logging_setup.get("notifications")
_lock = threading.Lock()
VAULT_NAME = "notification-channels"
KINDS = {"slack": "Slack", "teams": "Microsoft Teams", "webhook": "Webhook"}
EVENTS = {"findings": msg("integrations.notifications.events.findings"), "batches": msg("integrations.notifications.events.batches")}
THRESHOLDS = ("critical", "high", "medium")
ORDER = ("critical", "high", "medium", "low", "info")
LABEL = {"critical": msg("integrations.notifications.severity.critical"), "high": msg("integrations.notifications.severity.high"),
         "medium": msg("integrations.notifications.severity.medium"), "low": msg("integrations.notifications.severity.low"),
         "info": msg("integrations.notifications.severity.info")}


def _count(level: str, count: int, locale: str) -> str:
    keys = {"critical": "integrations.notifications.count.critical", "high": "integrations.notifications.count.high",
            "medium": "integrations.notifications.count.medium", "low": "integrations.notifications.count.low",
            "info": "integrations.notifications.count.info"}
    return t(keys[level], locale, count=count)
MAX_CHANNELS = 10
HOSTS = {"slack": re.compile(r"hooks\.slack\.com"),
         # Teams: los flujos de Workflows/Power Automate (los conectores clásicos de Office 365 se retiran).
         "teams": re.compile(r"(?:[a-z0-9-]+\.)*(?:logic\.azure\.com|webhook\.office\.com|environment\.api\.powerplatform\.com)")}


class NotificationError(ValueError):
    """`message` is what people read (rendered per reader); str() stays English, for logs."""

    def __init__(self, message):
        super().__init__(text(message, "en"))
        self.message = message


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
        raise NotificationError(msg("integrations.notifications.errors.invalid_url"))
    parts = urlsplit(url.strip())
    host = (parts.hostname or "").lower()
    if parts.scheme != "https" or not host or parts.username or parts.password:
        raise NotificationError(msg("integrations.notifications.errors.https_only"))
    if kind in HOSTS and not HOSTS[kind].fullmatch(host):
        raise NotificationError(msg("integrations.notifications.errors.wrong_host", kind=KINDS[kind], host=host))
    if not settings.flag("TAMANDUA_ALLOW_PRIVATE_WEBHOOKS"):
        # El servidor hará la petición: una dirección interna convertiría el formulario en un SSRF.
        try:
            addresses = {info[4][0] for info in socket.getaddrinfo(host, parts.port or 443, proto=socket.IPPROTO_TCP)}
        except OSError as exc:
            raise NotificationError(msg("integrations.notifications.errors.unresolved", host=host)) from exc
        if not addresses or not all(ipaddress.ip_address(address.split("%")[0]).is_global for address in addresses):
            raise NotificationError(msg("integrations.notifications.errors.private_host", host=host))
    return url.strip()


def save(kind: str, name: str, url: str, events: list[str], threshold: str, *, by: str) -> tuple[dict, str | None]:
    """Crea un canal. Devuelve la fila y, en un webhook, el secreto de firma (se muestra una sola vez)."""
    from tamandua.shared.vault import put
    if kind not in KINDS:
        raise NotificationError(msg("integrations.notifications.errors.invalid_kind"))
    if not isinstance(name, str) or not 1 <= len(name.strip()) <= 60 or any(not char.isprintable() for char in name):
        raise NotificationError(msg("integrations.notifications.errors.invalid_name"))
    if not isinstance(events, list) or not events or any(item not in EVENTS for item in events):
        raise NotificationError(msg("integrations.notifications.errors.pick_event"))
    if threshold not in THRESHOLDS:
        raise NotificationError(msg("integrations.notifications.errors.invalid_threshold"))
    url = check_url(kind, url)
    with _lock:
        stored = _vault()
        if len(stored) >= MAX_CHANNELS:
            raise NotificationError(msg("integrations.notifications.errors.channel_limit", max=MAX_CHANNELS))
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
            raise NotificationError(msg("integrations.notifications.errors.channel_not_found"))
        put(VAULT_NAME, stored)
    _log.info("channel_removed", extra={"user": by, "reason": identifier})


def _record_delivery(identifier: str, ok: bool, detail) -> None:
    from tamandua.shared.vault import put
    with _lock:
        stored = _vault()
        if identifier in stored:
            stored[identifier]["last"] = {"at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "ok": ok,
                                          "detail": detail if isinstance(detail, dict) else str(detail)[:160]}
            put(VAULT_NAME, stored)


# ------------------------------------------------------------------ mensajes

def panel_link(run_id: str | None = None) -> str | None:
    base = settings.text("TAMANDUA_PUBLIC_URL").rstrip("/")
    if not base.startswith(("https://", "http://")):
        return None
    return f"{base}/#/hallazgos?run={run_id}" if run_id else base


def _where(finding: dict) -> str:
    package = finding.get("package") or {}
    if package.get("name"):
        return f"{package['name']} {package.get('version') or ''}".strip()
    return f"{finding.get('path')}:{finding.get('line')}"


def findings_message(record: dict, opened: list[dict], locale: str | None = None) -> dict:
    """What a findings notice says; each channel draws it its own way. A channel is read by a team, not by someone
    who asked in person, so it speaks TAMANDUA_DEFAULT_LOCALE."""
    locale = locale or default_locale()
    counts = {level: sum(1 for item in opened if item.get("severity") == level) for level in ORDER}
    top = sorted(opened, key=lambda item: (ORDER.index(item.get("severity", "info")) if item.get("severity") in ORDER else 9, not item.get("kev")))[:5]
    name = text((record.get("source") or {}).get("name") or record.get("target"), locale) or t("integrations.notifications.asset_fallback", locale)
    origin = {"advisory_watch": msg("integrations.notifications.origin.advisory_watch"),
              "image_scan": msg("integrations.notifications.origin.image_scan")}.get(record.get("type"), msg("integrations.notifications.origin.full_scan"))
    if (record.get("trigger") or {}).get("kind") == "branch":
        origin = msg("integrations.notifications.origin.branch")
    summary = ", ".join(_count(level, counts[level], locale) for level in ORDER if counts[level])
    kev = sum(1 for item in opened if item.get("kev"))
    return {"event": "findings", "title": t("integrations.notifications.findings_title", locale, count=len(opened), asset=name),
            "text": t("integrations.notifications.findings_text", locale, summary=summary, origin=origin)
            + (t("integrations.notifications.kev_suffix", locale, count=kev) if kev else ""),
            "asset": name, "run_id": record.get("id"), "link": panel_link(record.get("id")), "counts": counts,
            "items": [{"severity": item.get("severity"), "title": text(item.get("title"), locale)[:140], "where": _where(item)[:120],
                       "kev": bool(item.get("kev")), "fingerprint": item.get("fingerprint")} for item in top],
            "more": max(0, len(opened) - len(top))}


def batch_message(summary: dict, locale: str | None = None) -> dict:
    locale = locale or default_locale()
    label = text(summary.get("label"), locale)
    done = (t("integrations.notifications.batch_done_failed", locale, done=summary.get("done", 0), failed=summary["failed"])
            if summary.get("failed") else t("integrations.notifications.batch_done", locale, done=summary.get("done", 0)))
    severe = ", ".join(_count(level, summary[level], locale) for level in ("critical", "high") if summary.get(level))
    return {"event": "batches", "title": t("integrations.notifications.batch_title", locale, label=label),
            "text": " · ".join(part for part in (done, severe) if part),
            "asset": label, "run_id": None, "link": panel_link(), "counts": {"critical": summary.get("critical", 0),
            "high": summary.get("high", 0)}, "items": [], "more": 0}


def _slack_escape(value: str) -> str:
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _teams_escape(value: str) -> str:
    """Las tarjetas de Teams interpretan Markdown: un nombre con [texto](url) no debe convertirse en enlace."""
    return re.sub(r"([\\`*_\[\]()#>])", r"\\\1", str(value))


def render(kind: str, message: dict, locale: str | None = None) -> dict:
    locale = locale or default_locale()
    label = lambda severity: text(LABEL.get(severity, severity), locale)
    more = t("integrations.notifications.more", locale, count=message["more"])
    open_label = t("integrations.notifications.open", locale)
    icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
    lines = [f"{icon.get(item['severity'], '•')} *{_slack_escape(label(item['severity']))}* "
             f"{_slack_escape(item['title'])} · `{_slack_escape(item['where'])}`" + (" · KEV" if item["kev"] else "") for item in message["items"]]
    if message["more"]:
        lines.append(more)
    if kind == "slack":
        blocks = [{"type": "header", "text": {"type": "plain_text", "text": message["title"][:150]}},
                  {"type": "section", "text": {"type": "mrkdwn", "text": _slack_escape(message["text"])}}]
        if lines:
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(lines)[:2900]}})
        if message["link"]:
            blocks.append({"type": "actions", "elements": [{"type": "button", "text": {"type": "plain_text", "text": open_label},
                                                            "url": message["link"]}]})
        return {"text": f"{message['title']}: {message['text']}", "blocks": blocks}
    if kind == "teams":
        body = [{"type": "TextBlock", "text": _teams_escape(message["title"]), "weight": "Bolder", "size": "Medium", "wrap": True},
                {"type": "TextBlock", "text": _teams_escape(message["text"]), "wrap": True, "isSubtle": True}]
        body += [{"type": "TextBlock", "wrap": True, "text": f"**{label(item['severity'])}** · {_teams_escape(item['title'])} · {_teams_escape(item['where'])}"
                                                             + (" · KEV" if item["kev"] else "")} for item in message["items"]]
        if message["more"]:
            body.append({"type": "TextBlock", "text": more, "isSubtle": True})
        card = {"type": "AdaptiveCard", "$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "version": "1.4", "body": body}
        if message["link"]:
            card["actions"] = [{"type": "Action.OpenUrl", "title": open_label, "url": message["link"]}]
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
        # No redirects: a validated public URL could otherwise bounce the signed payload to an internal address.
        with http.opener().open(Request(channel["url"], data=body, headers=headers, method="POST"), timeout=10) as response:
            return 200 <= response.status < 300, f"HTTP {response.status}"
    except HTTPError as exc:  # 404: la URL ya no existe; 401/403: sin permiso. Nunca se incluye la URL.
        return False, f"HTTP {exc.code}"
    except URLError as exc:
        return False, msg("integrations.notifications.delivery.no_connection", reason=str(exc.reason)[:80])
    except Exception as exc:  # noqa: BLE001 — un canal caído se anota, no rompe nada
        return False, exc.message if isinstance(exc, NotificationError) else type(exc).__name__


def _send(identifier: str, channel: dict, payload: dict, sender=None) -> threading.Thread:
    def send():
        ok, detail = _post(channel, payload, sender=sender)
        _record_delivery(identifier, ok, detail)
        (_log.info if ok else _log.warning)("notification_sent" if ok else "notification_failed",
                                           extra={"reason": f"{channel['kind']} {channel['name']}: {text(detail, 'en')}"})
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


OUTBOX_LEASE = timedelta(minutes=5)  # a claimed message nobody finished sending is due again after this


def drain(data_dir: Path, *, sender=None, limit: int = 20) -> int:
    """Delivers the due outbox messages (the worker calls it every few seconds). Returns how many it tried.

    Messages are claimed in a short transaction (their next attempt moves past a lease, so another worker skips
    them) and sent outside it: a slow webhook never holds a database connection or a lock. A worker that dies
    mid-delivery leaves them due again when the lease runs out: delivery is at least once."""
    channels = _vault()
    with db.transaction(data_dir) as connection:
        rows = connection.execute(select(outbox.c.id, outbox.c.channel_id, outbox.c.payload, outbox.c.attempts)
                                  .where(outbox.c.tenant_id == db.TENANT, outbox.c.status == "pending", outbox.c.next_attempt_at <= func.now())
                                  .order_by(outbox.c.created_at).limit(limit).with_for_update(skip_locked=True)).all()
        if rows:
            connection.execute(update(outbox).where(outbox.c.tenant_id == db.TENANT, outbox.c.id.in_([row.id for row in rows]))
                               .values(next_attempt_at=func.now() + OUTBOX_LEASE))
    for row in rows:
        channel = channels.get(row.channel_id)
        if channel is None:  # the channel was deleted while the message waited
            values = {"status": "failed", "last_error": "Channel deleted"}
        else:
            ok, detail = _post(channel, row.payload, sender=sender)
            _record_delivery(row.channel_id, ok, detail)
            attempts = row.attempts + 1
            if ok:
                values = {"status": "sent", "attempts": attempts, "last_error": None}
            elif attempts >= len(RETRY_MINUTES):
                values = {"status": "failed", "attempts": attempts, "last_error": text(detail, "en")}
            else:
                values = {"attempts": attempts, "last_error": text(detail, "en"),
                          "next_attempt_at": func.now() + timedelta(minutes=RETRY_MINUTES[attempts - 1])}
            (_log.info if ok else _log.warning)("notification_sent" if ok else "notification_failed",
                                               extra={"reason": f"{channel['kind']} {channel['name']}: {text(detail, 'en')} (attempt {attempts})"})
        with db.transaction(data_dir) as connection:
            connection.execute(update(outbox).where(outbox.c.tenant_id == db.TENANT, outbox.c.id == row.id).values(**values))
    return len(rows)


def test(identifier: str, *, sender=None) -> tuple[bool, object]:
    channel = _vault().get(identifier)
    if channel is None:
        raise NotificationError(msg("integrations.notifications.errors.channel_not_found"))
    locale = default_locale()
    message = {"event": "test", "title": t("integrations.notifications.test_title", locale),
               "text": t("integrations.notifications.test_text", locale), "asset": None,
               "run_id": None, "link": panel_link(), "counts": {}, "items": [], "more": 0}
    ok, detail = _post(channel, render(channel["kind"], message), sender=sender)
    _record_delivery(identifier, ok, detail)
    return ok, detail


