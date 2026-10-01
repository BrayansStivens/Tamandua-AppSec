"""Jira Cloud connector: the credential, the REST calls and discovery of projects, issue types and create fields.

* The credential (Atlassian email + API token) is set by an administrator from the panel and checked against Jira
  before it is saved. It is sealed in the vault ("jira") and never goes back to the browser: only the email and the
  token's last four characters do.
* Only ``https://<site>.atlassian.net`` is contacted: the panel can't be used to send requests anywhere else (SSRF),
  redirects are not followed and responses are capped. Every path is built here from validated identifiers.
* Jira Server/Data Center is left out on purpose: it would mean accepting arbitrary hosts on the customer's network.

What goes into each issue (destinations, field mapping, routing rules) is `jira_mapping.py` and `jira_routing.py`;
creating issues from findings, `runs/jira_sync.py`.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import Request

from tamandua.shared import http
from tamandua.shared import log as logging_setup
from tamandua.shared.i18n import msg, text
from tamandua.version import USER_AGENT

SITE_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.atlassian\.net")
PROJECT_PATTERN = re.compile(r"[A-Z][A-Z0-9_]{1,9}")
PROJECT_REF = re.compile(r"[A-Z][A-Z0-9_]{1,9}|[0-9]{1,18}")
NUMERIC_ID = re.compile(r"[0-9]{1,18}")
ISSUE_KEY = re.compile(r"[A-Z][A-Z0-9_]{1,9}-[0-9]{1,12}")
FIELD_ID = re.compile(r"[A-Za-z0-9_.\-]{1,64}")
MAX_BATCH = 50
RESPONSE_LIMIT = 2_000_000
PAGE = 50
MAX_ISSUE_TYPES = 200
MAX_FIELDS = 500
MAX_ALLOWED_VALUES = 200          # sent to the panel per field; longer lists are searched (`field_values`)
MAX_ALLOWED_CHECKED = 20_000      # read in full to validate a chosen value and to search
MAX_VALUE_RESULTS = 50
NAME_MAX = 255
COMMENT_PROPERTY = "tamandua"
_log = logging_setup.get("jira")


class JiraError(ValueError):
    """`message` is what people read (rendered per reader); str() stays English, for logs. `status` is Jira's HTTP code
    (None when it couldn't be reached) and `retry_after` its Retry-After, to tell a retry from a permanent failure."""

    def __init__(self, message, *, status: int | None = None, retry_after: int | None = None):
        super().__init__(text(message, "en"))
        self.message, self.status, self.retry_after = message, status, retry_after

    @property
    def retryable(self) -> bool:
        return self.status is None or self.status == 429 or self.status >= 500


# ------------------------------------------------------------ credential

def _load() -> dict | None:
    from tamandua.shared.vault import VaultError, get
    try:
        data = get("jira")
    except VaultError:
        return None
    return data if isinstance(data, dict) and data.get("token") else None


def credentials() -> dict:
    data = _load()
    if not data:
        raise JiraError(msg("integrations.jira.not_configured"))
    return data


def configured() -> bool:
    return _load() is not None


def _write(data: dict) -> None:
    from tamandua.shared.vault import put
    put("jira", data)


def normalize_site(value) -> str:
    if not isinstance(value, str) or len(value) > 120:
        raise JiraError(msg("integrations.jira.invalid_site"))
    site = value.strip().lower()
    if "://" not in site:
        site = "https://" + site
    try:
        parts = urlsplit(site)
        host, port = (parts.hostname or "").rstrip("."), parts.port
    except ValueError:
        raise JiraError(msg("integrations.jira.use_cloud_url")) from None
    if (parts.scheme != "https" or parts.username or parts.password or port or parts.query or parts.fragment
            or parts.path not in ("", "/") or not SITE_PATTERN.fullmatch(host)):
        raise JiraError(msg("integrations.jira.use_cloud_url"))
    return host


def status() -> dict:
    data = _load()
    if not data:
        return {"configured": False}
    return {"configured": True, "site": data["site"], "email": data["email"], "last4": data["token"][-4:],
            "saved_at": data.get("saved_at"), "saved_by": data.get("saved_by")}


def check_project_key(project) -> str:
    project = project.strip().upper() if isinstance(project, str) else ""
    if not PROJECT_PATTERN.fullmatch(project):
        raise JiraError(msg("integrations.jira.invalid_project"))
    return project


def configure(site, email, token, *, by: str, http=None) -> dict:
    """Checks the credential against Jira (who it belongs to) and only then saves it. Returns the status."""
    host = normalize_site(site)
    if not isinstance(email, str) or not re.fullmatch(r"[^@\s]{1,64}@[^@\s]{1,190}", email.strip()):
        raise JiraError(msg("integrations.jira.invalid_email"))
    if (not isinstance(token, str) or not 16 <= len(token) <= 400
            or any(character.isspace() or ord(character) < 33 or ord(character) > 126 for character in token)):
        raise JiraError(msg("integrations.jira.invalid_token"))
    found = {"site": host, "email": email.strip(), "token": token}
    me = (http or _http)(found, "GET", "/rest/api/3/myself")
    _write({**found, "account": me.get("accountId"), "saved_at": _stamp(), "saved_by": by})
    _log.info("jira_configured", extra={"user": by, "reason": host})
    return status()


def forget() -> None:
    from tamandua.shared.vault import delete
    delete("jira")


# ------------------------------------------------------------------ HTTP

def _http(credentials: dict, method: str, path: str, body: dict | None = None) -> dict:
    """A request to the REST API v3. Errors become our own messages; Jira's field errors travel as a raw parameter."""
    token = base64.b64encode(f"{credentials['email']}:{credentials['token']}".encode()).decode("ascii")
    request = Request(f"https://{credentials['site']}{path}", method=method,
                      data=json.dumps(body).encode("utf-8") if body is not None else None,
                      headers={"Authorization": f"Basic {token}", "Accept": "application/json",
                               "Content-Type": "application/json", "User-Agent": USER_AGENT})
    try:
        with http.opener().open(request, timeout=15) as response:
            raw = response.read(RESPONSE_LIMIT + 1)
    except HTTPError as exc:
        detail, retry_after = "", None
        try:
            retry_after = int(exc.headers.get("Retry-After") or 0) or None
        except (ValueError, TypeError, AttributeError):
            retry_after = None
        try:
            payload = json.loads(exc.read(20_000) or b"{}")
            messages = list((payload.get("errors") or {}).items())[:3]
            detail = "; ".join(f"{field}: {reason}" for field, reason in messages) or "; ".join(payload.get("errorMessages", [])[:2])
        except (ValueError, OSError, AttributeError, TypeError):
            pass
        finally:
            exc.close()
        if exc.code in (401, 403):
            raise JiraError(msg("integrations.jira.rejected_credential"), status=exc.code) from None
        if exc.code == 404:
            raise JiraError(msg("integrations.jira.not_found"), status=404) from None
        if exc.code == 429:
            raise JiraError(msg("integrations.jira.rate_limited"), status=429, retry_after=retry_after) from None
        raise JiraError(msg("integrations.jira.http_error_detail", code=exc.code, detail=str(detail)[:300]) if detail
                        else msg("integrations.jira.http_error", code=exc.code), status=exc.code) from None
    except (URLError, TimeoutError, OSError):
        raise JiraError(msg("integrations.jira.unreachable")) from None
    if len(raw) > RESPONSE_LIMIT:
        raise JiraError(msg("integrations.jira.too_large"), status=200)
    try:
        payload = json.loads(raw or b"{}")
    except ValueError:
        raise JiraError(msg("integrations.jira.unreadable"), status=200) from None
    return payload if isinstance(payload, dict) else {}


def _client(http):
    return http or _http


def _query(path: str, **params) -> str:
    return f"{path}?{urlencode({key: value for key, value in params.items() if value is not None})}"


def _name(value) -> str:
    return " ".join(str(value or "").split())[:NAME_MAX]


# ------------------------------------------------------------- discovery

def project_ref(value) -> str:
    """A project key (SEC) or numeric id, as the only thing that goes into its URL paths."""
    ref = value.strip() if isinstance(value, str) else ""
    ref = ref.upper() if not ref.isdigit() else ref
    if not PROJECT_REF.fullmatch(ref):
        raise JiraError(msg("integrations.jira.invalid_project"))
    return ref


def _issue_type_ref(value) -> str:
    ref = value.strip() if isinstance(value, str) else ""
    if not NUMERIC_ID.fullmatch(ref):
        raise JiraError(msg("integrations.jira.invalid_issue_type"))
    return ref


def projects(query: str = "", start: int = 0, limit: int = PAGE, *, http=None) -> dict:
    """A page of the projects the credential can see (name or key containing `query`)."""
    query = " ".join(query.split())[:80] if isinstance(query, str) else ""
    start, limit = max(0, min(int(start), 10_000)), max(1, min(int(limit), PAGE))
    page = _client(http)(credentials(), "GET", _query("/rest/api/3/project/search", query=query or None, startAt=start,
                                                      maxResults=limit, orderBy="key"))
    items = [{"id": str(item["id"]), "key": str(item["key"]), "name": _name(item.get("name"))}
             for item in (page.get("values") or [])[:limit]
             if isinstance(item, dict) and NUMERIC_ID.fullmatch(str(item.get("id", ""))) and PROJECT_PATTERN.fullmatch(str(item.get("key", "")))]
    total = page.get("total") if isinstance(page.get("total"), int) else start + len(items)
    return {"items": items, "total": total, "start": start, "limit": limit, "last": bool(page.get("isLast", start + len(items) >= total))}


def project(ref, *, http=None) -> dict:
    found = _client(http)(credentials(), "GET", f"/rest/api/3/project/{quote(project_ref(ref), safe='')}")
    if not NUMERIC_ID.fullmatch(str(found.get("id", ""))) or not PROJECT_PATTERN.fullmatch(str(found.get("key", ""))):
        raise JiraError(msg("integrations.jira.unexpected"))
    return {"id": str(found["id"]), "key": str(found["key"]), "name": _name(found.get("name"))}


def _pages(http, path: str, key: str, cap: int) -> tuple[list[dict], bool]:
    """Follows startAt/maxResults up to `cap` items. Returns the items and whether there were more."""
    client, found, start = _client(http), [], 0
    while len(found) < cap:
        page = client(credentials(), "GET", _query(path, startAt=start, maxResults=PAGE))
        values = page.get(key)
        if values is None:
            values = page.get("values") or []
        values = [item for item in values if isinstance(item, dict)] if isinstance(values, list) else []
        found.extend(values)
        total = page.get("total") if isinstance(page.get("total"), int) else None
        start += len(values)
        if not values or (total is not None and start >= total) or (total is None and len(values) < PAGE):
            return found[:cap], False
    return found[:cap], True


def issue_types(ref, *, http=None) -> dict:
    """The issue types a project lets the credential create (create metadata)."""
    items, truncated = _pages(http, f"/rest/api/3/issue/createmeta/{quote(project_ref(ref), safe='')}/issuetypes",
                              "issueTypes", MAX_ISSUE_TYPES)
    return {"items": [{"id": str(item["id"]), "name": _name(item.get("name")), "subtask": bool(item.get("subtask"))}
                      for item in items if NUMERIC_ID.fullmatch(str(item.get("id", "")))], "truncated": truncated}


def create_fields(ref, issue_type, *, http=None, allowed_limit: int = MAX_ALLOWED_VALUES) -> dict:
    """The fields on the create screen of an issue type, normalized (see `normalize_field`).

    `allowed_limit`: how many allowed values to keep per field; validation asks for all of them (MAX_ALLOWED_CHECKED)."""
    path = f"/rest/api/3/issue/createmeta/{quote(project_ref(ref), safe='')}/issuetypes/{quote(_issue_type_ref(issue_type), safe='')}"
    items, truncated = _pages(http, path, "fields", MAX_FIELDS)
    fields = [field for field in (normalize_field(item, allowed_limit=allowed_limit) for item in items) if field]
    return {"fields": fields, "truncated": truncated}


def field_values(ref, issue_type, field_id: str, query: str = "", *, limit: int = MAX_VALUE_RESULTS, http=None) -> dict:
    """Allowed values of one field whose name contains `query` (ignoring case): for lists too long to send whole."""
    if not isinstance(field_id, str) or not FIELD_ID.fullmatch(field_id):
        raise JiraError(msg("integrations.jira.invalid_field"))
    needle = " ".join(str(query or "").split()).lower()[:100]
    limit = max(1, min(int(limit), MAX_VALUE_RESULTS))
    fields = create_fields(ref, issue_type, http=http, allowed_limit=MAX_ALLOWED_CHECKED)["fields"]
    field = next((item for item in fields if item["id"] == field_id), None)
    if field is None:
        raise JiraError(msg("integrations.jira.invalid_field"))
    matches = [item for item in field["allowed"] if needle in item["name"].lower()]
    return {"items": matches[:limit], "total": len(matches), "truncated": len(matches) > limit}


RICH_SYSTEM = ("description", "environment")
UNSETTABLE = ("project", "issuetype", "attachment", "issuelinks", "parent", "reporter")


def normalize_field(raw: dict, *, allowed_limit: int = MAX_ALLOWED_VALUES) -> dict | None:
    """One create field as Tamandua sees it: id, name, required, `type` (what can be put in it) and its allowed values.

    Types Tamandua fills: text, rich_text (ADF), number, date, datetime, option, options (several, by id), priority,
    labels and strings. Everything else (users, cascading selects, links…) is `unsupported`: it can only be left empty.
    `project` and `issuetype` are `managed`: the destination sets them."""
    identifier = str(raw.get("fieldId") or raw.get("key") or "")
    if not FIELD_ID.fullmatch(identifier):
        return None
    schema = raw.get("schema") if isinstance(raw.get("schema"), dict) else {}
    kind_, items = str(schema.get("type") or ""), str(schema.get("items") or "")
    system, custom = str(schema.get("system") or ""), str(schema.get("custom") or "")
    if identifier in ("project", "issuetype"):
        kind = "managed"
    elif identifier in UNSETTABLE:
        kind = "unsupported"
    elif kind_ == "string":
        kind = "rich_text" if system in RICH_SYSTEM or custom.endswith(":textarea") else "text"
    elif kind_ in ("number", "date", "datetime", "priority"):
        kind = kind_
    elif kind_ in ("option", "securitylevel"):
        kind = "option"
    elif kind_ == "array" and items in ("option", "component", "version"):
        kind = "options"
    elif kind_ == "array" and items == "string":
        kind = "labels" if system == "labels" or custom.endswith(":labels") else "strings"
    else:
        kind = "unsupported"
    allowed = []
    for value in (raw.get("allowedValues") or [])[:allowed_limit] if isinstance(raw.get("allowedValues"), list) else []:
        if isinstance(value, dict) and value.get("id") is not None and re.fullmatch(r"[A-Za-z0-9_.\-]{1,64}", str(value["id"])):
            allowed.append({"id": str(value["id"]), "name": _name(value.get("name") or value.get("value") or value["id"])})
    total_allowed = len(raw["allowedValues"]) if isinstance(raw.get("allowedValues"), list) else 0
    return {"id": identifier, "name": _name(raw.get("name") or identifier), "required": bool(raw.get("required")),
            "has_default": bool(raw.get("hasDefaultValue")), "type": kind,
            "schema": {"type": kind_[:40], "items": items[:40] or None, "system": system[:40] or None, "custom": custom[:120] or None},
            "allowed": allowed, "allowed_truncated": total_allowed > len(allowed),
            "fillable": kind not in ("unsupported", "managed")}


# ------------------------------------------------------------------- issues

def label_for(fingerprint: str) -> str:
    return f"appsec-{fingerprint[:16]}"


def identity_label(asset: str, group: str) -> str:
    """The one label that identifies an issue, so it can be found again: a finding's own (its fingerprint), or for one
    package's advisories, one derived from the repository and the package, whichever advisories an export carries."""
    if re.fullmatch(r"[0-9a-f]{64}", group):
        return label_for(group)
    return "appsec-" + hashlib.sha256(f"{asset}\x1f{group}".encode()).hexdigest()[:16]


_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def plain(value, limit: int) -> str:
    """One line of plain text (summary, text fields): no control characters, no line breaks."""
    return " ".join(_CONTROL.sub(" ", str(value or "")).split())[:limit]


def adf(value: str) -> dict:
    """Atlassian Document Format from plain text: one paragraph per line, Markdown headings in bold. Only text nodes
    with a strong mark are built: nothing in the text can become a link, a macro or any other node."""
    content = []
    for line in _CONTROL.sub(" ", str(value or "")).splitlines()[:300]:
        line = line.rstrip()[:2000]
        if not line:
            continue
        bold = line.startswith("#")
        clean = line.lstrip("#").strip().replace("**", "").replace("`", "")
        if not clean:
            continue
        node: dict = {"type": "text", "text": clean}
        if bold:
            node["marks"] = [{"type": "strong"}]
        content.append({"type": "paragraph", "content": [node]})
    return {"type": "doc", "version": 1, "content": content or [{"type": "paragraph", "content": [{"type": "text", "text": "—"}]}]}


HTTPS_URL = re.compile(r"https://[^\s<>\"']{1,500}")
CODE_LANGUAGE = re.compile(r"[a-z0-9+#.-]{1,20}")
DOC_TEXT_MAX = 4000
DOC_BLOCKS_MAX = 200


def _inline(item) -> dict | None:
    """One inline node: plain text, {"strong"}, {"code"} or {"link", "url"} (https only; anything else stays text)."""
    if isinstance(item, str):
        value, marks = item, []
    elif isinstance(item, dict) and "link" in item:
        value = str(item["link"])
        url = str(item.get("url") or "")
        marks = [{"type": "link", "attrs": {"href": url}}] if HTTPS_URL.fullmatch(url) else []
    elif isinstance(item, dict) and ("strong" in item or "code" in item):
        kind = "strong" if "strong" in item else "code"
        value, marks = str(item[kind]), [{"type": kind}]
    else:
        return None
    value = " ".join(_CONTROL.sub(" ", value).split())[:DOC_TEXT_MAX]  # one line: a paragraph's text
    if not value:
        return None
    return {"type": "text", "text": value, **({"marks": marks} if marks else {})}


def _paragraph(items) -> dict | None:
    content = [node for node in (_inline(item) for item in (items if isinstance(items, list) else [items])) if node]
    return {"type": "paragraph", "content": content} if content else None


def adf_document(blocks: list[dict]) -> dict:
    """Atlassian Document Format from Tamandua's own structure, never from Markdown: `{"heading": text}`,
    `{"paragraph": [inline…]}`, `{"bullets"|"ordered": [[inline…], …]}` and `{"code": text, "language": …}`.
    Every node is built here, so no text a finding carries (a title, a path, an advisory) can become a link, a macro
    or any other node; links are only the https URLs Tamandua itself puts in."""
    content: list[dict] = []
    for block in blocks[:DOC_BLOCKS_MAX]:
        if "heading" in block:
            text_ = _CONTROL.sub(" ", str(block["heading"]))[:200]
            if text_:
                content.append({"type": "heading", "attrs": {"level": 3}, "content": [{"type": "text", "text": text_}]})
        elif "paragraph" in block:
            node = _paragraph(block["paragraph"])
            if node:
                content.append(node)
        elif "bullets" in block or "ordered" in block:
            kind = "bulletList" if "bullets" in block else "orderedList"
            items = [paragraph for paragraph in (_paragraph(item) for item in (block.get("bullets") or block.get("ordered") or [])[:50]) if paragraph]
            if items:
                content.append({"type": kind, "content": [{"type": "listItem", "content": [item]} for item in items]})
        elif "code" in block:
            code = _CONTROL.sub(" ", str(block["code"]).replace("\r", ""))[:DOC_TEXT_MAX]
            language = str(block.get("language") or "").lower()
            if code.strip():
                content.append({"type": "codeBlock", **({"attrs": {"language": language}} if CODE_LANGUAGE.fullmatch(language) else {}),
                                "content": [{"type": "text", "text": code}]})
    return {"type": "doc", "version": 1, "content": content or [{"type": "paragraph", "content": [{"type": "text", "text": "-"}]}]}


def search_labels(project_key: str, fingerprints: list[str], *, identity: str | None = None, http=None) -> str | None:
    """The key of an issue in the project carrying this issue's identity label, or one of its findings' own labels
    (how earlier versions labelled every finding of a group), created earlier or elsewhere."""
    wanted = ([identity] if identity and re.fullmatch(r"appsec-[0-9a-f]{16}", identity) else []) \
        + [label_for(item) for item in fingerprints[:50] if re.fullmatch(r"[0-9a-f]{64}", item)]
    labels = ", ".join(f'"{item}"' for item in dict.fromkeys(wanted))
    if not labels:
        return None
    found = _client(http)(credentials(), "POST", "/rest/api/3/search/jql",
                          {"jql": f'project = "{check_project_key(project_key)}" AND labels in ({labels})', "maxResults": 1, "fields": ["key"]})
    issues = [item for item in found.get("issues") or [] if isinstance(item, dict) and ISSUE_KEY.fullmatch(str(item.get("key", "")))]
    return issues[0]["key"] if issues else None


def missing_issues(keys: list[str], *, http=None) -> set[str]:
    """Which of these issue keys Jira no longer has (deleted, moved, or out of this account's reach): Tamandua's
    links can go stale when someone deletes issues in Jira. Asked 100 at a time (bulk fetch); a key Jira reports as
    missing is missing, and a key it leaves unmentioned too."""
    wanted = sorted({key for key in keys if isinstance(key, str) and ISSUE_KEY.fullmatch(key)})
    missing: set[str] = set()
    client, found = _client(http), credentials()
    for start in range(0, len(wanted), 100):
        chunk = wanted[start:start + 100]
        answer = client(found, "POST", "/rest/api/3/issue/bulkfetch", {"issueIdsOrKeys": chunk, "fields": ["key"]})
        present = {str(item.get("key")) for item in answer.get("issues") or [] if isinstance(item, dict)}
        missing |= {key for key in chunk if key not in present}
    return missing


def create_issue(fields: dict, *, http=None) -> str:
    result = _client(http)(credentials(), "POST", "/rest/api/3/issue", {"fields": fields})
    key = str(result.get("key", ""))
    if not ISSUE_KEY.fullmatch(key):
        raise JiraError(msg("integrations.jira.unexpected"), status=200)
    return key


def browse_url(key: str) -> str:
    return f"https://{credentials()['site']}/browse/{key}"


def comment(key: str, body: str, marker: dict, *, http=None) -> bool:
    """Adds a comment unless one with the same marker (a comment property) is already there. Returns whether it wrote.
    The outbox delivers at least once: the marker is what keeps a retried delivery from commenting twice."""
    if not ISSUE_KEY.fullmatch(key):
        raise JiraError(msg("integrations.jira.not_found"), status=404)
    client, found = _client(http), credentials()
    recent = client(found, "GET", _query(f"/rest/api/3/issue/{quote(key, safe='')}/comment", orderBy="-created", maxResults=50,
                                         expand="properties"))
    for item in recent.get("comments") or []:
        for prop in (item.get("properties") or []) if isinstance(item, dict) else []:
            if isinstance(prop, dict) and prop.get("key") == COMMENT_PROPERTY and prop.get("value") == marker:
                return False
    client(found, "POST", f"/rest/api/3/issue/{quote(key, safe='')}/comment",
           {"body": adf(body), "properties": [{"key": COMMENT_PROPERTY, "value": marker}]})
    return True


def _stamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
