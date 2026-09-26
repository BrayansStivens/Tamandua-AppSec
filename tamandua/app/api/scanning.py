"""Secret detection settings (Gitleaks and Trivy), organization defaults and per repository: anyone signed in reads
them (without the patterns unless an admin), an admin changes them."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict, Field

from tamandua.app.api.deps import ApiError, Context, Policy, guard
from tamandua.modules.findings import registry as findings_registry
from tamandua.modules.findings.exclusions import ASSET_KEY
from tamandua.modules.scanning import secret_rules
from tamandua.modules.scanning.engines import IMAGES
from tamandua.modules.scanning.secret_builtin_rules import GITLEAKS_DEFAULT_RULES, TRIVY_EQUIVALENTS
from tamandua.modules.sources.assets import overview as assets_overview
from tamandua.shared.i18n import msg

router = APIRouter(tags=["scanning"])

# Loose caps against oversized input; the precise limits (and their localized errors) are in secret_rules.
_TEXT = 2_000


class SecretAllowlist(BaseModel):
    """Regexes are matched against the detected secret; paths are globs relative to the repository root."""
    model_config = ConfigDict(extra="forbid")
    regexes: list[str] = Field(default_factory=list, max_length=200)
    paths: list[str] = Field(default_factory=list, max_length=200)
    stopwords: list[str] = Field(default_factory=list, max_length=200)


class SecretRule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(max_length=200)
    description: str = Field(max_length=_TEXT)
    regex: str = Field(max_length=_TEXT)
    keywords: list[str] = Field(default_factory=list, max_length=50)


class SecretConfigIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    allowlist: SecretAllowlist
    rules: list[SecretRule] = Field(max_length=100)
    disabled_rules: list[str] = Field(max_length=400)
    reason: str = Field(max_length=_TEXT)


class SecretHistoryEntry(BaseModel):
    at: str
    by: str
    reason: str | None
    changes: dict[str, dict[str, Annotated[list[str], Field(max_length=secret_rules.CHANGES_SHOWN)]]] = Field(default_factory=dict)


class SecretLimits(BaseModel):
    rules: int
    entries: int
    regex: int
    description: int
    keywords: int


class SecretAllowlistView(BaseModel):
    regexes: list[str] = Field(max_length=secret_rules.MAX_ENTRIES)
    paths: list[str] = Field(max_length=secret_rules.MAX_ENTRIES)
    stopwords: list[str] = Field(max_length=secret_rules.MAX_ENTRIES)


class SecretRuleView(BaseModel):
    id: str
    description: str
    regex: str
    keywords: list[str] = Field(max_length=secret_rules.MAX_KEYWORDS)


class SecretConfig(BaseModel):
    allowlist: SecretAllowlistView
    rules: list[SecretRuleView] = Field(max_length=secret_rules.MAX_RULES)
    disabled_rules: list[str] = Field(max_length=secret_rules.MAX_DISABLED)
    reason: str | None
    by: str | None
    at: str | None
    history: list[SecretHistoryEntry] = Field(max_length=secret_rules.HISTORY)
    limits: SecretLimits


class AssetSecretConfigIn(SecretConfigIn):
    key: str = Field(max_length=200)


class SecretCounts(BaseModel):
    rules: int
    disabled: int
    allowlist: int


class AssetSecretConfig(SecretConfig):
    """A repository's own entries, added to the defaults (`defaults` counts them) in its scans."""
    key: str
    defaults: SecretCounts


class BuiltinRule(BaseModel):
    id: str
    trivy: str | None


class BuiltinRules(BaseModel):
    engine: str
    version: str
    rules: list[BuiltinRule] = Field(max_length=len(GITLEAKS_DEFAULT_RULES))


HIDDEN = "••••••"
SENSITIVE = ("regexes", "stopwords")  # an allowlisted pattern may contain a real secret


def _view(settings: dict) -> dict:
    return {**settings, "history": list(reversed(settings["history"])), "limits": secret_rules.LIMITS}


def _redacted(view: dict) -> dict:
    """What a non-admin may see: the shape and counts, never the patterns themselves."""
    allowlist = {name: [HIDDEN] * len(items) if name in SENSITIVE else items for name, items in view["allowlist"].items()}
    rules = [{**rule, "regex": HIDDEN, "keywords": []} for rule in view["rules"]]
    history = [{**entry, "changes": {name: ({kind: [HIDDEN] * len(items) for kind, items in change.items()} if name in SENSITIVE else change)
                                     for name, change in (entry.get("changes") or {}).items()}} for entry in view["history"]]
    return {**view, "allowlist": allowlist, "rules": rules, "history": history}


@router.get("/api/secrets/config", response_model=SecretConfig)
def config(context: Context = Depends(guard())) -> dict:
    """What secret detection applies to every repository scan; only admins see (and change) the patterns."""
    view = _view(secret_rules.get(context.data_dir))
    return view if (context.user or {}).get("role") == "admin" else _redacted(view)


@router.post("/api/secrets/config", response_model=SecretConfig)
def save_config(body: SecretConfigIn,
                context: Context = Depends(guard(Policy(admin=True, action="save-secret-rules", body=200_000)))) -> dict:
    """Replaces the settings; takes effect from the next scan. A reason is required and kept in the history."""
    try:
        saved = secret_rules.save(context.data_dir, body.model_dump(exclude={"reason"}), reason=body.reason, user=context.user)
    except secret_rules.SecretRulesError as exc:
        raise ApiError(400, exc.message, **({"field": exc.field} if exc.field else {})) from exc
    return _view(saved)


def _asset_key(key: str) -> str:
    # Images don't run the repository secret engines: their settings would never apply.
    if not ASSET_KEY.fullmatch(key) or key.startswith("image:"):
        raise ApiError(400, msg("api.invalid_repository"))
    return key


def _asset_view(context: Context, key: str, settings: dict) -> dict:
    view = {**_view(settings), "key": key, "defaults": secret_rules.counts(secret_rules.get(context.data_dir))}
    return view if (context.user or {}).get("role") == "admin" else _redacted(view)


@router.get("/api/assets/secrets", response_model=AssetSecretConfig)
def asset_config(key: str = Query(max_length=200), context: Context = Depends(guard())) -> dict:
    """A repository's own secret detection entries (empty: it uses the defaults as they are)."""
    key = _asset_key(key)
    return _asset_view(context, key, secret_rules.get(context.data_dir, key))


@router.post("/api/assets/secrets", response_model=AssetSecretConfig)
def save_asset_config(body: AssetSecretConfigIn,
                      context: Context = Depends(guard(Policy(admin=True, action="save-asset-secret-rules", body=200_000)))) -> dict:
    """Replaces a repository's own entries; they add to the defaults from its next scan. A reason is required."""
    key = _asset_key(body.key)
    state = findings_registry.load(context.data_dir, key)
    name = state["name"] or next((row["name"] for row in assets_overview(context.data_dir) if row["key"] == key), None)
    if name is None and not state["findings"]:
        raise ApiError(404, msg("api.repository_not_found"))
    try:
        saved = secret_rules.save(context.data_dir, body.model_dump(exclude={"reason", "key"}), reason=body.reason,
                                  user=context.user, asset=key, name=name)
    except secret_rules.SecretRulesError as exc:
        raise ApiError(400, exc.message, **({"field": exc.field} if exc.field else {})) from exc
    return _asset_view(context, key, saved)


@router.get("/api/secrets/builtin-rules", response_model=BuiltinRules)
def builtin_rules(context: Context = Depends(guard())) -> dict:
    """Gitleaks' default rules (what can be turned off), with the Trivy rule that is turned off with each, if any."""
    return {"engine": "gitleaks", "version": IMAGES["gitleaks"]["version"],
            "rules": [{"id": rule, "trivy": TRIVY_EQUIVALENTS.get(rule)} for rule in GITLEAKS_DEFAULT_RULES]}
