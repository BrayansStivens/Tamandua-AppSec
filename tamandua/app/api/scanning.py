"""Organization-wide secret detection settings (Gitleaks and Trivy): anyone signed in reads them, an admin changes them."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field

from tamandua.app.api.deps import ApiError, Context, Policy, guard
from tamandua.modules.scanning import secret_rules
from tamandua.modules.scanning.engines import IMAGES
from tamandua.modules.scanning.secret_builtin_rules import GITLEAKS_DEFAULT_RULES, TRIVY_EQUIVALENTS

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
    severity: Literal["critical", "high", "medium", "low"]


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
    changes: dict[str, dict[str, list[str]]] = Field(default_factory=dict)


class SecretLimits(BaseModel):
    rules: int
    entries: int
    regex: int
    description: int
    keywords: int


class SecretAllowlistView(BaseModel):
    regexes: list[str]
    paths: list[str]
    stopwords: list[str]


class SecretRuleView(BaseModel):
    id: str
    description: str
    regex: str
    keywords: list[str]
    severity: Literal["critical", "high", "medium", "low"]


class SecretConfig(BaseModel):
    allowlist: SecretAllowlistView
    rules: list[SecretRuleView]
    disabled_rules: list[str]
    reason: str | None
    by: str | None
    at: str | None
    history: list[SecretHistoryEntry]
    limits: SecretLimits


class BuiltinRule(BaseModel):
    id: str
    trivy: str | None


class BuiltinRules(BaseModel):
    engine: str
    version: str
    rules: list[BuiltinRule]


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


@router.get("/api/secrets/builtin-rules", response_model=BuiltinRules)
def builtin_rules(context: Context = Depends(guard())) -> dict:
    """Gitleaks' default rules (what can be turned off), with the Trivy rule that is turned off with each, if any."""
    return {"engine": "gitleaks", "version": IMAGES["gitleaks"]["version"],
            "rules": [{"id": rule, "trivy": TRIVY_EQUIVALENTS.get(rule)} for rule in GITLEAKS_DEFAULT_RULES]}
