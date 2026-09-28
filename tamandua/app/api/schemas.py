"""Response models shared by several routes: a run (its list row and its whole record) and a finding.

They document the fields readers rely on; the rest of what a module returns goes through as it is (`Open`). Routes
that answer with them set `response_model_exclude_unset=True`, so the body is exactly the module's result and
FastAPI never adds a missing field as null.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# The arguments every route answering with an `Open` model passes to its decorator.
AS_RETURNED: dict[str, Any] = {"response_model_exclude_unset": True}

# Upper bounds of lists in the OpenAPI document (every array declares one: tests/test_api.py, Checkov CKV_OPENAPI_21).
# A model uses its module's own limit where there is one; these cover what only grows with use, far above any real
# workspace. The response model checks them on every answer.
MANY = 10_000          # things a workspace registers or accumulates: domains, registries, models, runs listed…
FINDINGS_MAX = 100_000  # findings in one run
IDS_MAX = 1_000         # identifiers of one finding (CWE, OWASP, CVE, GHSA)


class Open(BaseModel):
    """Documents its fields and keeps any other one the module returns."""
    model_config = ConfigDict(extra="allow")


class FindingOut(Open):
    """A finding as served: messages rendered in the reader's language, with its triage, fix and lifecycle."""
    finding_id: str
    fingerprint: str
    scanner: str
    rule_id: str
    title: str | None = None
    path: str
    line: int | None = None
    severity: str
    confidence: int | None = None
    tool: str | None = None
    cwe: list[int] | None = Field(None, max_length=IDS_MAX)
    owasp: list[str] | None = Field(None, max_length=IDS_MAX)
    cve: list[str] | None = Field(None, max_length=IDS_MAX)
    ghsa: list[str] | None = Field(None, max_length=IDS_MAX)
    package: dict[str, Any] | None = None
    advisory: dict[str, Any] | None = None
    priority: dict[str, Any] | None = None
    reason: str | None = None
    remediation: str | None = None
    triage: dict[str, Any] | None = None
    fix: dict[str, Any] | None = None
    lifecycle: dict[str, Any] | None = None
    ticket: dict[str, Any] | None = None
    verification: dict[str, Any] | None = None


class RunRow(Open):
    """A run's list row (no findings)."""
    id: str
    type: str
    status: str
    created_at: str
    target: str | None = None
    summary: dict[str, Any] | None = None
    source: dict[str, Any] | None = None
    variant: str | None = None
    started_at: str | None = None
    finished_at: str | None = None
    pull_request: dict[str, Any] | None = None
    trigger: dict[str, Any] | None = None


class RunDetail(RunRow):
    """A whole run record, or a repository's state served in the same shape (`type` asset_state)."""
    findings: list[FindingOut] = Field([], max_length=FINDINGS_MAX)
    steps: list[dict[str, Any]] = Field([], max_length=MANY)
    limitations: list[str] = Field([], max_length=MANY)
    owasp_coverage: list[Any] = Field([], max_length=MANY)
    progress: list[dict[str, Any]] | None = Field(None, max_length=MANY)
    context: str | None = None
