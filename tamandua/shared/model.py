"""The shapes the domain passes around: a finding, an engine's result and a run record.

They are TypedDicts over the plain dicts the code has always used, and that the database stores as JSONB: they give
readers and mypy names and types, never a conversion. `Required` marks what every reader relies on; the rest may be
missing (older runs, other engines).
"""

from __future__ import annotations

from typing import Any, Required, TypedDict

# Plain text, or an i18n message ({"$t": key, ...}) rendered in each reader's language (shared/i18n).
Message = str | dict[str, Any]


class Package(TypedDict, total=False):
    ecosystem: str
    name: str
    version: str
    fixed_version: str | None
    introduced: str | None
    dev: bool
    direct: bool | None


class Advisory(TypedDict, total=False):
    id: str
    aliases: list[str]
    summary: Message
    details: str
    cvss_vector: str | None
    cvss_score: float | None
    published: str | None
    modified: str | None
    references: list[str]


class Priority(TypedDict, total=False):
    action: Required[str]  # act · attend · track
    factors: list[Message]


class Finding(TypedDict, total=False):
    finding_id: Required[str]
    fingerprint: Required[str]
    previous_fingerprint: str  # the former formula's, so the registry carries state over (findings/registry.py)
    scanner: Required[str]     # sast · secrets · sca · iac · cicd · image-config
    tool: str
    rule_id: Required[str]
    title: Message
    path: Required[str]
    line: int
    severity: Required[str]    # critical · high · medium · low · info
    confidence: int
    verdict: str
    cwe: list[int]
    owasp: list[str]
    cve: list[str]
    ghsa: list[str]
    package: Package | None
    advisory: Advisory | None
    kev: dict[str, Any] | None
    epss: dict[str, Any] | None
    source: dict[str, Any] | None
    priority: Priority
    reason: Message
    remediation: Message
    also_detected_by: list[str]
    malicious: bool
    excluded_by: str | None
    excluded_reason: Message | None
    # Added when a run is served, never stored with it.
    triage: dict[str, Any]
    ticket: dict[str, Any]
    fix: dict[str, Any]
    lifecycle: dict[str, Any]
    verification: dict[str, Any]


class EngineResult(TypedDict, total=False):
    tool: Required[str]
    name: str
    version: str
    image: str
    status: Required[str]      # completed · inconclusive · not_tested
    detail: Message
    findings: list[Finding]
    duration_s: float | None
    packages: list[dict[str, Any]]
    system_packages: list[dict[str, Any]]
    withheld: list[Finding] | None


class RunRecord(TypedDict, total=False):
    schema_version: str
    id: str
    type: Required[str]        # repository_scan · image_scan · pr_review · advisory_watch · …
    status: str                # queued · running · completed · incomplete · failed
    created_at: str
    started_at: str
    finished_at: str
    requested_by: str
    source: dict[str, Any]
    target: str
    variant: str
    context: str
    trigger: dict[str, Any]
    pull_request: dict[str, Any]
    review: dict[str, Any]
    steps: list[dict[str, Any]]
    findings: list[Finding]
    excluded_findings: list[Finding]
    summary: dict[str, Any]
    owasp_coverage: list[Any]
    limitations: list[Message]
    progress: list[dict[str, Any]]
    dependencies: list[dict[str, Any]]
    system_packages: list[dict[str, Any]]
    inventory: dict[str, Any]
    unused_dependencies: list[Any]
