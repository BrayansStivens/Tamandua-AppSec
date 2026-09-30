"""Scan of a local folder: `tamandua scan`. For the terminal, pre-commit and CI.

Without `--base` everything is scanned. With `--base main` the starting point (the merge-base
with that branch) is scanned too and only what the change introduces is reported: what was
already there doesn't block. It counts what hasn't been pushed yet (uncommitted changes and new
non-ignored files), so it works before the push and in the pipeline.

An incomplete scan never passes as clean: if an engine couldn't run, the command
says so and exits with its own code.
"""

from __future__ import annotations

import io
import json
import re
import subprocess
import tarfile
from pathlib import Path
from tempfile import TemporaryDirectory

from tamandua.modules.pullrequests.review import SEVERITY_ORDER, changed_lines, classify, verdict
from tamandua.modules.scanning.repository import scan_repository
from tamandua.modules.sources.repositories import snapshot_directory
from tamandua.shared.i18n import default_locale, localize, msg, t, text

# Exit codes (documented in docs/cli.md).
EXIT_OK, EXIT_BLOCKED, EXIT_ERROR, EXIT_INCOMPLETE = 0, 1, 2, 3
FAIL_ON = ("critical", "high", "medium", "low", "never")
# Branch, tag, SHA or git expression (HEAD~1, origin/main…). Never starts with "-": it can't
# sneak in as a git option.
REF = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._/@^~{}+-]{0,199}")
CORE_ENGINES = ("opengrep", "gitleaks", "trivy", "osv-scanner")


class LocalScanError(ValueError):
    """Carries a message; `str()` renders it in the default locale (the CLI's)."""

    def __init__(self, message):
        super().__init__(message)
        self.message = message

    def __str__(self) -> str:
        return text(self.message, default_locale())


def _git(path: Path, *args: str, binary: bool = False, timeout: int = 120):
    try:
        # safe.directory: inside the container the mounted folder belongs to another user. core.fsmonitor=false:
        # a repository's local config can't launch programs while the diff is computed.
        completed = subprocess.run(["git", "-c", f"safe.directory={path}", "-c", "core.fsmonitor=false", "-C", str(path), *args],
                                   capture_output=True, text=not binary, timeout=timeout)
    except FileNotFoundError as exc:
        raise LocalScanError(msg("scanning.local.errors.no_git")) from exc
    except subprocess.TimeoutExpired as exc:
        raise LocalScanError(msg("scanning.local.errors.git_timeout", command=args[0])) from exc
    if completed.returncode != 0:
        detail = " ".join((completed.stderr.decode(errors="replace") if binary else completed.stderr).split())[:200]
        raise LocalScanError(msg("scanning.local.errors.git_failed", command=args[0], detail=detail) if detail
                             else msg("scanning.local.errors.git_failed_silently", command=args[0]))
    return completed.stdout


def merge_base(path: Path, base: str) -> str:
    """The commit the change starts from: the merge-base between the base and HEAD."""
    if not REF.fullmatch(base or ""):
        raise LocalScanError(msg("scanning.local.errors.invalid_ref", ref=repr(base)))
    commit = _git(path, "rev-parse", "--verify", "--quiet", "--end-of-options", f"{base}^{{commit}}").strip()
    if not re.fullmatch(r"[0-9a-f]{40,64}", commit):
        raise LocalScanError(msg("scanning.local.errors.unknown_ref", ref=repr(base)))
    return _git(path, "merge-base", commit, "HEAD").strip()


def parse_diff(text: str) -> list[dict]:
    """`git diff --unified=0` → the same shape as a GitHub PR's files (filename, status, patch)."""
    files, current, patch = [], None, []
    def close():
        if current is not None:
            current["patch"] = None if current.pop("binary", False) else "\n".join(patch)
            files.append(current)
    for line in text.splitlines():
        if line.startswith("diff --git "):
            close()
            current, patch = {"filename": None, "status": "modified"}, []
        elif current is None:
            continue
        elif line.startswith("+++ "):
            target = line[4:]
            if target == "/dev/null":
                current["status"] = "removed"
            else:
                current["filename"] = target[2:] if target.startswith("b/") else target
        elif line.startswith("--- "):
            source = line[4:]
            if source == "/dev/null":
                current["status"] = "added"
            elif not current["filename"]:
                current["filename"] = source[2:] if source.startswith("a/") else source
        elif line.startswith("rename to "):
            current["filename"] = line[len("rename to "):]
        elif line.startswith("Binary files "):
            current["binary"] = True
            match = re.search(r" and (?:b/)?(.+) differ$", line)
            if match and match.group(1) != "/dev/null":
                current["filename"] = match.group(1)
        elif line.startswith(("@@", "+", "-", " ", "\\")):
            patch.append(line)
    close()
    return [item for item in files if item["filename"]]


def diff_files(path: Path, commit: str) -> list[dict]:
    """What changed from `commit` to the working tree, plus new non-ignored files."""
    text = _git(path, "diff", "--unified=0", "--no-color", "--no-ext-diff", "--relative", "-M", commit, "--")
    files = parse_diff(text)
    untracked = _git(path, "ls-files", "--others", "--exclude-standard", "--", ".").splitlines()
    return files + [{"filename": name, "status": "added", "patch": None} for name in untracked if name]


def snapshot_commit(path: Path, commit: str, destination: Path) -> dict:
    """The folder as it was at `commit`, with the same filters as the current scan."""
    prefix = _git(path, "rev-parse", "--show-prefix").strip()
    # From the top level: older git (2.39, in the image) applies the subfolder's prefix twice to `commit:prefix`.
    top = Path(_git(path, "rev-parse", "--show-toplevel").strip()) if prefix else path
    raw = destination.parent / f"{destination.name}-raw"
    raw.mkdir(parents=True, exist_ok=True)
    if prefix and _git(top, "ls-tree", "-d", "--name-only", commit, "--", prefix.rstrip("/")).strip() == "":
        destination.mkdir(parents=True, exist_ok=True)  # the change creates the folder: the baseline is empty
        return snapshot_directory(raw, destination)
    archive = _git(top, "archive", "--format=tar", f"{commit}:{prefix}" if prefix else commit, binary=True, timeout=600)
    with tarfile.open(fileobj=io.BytesIO(archive)) as bundle:
        # "data" filter (PEP 706): no absolute paths, no escaping the folder, no devices or links pointing outside.
        bundle.extractall(raw, filter="data")
    return snapshot_directory(raw, destination)


def _engines(scan: dict) -> tuple[list[str], list[str]]:
    ran, failed = [], []
    for step in scan.get("steps") or []:
        tool = (step.get("tool") or {}).get("name")
        if tool in CORE_ENGINES:
            (ran if step["status"] in ("completed", "partial") else failed).append(step["name"])
    return ran, failed


def run(path: Path, *, data_dir: Path, base: str | None = None, baseline: bool = True, fail_on: str = "high",
        allow_osv_upload: bool = False, progress=None, name: str | None = None, exclude: list[str] | None = None) -> dict:
    """Scans `path` and applies the threshold. Returns the result ready to display and the exit code.

    `exclude`: glob patterns relative to the root (`fixtures/**`, `**/testdata/**`) whose findings don't count.
    The output mentions them ("N in excluded paths"): nothing is hidden without saying so."""
    from tamandua.modules.findings.exclusions import ExclusionError, excluded, normalize
    from tamandua.modules.scanning.engines import engines_available, engines_problem
    try:
        patterns = normalize(list(exclude or []))
    except ExclusionError as exc:
        raise LocalScanError(msg("scanning.local.errors.exclude", error=exc.args[0] if exc.args else str(exc))) from exc
    path = path.expanduser().resolve()
    if not path.is_dir():
        raise LocalScanError(msg("scanning.local.errors.not_a_folder", path=str(path)))
    if fail_on not in FAIL_ON:
        raise LocalScanError(msg("scanning.local.errors.fail_on", options=", ".join(FAIL_ON)))
    report = progress or (lambda level, message: None)
    work = data_dir / "work"
    work.mkdir(parents=True, exist_ok=True)
    name = (name or path.name).strip()[:100] or path.name
    source = {"id": f"local:{name}", "name": name, "provider": "local"}
    comparison = None
    with TemporaryDirectory(prefix="scan-", dir=work) as temporary:
        head = Path(temporary) / "head"
        stats = snapshot_directory(path, head)
        report("info", msg("scanning.local.progress.copied", files=stats["files"]))
        scan = scan_repository(head, {**source, "files": stats["files"], "snapshot": stats},
                               allow_osv_upload=allow_osv_upload, data_dir=data_dir, progress=report)
        findings = [item for item in scan["findings"] if not excluded(item.get("path", ""), patterns)]
        skipped = len(scan["findings"]) - len(findings)
        if base:
            commit = merge_base(path, base)
            changed = changed_lines(diff_files(path, commit))
            report("info", msg("scanning.local.progress.comparing", base=base, commit=commit[:8], files=len(changed)))
            prints, base_status = None, None
            if baseline and changed:
                base_dir = Path(temporary) / "base"
                base_stats = snapshot_commit(path, commit, base_dir)
                report("info", msg("scanning.local.progress.baseline", files=base_stats["files"]))
                base_scan = scan_repository(base_dir, {**source, "files": base_stats["files"], "snapshot": base_stats},
                                            allow_osv_upload=allow_osv_upload, data_dir=data_dir)
                prints, base_status = {item["fingerprint"] for item in base_scan["findings"]}, base_scan["status"]
            outcome = classify(findings, changed, prints)
            findings = outcome["introduced"]
            comparison = {"base": base, "merge_base": commit, "changed_files": len(changed),
                          "baseline": prints is not None, "baseline_status": base_status,
                          "preexisting_in_changed_code": len(outcome["preexisting"])}
    ran, failed = _engines(scan)
    missing = [] if engines_available() else [engines_problem() or msg("scanning.local.no_docker")]
    incomplete = scan["status"] == "incomplete" or bool(failed) or bool(missing)
    order = {level: index for index, level in enumerate(SEVERITY_ORDER)}
    findings = sorted(findings, key=lambda item: (order.get(item["severity"], 9), item["path"], item["line"]))
    gate = verdict(findings, fail_on)
    code = EXIT_BLOCKED if gate["blocking"] else EXIT_OK
    if incomplete and code == EXIT_OK:
        code = EXIT_INCOMPLETE
    return {"target": str(path), "name": name, "comparison": comparison, "fail_on": fail_on,
            "excluded": {"patterns": patterns, "findings": skipped},
            "status": "incomplete" if incomplete else "completed", "engines": {"ran": ran, "failed": failed},
            "not_analyzed": missing + [msg("scanning.local.not_analyzed_step", step=step["name"], detail=step["detail"])
                                       for step in scan.get("steps") or []
                                       if (step.get("tool") or {}).get("name") in CORE_ENGINES and step["status"] not in ("completed", "partial")],
            "findings": findings, "gate": gate, "exit_code": code, "scan": scan}


# --- output ----------------------------------------------------------------------------

SEVERITY_TEXT = {"critical": "scanning.cli.severity.critical", "high": "scanning.cli.severity.high",
                 "medium": "scanning.cli.severity.medium", "low": "scanning.cli.severity.low", "info": "scanning.cli.severity.info"}
FAIL_ON_TEXT = {"critical": "scanning.cli.fail_on.critical", "high": "scanning.cli.fail_on.high", "medium": "scanning.cli.fail_on.medium",
                "low": "scanning.cli.fail_on.low", "never": "scanning.cli.fail_on.never"}


def _severity(level: str, locale: str) -> str:
    return t(SEVERITY_TEXT[level], locale) if level in SEVERITY_TEXT else level


def _grouped(findings: list[dict], locale: str) -> list[tuple[str, str, str]]:
    """One line per fix: advisories of the same package are closed by a single upgrade.

    The proposed version is the highest of the ones that fix each advisory (the one that closes them all)."""
    from tamandua.modules.intel.advisories import compare_versions
    order = {level: index for index, level in enumerate(SEVERITY_ORDER)}
    rows, packages = [], {}
    for item in findings:
        package = item.get("package") or {}
        if item.get("scanner") == "sca" and package.get("name"):
            packages.setdefault((item["path"], package["name"], package.get("version") or ""), []).append(item)
        else:
            rows.append((item["severity"], f"{item['path']}:{item['line']}", text(item["title"], locale)))
    for (path, name, version), items in packages.items():
        worst = min((item["severity"] for item in items), key=lambda level: order.get(level, 9))
        fixes = [item["package"]["fixed_version"] for item in items if item["package"].get("fixed_version")]
        target = None
        for fix in fixes:
            target = fix if target is None or compare_versions(fix, target) > 0 else target
        counts = ", ".join(f"{sum(1 for item in items if item['severity'] == level)} {_severity(level, locale).lower()}"
                           for level in SEVERITY_ORDER if any(item["severity"] == level for item in items))
        advice = t("scanning.cli.upgrade", locale, version=target) if target and len(fixes) == len(items) else \
            t("scanning.cli.upgrade_partial", locale, version=target) if target else t("scanning.cli.no_fix", locale)
        rows.append((worst, path, t("scanning.cli.package_row", locale, package=name, version=version,
                                    advisories=t("scanning.cli.advisories", locale, count=len(items)), counts=counts, advice=advice)))
    return sorted(rows, key=lambda row: (order.get(row[0], 9), row[1]))


_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def _safe(value) -> str:
    """Paths and titles come from the scanned repository: with no control characters, a file name can't
    move the cursor, erase lines or fake the verdict in the terminal or the CI log (CWE-150)."""
    return _CONTROL.sub("?", str(value))


def render_text(result: dict, *, limit: int = 50, locale: str | None = None) -> str:
    locale = locale or default_locale()
    comparison = result["comparison"]
    scope = (t("scanning.cli.scope_changes", locale, base=comparison["base"], commit=comparison["merge_base"][:8],
               files=comparison["changed_files"]) if comparison else t("scanning.cli.scope_all", locale))
    lines = [f"Tamandua · {_safe(result['name'])} · {scope}", ""]
    if comparison and not comparison["baseline"] and comparison["changed_files"]:
        lines += [t("scanning.cli.no_baseline", locale), ""]
    findings = result["findings"]
    if findings:
        rows = _grouped(findings, locale)
        for severity, where, title in rows[:limit]:
            lines.append(f"{_severity(severity, locale).upper().ljust(8)} {_safe(where)}  {_safe(title)}")
        if len(rows) > limit:
            lines.append(t("scanning.cli.more", locale, count=len(rows) - limit))
    else:
        lines.append(t("scanning.cli.no_new_findings", locale) if comparison else t("scanning.cli.no_findings", locale))
    if comparison and comparison["preexisting_in_changed_code"]:
        lines += ["", t("scanning.cli.preexisting", locale, count=comparison["preexisting_in_changed_code"])]
    skipped = (result.get("excluded") or {}).get("findings") or 0
    if skipped:
        lines += ["", t("scanning.cli.excluded", locale, count=skipped,
                        patterns=", ".join(_safe(item) for item in result["excluded"]["patterns"]))]
    ran = ", ".join(text(item, locale) for item in result["engines"]["ran"]) or t("scanning.cli.no_engines", locale)
    failed = ", ".join(text(item, locale) for item in result["engines"]["failed"])
    lines += ["", t("scanning.cli.engines_failed", locale, ran=ran, failed=failed) if failed else t("scanning.cli.engines", locale, ran=ran)]
    for item in result["not_analyzed"]:
        lines.append(t("scanning.cli.not_analyzed", locale, item=_safe(text(item, locale))))
    gate = result["gate"]
    verdict_line = t({EXIT_OK: "scanning.cli.verdict.pass", EXIT_BLOCKED: "scanning.cli.verdict.blocked",
                      EXIT_INCOMPLETE: "scanning.cli.verdict.incomplete"}[result["exit_code"]], locale)
    detail = text(gate["description"], locale) if result["exit_code"] != EXIT_INCOMPLETE else t("scanning.cli.incomplete", locale)
    lines += ["", t("scanning.cli.verdict_line", locale, verdict=verdict_line, threshold=t(FAIL_ON_TEXT[result["fail_on"]], locale),
                    detail=detail)]
    return "\n".join(lines) + "\n"


def render_json(result: dict, *, locale: str | None = None) -> str:
    from tamandua.modules.findings.fix_guide import attach
    fields = ("fingerprint", "severity", "scanner", "tool", "also_detected_by", "rule_id", "title", "path", "line",
              "cwe", "cve", "ghsa", "package", "malicious", "remediation", "fix", "priority", "kev", "epss")
    payload = {key: result.get(key) for key in ("target", "status", "comparison", "fail_on", "excluded", "engines", "not_analyzed", "exit_code")}
    payload["gate"] = result["gate"]
    # `fix`: the same fix guide as the panel (steps, commands and example), for whoever fixes from the terminal.
    findings = attach([dict(item) for item in result["findings"]])
    payload["findings"] = [{key: item.get(key) for key in fields if item.get(key) is not None} for item in findings]
    return json.dumps(localize(payload, locale or default_locale()), ensure_ascii=False, indent=2) + "\n"


def render_sarif(result: dict, *, locale: str | None = None) -> str:
    from tamandua.modules.runs.store import render_repository_sarif
    locale = locale or default_locale()
    sarif = render_repository_sarif({"findings": localize(result["findings"], locale)})
    return json.dumps(localize(sarif, locale), ensure_ascii=False, indent=2) + "\n"
