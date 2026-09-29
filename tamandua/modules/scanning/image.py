"""Container image scanning straight from the registry, without running the image.

What gets checked in an image (`registry/repository:tag` or `@sha256:…`):

* **Packages** of the operating system and of packaged applications, with two engines:
  Trivy and Grype. They agree on the vast majority of CVEs but disagree on packages with
  patches backported by the distributions; what both see is marked as such.
* **Secrets** inside the layers and in the **image configuration**: environment
  variables (`ENV`) and build history (`ARG` used in `RUN`), which is where credentials
  passed in to download private dependencies end up.
* **Configuration**: root user, missing `HEALTHCHECK` and our other configuration rules,
  plus Checkov on a Dockerfile rebuilt from the history (downloads without TLS
  verification, `sudo`, package managers without signatures…). Without duplicating what our
  own rules already see (`config_scanners.merge_image`).

The image is never run or built: the engines read the manifest and the layers from the
registry. Private registry credentials are stored encrypted (`vault`) and reach the
engines through environment variables, not the command line.
"""

from __future__ import annotations

import json
import re
import socket
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from tamandua.modules.intel import data_sources
from tamandua.shared import log as logging_setup, settings
from tamandua.shared.i18n import default_locale, msg, text
from tamandua.modules.intel.advisories import cvss3_base_score, fingerprint as sca_fingerprint, prioritize, severity_from_score
from tamandua.modules.intel.packages import OS_FAMILIES, canonical_id, dependency_fingerprint, family
from tamandua.modules.scanning.coverage import owasp_coverage
from tamandua.modules.scanning.config_engines import merge_image, run_checkov_image
from tamandua.modules.scanning.engines import _pick_fixed, _result, _run, parse_trivy, trivy_packages, unavailable, writable_cache
from tamandua.shared.model import RunRecord

_log = logging_setup.get("images")
VAULT_NAME = "registries"
DOCKER_HUB = "docker.io"
_COMPONENT = r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*"
REFERENCE = re.compile(rf"(?:(?P<registry>(?:[a-zA-Z0-9-]+\.)+[a-zA-Z0-9-]+(?::\d{{1,5}})?|localhost(?::\d{{1,5}})?|[a-zA-Z0-9-]+:\d{{1,5}})/)?"
                       rf"(?P<repository>{_COMPONENT}(?:/{_COMPONENT}){{0,5}})"
                       r"(?::(?P<tag>[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}))?"
                       r"(?:@(?P<digest>sha256:[0-9a-f]{64}))?")
HOST = re.compile(r"(?:[a-z0-9-]+\.)+[a-z0-9-]+(?::\d{1,5})?|localhost(?::\d{1,5})?|[a-z0-9-]+:\d{1,5}")

# The package families image fingerprints used before intel/packages.py unified them; only for `_former_fingerprint`.
_FORMER_FAMILY = {"node-pkg": "npm", "npm": "npm", "yarn": "npm", "pnpm": "npm", "python-pkg": "pypi", "pip": "pypi", "pipenv": "pypi",
                  "poetry": "pypi", "python": "pypi", "gobinary": "go", "gomod": "go", "go-module": "go", "jar": "maven", "pom": "maven",
                  "gradle": "maven", "java-archive": "maven", "gemspec": "rubygems", "bundler": "rubygems", "gem": "rubygems",
                  "cargo": "cargo", "rust-binary": "cargo", "rust-crate": "cargo", "composer": "composer", "php-composer": "composer",
                  "nuget": "nuget", "dotnet-core": "nuget", "dotnet": "nuget", "deb": "os", "apk": "os", "rpm": "os"}
GRYPE_SEVERITY = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "negligible": "low"}


class ImageError(ValueError):
    """Carries a message; `str()` renders it in the default locale, `.message` keeps it for the reader's."""

    def __init__(self, message):
        super().__init__(message)
        self.message = message

    def __str__(self) -> str:
        return text(self.message, default_locale())


# --- references ---------------------------------------------------------------------------

def parse_reference(text: str) -> dict:
    """Normalizes an image reference. Docker Hub is written out in full (`docker.io/library/nginx`)."""
    raw = str(text or "").strip()
    match = REFERENCE.fullmatch(raw) if 3 <= len(raw) <= 300 else None
    if not match:
        raise ImageError(msg("scanning.image.errors.invalid_reference"))
    registry = (match["registry"] or DOCKER_HUB).lower()
    repository = match["repository"]
    if registry in ("index.docker.io", "registry-1.docker.io"):
        registry = DOCKER_HUB
    if registry == DOCKER_HUB and "/" not in repository:
        repository = f"library/{repository}"
    tag = match["tag"] or (None if match["digest"] else "latest")
    reference = f"{registry}/{repository}" + (f":{tag}" if tag else "") + (f"@{match['digest']}" if match["digest"] else "")
    return {"registry": registry, "repository": repository, "tag": tag, "digest": match["digest"],
            "reference": reference, "asset": f"image:{registry}/{repository}", "name": f"{registry}/{repository}"}


def _host_only(registry: str) -> str:
    return "registry-1.docker.io" if registry == DOCKER_HUB else registry.rsplit(":", 1)[0] if re.search(r":\d+$", registry) else registry


def check_registry_address(registry: str) -> dict[str, str]:
    """The engine will connect to that registry: if it resolves to an internal network, explicit permission is needed.

    Keeps the form from being used to make the server talk to internal services (SSRF).
    For your own registries on the local network: TAMANDUA_ALLOW_PRIVATE_REGISTRIES=1.

    Returns the address to pin the registry's name to ({host: address}) so the engine can't resolve it again to
    another one (DNS rebinding between this check and the scan). Empty for Docker Hub, whose name nobody here chooses,
    and when private registries are allowed.
    """
    if settings.flag("TAMANDUA_ALLOW_PRIVATE_REGISTRIES"):
        return {}
    import ipaddress
    host = _host_only(registry)
    try:
        addresses = {info[4][0] for info in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)}
    except OSError as exc:
        raise ImageError(msg("scanning.image.errors.unresolvable", registry=registry)) from exc
    if not addresses or not all(ipaddress.ip_address(address.split("%")[0]).is_global for address in addresses):
        raise ImageError(msg("scanning.image.errors.private_address", registry=registry))
    if registry == DOCKER_HUB:
        return {}
    # IPv4 first: engine containers on Docker's default bridge often have no IPv6 route.
    return {host: sorted(addresses, key=lambda address: (":" in address, address))[0].split("%")[0]}


# --- registry credentials -----------------------------------------------------------------

def _stored() -> dict:
    from tamandua.shared.vault import VaultError, get
    try:
        data = get(VAULT_NAME)
    except VaultError:
        return {}
    return data if isinstance(data, dict) else {}


def registries() -> list[dict]:
    """Registries with stored credentials. Never returns the token."""
    return [{"registry": host, "username": entry.get("username"), "last4": (entry.get("token") or "")[-4:],
             "saved_at": entry.get("saved_at"), "saved_by": entry.get("saved_by")}
            for host, entry in sorted(_stored().items()) if isinstance(entry, dict)]


def save_registry(registry: str, username: str, token: str, *, by: str) -> list[dict]:
    from tamandua.shared.vault import put
    host = str(registry or "").strip().lower()
    if host in ("index.docker.io", "registry-1.docker.io", "hub.docker.com"):
        host = DOCKER_HUB
    if not HOST.fullmatch(host) or len(host) > 200:
        raise ImageError(msg("scanning.image.errors.invalid_registry"))
    if not isinstance(username, str) or not 1 <= len(username.strip()) <= 200 or any(ord(char) < 33 for char in username.strip()):
        raise ImageError(msg("scanning.image.errors.invalid_username"))
    if not isinstance(token, str) or not 8 <= len(token) <= 4096 or any(ord(char) < 33 or ord(char) > 126 for char in token):
        raise ImageError(msg("scanning.image.errors.invalid_token"))
    data = _stored()
    data[host] = {"username": username.strip(), "token": token,
                  "saved_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "saved_by": by}
    put(VAULT_NAME, data)
    _log.info("registry_saved", extra={"user": by, "reason": host})
    return registries()


def forget_registry(registry: str) -> list[dict]:
    from tamandua.shared.vault import delete, put
    data = _stored()
    if data.pop(str(registry or "").strip().lower(), None) is not None:
        put(VAULT_NAME, data) if data else delete(VAULT_NAME)
    return registries()


def credentials_for(registry: str) -> dict | None:
    entry = _stored().get(registry)
    return entry if isinstance(entry, dict) and entry.get("token") else None


# --- engines ------------------------------------------------------------------------------

def _former_fingerprint(identifiers: set[str], fallback: str, ecosystem: str, name: str, version: str) -> str:
    """The image fingerprint before it was unified with the repository one (intel/packages.py): kept as
    `previous_fingerprint` so the registry carries state and triage over."""
    value = (ecosystem or "").lower()
    kind = "os" if value in OS_FAMILIES else _FORMER_FAMILY.get(value, value or "unknown")
    return sca_fingerprint("sca", canonical_id(identifiers | {fallback}, fallback), kind, name, version)


def _with_fingerprint(finding: dict, identifiers: set[str], fallback: str, ecosystem: str, name: str, version: str) -> dict:
    digest = dependency_fingerprint(identifiers, fallback, ecosystem, name, version)
    former = _former_fingerprint(identifiers, fallback, ecosystem, name, version)
    rest = {key: value for key, value in finding.items() if key != "previous_fingerprint"}
    return {**rest, "fingerprint": digest, "finding_id": digest[:16], **({"previous_fingerprint": former} if former != digest else {})}


def run_trivy_image(reference: str, cache_dir: Path, feeds: dict, credentials: dict | None,
                    hosts: dict[str, str] | None = None) -> tuple[dict, dict]:
    started = time.time()
    if problem := unavailable("trivy", msg("scanning.image.no_docker", engine="Trivy")):
        return _result("trivy", "not_tested", problem), {}
    cache_dir = writable_cache(cache_dir)
    secrets = {"TRIVY_USERNAME": credentials["username"], "TRIVY_PASSWORD": credentials["token"]} if credentials else None
    try:
        completed = _run("trivy", ["image", "--image-src", "remote", "--scanners", "vuln,secret", "--list-all-pkgs",
                                   "--image-config-scanners", "misconfig,secret", "--cache-dir", "/cache", "--format", "json", "--quiet",
                                   "--timeout", "14m", reference], None, network=True, secret_env=secrets,
                         mounts=["-v", f"{_host(cache_dir)}:/cache"], hosts=hosts)
        if completed.returncode != 0 and not completed.stdout.strip():
            return _result("trivy", "inconclusive", _registry_error(completed.stderr, credentials), started=started), {}
        payload = json.loads(completed.stdout or "{}")
    except subprocess.TimeoutExpired:
        return _result("trivy", "inconclusive", msg("scanning.image.timeout", engine="Trivy"), started=started), {}
    except (OSError, ValueError):
        return _result("trivy", "inconclusive", msg("scanning.engines.unreadable", engine="Trivy"), started=started), {}
    findings = parse_trivy(payload, feeds)
    metadata = payload.get("Metadata") or {}
    counts = {kind: sum(1 for item in findings if item["scanner"] == kind) for kind in ("sca", "iac", "secrets")}
    detail = msg("scanning.image.trivy_detail", **counts)
    return {**_result("trivy", "completed", detail, findings, started), "packages": trivy_packages(payload),
            "system_packages": trivy_packages(payload, system=True)}, metadata


def _grype_finding(match: dict, feeds: dict) -> dict:
    vulnerability, artifact = match.get("vulnerability") or {}, match.get("artifact") or {}
    identifier = str(vulnerability.get("id") or "")
    related = {str(item.get("id")) for item in match.get("relatedVulnerabilities") or [] if item.get("id")}
    aliases = {identifier, *related} - {""}
    name, installed = str(artifact.get("name") or ""), str(artifact.get("version") or "")
    fixed = _pick_fixed(", ".join((vulnerability.get("fix") or {}).get("versions") or []), installed)
    vector = score = None
    for block in sorted(vulnerability.get("cvss") or [], key=lambda item: str(item.get("version")) != "3.1"):
        if str(block.get("version", "")).startswith("3") and block.get("vector"):
            vector = block["vector"]
            score = cvss3_base_score(vector) or (block.get("metrics") or {}).get("baseScore")
            break
    label = GRYPE_SEVERITY.get(str(vulnerability.get("severity") or "").lower())
    severity = severity_from_score(score, label.upper() if label else None)
    cves = sorted(item for item in aliases if item.startswith("CVE-"))
    ghsas = sorted(item for item in aliases if item.startswith("GHSA-"))
    kev = next((feeds.get("kev", {}).get(cve) for cve in cves if feeds.get("kev", {}).get(cve)), None)
    epss = next((feeds.get("epss", {}).get(cve) for cve in cves if feeds.get("epss", {}).get(cve)), None)
    summary = str(vulnerability.get("description") or "").strip() or identifier
    location = next((item.get("path") for item in artifact.get("locations") or [] if item.get("path")), "") or "image"
    ecosystem = str(artifact.get("type") or "unknown")
    cwe = sorted({int(found.group(1)) for item in vulnerability.get("cwes") or [] if (found := re.fullmatch(r"CWE-(\d+)", str(item.get("cwe"))))})
    references = [url for url in vulnerability.get("urls") or [] if isinstance(url, str) and url.startswith("https://")][:8]
    return _with_fingerprint({"scanner": "sca", "tool": "grype", "rule_id": identifier,
            "title": f"{name} {installed}: {summary.splitlines()[0]}"[:200], "path": location.lstrip("/"), "line": 1,
            "severity": severity, "confidence": 8 if score is not None else 6, "verdict": "candidate", "cwe": cwe,
            "owasp": ["A03:2025"], "cve": cves, "ghsa": ghsas,
            "package": {"ecosystem": ecosystem, "name": name, "version": installed, "fixed_version": fixed, "introduced": None},
            "advisory": {"id": identifier, "aliases": sorted(aliases), "summary": summary[:300], "details": summary[:2000],
                         "cvss_vector": vector, "cvss_score": score, "published": None, "modified": None, "references": references},
            "kev": kev, "epss": {"score": epss[0], "percentile": epss[1]} if epss else None,
            "source": data_sources.from_grype(vulnerability),
            "priority": prioritize(severity, score, kev, epss, fixed), "reason": summary[:300], "remediation": ""},
        aliases, identifier, ecosystem, name, installed)


def run_grype_image(reference: str, cache_dir: Path, feeds: dict, credentials: dict | None, registry: str,
                    hosts: dict[str, str] | None = None) -> dict:
    started = time.time()
    if problem := unavailable("grype", msg("scanning.image.no_docker", engine="Grype")):
        return _result("grype", "not_tested", problem)
    cache_dir = writable_cache(cache_dir)
    (cache_dir / "tmp").mkdir(exist_ok=True)
    secrets = ({"GRYPE_REGISTRY_AUTH_AUTHORITY": _host_only(registry) if registry != DOCKER_HUB else "index.docker.io",
                "GRYPE_REGISTRY_AUTH_USERNAME": credentials["username"], "GRYPE_REGISTRY_AUTH_PASSWORD": credentials["token"]}
               if credentials else None)
    try:
        completed = _run("grype", [f"registry:{reference}", "-o", "json", "-q"], None, network=True, secret_env=secrets,
                         # Grype's image has no /tmp writable by non-root users: its temporary files
                         # (layers of the scanned image) go to disk, inside its cache.
                         env={"GRYPE_DB_CACHE_DIR": "/cache", "GRYPE_CHECK_FOR_APP_UPDATE": "false", "TMPDIR": "/cache/tmp", "HOME": "/cache/tmp"},
                         mounts=["-v", f"{_host(cache_dir)}:/cache"], hosts=hosts)
        if completed.returncode != 0 and not completed.stdout.strip():
            return _result("grype", "inconclusive", _registry_error(completed.stderr, credentials), started=started)
        payload = json.loads(completed.stdout or "{}")
    except subprocess.TimeoutExpired:
        return _result("grype", "inconclusive", msg("scanning.image.timeout", engine="Grype"), started=started)
    except (OSError, ValueError):
        return _result("grype", "inconclusive", msg("scanning.engines.unreadable", engine="Grype"), started=started)
    findings = [_grype_finding(match, feeds) for match in payload.get("matches") or []]
    return _result("grype", "completed", msg("scanning.image.grype_detail", advisories=len(findings)), findings, started)


def _host(path: Path) -> str:
    from tamandua.modules.scanning.engines import host_path
    return host_path(path)


def _registry_error(stderr: str, credentials: dict | None) -> dict:
    output = (stderr or "").lower()
    if any(marker in output for marker in ("unauthorized", "denied", "401", "403", "authentication required")):
        return msg("scanning.image.registry.denied") if credentials else msg("scanning.image.registry.credentials_needed")
    if "manifest unknown" in output or "not found" in output or "name unknown" in output:
        return msg("scanning.image.registry.not_found")
    return msg("scanning.image.registry.unreadable")


# --- image configuration --------------------------------------------------------------------

SECRET_NAME = re.compile(r"(?i)(pass(word|wd)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|auth|pat)$|"
                         r"(^|_)(npm_token|github_token|gh_token|pip_index_url|aws_secret_access_key|database_url|dsn)$")
HISTORY_SECRET = re.compile(r"(?i)\b([A-Z0-9_]*(?:TOKEN|PASSWORD|PASSWD|SECRET|API_KEY|ACCESS_KEY|PRIVATE_KEY)[A-Z0-9_]*)=(?![$'\"]?\$)['\"]?([^\s'\"]{6,})")
URL_CREDENTIALS = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://([^/\s:@]+):([^/\s@]{3,})@")
AUTH_HEADER = re.compile(r"(?i)authorization:\s*(bearer|basic|token)\s+(?!\$)[A-Za-z0-9._~+/=-]{8,}")


def _config_finding(rule: str, title, severity: str, reason, remediation, cwe: int, asset: str, key: str,
                    path: str = "image-config") -> dict:
    from tamandua.modules.scanning.engines import _base, _stable
    finding = _base("iac" if cwe != 798 else "secrets", rule, title, path, 1, severity, tool="tamandua",
                    reason=reason, remediation=remediation, cwe=[cwe], owasp="A02:2025" if cwe != 798 else "A04:2025",
                    confidence=8, digest=_stable("image-config", rule, asset, key))
    return finding


def config_findings(metadata: dict, image: dict) -> list[dict]:
    """Our own rules on the image's configuration and history. No secret value is ever copied."""
    config_block = metadata.get("ImageConfig") or {}
    config = config_block.get("config") or {}
    history = [str(item.get("created_by") or "") for item in config_block.get("history") or []]
    asset = image["asset"]
    findings = []
    user = str(config.get("User") or "").strip()
    if user in ("", "root", "0", "0:0", "root:root"):
        findings.append(_config_finding("IMG-ROOT", msg("scanning.image.rules.root.title"), "medium",
            msg("scanning.image.rules.root.reason"), msg("scanning.image.rules.root.remediation"), 250, asset, "user"))
    for entry in config.get("Env") or []:
        name, _, value = str(entry).partition("=")
        if value.strip() and not value.startswith("$") and SECRET_NAME.search(name):
            findings.append(_config_finding("IMG-ENV-SECRET", msg("scanning.image.rules.env_secret.title", name=name), "critical",
                msg("scanning.image.rules.env_secret.reason", name=name), msg("scanning.image.rules.env_secret.remediation"),
                798, asset, f"env:{name}", path=f"ENV {name}"))
    for index, step in enumerate(history):
        for match in HISTORY_SECRET.finditer(step):
            findings.append(_config_finding("IMG-BUILD-SECRET", msg("scanning.image.rules.build_secret.title", name=match.group(1)), "critical",
                msg("scanning.image.rules.build_secret.reason", step=index + 1, name=match.group(1)),
                msg("scanning.image.rules.build_secret.remediation"), 798, asset, f"history:{index}:{match.group(1)}",
                path=f"image-history/step-{index + 1}"))
        if URL_CREDENTIALS.search(step) or AUTH_HEADER.search(step):
            findings.append(_config_finding("IMG-BUILD-URL-CREDENTIAL", msg("scanning.image.rules.build_url_credential.title"), "critical",
                msg("scanning.image.rules.build_url_credential.reason", step=index + 1),
                msg("scanning.image.rules.build_url_credential.remediation"),
                798, asset, f"history-url:{index}", path=f"image-history/step-{index + 1}"))
        if re.match(r"(?i)\s*ADD\s+(file:)?\s*https?://", step) or re.search(r"(?i)/bin/sh -c #\(nop\) ADD https?://", step):
            findings.append(_config_finding("IMG-ADD-URL", msg("scanning.image.rules.add_url.title"), "medium",
                msg("scanning.image.rules.add_url.reason", step=index + 1), msg("scanning.image.rules.add_url.remediation"),
                494, asset, f"add:{index}"))
    if "22/tcp" in (config.get("ExposedPorts") or {}):
        findings.append(_config_finding("IMG-SSH", msg("scanning.image.rules.ssh.title"), "medium",
            msg("scanning.image.rules.ssh.reason"), msg("scanning.image.rules.ssh.remediation"), 1188, asset, "ssh"))
    if not config.get("Healthcheck"):
        findings.append(_config_finding("IMG-NO-HEALTHCHECK", msg("scanning.image.rules.no_healthcheck.title"), "low",
            msg("scanning.image.rules.no_healthcheck.reason"), msg("scanning.image.rules.no_healthcheck.remediation"),
            1188, asset, "healthcheck"))
    if image.get("tag") == "latest" and not image.get("digest"):
        findings.append(_config_finding("IMG-LATEST", msg("scanning.image.rules.latest.title"), "info",
            msg("scanning.image.rules.latest.reason"), msg("scanning.image.rules.latest.remediation"), 1357, asset, "latest"))
    created = str(config_block.get("created") or "")
    try:
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(created.replace("Z", "+00:00"))).days if created else None
    except ValueError:
        age = None
    if age is not None and age > 365:
        findings.append(_config_finding("IMG-STALE", msg("scanning.image.rules.stale.title", months=age // 30), "low",
            msg("scanning.image.rules.stale.reason"), msg("scanning.image.rules.stale.remediation"), 1104, asset, "stale"))
    return findings


def merge_packages(trivy: list[dict], grype: list[dict]) -> tuple[list[dict], dict]:
    """Merges both engines' package advisories. Same package and version with a shared identifier = same advisory."""
    index: dict[tuple[str, str], list[dict]] = {}
    for finding in trivy:
        package = finding.get("package") or {}
        index.setdefault((package.get("name", "").lower(), package.get("version", "")), []).append(finding)
    extra, agreed = [], 0
    for finding in grype:
        package = finding["package"]
        aliases = set(finding["advisory"]["aliases"])
        twin = next((item for item in index.get((package["name"].lower(), package["version"]), [])
                     if aliases & ({item["rule_id"], *item.get("cve", []), *item.get("ghsa", [])})), None)
        if twin is not None:
            if "grype" not in twin.setdefault("also_detected_by", []):
                twin["also_detected_by"].append("grype")
                twin["confidence"] = min(10, twin["confidence"] + 1)
                agreed += 1
            if not twin.get("source") and finding.get("source"):
                twin["source"] = finding["source"]
            if not (twin.get("package") or {}).get("fixed_version") and package.get("fixed_version"):
                twin["package"]["fixed_version"] = package["fixed_version"]
        else:
            extra.append(finding)
    merged = trivy + extra
    return merged, {"trivy": len(trivy), "grype": len(grype), "both": agreed, "only_trivy": len(trivy) - agreed,
                    "only_grype": len(extra)}


def _finish_package(finding: dict) -> dict:
    """Stable fingerprint for images (canonical CVE + ecosystem family) and remediation in image terms."""
    package = finding.get("package") or {}
    aliases = {finding["rule_id"], *finding.get("cve", []), *finding.get("ghsa", [])}
    kind = family(package.get("ecosystem", ""))
    fixed = package.get("fixed_version")
    name = package.get("name")
    if kind == "os":
        remediation = (msg("scanning.image.remediation.os_upgrade", package=name, fixed=fixed) if fixed
                       else msg("scanning.image.remediation.os_no_fix", package=name))
    else:
        remediation = (msg("scanning.image.remediation.app_upgrade", package=name, fixed=fixed) if fixed
                       else msg("scanning.image.remediation.app_no_fix", package=name))
    return _with_fingerprint({**finding, "remediation": remediation}, aliases, finding["rule_id"], package.get("ecosystem", ""),
                             package.get("name", ""), package.get("version", ""))


# --- full scan ----------------------------------------------------------------------------

def scan_image(image: dict, *, data_dir: Path, context: str = "", progress=None) -> RunRecord:
    from tamandua.modules.intel.advisories import load_feeds

    def report(level: str, message) -> None:
        if progress:
            progress(level, message)

    # Checked again here, when the engines are about to connect, and pinned: the request was checked minutes ago.
    hosts = check_registry_address(image["registry"])
    feeds = load_feeds(data_dir)
    credentials = credentials_for(image["registry"])
    report("info", msg("scanning.image.progress.reading_credentials" if credentials else "scanning.image.progress.reading_public",
                       reference=image["reference"]))
    trivy, metadata = run_trivy_image(image["reference"], data_dir / "trivy-cache", feeds, credentials, hosts)
    report("ok" if trivy["status"] == "completed" else "warn", msg("scanning.progress.engine", engine="Trivy", detail=trivy["detail"]))
    report("info", msg("scanning.image.progress.grype"))
    grype = run_grype_image(image["reference"], data_dir / "grype-cache", feeds, credentials, image["registry"], hosts)
    report("ok" if grype["status"] == "completed" else "warn", msg("scanning.progress.engine", engine="Grype", detail=grype["detail"]))

    if metadata:
        report("info", msg("scanning.image.progress.checkov"))
        checkov = run_checkov_image(metadata, image, data_dir / "tmp")
    else:
        checkov = _result("checkov", "not_tested", msg("scanning.image.checkov_without_config"))
    report("ok" if checkov["status"] == "completed" else "warn", msg("scanning.progress.engine", engine="Checkov", detail=checkov["detail"]))

    packages, agreement = merge_packages([item for item in trivy["findings"] if item["scanner"] == "sca"], grype["findings"])
    # Configuration: our own rules lead; Trivy and Checkov only add what those rules don't cover.
    configuration, joined_rules = merge_image(config_findings(metadata, image) if metadata else [],
                                        [item for item in trivy["findings"] if item["scanner"] == "iac"], checkov["findings"])
    findings = ([_finish_package(item) for item in packages] + [item for item in trivy["findings"] if item["scanner"] == "secrets"]
                + configuration)
    unique, seen = [], set()
    for finding in findings:
        if finding["fingerprint"] not in seen:
            seen.add(finding["fingerprint"])
            unique.append(finding)
    findings = unique

    digests = [item for item in metadata.get("RepoDigests") or [] if isinstance(item, str)]
    resolved = next((item.rsplit("@", 1)[1] for item in digests if "@" in item), image.get("digest"))
    os_info = metadata.get("OS") or {}
    config = (metadata.get("ImageConfig") or {}).get("config") or {}
    image_meta = {**image, "resolved_digest": resolved, "os": " ".join(str(os_info.get(key) or "") for key in ("Family", "Name")).strip() or None,
                  "user": config.get("User") or "root", "architecture": (metadata.get("ImageConfig") or {}).get("architecture")}
    engines_ok = [tool for tool in (trivy, grype) if tool["status"] == "completed"]
    sca_count = sum(1 for item in findings if item["scanner"] == "sca")
    iac_count = sum(1 for item in findings if item["scanner"] == "iac")
    secret_count = sum(1 for item in findings if item["scanner"] == "secrets")
    where = " · ".join([image["reference"], *([f"{resolved[:19]}…"] if resolved else []), *([image_meta["os"]] if image_meta["os"] else [])])
    steps = [
        {"id": "image", "name": msg("scanning.image.steps.image.name"), "status": "completed" if trivy["status"] == "completed" else trivy["status"],
         "detail": msg("scanning.image.steps.image.detail", where=where, user=image_meta["user"])},
        {"id": "sca", "name": msg("scanning.image.steps.sca.name"),
         "status": "partial" if len(engines_ok) == 2 else ("inconclusive" if not engines_ok else "partial"),
         "detail": msg("scanning.image.steps.sca.detail", advisories=sca_count, both=agreement["both"], only_trivy=agreement["only_trivy"],
                       only_grype=agreement["only_grype"])
                   if len(engines_ok) == 2 else msg("scanning.image.steps.sca.single_engine", advisories=sca_count,
                                                    trivy=trivy["detail"], grype=grype["detail"])},
        {"id": "config", "name": msg("scanning.image.steps.config.name"),
         "status": "completed" if trivy["status"] == "completed" else "not_tested",
         "detail": msg("scanning.image.steps.config.detail_checkov", problems=iac_count, failures=len(checkov["findings"]), joined=joined_rules)
                   if checkov["status"] == "completed" else msg("scanning.image.steps.config.detail", problems=iac_count, checkov=checkov["detail"]),
         "tool": {"name": "checkov", "version": checkov["version"], "image": checkov["image"], "duration_s": checkov["duration_s"]}},
        {"id": "secrets", "name": msg("scanning.image.steps.secrets.name"), "status": "completed" if trivy["status"] == "completed" else "not_tested",
         "detail": msg("scanning.image.steps.secrets.detail", secrets=secret_count)},
        {"id": "review", "name": msg("scanning.steps.review"), "status": "pending", "detail": msg("scanning.image.steps.review.detail")},
    ]
    sca_status = "partial" if engines_ok else "inconclusive"
    coverage = owasp_coverage(findings, sast_ran=False, sca_status=sca_status, iac_ran=trivy["status"] == "completed",
                              iac_files=1, secrets_ran=trivy["status"] == "completed", engines=bool(engines_ok))
    severities = {level: sum(1 for item in findings if item["severity"] == level) for level in ("critical", "high", "medium", "low", "info")}
    priorities = {action: sum(1 for item in findings if (item.get("priority") or {}).get("action") == action) for action in ("act", "attend", "track")}
    tools = [trivy, grype, checkov]
    return {"type": "image_scan", "status": "completed" if trivy["status"] == "completed" and grype["status"] == "completed" else "incomplete",
            "source": {"id": image["asset"], "uid": None, "name": image["name"], "provider": "registry", "image": image_meta},
            "target": image["reference"], "variant": "image", "context": " ".join(str(context).split())[:400],
            "steps": steps, "findings": findings, "owasp_coverage": coverage,
            "dependencies": trivy.get("packages") or [],
            "system_packages": trivy.get("system_packages") or [],  # only for the SBOM
            "summary": {"files": 0, "dependencies": 0, "candidates": len(findings), "sast": 0, "secrets": secret_count,
                        "sca": sca_count, "iac": iac_count, "severities": severities, "priorities": priorities,
                        "kev": sum(1 for item in findings if item.get("kev")),
                        "fixable": sum(1 for item in findings if (item.get("package") or {}).get("fixed_version")),
                        "agreement": agreement,
                        "tools": [{"name": tool["tool"], "version": tool["version"], "status": tool["status"]} for tool in tools],
                        "planned": 3, "executed": sum(1 for step in steps[1:4] if step["status"] in ("completed", "partial")), "confirmed": 0},
            "limitations": [msg("scanning.image.limitations.read_only"), msg("scanning.image.limitations.no_source"),
                            msg("scanning.image.limitations.backports"), msg("scanning.image.limitations.system_package")],
            "scanned_at": datetime.now(timezone.utc).isoformat()}
