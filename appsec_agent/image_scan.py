"""Análisis de imágenes de contenedor directamente desde su registro, sin ejecutarlas.

Qué se revisa de una imagen (`registry/repositorio:etiqueta` o `@sha256:…`):

* **Paquetes** del sistema operativo y de las aplicaciones empaquetadas, con dos motores:
  Trivy y Grype. Coinciden en la gran mayoría de CVE, pero discrepan en los paquetes con
  parches retroportados de las distribuciones; lo que ven ambos se marca como tal.
* **Secretos** dentro de las capas y en la **configuración de la imagen**: variables de
  entorno (`ENV`) e historial de construcción (`ARG` usados en `RUN`), que es donde acaban
  las credenciales que se pasan para descargar dependencias privadas.
* **Configuración**: usuario root, falta de `HEALTHCHECK` y demás reglas propias sobre la
  configuración, más Checkov sobre un Dockerfile reconstruido del historial (descargas sin
  verificar TLS, `sudo`, gestores de paquetes sin firma…). Sin duplicar lo que ya ven las
  reglas propias (`config_scanners.merge_image`).

La imagen nunca se ejecuta ni se construye: los motores leen el manifiesto y las capas del
registro. Las credenciales de registros privados se guardan cifradas (`vault`) y llegan a
los motores por variable de entorno, no por la línea de comandos.
"""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from . import data_sources, logging_setup
from .advisories import cvss3_base_score, fingerprint as sca_fingerprint, prioritize, severity_from_score
from .coverage import owasp_coverage
from .config_scanners import merge_image, run_checkov_image
from .scanners import _pick_fixed, _result, _run, docker_available, parse_trivy, writable_cache

_log = logging_setup.get("images")
VAULT_NAME = "registries"
DOCKER_HUB = "docker.io"
_COMPONENT = r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*"
REFERENCE = re.compile(rf"(?:(?P<registry>(?:[a-zA-Z0-9-]+\.)+[a-zA-Z0-9-]+(?::\d{{1,5}})?|localhost(?::\d{{1,5}})?|[a-zA-Z0-9-]+:\d{{1,5}})/)?"
                       rf"(?P<repository>{_COMPONENT}(?:/{_COMPONENT}){{0,5}})"
                       r"(?::(?P<tag>[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}))?"
                       r"(?:@(?P<digest>sha256:[0-9a-f]{64}))?")
HOST = re.compile(r"(?:[a-z0-9-]+\.)+[a-z0-9-]+(?::\d{1,5})?|localhost(?::\d{1,5})?|[a-z0-9-]+:\d{1,5}")

# Ecosistema común a los dos motores, para reconocer el mismo paquete aunque cada uno lo nombre distinto.
FAMILY = {"node-pkg": "npm", "npm": "npm", "yarn": "npm", "pnpm": "npm", "python-pkg": "pypi", "pip": "pypi", "pipenv": "pypi",
          "poetry": "pypi", "python": "pypi", "gobinary": "go", "gomod": "go", "go-module": "go", "jar": "maven", "pom": "maven",
          "gradle": "maven", "java-archive": "maven", "gemspec": "rubygems", "bundler": "rubygems", "gem": "rubygems",
          "cargo": "cargo", "rust-binary": "cargo", "rust-crate": "cargo", "composer": "composer", "php-composer": "composer",
          "nuget": "nuget", "dotnet-core": "nuget", "dotnet": "nuget", "deb": "os", "apk": "os", "rpm": "os"}
OS_FAMILIES = {"debian", "ubuntu", "alpine", "redhat", "centos", "rocky", "alma", "amazon", "oracle", "photon", "suse",
               "opensuse", "opensuse.leap", "sles", "wolfi", "chainguard", "mariner", "azurelinux", "fedora", "bitnami"}
GRYPE_SEVERITY = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "negligible": "low"}


class ImageError(ValueError):
    pass


# --- referencias --------------------------------------------------------------------------

def parse_reference(text: str) -> dict:
    """Normaliza una referencia de imagen. Docker Hub se escribe completo (`docker.io/library/nginx`)."""
    raw = str(text or "").strip()
    match = REFERENCE.fullmatch(raw) if 3 <= len(raw) <= 300 else None
    if not match:
        raise ImageError("Referencia de imagen inválida: usa registro/repositorio:etiqueta, p. ej. ghcr.io/acme/api:1.4")
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


def check_registry_address(registry: str) -> None:
    """El motor se conectará a ese registro: si resuelve a una red interna, se exige permiso expreso.

    Evita que el formulario sirva para que el servidor hable con servicios internos (SSRF).
    Para registros propios en la red local: APPSEC_AGENT_ALLOW_PRIVATE_REGISTRIES=1.
    """
    if os.environ.get("APPSEC_AGENT_ALLOW_PRIVATE_REGISTRIES", "").strip() == "1":
        return
    import ipaddress
    host = _host_only(registry)
    try:
        addresses = {info[4][0] for info in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)}
    except OSError as exc:
        raise ImageError(f"No se pudo resolver el registro {registry}") from exc
    if not addresses or not all(ipaddress.ip_address(address.split("%")[0]).is_global for address in addresses):
        raise ImageError(f"El registro {registry} resuelve a una dirección privada. Si es un registro propio de tu red, "
                         "arranca el servidor con APPSEC_AGENT_ALLOW_PRIVATE_REGISTRIES=1.")


# --- credenciales de registros ------------------------------------------------------------

def _stored() -> dict:
    from .vault import VaultError, get
    try:
        data = get(VAULT_NAME)
    except VaultError:
        return {}
    return data if isinstance(data, dict) else {}


def registries() -> list[dict]:
    """Registros con credenciales guardadas. Nunca devuelve el token."""
    return [{"registry": host, "username": entry.get("username"), "last4": (entry.get("token") or "")[-4:],
             "saved_at": entry.get("saved_at"), "saved_by": entry.get("saved_by")}
            for host, entry in sorted(_stored().items()) if isinstance(entry, dict)]


def save_registry(registry: str, username: str, token: str, *, by: str) -> list[dict]:
    from .vault import put
    host = str(registry or "").strip().lower()
    if host in ("index.docker.io", "registry-1.docker.io", "hub.docker.com"):
        host = DOCKER_HUB
    if not HOST.fullmatch(host) or len(host) > 200:
        raise ImageError("Registro inválido: solo el host, p. ej. ghcr.io o 123456789.dkr.ecr.us-east-1.amazonaws.com")
    if not isinstance(username, str) or not 1 <= len(username.strip()) <= 200 or any(ord(char) < 33 for char in username.strip()):
        raise ImageError("Usuario inválido")
    if not isinstance(token, str) or not 8 <= len(token) <= 4096 or any(ord(char) < 33 or ord(char) > 126 for char in token):
        raise ImageError("Token inválido: pega el token de acceso de solo lectura del registro")
    data = _stored()
    data[host] = {"username": username.strip(), "token": token,
                  "saved_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "saved_by": by}
    put(VAULT_NAME, data)
    _log.info("registry_saved", extra={"user": by, "reason": host})
    return registries()


def forget_registry(registry: str) -> list[dict]:
    from .vault import delete, put
    data = _stored()
    if data.pop(str(registry or "").strip().lower(), None) is not None:
        put(VAULT_NAME, data) if data else delete(VAULT_NAME)
    return registries()


def credentials_for(registry: str) -> dict | None:
    entry = _stored().get(registry)
    return entry if isinstance(entry, dict) and entry.get("token") else None


# --- motores ------------------------------------------------------------------------------

def _canonical_id(identifiers: set[str], fallback: str) -> str:
    cves = sorted(item for item in identifiers if item.startswith("CVE-"))
    return cves[0] if cves else fallback


def _family(ecosystem: str) -> str:
    value = (ecosystem or "").lower()
    return "os" if value in OS_FAMILIES else FAMILY.get(value, value or "unknown")


def run_trivy_image(reference: str, cache_dir: Path, feeds: dict, credentials: dict | None) -> tuple[dict, dict]:
    started = time.time()
    if not docker_available():
        return _result("trivy", "not_tested", "Docker no disponible: la imagen no se analizó con Trivy."), {}
    cache_dir = writable_cache(cache_dir)
    secrets = {"TRIVY_USERNAME": credentials["username"], "TRIVY_PASSWORD": credentials["token"]} if credentials else None
    try:
        completed = _run("trivy", ["image", "--image-src", "remote", "--scanners", "vuln,secret",
                                   "--image-config-scanners", "misconfig,secret", "--cache-dir", "/cache", "--format", "json", "--quiet",
                                   "--timeout", "14m", reference], None, network=True, secret_env=secrets,
                         mounts=["-v", f"{_host(cache_dir)}:/cache"])
        if completed.returncode != 0 and not completed.stdout.strip():
            return _result("trivy", "inconclusive", _registry_error(completed.stderr, credentials), started=started), {}
        payload = json.loads(completed.stdout or "{}")
    except subprocess.TimeoutExpired:
        return _result("trivy", "inconclusive", "Trivy superó el tiempo máximo con esta imagen.", started=started), {}
    except (OSError, ValueError):
        return _result("trivy", "inconclusive", "Trivy no devolvió una salida legible.", started=started), {}
    findings = parse_trivy(payload, feeds)
    metadata = payload.get("Metadata") or {}
    counts = {kind: sum(1 for item in findings if item["scanner"] == kind) for kind in ("sca", "iac", "secrets")}
    detail = (f"{counts['sca']} avisos en paquetes, {counts['iac']} problemas de configuración de la imagen y "
              f"{counts['secrets']} secretos en capas, variables de entorno o historial.")
    return _result("trivy", "completed", detail, findings, started), metadata


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
    location = next((item.get("path") for item in artifact.get("locations") or [] if item.get("path")), "") or "imagen"
    ecosystem = str(artifact.get("type") or "unknown")
    cwe = sorted({int(found.group(1)) for item in vulnerability.get("cwes") or [] if (found := re.fullmatch(r"CWE-(\d+)", str(item.get("cwe"))))})
    references = [url for url in vulnerability.get("urls") or [] if isinstance(url, str) and url.startswith("https://")][:8]
    digest = sca_fingerprint("sca", _canonical_id(aliases, identifier), _family(ecosystem), name, installed)
    return {"finding_id": digest[:16], "fingerprint": digest, "scanner": "sca", "tool": "grype", "rule_id": identifier,
            "title": f"{name} {installed}: {summary.splitlines()[0]}"[:200], "path": location.lstrip("/"), "line": 1,
            "severity": severity, "confidence": 8 if score is not None else 6, "verdict": "candidate", "cwe": cwe,
            "owasp": ["A03:2025"], "cve": cves, "ghsa": ghsas,
            "package": {"ecosystem": ecosystem, "name": name, "version": installed, "fixed_version": fixed, "introduced": None},
            "advisory": {"id": identifier, "aliases": sorted(aliases), "summary": summary[:300], "details": summary[:2000],
                         "cvss_vector": vector, "cvss_score": score, "published": None, "modified": None, "references": references},
            "kev": kev, "epss": {"score": epss[0], "percentile": epss[1]} if epss else None,
            "source": data_sources.from_grype(vulnerability),
            "priority": prioritize(severity, score, kev, epss, fixed), "reason": summary[:300], "remediation": ""}


def run_grype_image(reference: str, cache_dir: Path, feeds: dict, credentials: dict | None, registry: str) -> dict:
    started = time.time()
    if not docker_available():
        return _result("grype", "not_tested", "Docker no disponible: la imagen no se analizó con Grype.")
    cache_dir = writable_cache(cache_dir)
    (cache_dir / "tmp").mkdir(exist_ok=True)
    secrets = ({"GRYPE_REGISTRY_AUTH_AUTHORITY": _host_only(registry) if registry != DOCKER_HUB else "index.docker.io",
                "GRYPE_REGISTRY_AUTH_USERNAME": credentials["username"], "GRYPE_REGISTRY_AUTH_PASSWORD": credentials["token"]}
               if credentials else None)
    try:
        completed = _run("grype", [f"registry:{reference}", "-o", "json", "-q"], None, network=True, secret_env=secrets,
                         # La imagen de Grype no trae un /tmp escribible para usuarios no root: sus temporales
                         # (capas de la imagen analizada) van a disco, dentro de su caché.
                         env={"GRYPE_DB_CACHE_DIR": "/cache", "GRYPE_CHECK_FOR_APP_UPDATE": "false", "TMPDIR": "/cache/tmp", "HOME": "/cache/tmp"},
                         mounts=["-v", f"{_host(cache_dir)}:/cache"])
        if completed.returncode != 0 and not completed.stdout.strip():
            return _result("grype", "inconclusive", _registry_error(completed.stderr, credentials), started=started)
        payload = json.loads(completed.stdout or "{}")
    except subprocess.TimeoutExpired:
        return _result("grype", "inconclusive", "Grype superó el tiempo máximo con esta imagen.", started=started)
    except (OSError, ValueError):
        return _result("grype", "inconclusive", "Grype no devolvió una salida legible.", started=started)
    findings = [_grype_finding(match, feeds) for match in payload.get("matches") or []]
    return _result("grype", "completed", f"{len(findings)} avisos en paquetes.", findings, started)


def _host(path: Path) -> str:
    from .scanners import host_path
    return host_path(path)


def _registry_error(stderr: str, credentials: dict | None) -> str:
    text = (stderr or "").lower()
    if any(marker in text for marker in ("unauthorized", "denied", "401", "403", "authentication required")):
        return ("El registro rechazó el acceso: revisa que la imagen exista y que las credenciales guardadas para ese registro "
                "tengan permiso de lectura." if credentials else
                "El registro pide credenciales: guárdalas en Integraciones → Registros de contenedores.")
    if "manifest unknown" in text or "not found" in text or "name unknown" in text:
        return "El registro no tiene esa imagen o esa etiqueta."
    return "No se pudo leer la imagen del registro."


# --- configuración de la imagen -------------------------------------------------------------

SECRET_NAME = re.compile(r"(?i)(pass(word|wd)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|auth|pat)$|"
                         r"(^|_)(npm_token|github_token|gh_token|pip_index_url|aws_secret_access_key|database_url|dsn)$")
HISTORY_SECRET = re.compile(r"(?i)\b([A-Z0-9_]*(?:TOKEN|PASSWORD|PASSWD|SECRET|API_KEY|ACCESS_KEY|PRIVATE_KEY)[A-Z0-9_]*)=(?![$'\"]?\$)['\"]?([^\s'\"]{6,})")
URL_CREDENTIALS = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://([^/\s:@]+):([^/\s@]{3,})@")
AUTH_HEADER = re.compile(r"(?i)authorization:\s*(bearer|basic|token)\s+(?!\$)[A-Za-z0-9._~+/=-]{8,}")


def _config_finding(rule: str, title: str, severity: str, reason: str, remediation: str, cwe: int, asset: str, key: str,
                    path: str = "configuración de la imagen") -> dict:
    from .scanners import _base, _stable
    finding = _base("iac" if cwe != 798 else "secrets", rule, title, path, 1, severity, tool="appsec-agent",
                    reason=reason, remediation=remediation, cwe=[cwe], owasp="A02:2025" if cwe != 798 else "A04:2025",
                    confidence=8, digest=_stable("image-config", rule, asset, key))
    return finding


def config_findings(metadata: dict, image: dict) -> list[dict]:
    """Reglas propias sobre la configuración y el historial de la imagen. Ningún valor secreto se copia."""
    config_block = metadata.get("ImageConfig") or {}
    config = config_block.get("config") or {}
    history = [str(item.get("created_by") or "") for item in config_block.get("history") or []]
    asset = image["asset"]
    findings = []
    user = str(config.get("User") or "").strip()
    if user in ("", "root", "0", "0:0", "root:root"):
        findings.append(_config_finding("IMG-ROOT", "La imagen se ejecuta como root", "medium",
            "No declara USER (o declara root): un fallo en la aplicación da control de root dentro del contenedor y facilita escapar de él.",
            "Añade un usuario sin privilegios en el Dockerfile (RUN adduser … && USER app) o ejecútala con --user.", 250, asset, "user"))
    for entry in config.get("Env") or []:
        name, _, value = str(entry).partition("=")
        if value.strip() and not value.startswith("$") and SECRET_NAME.search(name):
            findings.append(_config_finding("IMG-ENV-SECRET", f"Posible credencial en la variable de entorno {name}", "high",
                f"La imagen define {name} con un valor fijo (redactado): cualquiera que pueda descargar la imagen puede leerlo con docker inspect.",
                "Rota la credencial. No la pongas en ENV: pásala en tiempo de ejecución (secreto de Docker/Kubernetes o variable del orquestador) "
                "o, si solo hace falta al construir, con RUN --mount=type=secret de BuildKit.", 798, asset, f"env:{name}", path=f"ENV {name}"))
    for index, step in enumerate(history):
        for match in HISTORY_SECRET.finditer(step):
            findings.append(_config_finding("IMG-BUILD-SECRET", f"Credencial en el historial de construcción ({match.group(1)})", "critical",
                f"El paso {index + 1} del historial contiene {match.group(1)} con un valor (redactado). Los ARG y las variables de un RUN quedan "
                "guardados en la imagen y se leen con docker history.",
                "Rota la credencial ya. Reconstruye usando secretos de BuildKit (RUN --mount=type=secret,id=npm …) en lugar de ARG o ENV, "
                "y borra las etiquetas publicadas con la credencial.", 798, asset, f"history:{index}:{match.group(1)}", path=f"historial, paso {index + 1}"))
        if URL_CREDENTIALS.search(step) or AUTH_HEADER.search(step):
            findings.append(_config_finding("IMG-BUILD-URL-CREDENTIAL", "Credencial en una URL o cabecera del historial de construcción", "critical",
                f"El paso {index + 1} del historial usa una URL con usuario y contraseña o una cabecera Authorization con valor fijo (redactado).",
                "Rota la credencial y usa secretos de BuildKit o un fichero .netrc montado como secreto durante la construcción.",
                798, asset, f"history-url:{index}", path=f"historial, paso {index + 1}"))
        if re.match(r"(?i)\s*ADD\s+(file:)?\s*https?://", step) or re.search(r"(?i)/bin/sh -c #\(nop\) ADD https?://", step):
            findings.append(_config_finding("IMG-ADD-URL", "ADD descarga ficheros desde una URL", "medium",
                f"El paso {index + 1} usa ADD con una URL: el contenido no se verifica y puede cambiar entre construcciones.",
                "Descarga con curl y comprueba el SHA-256 (o usa ADD --checksum=sha256:… con BuildKit).", 494, asset, f"add:{index}"))
    if "22/tcp" in (config.get("ExposedPorts") or {}):
        findings.append(_config_finding("IMG-SSH", "La imagen expone SSH (22/tcp)", "medium",
            "Un servidor SSH en un contenedor amplía la superficie de ataque y suele indicar credenciales dentro de la imagen.",
            "Quita el servidor SSH; para depurar usa docker exec o kubectl exec.", 1188, asset, "ssh"))
    if not config.get("Healthcheck"):
        findings.append(_config_finding("IMG-NO-HEALTHCHECK", "La imagen no define HEALTHCHECK", "low",
            "Sin HEALTHCHECK, el orquestador no detecta un proceso colgado o degradado.",
            "Añade HEALTHCHECK en el Dockerfile o define la sonda en el orquestador.", 1188, asset, "healthcheck"))
    if image.get("tag") == "latest" and not image.get("digest"):
        findings.append(_config_finding("IMG-LATEST", "Se analiza la etiqueta latest", "info",
            "latest cambia sin aviso: lo que se analiza hoy puede no ser lo que se despliega mañana.",
            "Despliega y analiza etiquetas inmutables (versión o @sha256:…).", 1357, asset, "latest"))
    created = str(config_block.get("created") or "")
    try:
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(created.replace("Z", "+00:00"))).days if created else None
    except ValueError:
        age = None
    if age is not None and age > 365:
        findings.append(_config_finding("IMG-STALE", f"La imagen se construyó hace {age // 30} meses", "low",
            "Una imagen antigua acumula parches de seguridad sin aplicar en su base.",
            "Reconstruye la imagen periódicamente (p. ej. cada semana) para recoger los parches de la base.", 1104, asset, "stale"))
    return findings


def merge_packages(trivy: list[dict], grype: list[dict]) -> tuple[list[dict], dict]:
    """Une los avisos de paquetes de los dos motores. Mismo paquete y versión con algún identificador en común = el mismo aviso."""
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
    """Huella estable para imágenes (CVE canónico + familia de ecosistema) y remediación en términos de imagen."""
    package = finding.get("package") or {}
    aliases = {finding["rule_id"], *finding.get("cve", []), *finding.get("ghsa", [])}
    family = _family(package.get("ecosystem", ""))
    digest = sca_fingerprint("sca", _canonical_id(aliases, finding["rule_id"]), family, package.get("name", ""), package.get("version", ""))
    fixed = package.get("fixed_version")
    if family == "os":
        remediation = (f"Reconstruye la imagen sobre una base actualizada o actualiza {package.get('name')} a {fixed} en el Dockerfile "
                       "(apt/apk/dnf upgrade)." if fixed else
                       f"La distribución no publica aún una versión corregida de {package.get('name')}. Valora otra imagen base "
                       "(slim, distroless) o si el paquete se usa de verdad.")
    else:
        remediation = (f"Actualiza {package.get('name')} a {fixed} en la aplicación empaquetada y reconstruye la imagen."
                       if fixed else f"No hay versión corregida de {package.get('name')}: evalúa sustituirla o mitigar.")
    return {**finding, "fingerprint": digest, "finding_id": digest[:16], "remediation": remediation}


# --- análisis completo --------------------------------------------------------------------

def scan_image(image: dict, *, data_dir: Path, context: str = "", progress=None) -> dict:
    from .advisories import load_feeds

    def report(level: str, message: str) -> None:
        if progress:
            progress(level, message)

    feeds = load_feeds(data_dir)
    credentials = credentials_for(image["registry"])
    report("info", f"Leyendo {image['reference']} desde el registro"
                   + (" con las credenciales guardadas" if credentials else " sin credenciales (imagen pública)") + "…")
    trivy, metadata = run_trivy_image(image["reference"], data_dir / "trivy-cache", feeds, credentials)
    report("ok" if trivy["status"] == "completed" else "warn", f"Trivy: {trivy['detail']}")
    report("info", "Segunda opinión sobre los paquetes con Grype…")
    grype = run_grype_image(image["reference"], data_dir / "grype-cache", feeds, credentials, image["registry"])
    report("ok" if grype["status"] == "completed" else "warn", f"Grype: {grype['detail']}")

    if metadata:
        report("info", "Checkov sobre el Dockerfile reconstruido del historial de la imagen…")
        checkov = run_checkov_image(metadata, image, data_dir / "tmp")
    else:
        checkov = _result("checkov", "not_tested", "Sin la configuración de la imagen (Trivy no pudo leerla), Checkov no tiene qué revisar.")
    report("ok" if checkov["status"] == "completed" else "warn", f"Checkov: {checkov['detail']}")

    packages, agreement = merge_packages([item for item in trivy["findings"] if item["scanner"] == "sca"], grype["findings"])
    # Configuración: las reglas propias mandan; Trivy y Checkov solo suman lo que ellas no cubren.
    configuration, joined = merge_image(config_findings(metadata, image) if metadata else [],
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
    steps = [
        {"id": "image", "name": "Imagen", "status": "completed" if trivy["status"] == "completed" else trivy["status"],
         "detail": f"{image['reference']}" + (f" · {resolved[:19]}…" if resolved else "") + (f" · {image_meta['os']}" if image_meta["os"] else "")
                   + f" · usuario {image_meta['user']}. Leída del registro, sin ejecutarla."},
        {"id": "sca", "name": "Paquetes · Trivy + Grype",
         "status": "partial" if len(engines_ok) == 2 else ("inconclusive" if not engines_ok else "partial"),
         "detail": (f"{sca_count} avisos: {agreement['both']} los ven ambos motores, {agreement['only_trivy']} solo Trivy y "
                    f"{agreement['only_grype']} solo Grype. Prioridad con CVSS, KEV y EPSS.")
                   if len(engines_ok) == 2 else f"{sca_count} avisos con un solo motor: " + " · ".join(f"{tool['name']}: {tool['detail']}" for tool in (trivy, grype))},
        {"id": "config", "name": "Configuración de la imagen · reglas propias + Checkov",
         "status": "completed" if trivy["status"] == "completed" else "not_tested",
         "detail": f"{iac_count} problemas (usuario root, HEALTHCHECK, instrucciones inseguras) en la configuración y el historial."
                   + (f" Checkov revisó el Dockerfile reconstruido: {len(checkov['findings'])} fallos, {joined} ya cubiertos por otra regla."
                      if checkov["status"] == "completed" else f" {checkov['detail']}"),
         "tool": {"name": "checkov", "version": checkov["version"], "image": checkov["image"], "duration_s": checkov["duration_s"]}},
        {"id": "secrets", "name": "Secretos en capas, ENV e historial", "status": "completed" if trivy["status"] == "completed" else "not_tested",
         "detail": f"{secret_count} secretos; valores redactados. Incluye variables de entorno y argumentos de construcción que quedaron en la imagen."},
        {"id": "review", "name": "Triage humano", "status": "pending", "detail": "Confirma que los paquetes se usan y prioriza por exposición de la imagen."},
    ]
    sca_status = "partial" if engines_ok else "inconclusive"
    coverage = owasp_coverage(findings, sast_ran=False, sca_status=sca_status, iac_ran=trivy["status"] == "completed",
                              iac_files=1, secrets_ran=trivy["status"] == "completed", engines=bool(engines_ok))
    severities = {level: sum(1 for item in findings if item["severity"] == level) for level in ("critical", "high", "medium", "low", "info")}
    priorities = {action: sum(1 for item in findings if (item.get("priority") or {}).get("action") == action) for action in ("act", "attend", "track")}
    tools = [trivy, grype, checkov]
    return {"type": "image_scan", "status": "completed" if trivy["status"] == "completed" and grype["status"] == "completed" else "incomplete",
            "source": {"id": image["asset"], "uid": None, "name": image["name"], "provider": "registry", "image": image_meta},
            "fixture": image["reference"], "variant": "image", "context": " ".join(str(context).split())[:400],
            "steps": steps, "findings": findings, "owasp_coverage": coverage,
            "summary": {"files": 0, "dependencies": 0, "candidates": len(findings), "sast": 0, "secrets": secret_count,
                        "sca": sca_count, "iac": iac_count, "severities": severities, "priorities": priorities,
                        "kev": sum(1 for item in findings if item.get("kev")),
                        "fixable": sum(1 for item in findings if (item.get("package") or {}).get("fixed_version")),
                        "agreement": agreement,
                        "tools": [{"name": tool["tool"], "version": tool["version"], "status": tool["status"]} for tool in tools],
                        "planned": 3, "executed": sum(1 for step in steps[1:4] if step["status"] in ("completed", "partial")), "confirmed": 0},
            "limitations": ["La imagen se leyó del registro: no se ejecutó ni se construyó",
                            "No se analizó el código fuente que generó la imagen (para eso, analiza su repositorio)",
                            "Los motores pueden discrepar en paquetes con parches retroportados por la distribución",
                            "Un aviso en un paquete del sistema no prueba que la aplicación lo use"],
            "scanned_at": datetime.now(timezone.utc).isoformat()}
