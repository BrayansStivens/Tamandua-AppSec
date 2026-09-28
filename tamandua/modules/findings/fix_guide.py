"""Cómo corregir cada hallazgo, en concreto: el comando del gestor de paquetes, el ejemplo de código, los pasos.

- Dependencias: el gestor sale del archivo donde se declaró (package-lock.json → npm, poetry.lock → Poetry…)
  y la corrección depende de si la dependencia es directa o transitiva (en una transitiva se fuerza con un
  override). La versión es la que cierra todos los avisos de ese paquete, no solo el del hallazgo.
- Código: un ejemplo antes/después de la regla (fix_examples), en su lenguaje.
- Secretos: rotar primero; borrar del código no basta, ya está en el historial.
- Paquetes del sistema de una imagen: en el Dockerfile.

Todo lo que se interpola viene del repositorio analizado (nombres de paquete, rutas): se usa como texto y
quien lo pinta lo escapa. Los nombres raros (espacios, comillas) no generan comando: solo pasos.
"""

from __future__ import annotations

import posixpath
import re

from tamandua.modules.intel.advisories import compare_versions
from tamandua.modules.findings.fix_examples import EXAMPLES
from tamandua.shared.i18n import msg
from tamandua.shared.model import Finding

# Lo que entra en una orden: sin metacaracteres de shell y sin empezar por «-» (se leería como una opción del gestor).
SAFE_NAME = re.compile(r"[A-Za-z0-9@._][A-Za-z0-9@/._:+-]{0,199}")
SAFE_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+~:-]{0,99}")
# «Reverificar» analiza la rama principal remota (o la imagen publicada), no la copia local.
VERIFY = msg("findings.fix.verify")
VERIFY_DEPENDENCY = msg("findings.fix.verify_dependency")
VERIFY_IMAGE = msg("findings.fix.verify_image")
# `action` is the language-neutral code for consumers that filter commands; `label` is what people read.
COMMAND_LABELS = {"update": msg("findings.fix.commands.update"), "reinstall": msg("findings.fix.commands.reinstall"),
                  "install": msg("findings.fix.commands.install")}

# Archivo de dependencias → gestor.
MANAGERS = {"package-lock.json": "npm", "npm-shrinkwrap.json": "npm", "package.json": "npm", "yarn.lock": "yarn",
            "pnpm-lock.yaml": "pnpm", "bun.lock": "bun", "bun.lockb": "bun", "poetry.lock": "poetry", "uv.lock": "uv",
            "pipfile.lock": "pipenv", "pdm.lock": "pdm", "go.mod": "go", "go.sum": "go", "cargo.lock": "cargo", "cargo.toml": "cargo",
            "composer.lock": "composer", "composer.json": "composer", "gemfile.lock": "bundler", "pom.xml": "maven",
            "gradle.lockfile": "gradle", "packages.lock.json": "dotnet", "packages.config": "dotnet", "pubspec.lock": "pub", "mix.lock": "mix"}
OS_DATABASES = {"var/lib/dpkg/status": "apt", "lib/apk/db/installed": "apk", "var/lib/rpm": "dnf", "usr/lib/sysimage/rpm": "dnf"}


def manager(path: str, ecosystem: str) -> str | None:
    name = posixpath.basename(path or "").lower()
    if name in MANAGERS:
        return MANAGERS[name]
    if re.fullmatch(r".*requirements.*\.txt", name):
        return "pip"
    if name.endswith((".gradle", ".gradle.kts")):
        return "gradle"
    if name.endswith((".csproj", ".fsproj", ".vbproj")):
        return "dotnet"
    for database, tool in OS_DATABASES.items():
        if (path or "").lstrip("/").startswith(database):
            return tool
    return {"debian": "apt", "ubuntu": "apt", "alpine": "apk", "redhat": "dnf", "rocky": "dnf", "alma": "dnf",
            "amazon": "dnf", "oracle": "dnf", "centos": "dnf", "fedora": "dnf"}.get((ecosystem or "").lower())


def _dependency(finding: Finding, target: str | None) -> dict:
    package = finding.get("package") or {}
    name, version, path = str(package.get("name") or ""), str(package.get("version") or ""), str(finding.get("path") or "")
    tool = manager(path, str(package.get("ecosystem") or ""))
    direct = package.get("direct")
    steps, commands, example = [], [], None
    if not target:
        steps = [msg("findings.fix.no_fix.none_published", package=name), msg("findings.fix.no_fix.check_usage"),
                 msg("findings.fix.no_fix.mitigate"), msg("findings.fix.no_fix.accept")]
        return {"kind": "dependency", "steps": steps, "commands": [], "example": None}
    if not SAFE_NAME.fullmatch(name) or not SAFE_VERSION.fullmatch(target):
        return {"kind": "dependency", "steps": [msg("findings.fix.manual_update", package=name, version=target, path=path), VERIFY_DEPENDENCY],
                "commands": [], "example": None}
    add = lambda action, code: commands.append({"label": COMMAND_LABELS[action], "action": action, "code": code})
    transitive = direct is False
    dev = bool(package.get("dev"))  # de desarrollo: el comando no debe moverla a producción
    fixed = package.get("fixed_version")
    if fixed and fixed != target:
        steps.append(msg("findings.fix.closes_all", version=target, package=name, fixed=fixed))
    if tool in ("npm", "yarn", "pnpm", "bun"):
        if transitive:
            key = {"npm": "overrides", "yarn": "resolutions", "pnpm": "pnpm.overrides", "bun": "overrides"}[tool]
            steps.append(msg("findings.fix.npm_transitive", package=name, field=key))
            example = {"language": "json", "before": "", "after": ("{\n  \"pnpm\": {\n    \"overrides\": {\n      \"" + name + "\": \">=" + target + "\"\n    }\n  }\n}"
                                                                   if tool == "pnpm" else
                                                                   "{\n  \"" + key + "\": {\n    \"" + name + "\": \">=" + target + "\"\n  }\n}"), "note": msg("findings.fix.override_note")}
            add("reinstall", {"npm": "npm install", "yarn": "yarn install", "pnpm": "pnpm install", "bun": "bun install"}[tool])
        else:
            flag = " -D" if dev else ""
            add("update", {"npm": f"npm install{flag} {name}@{target}", "yarn": f"yarn add{flag} {name}@{target}",
                              "pnpm": f"pnpm add{flag} {name}@{target}", "bun": f"bun add{' -d' if dev else ''} {name}@{target}"}[tool])
    elif tool == "pip":
        steps.append(msg("findings.fix.pip_line", path=path, package=name, version=target))
        add("install", f"pip install -r {path}" if SAFE_NAME.fullmatch(path) else f'pip install "{name}>={target}"')
    elif tool == "poetry":
        add("update", f"poetry update {name}" if transitive else f'poetry add{" --group dev" if dev else ""} "{name}>={target}"')
    elif tool == "uv":
        add("update", f"uv lock --upgrade-package {name}" if transitive else f'uv add{" --dev" if dev else ""} "{name}>={target}"')
    elif tool == "pipenv":
        add("update", f'pipenv install "{name}>={target}"')
    elif tool == "pdm":
        add("update", f"pdm update {name}" if transitive else f'pdm add{" -d" if dev else ""} "{name}>={target}"')
    elif tool == "go" and name in ("stdlib", "toolchain"):
        # La librería estándar de Go no se actualiza con go get: se compila con una versión de Go corregida.
        steps.append(msg("findings.fix.go_stdlib", version=target.lstrip("v")))
        add("update", f"go mod edit -toolchain=go{target.lstrip('v')}")
    elif tool == "go":
        add("update", f"go get {name}@{target if target.startswith('v') else 'v' + target} && go mod tidy")
    elif tool == "cargo":
        add("update", f"cargo update -p {name}@{version} --precise {target}" if SAFE_VERSION.fullmatch(version) else f"cargo update -p {name} --precise {target}")
    elif tool == "composer":
        add("update", f"composer update {name} --with-dependencies" if transitive else f'composer require{" --dev" if dev else ""} "{name}:^{target}"')
    elif tool == "bundler":
        steps.append(msg("findings.fix.bundler_pin", package=name, version=target))
        add("update", f"bundle update {name}")
    elif tool in ("maven", "gradle") and ":" in name:
        group, artifact = name.split(":", 1)
        if tool == "maven" and direct:
            steps.append(msg("findings.fix.maven_direct", artifact=artifact))
            example = {"language": "xml", "before": "", "note": "", "after":
                       f"<dependency>\n  <groupId>{group}</groupId>\n  <artifactId>{artifact}</artifactId>\n  <version>{target}</version>\n</dependency>"}
        elif tool == "maven":
            steps.append(msg("findings.fix.maven_managed"))
            example = {"language": "xml", "before": "", "note": "", "after":
                       f"<dependencyManagement>\n  <dependencies>\n    <dependency>\n      <groupId>{group}</groupId>\n"
                       f"      <artifactId>{artifact}</artifactId>\n      <version>{target}</version>\n    </dependency>\n  </dependencies>\n</dependencyManagement>"}
        else:
            steps.append(msg("findings.fix.gradle_constraint"))
            example = {"language": "kotlin", "before": "", "note": "",
                       "after": f"dependencies {{\n    constraints {{\n        implementation(\"{group}:{artifact}:{target}\")\n    }}\n}}"}
    elif tool == "dotnet":
        add("update", f"dotnet add package {name} --version {target}")
    elif tool == "pub":
        add("update", f"dart pub upgrade {name}")
    elif tool == "mix":
        add("update", f"mix deps.update {name}")
    elif tool in ("apt", "apk", "dnf"):
        steps.append(msg("findings.fix.os_rebuild"))
        steps.append(msg("findings.fix.os_dockerfile"))
        example = {"language": "dockerfile", "before": "", "note": "", "after": {
            "apt": f"RUN apt-get update && apt-get install -y --only-upgrade {name} && rm -rf /var/lib/apt/lists/*",
            "apk": f"RUN apk upgrade --no-cache {name}", "dnf": f"RUN dnf upgrade -y {name} && dnf clean all"}[tool]}
    else:
        steps.append(msg("findings.fix.generic_update", package=name, installed=version, version=target, path=path))
    if transitive and tool not in ("npm", "yarn", "pnpm", "bun", "maven", "gradle"):
        steps.insert(0, msg("findings.fix.transitive_other", package=name))
    steps.append(VERIFY_IMAGE if tool in ("apt", "apk", "dnf") else VERIFY_DEPENDENCY)
    return {"kind": "dependency", "steps": steps, "commands": commands, "example": example}


def _secret(finding: Finding) -> dict:
    return {"kind": "secret", "commands": [], "example": None, "steps": [
        msg("findings.fix.secret.revoke"), msg("findings.fix.secret.review_use"), msg("findings.fix.secret.vault"),
        msg("findings.fix.secret.remove", path=str(finding.get("path") or "")), msg("findings.fix.secret.history"),
        msg("findings.fix.secret.verify")]}


def guide(finding: Finding, *, target: str | None = None) -> dict | None:
    scanner = finding.get("scanner")
    if finding.get("malicious"):
        # Nada que actualizar: se quita y se da por comprometido lo que lo instaló (ver advisories.malicious_finding).
        return {"kind": "dependency", "steps": [finding.get("remediation") or "", VERIFY], "commands": [], "example": None}
    if scanner == "sca" and (finding.get("package") or {}).get("name"):
        return _dependency(finding, target or (finding.get("package") or {}).get("fixed_version"))
    if scanner == "secrets":
        return _secret(finding)
    if scanner == "sast" and finding.get("rule_id") in EXAMPLES:
        language, before, after, note = EXAMPLES[finding["rule_id"]]
        return {"kind": "code", "steps": [finding.get("remediation") or "", VERIFY], "commands": [],
                "example": {"language": language, "before": before, "after": after, "note": note}}
    if finding.get("remediation"):
        return {"kind": "config" if scanner in ("iac", "cicd") else "code", "steps": [finding["remediation"], VERIFY],
                "commands": [], "example": None}
    return None


def attach(findings: list[Finding]) -> list[Finding]:
    """Añade `fix` a cada hallazgo. En dependencias, la versión que cierra todos los avisos del mismo paquete."""
    targets: dict[tuple, str] = {}
    # Un paquete malicioso no se actualiza: sus otros avisos tampoco deben proponer «actualiza a…».
    hostile = {(item.get("path"), (item.get("package") or {}).get("name"), (item.get("package") or {}).get("version"))
               for item in findings if item.get("malicious")}
    for finding in findings:
        package = finding.get("package") or {}
        fixed = package.get("fixed_version")
        if finding.get("scanner") == "sca" and fixed and (finding.get("path"), package.get("name"), package.get("version")) not in hostile:
            key = (finding.get("path"), package.get("name"), package.get("version"))
            current = targets.get(key)
            targets[key] = fixed if current is None or compare_versions(fixed, current) > 0 else current
    for finding in findings:
        package = finding.get("package") or {}
        key = (finding.get("path"), package.get("name"), package.get("version"))
        if key in hostile and not finding.get("malicious"):
            finding["fix"] = {"kind": "dependency", "commands": [], "example": None,
                              "steps": [msg("findings.fix.malicious_sibling", package=str(package.get("name") or ""),
                                            version=str(package.get("version") or "")), VERIFY]}
            continue
        fix = guide(finding, target=targets.get(key))
        if fix:
            finding["fix"] = fix
    return findings
