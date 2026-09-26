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

from .advisories import compare_versions
from .fix_examples import EXAMPLES

SAFE_NAME = re.compile(r"[A-Za-z0-9@/._:+-]{1,200}")
SAFE_VERSION = re.compile(r"[A-Za-z0-9._+~:-]{1,100}")
# «Reverificar» analiza la rama principal remota (o la imagen publicada), no la copia local.
VERIFY = "Después: sube el cambio a la rama principal y pulsa «Reverificar» (o espera al análisis automático de la rama)."
VERIFY_DEPENDENCY = ("Después: regenera el lockfile, sube el cambio a la rama principal y pulsa «Reverificar» "
                     "(o espera al análisis automático de la rama).")
VERIFY_IMAGE = "Después: reconstruye y publica la imagen con la misma etiqueta y pulsa «Reverificar»."

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


def _dependency(finding: dict, target: str | None) -> dict:
    package = finding.get("package") or {}
    name, version, path = str(package.get("name") or ""), str(package.get("version") or ""), str(finding.get("path") or "")
    tool = manager(path, str(package.get("ecosystem") or ""))
    direct = package.get("direct")
    steps, commands, example = [], [], None
    if not target:
        steps = [f"No hay versión corregida publicada de {name}.",
                 "Comprueba si tu código usa la parte vulnerable (el aviso suele decir qué función o formato).",
                 "Si la usa: mitiga (valida la entrada, desactiva la función) o sustituye la dependencia.",
                 "Si no la usa: regístralo como riesgo aceptado con su motivo y una fecha de revisión."]
        return {"kind": "dependency", "steps": steps, "commands": [], "example": None}
    if not SAFE_NAME.fullmatch(name) or not SAFE_VERSION.fullmatch(target):
        return {"kind": "dependency", "steps": [f"Actualiza {name} a {target} o superior en {path} y regenera el lockfile.", VERIFY_DEPENDENCY],
                "commands": [], "example": None}
    add = lambda label, code: commands.append({"label": label, "code": code})
    transitive = direct is False
    dev = bool(package.get("dev"))  # de desarrollo: el comando no debe moverla a producción
    fixed = package.get("fixed_version")
    if fixed and fixed != target:
        steps.append(f"La versión {target} cierra todos los avisos de {name} (este aviso solo pide {fixed}).")
    if tool in ("npm", "yarn", "pnpm", "bun"):
        if transitive:
            key = {"npm": "overrides", "yarn": "resolutions", "pnpm": "pnpm.overrides", "bun": "overrides"}[tool]
            steps.append(f"{name} es una dependencia transitiva: fuerza la versión con «{key}» en package.json y reinstala.")
            example = {"language": "json", "before": "", "after": ("{\n  \"pnpm\": {\n    \"overrides\": {\n      \"" + name + "\": \">=" + target + "\"\n    }\n  }\n}"
                                                                   if tool == "pnpm" else
                                                                   "{\n  \"" + key + "\": {\n    \"" + name + "\": \">=" + target + "\"\n  }\n}"), "note": "Mejor aún: actualiza la dependencia directa que la trae."}
            add("Reinstala", {"npm": "npm install", "yarn": "yarn install", "pnpm": "pnpm install", "bun": "bun install"}[tool])
        else:
            flag = " -D" if dev else ""
            add("Actualiza", {"npm": f"npm install{flag} {name}@{target}", "yarn": f"yarn add{flag} {name}@{target}",
                              "pnpm": f"pnpm add{flag} {name}@{target}", "bun": f"bun add{' -d' if dev else ''} {name}@{target}"}[tool])
    elif tool == "pip":
        steps.append(f"En {path}, cambia la línea de {name} a «{name}>={target}» (o fija «=={target}»).")
        add("Instala", f"pip install -r {path}" if SAFE_NAME.fullmatch(path) else f'pip install "{name}>={target}"')
    elif tool == "poetry":
        add("Actualiza", f"poetry update {name}" if transitive else f'poetry add{" --group dev" if dev else ""} "{name}>={target}"')
    elif tool == "uv":
        add("Actualiza", f"uv lock --upgrade-package {name}" if transitive else f'uv add{" --dev" if dev else ""} "{name}>={target}"')
    elif tool == "pipenv":
        add("Actualiza", f'pipenv install "{name}>={target}"')
    elif tool == "pdm":
        add("Actualiza", f"pdm update {name}" if transitive else f'pdm add{" -d" if dev else ""} "{name}>={target}"')
    elif tool == "go" and name in ("stdlib", "toolchain"):
        # La librería estándar de Go no se actualiza con go get: se compila con una versión de Go corregida.
        steps.append(f"Es la librería estándar de Go: compila con Go {target.lstrip('v')} o superior (actualiza también la imagen de build y la CI).")
        add("Actualiza", f"go mod edit -toolchain=go{target.lstrip('v')}")
    elif tool == "go":
        add("Actualiza", f"go get {name}@{target if target.startswith('v') else 'v' + target} && go mod tidy")
    elif tool == "cargo":
        add("Actualiza", f"cargo update -p {name}@{version} --precise {target}" if SAFE_VERSION.fullmatch(version) else f"cargo update -p {name} --precise {target}")
    elif tool == "composer":
        add("Actualiza", f"composer update {name} --with-dependencies" if transitive else f'composer require{" --dev" if dev else ""} "{name}:^{target}"')
    elif tool == "bundler":
        steps.append(f"Si el Gemfile fija una versión de {name}, súbela a «>= {target}».")
        add("Actualiza", f"bundle update {name}")
    elif tool in ("maven", "gradle") and ":" in name:
        group, artifact = name.split(":", 1)
        if tool == "maven" and direct:
            steps.append(f"Cambia la <version> de {artifact} en las <dependencies> del pom.xml.")
            example = {"language": "xml", "before": "", "note": "", "after":
                       f"<dependency>\n  <groupId>{group}</groupId>\n  <artifactId>{artifact}</artifactId>\n  <version>{target}</version>\n</dependency>"}
        elif tool == "maven":
            steps.append("Fija la versión en dependencyManagement del pom.xml: así se impone también a la dependencia transitiva.")
            example = {"language": "xml", "before": "", "note": "", "after":
                       f"<dependencyManagement>\n  <dependencies>\n    <dependency>\n      <groupId>{group}</groupId>\n"
                       f"      <artifactId>{artifact}</artifactId>\n      <version>{target}</version>\n    </dependency>\n  </dependencies>\n</dependencyManagement>"}
        else:
            steps.append("Fija la versión con una restricción de Gradle (sirve también si es transitiva).")
            example = {"language": "kotlin", "before": "", "note": "",
                       "after": f"dependencies {{\n    constraints {{\n        implementation(\"{group}:{artifact}:{target}\")\n    }}\n}}"}
    elif tool == "dotnet":
        add("Actualiza", f"dotnet add package {name} --version {target}")
    elif tool == "pub":
        add("Actualiza", f"dart pub upgrade {name}")
    elif tool == "mix":
        add("Actualiza", f"mix deps.update {name}")
    elif tool in ("apt", "apk", "dnf"):
        steps.append("Es un paquete del sistema de la imagen: lo mejor es reconstruirla sobre una base actualizada (docker build --pull).")
        steps.append("Si la base aún no trae la corrección, actualiza el paquete en el Dockerfile:")
        example = {"language": "dockerfile", "before": "", "note": "", "after": {
            "apt": f"RUN apt-get update && apt-get install -y --only-upgrade {name} && rm -rf /var/lib/apt/lists/*",
            "apk": f"RUN apk upgrade --no-cache {name}", "dnf": f"RUN dnf upgrade -y {name} && dnf clean all"}[tool]}
    else:
        steps.append(f"Actualiza {name} de {version} a {target} o superior en {path} y regenera el lockfile.")
    if transitive and tool not in ("npm", "yarn", "pnpm", "bun", "maven", "gradle"):
        steps.insert(0, f"{name} llega como dependencia de otra: si el comando no la sube, actualiza la dependencia directa que la trae.")
    steps.append(VERIFY_IMAGE if tool in ("apt", "apk", "dnf") else VERIFY_DEPENDENCY)
    return {"kind": "dependency", "steps": steps, "commands": commands, "example": example}


def _secret(finding: dict) -> dict:
    return {"kind": "secret", "commands": [], "example": None, "steps": [
        "Revoca o rota la credencial ahora en su proveedor: borrarla del código no basta, ya está en el historial de Git.",
        "Revisa en el proveedor si se usó desde un origen que no reconoces.",
        "Muévela a un gestor de secretos o a una variable de entorno y léela desde ahí.",
        f"Quítala de {finding.get('path')} y haz commit.",
        "Si el repositorio es o fue público, considera reescribir el historial (git filter-repo); rotar es lo que te protege.",
        "Después pulsa «Reverificar»."]}


def guide(finding: dict, *, target: str | None = None) -> dict | None:
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


def attach(findings: list[dict]) -> list[dict]:
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
                              "steps": [f"{package.get('name')} {package.get('version')} es un paquete malicioso: elimínalo en lugar de actualizarlo "
                                        "(ver su aviso MAL-). Actualizar no basta.", VERIFY]}
            continue
        fix = guide(finding, target=targets.get(key))
        if fix:
            finding["fix"] = fix
    return findings
