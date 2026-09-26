"""Enfoques de modelado de amenazas: STRIDE, LINDDUN, PASTA, árboles de ataque, MITRE ATT&CK o personalizado.

Todos comparten el mismo diagrama (componentes, flujos y fronteras). Lo que cambia es cómo se piensa
sobre él y qué se guarda:

* **STRIDE** y **LINDDUN** aplican reglas visibles sobre el diagrama (seguridad y privacidad).
* **PASTA** son siete etapas con notas; la 3 es el diagrama, la 4 las amenazas STRIDE y la 5 los
  hallazgos de los análisis.
* **Árboles de ataque**: un objetivo del atacante desglosado en rutas (nodos Y / O).
* **MITRE ATT&CK**: técnicas de atacantes reales mapeadas a los componentes que afectan.
* **Personalizado**: solo amenazas escritas por el equipo.

En cualquiera se pueden añadir amenazas propias. Las guías de cada enfoque viven en el panel: aquí
solo está lo que el servidor necesita para validar y calcular.
"""

from __future__ import annotations

import re

from tamandua.shared.i18n import inline, msg, text

METHODOLOGIES = {
    "stride": msg("threats.methods.stride"), "linddun": msg("threats.methods.linddun"), "pasta": msg("threats.methods.pasta"),
    "attack_trees": msg("threats.methods.attack_trees"), "attack": msg("threats.methods.attack"), "custom": msg("threats.methods.custom"),
}
# Enfoques cuyas amenazas se generan con reglas sobre el diagrama.
RULE_BASED = {"stride": "stride", "pasta": "stride", "linddun": "linddun"}
SEVERITIES = ("critical", "high", "medium", "low")
LIMITS = {"manual_threats": 200, "attack_trees": 20, "tree_nodes": 120, "attack_mappings": 300}
CUSTOM_MODULES = {"stride", "linddun", "manual", "pasta", "trees", "attack", "elements"}
ID = re.compile(r"[a-z0-9][a-z0-9-]{0,39}")


class MethodError(ValueError):
    """A validation error; `message` is a language-neutral message, str() renders it in the default locale."""

    def __init__(self, message):
        super().__init__(message)
        self.message = message

    def __str__(self) -> str:
        return text(self.message)


# ------------------------------------------------------------------ LINDDUN (privacidad)

LINDDUN = {"L": msg("threats.linddun.l"), "I": msg("threats.linddun.i"), "Nr": msg("threats.linddun.nr"), "D": msg("threats.linddun.d"),
           "Dd": msg("threats.linddun.dd"), "U": msg("threats.linddun.u"), "Nc": msg("threats.linddun.nc")}


def rule(identifier: str, base: str, category: str, applies: str, cwe: list[int], *, mitigations: int = 2, **extra) -> dict:
    """A rule whose title, rationale and mitigations live in the catalog under threats.rules.<id>."""
    key = "threats.rules." + identifier.lower().replace("-", "_")
    return {"id": identifier, "base": base, "stride": category, "applies": applies, "title": msg(f"{key}.title"),
            "why": msg(f"{key}.why"), "mitigations": [msg(f"{key}.mitigation_{index}") for index in range(1, mitigations + 1)],
            "cwe": cwe, **extra}


# Same shape as the STRIDE rules; "stride" holds the LINDDUN category here.
LINDDUN_RULES = [
    rule("PV-L01", "medium", "L", "store_personal", [359]),
    rule("PV-I01", "medium", "I", "store_personal", [359, 200]),
    rule("PV-Nr01", "low", "Nr", "process_personal", [532]),
    rule("PV-D01", "medium", "D", "process_personal_facing_actor", [203, 204, 208]),
    rule("PV-Dd01", "high", "Dd", "flow_personal_to_external", [359, 200]),
    rule("PV-Dd02", "high", "Dd", "store_personal_unencrypted", [311, 312, 359]),
    rule("PV-U01", "medium", "U", "process_personal_facing_actor", []),
    rule("PV-Nc01", "medium", "Nc", "store_personal", []),
]

# ------------------------------------------------------------------ MITRE ATT&CK (Enterprise)

# Tactics (the attacker's "why"): MITRE's identifiers and names, with the Spanish interpretation.
TACTICS = {key: inline({"en": english, "es": spanish}) for key, (english, spanish) in {
    "TA0043": ("Reconnaissance", "Reconocimiento"), "TA0042": ("Resource Development", "Desarrollo de recursos"),
    "TA0001": ("Initial Access", "Acceso inicial"), "TA0002": ("Execution", "Ejecución"), "TA0003": ("Persistence", "Persistencia"),
    "TA0004": ("Privilege Escalation", "Escalada de privilegios"), "TA0005": ("Defense Evasion", "Evasión de defensas"),
    "TA0006": ("Credential Access", "Acceso a credenciales"), "TA0007": ("Discovery", "Descubrimiento"),
    "TA0008": ("Lateral Movement", "Movimiento lateral"), "TA0009": ("Collection", "Recolección"),
    "TA0011": ("Command and Control", "Mando y control"), "TA0010": ("Exfiltration", "Exfiltración"), "TA0040": ("Impact", "Impacto"),
}.items()}
# Técnicas (el «cómo») más útiles para aplicaciones web, APIs, contenedores y nube. No es el catálogo completo:
# cada una enlaza a attack.mitre.org.
TECHNIQUES = {
    "T1190": ("Exploit Public-Facing Application", "Explotar una aplicación expuesta", ["TA0001"]),
    "T1133": ("External Remote Services", "Servicios remotos expuestos", ["TA0001", "TA0003"]),
    "T1078": ("Valid Accounts", "Cuentas válidas", ["TA0001", "TA0003", "TA0004", "TA0005"]),
    "T1199": ("Trusted Relationship", "Relación de confianza", ["TA0001"]),
    "T1195.001": ("Compromise Software Dependencies and Development Tools", "Dependencias o herramientas comprometidas", ["TA0001"]),
    "T1195.002": ("Compromise Software Supply Chain", "Cadena de suministro comprometida", ["TA0001"]),
    "T1566": ("Phishing", "Phishing", ["TA0001"]),
    "T1189": ("Drive-by Compromise", "Compromiso al navegar", ["TA0001"]),
    "T1059": ("Command and Scripting Interpreter", "Intérprete de comandos", ["TA0002"]),
    "T1203": ("Exploitation for Client Execution", "Explotación para ejecutar en el cliente", ["TA0002"]),
    "T1648": ("Serverless Execution", "Ejecución en funciones serverless", ["TA0002"]),
    "T1610": ("Deploy Container", "Desplegar un contenedor", ["TA0002", "TA0005"]),
    "T1505.003": ("Web Shell", "Web shell", ["TA0003"]),
    "T1098": ("Account Manipulation", "Manipulación de cuentas", ["TA0003", "TA0004"]),
    "T1136": ("Create Account", "Crear cuentas", ["TA0003"]),
    "T1525": ("Implant Internal Image", "Imagen interna implantada", ["TA0003"]),
    "T1068": ("Exploitation for Privilege Escalation", "Explotación para escalar privilegios", ["TA0004"]),
    "T1611": ("Escape to Host", "Escapar del contenedor al host", ["TA0004"]),
    "T1562": ("Impair Defenses", "Debilitar las defensas", ["TA0005"]),
    "T1070": ("Indicator Removal", "Borrar rastros", ["TA0005"]),
    "T1550": ("Use Alternate Authentication Material", "Material de autenticación alternativo", ["TA0005", "TA0008"]),
    "T1110": ("Brute Force", "Fuerza bruta", ["TA0006"]),
    "T1552": ("Unsecured Credentials", "Credenciales sin proteger", ["TA0006"]),
    "T1528": ("Steal Application Access Token", "Robar tokens de acceso", ["TA0006"]),
    "T1539": ("Steal Web Session Cookie", "Robar la cookie de sesión", ["TA0006"]),
    "T1556": ("Modify Authentication Process", "Alterar la autenticación", ["TA0006", "TA0005", "TA0003"]),
    "T1606": ("Forge Web Credentials", "Falsificar credenciales web", ["TA0006"]),
    "T1621": ("Multi-Factor Authentication Request Generation", "Bombardeo de solicitudes MFA", ["TA0006"]),
    "T1212": ("Exploitation for Credential Access", "Explotación para obtener credenciales", ["TA0006"]),
    "T1087": ("Account Discovery", "Descubrir cuentas", ["TA0007"]),
    "T1046": ("Network Service Discovery", "Descubrir servicios de red", ["TA0007"]),
    "T1526": ("Cloud Service Discovery", "Descubrir servicios en la nube", ["TA0007"]),
    "T1580": ("Cloud Infrastructure Discovery", "Descubrir infraestructura en la nube", ["TA0007"]),
    "T1557": ("Adversary-in-the-Middle", "Intermediario (AitM)", ["TA0006", "TA0009"]),
    "T1040": ("Network Sniffing", "Captura de tráfico", ["TA0006", "TA0007"]),
    "T1213": ("Data from Information Repositories", "Datos de repositorios de información", ["TA0009"]),
    "T1530": ("Data from Cloud Storage", "Datos del almacenamiento en la nube", ["TA0009"]),
    "T1005": ("Data from Local System", "Datos del sistema local", ["TA0009"]),
    "T1041": ("Exfiltration Over C2 Channel", "Exfiltración por el canal de control", ["TA0010"]),
    "T1567": ("Exfiltration Over Web Service", "Exfiltración por un servicio web", ["TA0010"]),
    "T1537": ("Transfer Data to Cloud Account", "Transferir datos a otra cuenta en la nube", ["TA0010"]),
    "T1485": ("Data Destruction", "Destrucción de datos", ["TA0040"]),
    "T1486": ("Data Encrypted for Impact", "Cifrado de datos (ransomware)", ["TA0040"]),
    "T1565": ("Data Manipulation", "Manipulación de datos", ["TA0040"]),
    "T1498": ("Network Denial of Service", "Denegación de servicio de red", ["TA0040"]),
    "T1499": ("Endpoint Denial of Service", "Denegación de servicio de la aplicación", ["TA0040"]),
    "T1496": ("Resource Hijacking", "Secuestro de recursos (criptominería)", ["TA0040"]),
}
MAPPING_STATUS = ("relevant", "mitigated", "not_applicable")

# Sugerencias por tipo de componente: técnicas que conviene revisar, sin añadirlas solas.
SUGGESTIONS = {
    "internet_process": ["T1190", "T1110", "T1078", "T1539", "T1499"],
    "web_app": ["T1189", "T1539", "T1606"],
    "process": ["T1059", "T1195.001", "T1505.003"],
    "identity": ["T1556", "T1621", "T1528", "T1606"],
    "database": ["T1213", "T1485", "T1486", "T1565"],
    "storage": ["T1530", "T1537", "T1485"],
    "cache": ["T1552", "T1565"],
    "queue": ["T1565", "T1499"],
    "external": ["T1199", "T1195.002", "T1567"],
    "function": ["T1648", "T1552"],
    "service": ["T1046", "T1550"],
}

# ------------------------------------------------------------------ PASTA

PASTA_STAGES = [
    ("objectives", msg("threats.pasta.objectives")),
    ("scope", msg("threats.pasta.scope")),
    ("decomposition", msg("threats.pasta.decomposition")),
    ("threats", msg("threats.pasta.threats")),
    ("vulnerabilities", msg("threats.pasta.vulnerabilities")),
    ("attacks", msg("threats.pasta.attacks")),
    ("risk", msg("threats.pasta.risk")),
]


# ------------------------------------------------------------------ validación

def _text(value, limit: int, field, *, required: bool = False, multiline: bool = False) -> str:
    if value in (None, ""):
        if required:
            raise MethodError(msg("threats.errors.field_required", field=field))
        return ""
    if not isinstance(value, str) or len(value) > limit:
        raise MethodError(msg("threats.errors.field_too_long", field=field, limit=limit))
    cleaned = value.strip() if multiline else " ".join(value.split())
    allowed = {"\n", "\t"} if multiline else set()
    if any(ord(character) < 32 and character not in allowed for character in cleaned):
        raise MethodError(msg("threats.errors.control_characters", field=field))
    return cleaned


def _identifier(value, used: set[str], field) -> str:
    if not isinstance(value, str) or not ID.fullmatch(value) or value in used:
        raise MethodError(msg("threats.errors.unique_id", field=field))
    used.add(value)
    return value


def validate(payload: dict, *, elements: set[str]) -> dict:
    """Lo propio de cada enfoque. `elements`: ids de componentes y flujos del modelo, para los enlaces."""
    methodology = payload.get("methodology") or "stride"
    if methodology not in METHODOLOGIES:
        raise MethodError(msg("threats.errors.unknown_method"))
    result: dict = {"methodology": methodology}
    modules = payload.get("custom_modules", ["manual", "elements"])
    if not isinstance(modules, list) or len(modules) > len(CUSTOM_MODULES) or any(not isinstance(item, str) or item not in CUSTOM_MODULES for item in modules):
        raise MethodError(msg("threats.errors.invalid_custom_modules"))
    result["custom_modules"] = list(dict.fromkeys(modules))

    manual, used = [], set()
    raw_manual = payload.get("manual_threats") or []
    if not isinstance(raw_manual, list) or len(raw_manual) > LIMITS["manual_threats"]:
        raise MethodError(msg("threats.errors.too_many_manual", limit=LIMITS["manual_threats"]))
    for raw in raw_manual:
        if not isinstance(raw, dict):
            raise MethodError(msg("threats.errors.invalid_manual"))
        element = raw.get("element") or ""
        if element and element not in elements:
            raise MethodError(msg("threats.errors.manual_element"))
        severity = raw.get("severity") or "medium"
        if severity not in SEVERITIES:
            raise MethodError(msg("threats.errors.invalid_severity"))
        manual.append({"id": _identifier(raw.get("id"), used, msg("threats.fields.each_manual")),
                       "title": _text(raw.get("title"), 160, msg("threats.fields.title"), required=True),
                       "category": _text(raw.get("category"), 40, msg("threats.fields.category")),
                       "element": element, "severity": severity,
                       "scenario": _text(raw.get("scenario"), 1500, msg("threats.fields.scenario"), multiline=True),
                       "mitigation": _text(raw.get("mitigation"), 1500, msg("threats.fields.mitigation"), multiline=True),
                       "likelihood": raw.get("likelihood") if raw.get("likelihood") in ("low", "medium", "high") else None,
                       "impact": raw.get("impact") if raw.get("impact") in ("low", "medium", "high") else None,
                       "owner": _text(raw.get("owner"), 80, msg("threats.fields.owner"))})
    result["manual_threats"] = manual

    trees, tree_ids = [], set()
    raw_trees = payload.get("attack_trees") or []
    if not isinstance(raw_trees, list) or len(raw_trees) > LIMITS["attack_trees"]:
        raise MethodError(msg("threats.errors.too_many_trees", limit=LIMITS["attack_trees"]))
    for raw in raw_trees:
        if not isinstance(raw, dict):
            raise MethodError(msg("threats.errors.invalid_tree"))
        nodes, node_ids = [], set()
        raw_nodes = raw.get("nodes") or []
        if not isinstance(raw_nodes, list) or len(raw_nodes) > LIMITS["tree_nodes"]:
            raise MethodError(msg("threats.errors.too_many_nodes", limit=LIMITS["tree_nodes"]))
        for node in raw_nodes:
            if not isinstance(node, dict):
                raise MethodError(msg("threats.errors.invalid_node"))
            element = node.get("element") or ""
            if element and element not in elements:
                raise MethodError(msg("threats.errors.node_element"))
            nodes.append({"id": _identifier(node.get("id"), node_ids, msg("threats.fields.each_node")), "parent": node.get("parent") or None,
                          "text": _text(node.get("text"), 200, msg("threats.fields.step"), required=True),
                          "gate": "and" if node.get("gate") == "and" else "or", "element": element,
                          "difficulty": node.get("difficulty") if node.get("difficulty") in ("low", "medium", "high") else None,
                          "mitigated": bool(node.get("mitigated"))})
        ids = {node["id"] for node in nodes}
        parents = {node["id"]: node["parent"] for node in nodes}
        for node in nodes:
            if node["parent"] is not None and node["parent"] not in ids:
                raise MethodError(msg("threats.errors.node_parent"))
            seen, current = set(), node["id"]
            while current is not None:  # no cycles
                if current in seen:
                    raise MethodError(msg("threats.errors.tree_cycle"))
                seen.add(current)
                current = parents.get(current)
        trees.append({"id": _identifier(raw.get("id"), tree_ids, msg("threats.fields.each_tree")),
                      "goal": _text(raw.get("goal"), 200, msg("threats.fields.goal"), required=True), "nodes": nodes})
    result["attack_trees"] = trees

    mappings, seen_pairs = [], set()
    raw_mappings = payload.get("attack_mappings") or []
    if not isinstance(raw_mappings, list) or len(raw_mappings) > LIMITS["attack_mappings"]:
        raise MethodError(msg("threats.errors.too_many_mappings", limit=LIMITS["attack_mappings"]))
    for raw in raw_mappings:
        if not isinstance(raw, dict) or raw.get("technique") not in TECHNIQUES:
            raise MethodError(msg("threats.errors.unknown_technique"))
        element = raw.get("element") or ""
        if element and element not in elements:
            raise MethodError(msg("threats.errors.mapping_element"))
        pair = (raw["technique"], element)
        if pair in seen_pairs:
            continue
        seen_pairs.add(pair)
        mappings.append({"technique": raw["technique"], "element": element,
                         "status": raw.get("status") if raw.get("status") in MAPPING_STATUS else "relevant",
                         "note": _text(raw.get("note"), 600, msg("threats.fields.note"), multiline=True)})
    result["attack_mappings"] = mappings

    raw_pasta = payload.get("pasta") or {}
    if not isinstance(raw_pasta, dict) or not set(raw_pasta) <= {key for key, _ in PASTA_STAGES}:
        raise MethodError(msg("threats.errors.invalid_pasta"))
    result["pasta"] = {key: _text(raw_pasta.get(key), 4000, msg("threats.fields.pasta_stage", stage=title), multiline=True)
                       for key, title in PASTA_STAGES if raw_pasta.get(key)}
    return result


def technique_label(key: str):
    """A technique's name for the reader: MITRE's official English name, or its Spanish interpretation."""
    name, spanish, _ = TECHNIQUES[key]
    return inline({"en": name, "es": spanish})


def catalog() -> dict:
    """Lo que el panel necesita para cada enfoque; las guías de uso viven en el panel."""
    return {"methodologies": METHODOLOGIES, "linddun": LINDDUN, "tactics": TACTICS,
            "techniques": {key: {"name": name, "label": technique_label(key), "name_es": technique_label(key), "tactics": tactics}
                           for key, (name, _, tactics) in TECHNIQUES.items()},
            "suggestions": SUGGESTIONS, "pasta_stages": [{"key": key, "title": title} for key, title in PASTA_STAGES]}
