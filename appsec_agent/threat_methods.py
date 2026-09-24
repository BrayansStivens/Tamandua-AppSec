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

METHODOLOGIES = {
    "stride": "STRIDE", "linddun": "LINDDUN", "pasta": "PASTA", "attack_trees": "Árboles de ataque",
    "attack": "MITRE ATT&CK", "custom": "Personalizado",
}
# Enfoques cuyas amenazas se generan con reglas sobre el diagrama.
RULE_BASED = {"stride": "stride", "pasta": "stride", "linddun": "linddun"}
SEVERITIES = ("critical", "high", "medium", "low")
LIMITS = {"manual_threats": 200, "attack_trees": 20, "tree_nodes": 120, "attack_mappings": 300}
ID = re.compile(r"[a-z0-9][a-z0-9-]{0,39}")


class MethodError(ValueError):
    pass


# ------------------------------------------------------------------ LINDDUN (privacidad)

LINDDUN = {"L": "Vinculación", "I": "Identificación", "Nr": "No repudio", "D": "Detección",
           "Dd": "Divulgación de datos", "U": "Desconocimiento", "Nc": "Incumplimiento"}

# Misma forma que las reglas STRIDE; «stride» guarda aquí la categoría LINDDUN.
LINDDUN_RULES = [
    {"id": "PV-L01", "base": "medium", "stride": "L", "applies": "store_personal", "title": "Registros de una persona que se pueden cruzar",
     "why": "Este almacén guarda datos personales con identificadores estables: se pueden unir registros de la misma persona entre tablas, servicios o exportaciones y reconstruir su perfil.",
     "mitigations": ["Identificadores distintos por contexto (seudónimos) en lugar de uno global", "Minimizar los identificadores persistentes y separar conjuntos de datos"], "cwe": [359]},
    {"id": "PV-I01", "base": "medium", "stride": "I", "applies": "store_personal", "title": "Reidentificación de datos «anonimizados»",
     "why": "Datos personales exportados o agregados pueden volver a identificar a alguien combinándolos con otras fuentes.",
     "mitigations": ["Agregar o generalizar antes de exportar (k-anonimato)", "No compartir datos brutos para analítica ni pruebas"], "cwe": [359, 200]},
    {"id": "PV-Nr01", "base": "low", "stride": "Nr", "applies": "process_personal", "title": "Se guarda más de lo necesario sobre lo que hace cada persona",
     "why": "Un proceso que maneja datos personales puede registrar acciones con tanto detalle que el usuario ya no puede negar ni ocultar lo que hizo cuando debería poder hacerlo.",
     "mitigations": ["Registrar solo lo necesario para operar y auditar", "Plazos de retención de logs y seudonimizar al usuario en ellos"], "cwe": [532]},
    {"id": "PV-D01", "base": "medium", "stride": "D", "applies": "process_personal_facing_actor", "title": "Se puede deducir si alguien usa el servicio",
     "why": "Respuestas distintas (p. ej. «ese email ya está registrado»), tiempos o metadatos revelan a un tercero si una persona tiene cuenta o qué hace.",
     "mitigations": ["Mensajes y tiempos de respuesta uniformes en registro, login y recuperación", "Minimizar metadatos visibles (URLs, cabeceras, notificaciones)"], "cwe": [203, 204, 208]},
    {"id": "PV-Dd01", "base": "high", "stride": "Dd", "applies": "flow_personal_to_external", "title": "Datos personales enviados a un tercero",
     "why": "Este flujo lleva datos personales a un servicio de terceros: se pierde el control sobre su uso, conservación y país de destino.",
     "mitigations": ["Enviar solo los campos imprescindibles", "Contrato de encargo de tratamiento y revisión de transferencias internacionales"], "cwe": [359, 200]},
    {"id": "PV-Dd02", "base": "high", "stride": "Dd", "applies": "store_personal_unencrypted", "title": "Datos personales legibles si se filtra el almacén",
     "why": "Guarda datos personales sin cifrado en reposo: una copia de seguridad o un acceso indebido los expone tal cual.",
     "mitigations": ["Cifrado en reposo y de las copias", "Cifrar a nivel de campo los datos más sensibles"], "cwe": [311, 312, 359]},
    {"id": "PV-U01", "base": "medium", "stride": "U", "applies": "process_personal_facing_actor", "title": "La persona no sabe qué se hace con sus datos ni puede decidir",
     "why": "Un componente recoge datos personales directamente de los usuarios: sin aviso claro, consentimiento cuando aplica y forma de ver, corregir o borrar sus datos, no pueden ejercer control.",
     "mitigations": ["Aviso de privacidad en el punto de recogida", "Autoservicio para acceder, exportar y borrar los propios datos"], "cwe": []},
    {"id": "PV-Nc01", "base": "medium", "stride": "Nc", "applies": "store_personal", "title": "Tratamiento sin base legal, plazo ni registro",
     "why": "Un almacén de datos personales necesita finalidad, base legal y plazo de conservación documentados; sin ellos se incumple la normativa (RGPD, leyes locales).",
     "mitigations": ["Registro de actividades de tratamiento y política de retención con borrado automático", "Evaluación de impacto (EIPD/DPIA) si el tratamiento es de alto riesgo"], "cwe": []},
]

# ------------------------------------------------------------------ MITRE ATT&CK (Enterprise)

# Tácticas (el «por qué» del atacante). Identificadores y nombres de MITRE, con traducción.
TACTICS = {
    "TA0043": "Reconocimiento", "TA0042": "Desarrollo de recursos", "TA0001": "Acceso inicial", "TA0002": "Ejecución",
    "TA0003": "Persistencia", "TA0004": "Escalada de privilegios", "TA0005": "Evasión de defensas", "TA0006": "Acceso a credenciales",
    "TA0007": "Descubrimiento", "TA0008": "Movimiento lateral", "TA0009": "Recolección", "TA0011": "Mando y control",
    "TA0010": "Exfiltración", "TA0040": "Impacto",
}
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
    ("objectives", "1 · Objetivos de negocio y de seguridad"),
    ("scope", "2 · Alcance técnico"),
    ("decomposition", "3 · Descomposición de la aplicación"),
    ("threats", "4 · Análisis de amenazas"),
    ("vulnerabilities", "5 · Análisis de vulnerabilidades"),
    ("attacks", "6 · Modelado de ataques"),
    ("risk", "7 · Riesgo e impacto"),
]


# ------------------------------------------------------------------ validación

def _text(value, limit: int, field: str, *, required: bool = False, multiline: bool = False) -> str:
    if value in (None, ""):
        if required:
            raise MethodError(f"Falta {field}")
        return ""
    if not isinstance(value, str) or len(value) > limit:
        raise MethodError(f"{field} admite hasta {limit} caracteres")
    cleaned = value.strip() if multiline else " ".join(value.split())
    allowed = {"\n", "\t"} if multiline else set()
    if any(ord(character) < 32 and character not in allowed for character in cleaned):
        raise MethodError(f"{field} contiene caracteres de control")
    return cleaned


def _identifier(value, used: set[str], field: str) -> str:
    if not isinstance(value, str) or not ID.fullmatch(value) or value in used:
        raise MethodError(f"{field} necesita un identificador único (minúsculas, números y guiones)")
    used.add(value)
    return value


def validate(payload: dict, *, elements: set[str]) -> dict:
    """Lo propio de cada enfoque. `elements`: ids de componentes y flujos del modelo, para los enlaces."""
    methodology = payload.get("methodology") or "stride"
    if methodology not in METHODOLOGIES:
        raise MethodError("Enfoque de modelado desconocido")
    result: dict = {"methodology": methodology}

    manual, used = [], set()
    raw_manual = payload.get("manual_threats") or []
    if not isinstance(raw_manual, list) or len(raw_manual) > LIMITS["manual_threats"]:
        raise MethodError(f"Como mucho {LIMITS['manual_threats']} amenazas propias")
    for raw in raw_manual:
        if not isinstance(raw, dict):
            raise MethodError("Amenaza propia inválida")
        element = raw.get("element") or ""
        if element and element not in elements:
            raise MethodError("Una amenaza propia apunta a un elemento que no existe")
        severity = raw.get("severity") or "medium"
        if severity not in SEVERITIES:
            raise MethodError("Severidad inválida")
        manual.append({"id": _identifier(raw.get("id"), used, "Cada amenaza propia"),
                       "title": _text(raw.get("title"), 160, "El título", required=True),
                       "category": _text(raw.get("category"), 40, "La categoría"),
                       "element": element, "severity": severity,
                       "scenario": _text(raw.get("scenario"), 1500, "El escenario", multiline=True),
                       "mitigation": _text(raw.get("mitigation"), 1500, "La mitigación", multiline=True),
                       "likelihood": raw.get("likelihood") if raw.get("likelihood") in ("low", "medium", "high") else None,
                       "impact": raw.get("impact") if raw.get("impact") in ("low", "medium", "high") else None,
                       "owner": _text(raw.get("owner"), 80, "El responsable")})
    result["manual_threats"] = manual

    trees, tree_ids = [], set()
    raw_trees = payload.get("attack_trees") or []
    if not isinstance(raw_trees, list) or len(raw_trees) > LIMITS["attack_trees"]:
        raise MethodError(f"Como mucho {LIMITS['attack_trees']} árboles de ataque")
    for raw in raw_trees:
        if not isinstance(raw, dict):
            raise MethodError("Árbol de ataque inválido")
        nodes, node_ids = [], set()
        raw_nodes = raw.get("nodes") or []
        if not isinstance(raw_nodes, list) or len(raw_nodes) > LIMITS["tree_nodes"]:
            raise MethodError(f"Un árbol admite hasta {LIMITS['tree_nodes']} pasos")
        for node in raw_nodes:
            if not isinstance(node, dict):
                raise MethodError("Paso del árbol inválido")
            element = node.get("element") or ""
            if element and element not in elements:
                raise MethodError("Un paso del árbol apunta a un elemento que no existe")
            nodes.append({"id": _identifier(node.get("id"), node_ids, "Cada paso del árbol"), "parent": node.get("parent") or None,
                          "text": _text(node.get("text"), 200, "El paso", required=True),
                          "gate": "and" if node.get("gate") == "and" else "or", "element": element,
                          "difficulty": node.get("difficulty") if node.get("difficulty") in ("low", "medium", "high") else None,
                          "mitigated": bool(node.get("mitigated"))})
        ids = {node["id"] for node in nodes}
        parents = {node["id"]: node["parent"] for node in nodes}
        for node in nodes:
            if node["parent"] is not None and node["parent"] not in ids:
                raise MethodError("Un paso del árbol cuelga de otro que no existe")
            seen, current = set(), node["id"]
            while current is not None:  # sin ciclos
                if current in seen:
                    raise MethodError("El árbol de ataque tiene un ciclo")
                seen.add(current)
                current = parents.get(current)
        trees.append({"id": _identifier(raw.get("id"), tree_ids, "Cada árbol"),
                      "goal": _text(raw.get("goal"), 200, "El objetivo del atacante", required=True), "nodes": nodes})
    result["attack_trees"] = trees

    mappings, seen_pairs = [], set()
    raw_mappings = payload.get("attack_mappings") or []
    if not isinstance(raw_mappings, list) or len(raw_mappings) > LIMITS["attack_mappings"]:
        raise MethodError(f"Como mucho {LIMITS['attack_mappings']} técnicas mapeadas")
    for raw in raw_mappings:
        if not isinstance(raw, dict) or raw.get("technique") not in TECHNIQUES:
            raise MethodError("Técnica de ATT&CK desconocida")
        element = raw.get("element") or ""
        if element and element not in elements:
            raise MethodError("Una técnica apunta a un elemento que no existe")
        pair = (raw["technique"], element)
        if pair in seen_pairs:
            continue
        seen_pairs.add(pair)
        mappings.append({"technique": raw["technique"], "element": element,
                         "status": raw.get("status") if raw.get("status") in MAPPING_STATUS else "relevant",
                         "note": _text(raw.get("note"), 600, "La nota", multiline=True)})
    result["attack_mappings"] = mappings

    raw_pasta = payload.get("pasta") or {}
    if not isinstance(raw_pasta, dict) or not set(raw_pasta) <= {key for key, _ in PASTA_STAGES}:
        raise MethodError("Etapas de PASTA inválidas")
    result["pasta"] = {key: _text(raw_pasta.get(key), 4000, f"La etapa «{title}»", multiline=True)
                       for key, title in PASTA_STAGES if raw_pasta.get(key)}
    return result


def catalog() -> dict:
    """Lo que el panel necesita para cada enfoque; las guías de uso viven en el panel."""
    return {"methodologies": METHODOLOGIES, "linddun": LINDDUN, "tactics": TACTICS,
            "techniques": {key: {"name": name, "name_es": spanish, "tactics": tactics} for key, (name, spanish, tactics) in TECHNIQUES.items()},
            "suggestions": SUGGESTIONS, "pasta_stages": [{"key": key, "title": title} for key, title in PASTA_STAGES]}
