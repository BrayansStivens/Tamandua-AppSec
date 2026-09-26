"""Agrupar hallazgos por corrección: lo que un equipo de desarrollo hace, no lo que un motor reporta.

Los avisos de un mismo paquete (mismo manifiesto y versión) se cierran con una sola actualización: la
versión más alta entre las que corrigen cada aviso. El código, los secretos y la infraestructura se
atienden uno a uno, pero una misma regla repetida en varios archivos es un solo patrón que corregir.
"""

from __future__ import annotations

import re

from tamandua.modules.intel.advisories import compare_versions

ORDER = {level: index for index, level in enumerate(("critical", "high", "medium", "low", "info"))}


def _worst(items: list[dict]) -> str:
    return min((item.get("severity") or "info" for item in items), key=lambda level: ORDER.get(level, 9))


def _counts(items: list[dict]) -> dict[str, int]:
    return {level: sum(1 for item in items if item.get("severity") == level) for level in ORDER if any(item.get("severity") == level for item in items)}


def _ids(items: list[dict]) -> list[str]:
    ids = []
    for item in items:
        ids += (item.get("cve") or [])[:1] or (item.get("ghsa") or [])[:1] or ([item["rule_id"]] if item.get("rule_id") else [])
    return list(dict.fromkeys(ids))


def fix_groups(findings: list[dict], *, by_rule: bool = False) -> list[dict]:
    """Una entrada por corrección, en orden de prioridad (explotación activa, severidad, alcance).

    Cada entrada: kind («package» o «finding»), severity (la peor), items, counts, ids, kev, epss,
    y para paquetes name, version, path, target (versión que cierra todos) y complete (todos tienen corrección).
    Con by_rule, los hallazgos de código de una misma regla se juntan (kind «rule»)."""
    groups: dict[tuple, list[dict]] = {}
    for item in findings:
        package = item.get("package") or {}
        if item.get("scanner") == "sca" and package.get("name"):
            key = ("package", item.get("path") or "", package["name"], package.get("version") or "")
        elif by_rule and item.get("rule_id"):
            key = ("rule", item.get("scanner") or "", item["rule_id"])
        else:
            key = ("finding", item.get("fingerprint") or id(item))
        groups.setdefault(key, []).append(item)
    result = []
    for key, items in groups.items():
        entry = {"kind": key[0], "severity": _worst(items), "items": items, "counts": _counts(items), "ids": _ids(items),
                 "kev": any(item.get("kev") for item in items), "malicious": any(item.get("malicious") for item in items),
                 "epss": max(((item.get("epss") or {}).get("score") or 0 for item in items), default=0)}
        if key[0] == "package":
            fixes = [item["package"]["fixed_version"] for item in items if item["package"].get("fixed_version")]
            target = None
            for fix in fixes:
                target = fix if target is None or compare_versions(fix, target) > 0 else target
            entry.update(path=key[1], name=key[2], version=key[3], target=target, complete=bool(fixes) and len(fixes) == len(items),
                         ecosystem=(items[0]["package"].get("ecosystem") or ""))
        elif key[0] == "rule":
            entry.update(rule=key[2], title=items[0].get("title") or key[2])
        result.append(entry)
    # Lo malicioso y lo explotado activamente, primero.
    return sorted(result, key=lambda entry: (not entry["malicious"], not entry["kev"], ORDER.get(entry["severity"], 9), -len(entry["items"]), -entry["epss"],
                                             entry.get("path") or entry["items"][0].get("path") or ""))


def action(entry: dict, *, short: bool = False) -> str:
    """Qué hacer, en una frase. `short`: para una celda de tabla (el detalle lleva la guía completa)."""
    if entry.get("malicious"):
        # Código hostil: no hay versión que «corrija», se quita (mismo criterio que la guía de corrección del panel).
        return f"Eliminar {entry.get('name') or 'el paquete'} {entry.get('version') or ''} y rotar las credenciales de donde se instaló".replace("  ", " ")
    if entry["kind"] == "package":
        name, count = entry["name"], len(entry["items"])
        fixed = sum(1 for item in entry["items"] if item["package"].get("fixed_version"))
        if entry["target"] and entry["complete"]:
            return f"Actualizar {name} a {entry['target']}" + (f" (cierra los {count})" if count > 1 else "")
        if entry["target"]:
            return f"Actualizar {name} a {entry['target']}: cierra {fixed} de {count}; el resto no tiene corrección publicada"
        return "Sin versión corregida: evaluar alcanzabilidad, mitigar o sustituir" if short else \
               f"No hay versión corregida de {name}: evalúa alcanzabilidad, mitiga o sustituye la dependencia"
    text = entry["items"][0].get("remediation") or "Revisar y corregir según la guía del hallazgo"
    if short:
        first = re.split(r"(?<=[.;])\s", text, maxsplit=1)[0]
        return first if len(first) <= 110 else first[:110].rsplit(" ", 1)[0] + "…"
    return text


def counts_text(counts: dict[str, int]) -> str:
    names = {"critical": ("crítica", "críticas"), "high": ("alta", "altas"), "medium": ("media", "medias"),
             "low": ("baja", "bajas"), "info": ("informativa", "informativas")}
    return ", ".join(f"{value} {names[level][value != 1]}" for level, value in counts.items())
