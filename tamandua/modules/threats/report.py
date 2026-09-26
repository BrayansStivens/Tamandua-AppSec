"""Informe del modelo de amenazas para el equipo de desarrollo (PDF y Markdown).

Lo que un equipo necesita para actuar, en este orden: cuánto hay y qué atender primero; el diagrama;
las amenazas que escribió el equipo (las más concretas); las que tienen indicios en los análisis; y las
de las reglas agrupadas por patrón (una medida corrige el patrón en todos sus componentes, en vez de
repetir la misma amenaza veinte veces). Lo exhaustivo (flujos, componentes, PASTA, árboles, ATT&CK) va
en anexos. El diagrama y la tabla de flujos comparten la numeración.
"""

from __future__ import annotations

from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, Spacer

from tamandua.modules.threats import diagram as threat_diagram
from tamandua.modules.threats import methods as threat_methods
from tamandua.modules.reporting.design import (ATTENTION, ATTENTION_BG, BRAND, BRAND_BG, DANGER_BG, INK, SEVERITY, SOFT, STYLE, SUCCESS,
                            SUCCESS_BG, WIDTH, DISCLAIMER, build, bullets, chip, h2, header, kpis, listing, meta, n, t, table, wide_page,
                            wide_size)

ORDER = ("critical", "high", "medium", "low")
PENDING = ("evidenced", "open")
STATUS = {"evidenced": "Con indicios", "open": "Abierta", "mitigated": "Mitigada", "accepted": "Aceptada", "not_applicable": "No aplica"}
LEVELS = {"low": "baja", "medium": "media", "high": "alta"}
FAMILY = {"stride": "STRIDE", "linddun": "LINDDUN", "manual": "Propia"}
SEVERITY_WORDS = {"critical": ("crítica", "críticas"), "high": ("alta", "altas"), "medium": ("media", "medias"), "low": ("baja", "bajas")}
NOTE = ("Las amenazas salen de reglas sobre el modelo declarado y de lo que escribe el equipo: si el modelo no refleja el sistema, "
        "tampoco lo harán las amenazas. Los indicios de los análisis son señales para revisar, no confirmaciones.")


def _worst(items: list[dict]) -> str:
    return min((item["severity"] for item in items), key=ORDER.index)


def _counts(items: list[dict]) -> str:
    return ", ".join(f"{value} {SEVERITY_WORDS[level][value != 1]}" for level in ORDER
                     if (value := sum(1 for item in items if item["severity"] == level)))


def digest(model: dict, rows: list[dict]) -> dict:
    """Todo lo que muestran el PDF y el Markdown, ya agrupado y ordenado."""
    from tamandua.modules.threats import model as tm
    components = {item["id"]: item for item in model.get("components", [])}
    flows = model.get("flows", [])
    number = {flow["id"]: index for index, flow in enumerate(flows, start=1)}
    pending = [row for row in rows if row["status"] in PENDING]
    team = [row for row in rows if row.get("framework") == "manual"]
    evidenced = [row for row in rows if row["status"] == "evidenced"]
    patterns: dict[tuple, list[dict]] = {}
    for row in pending:
        if row.get("framework") != "manual":
            patterns.setdefault((row["framework"], row["rule"]), []).append(row)

    def where(items: list[dict], limit: int = 8) -> str:
        flows_hit = sorted(number[item["element"]] for item in items if item["element_type"] == "flow" and item["element"] in number)
        names = [item["element_name"] for item in items if item["element_type"] != "flow"]
        parts = []
        if names:
            parts.append(listing(list(dict.fromkeys(names)), limit))
        if flows_hit:
            parts.append(("flujo " if len(flows_hit) == 1 else "flujos ") + listing([str(value) for value in flows_hit], limit + 2))
        return "; ".join(parts)

    grouped = []
    for (family, rule), items in patterns.items():
        first = items[0]
        grouped.append({"rule": rule, "family": family, "title": first["title"], "category": first["category"], "cwe": first["cwe"],
                        "why": first["why"], "mitigations": first["mitigations"], "severity": _worst(items), "count": len(items),
                        "counts": _counts(items), "where": where(items), "where_short": where(items, 3), "evidenced": sum(1 for item in items if item["status"] == "evidenced")})
    grouped.sort(key=lambda entry: (ORDER.index(entry["severity"]), -entry["evidenced"], -entry["count"], entry["title"]))
    team.sort(key=lambda row: (row["status"] not in PENDING, ORDER.index(row["severity"]), row["element_name"]))
    evidenced.sort(key=lambda row: (ORDER.index(row["severity"]), -row["evidence_count"], row["element_name"]))
    # Qué atender primero: lo concreto (indicios, lo que escribió el equipo) antes que los patrones genéricos.
    first = [("evidence", row) for row in evidenced if row["severity"] in ("critical", "high")]
    first += [("team", row) for row in team if row["status"] in PENDING and row["severity"] in ("critical", "high")]
    first += [("pattern", entry) for entry in grouped if entry["severity"] == "critical"]
    first.sort(key=lambda pair: ORDER.index(pair[1]["severity"]))
    by_component = []
    for component in model.get("components", []):
        own = [row for row in pending if row["element"] == component["id"]]
        by_component.append({"component": component, "counts": {level: sum(1 for row in own if row["severity"] == level) for level in ORDER},
                             "total": len(own)})
    by_component.sort(key=lambda entry: tuple(-entry["counts"][level] for level in ORDER) + (entry["component"]["name"],))
    member_of = {member: boundary["name"] for boundary in model.get("boundaries", []) for member in boundary["components"]}
    decided = [row for row in rows if row["status"] not in PENDING]
    method = model.get("methodology") or "stride"
    linked = [item for item in model.get("components", []) if item.get("asset")]
    return {"linked": linked, "components": components, "flows": flows, "number": number, "pending": pending, "team": team, "evidenced": evidenced,
            "patterns": grouped, "first": first[:8], "by_component": by_component, "member_of": member_of, "decided": decided,
            "method_label": threat_methods.METHODOLOGIES.get(method, method), "kinds": tm.KINDS, "labels": tm.CLASSIFICATION_LABELS,
            "severity": {level: sum(1 for row in pending if row["severity"] == level) for level in ORDER},
            "rule_based": sum(1 for row in rows if row.get("framework") != "manual")}


def coverage(model: dict, data: dict) -> list[str]:
    """Cómo salen las amenazas y qué no se pudo contrastar: sin repositorios, «sin indicios» no significa «sin fallos»."""
    total, linked = len(data["components"]), len(data["linked"])
    lines = [f"Enfoque {data['method_label']}: las amenazas salen de reglas sobre el modelo declarado (componentes, flujos, datos y "
             f"exposición) y de las que escribe el equipo ({len(data['team'])})."]
    if linked:
        lines.append(f"{linked} de {total} componentes tienen repositorio enlazado: solo en ellos se buscan indicios en los hallazgos "
                     "abiertos del último análisis. Los demás se evalúan solo por lo declarado.")
    else:
        lines.append("Ningún componente tiene repositorio enlazado: no se buscaron indicios en los análisis. Que ninguna amenaza tenga "
                     "indicios no significa que el sistema no tenga fallos.")
    if model.get("repository_refs"):
        lines.append(f"Referencias a repositorios pendientes de vincular: {listing(list(model['repository_refs']), 6)}.")
    return lines


def _kind(entry: dict, kinds: dict) -> str:
    return entry.get("custom_kind") or kinds.get(entry["kind"], entry["kind"])


def _element_name(model: dict, data: dict, element: str) -> str:
    if element in data["components"]:
        return data["components"][element]["name"]
    for flow in data["flows"]:
        if flow["id"] == element:
            return f"flujo {data['number'][element]} ({data['components'][flow['source']]['name']} → {data['components'][flow['target']]['name']})"
    return "todo el sistema"


# ------------------------------------------------------------------ PDF

def render_pdf(model: dict, rows: list[dict], *, version: str) -> bytes:
    data = digest(model, rows)
    counts = data["severity"]
    team_open = sum(1 for row in data["team"] if row["status"] in PENDING)
    story = header("Modelo de amenazas", model["name"], model.get("description") or "")
    repositories = len(model.get("repositories") or []) + len(model.get("repository_refs") or [])
    story.append(meta([("Enfoque", data["method_label"]),
                       ("Actualizado", f"{str(model.get('updated_at') or '')[:10] or '—'} · {model.get('updated_by') or '—'}"),
                       ("Alcance", f"{len(data['components'])} componentes · {len(data['flows'])} flujos · {len(model.get('boundaries') or [])} fronteras"),
                       ("Repositorios enlazados", str(repositories) if repositories else "Ninguno"),
                       ("Amenazas del equipo", str(len(data["team"]))), ("Referencia", str(model.get("id") or "—")[:24])]))
    story += [Spacer(1, 10), h2("Resumen"),
              kpis([("abiertas", len(data["pending"]), INK, SOFT), ("críticas", counts["critical"], SEVERITY["critical"][1], DANGER_BG),
                    ("altas", counts["high"], ATTENTION, ATTENTION_BG), ("con indicios en los análisis", len(data["evidenced"]), ATTENTION, ATTENTION_BG),
                    ("escritas por el equipo", team_open, BRAND, BRAND_BG), ("decididas", len(data["decided"]), SUCCESS, SUCCESS_BG)]),
              Spacer(1, 6),
              Paragraph(t(f"{n(len(rows), 'amenaza', 'amenazas')}: {data['rule_based']} de las reglas del enfoque sobre {len(data['components'])} "
                          f"componentes y {len(data['flows'])} flujos, que se reducen a {n(len(data['patterns']), 'patrón', 'patrones')}, y "
                          f"{len(data['team'])} escritas por el equipo. "
                          + (f"{n(len(data['evidenced']), 'tiene', 'tienen')} indicios en hallazgos abiertos de los análisis. " if data["evidenced"]
                             else "Ninguna tiene indicios en los análisis enlazados. " if data["linked"]
                             else "No se buscaron indicios: ningún componente tiene un repositorio enlazado. ")
                          + f"{n(len(data['decided']), 'está decidida', 'están decididas')} (mitigada, aceptada o no aplica).", 900), STYLE["body"]),
              Paragraph("Cómo leerlo: empieza por «Qué atender primero»; cada patrón de las reglas se corrige con una misma medida en todos los "
                        "componentes que lista; el diagrama y la tabla de flujos (anexo A) usan la misma numeración.", STYLE["note"])]
    if data["first"]:
        story.append(h2("Qué atender primero"))
        body = []
        for source, item in data["first"]:
            if source == "pattern":
                body.append([chip(item["severity"]), f"<b>{t(item['title'], 140)}</b><br/>{t(item['category'], 80)} · patrón en {item['count']}",
                             t(item["where_short"], 200), t("; ".join(item["mitigations"][:2]), 260)])
            else:
                label = "Con indicios" if source == "evidence" else "Del equipo"
                body.append([chip(item["severity"]), f"<b>{t(item['title'], 140)}</b><br/><font color=\"#636363\">{label}</font>",
                             t(_element_name(model, data, item["element"]) if item["element"] else item["element_name"], 160),
                             t("; ".join(item["mitigations"][:2]) or "—", 260)])
        story.append(table(["Severidad", "Amenaza", "Dónde", "Qué hacer"], body, [19 * mm, 55 * mm, 45 * mm, WIDTH - 119 * mm]))
    # El diagrama, en una página apaisada (A3 si es grande: sigue siendo vectorial y se puede ampliar).
    if data["components"]:
        drawn = threat_diagram.scene(model, data["kinds"])
        _, _, width, height = drawn["bounds"]
        area = wide_size(None)
        size = "a3" if min(area[0] / width, area[1] / height) < 0.5 else None  # por debajo, el texto no se lee impreso
        area = wide_size(size)
        story += wide_page([Paragraph("Diagrama", STYLE["h3"]), threat_diagram.to_drawing(model, area[0], area[1] - 12 * mm, data["kinds"])], size=size)
    if data["team"]:
        story.append(h2(f"Amenazas identificadas por el equipo ({len(data['team'])})"))
        body = []
        for row in data["team"]:
            extra = " · ".join(value for value in (f"posibilidad {LEVELS[row['likelihood']]}" if row.get("likelihood") else "",
                                                     f"impacto {LEVELS[row['impact']]}" if row.get("impact") else "") if value)
            body.append([chip(row["severity"]),
                         f"<b>{t(row['title'], 160)}</b>" + (f'<br/><font color="#636363">{t(row["why"], 320)}</font>' if row["why"] else ""),
                         t(row["element_name"], 120) + (f'<br/><font color="#636363">{t(extra, 80)}</font>' if extra else ""),
                         t("; ".join(row["mitigations"]) or "—", 320),
                         t(STATUS[row["status"]], 30) + (f'<br/><font color="#636363">{t(row["owner"], 60)}</font>' if row.get("owner") else "")])
        story.append(table(["Severidad", "Amenaza y escenario", "Dónde", "Mitigación", "Estado"], body,
                           [19 * mm, 62 * mm, 32 * mm, WIDTH - 131 * mm, 18 * mm]))
    if data["evidenced"]:
        story.append(h2(f"Con indicios en los análisis ({len(data['evidenced'])})"))
        body = []
        for row in data["evidenced"]:
            evidence = "<br/>".join(f"{t(item['title'], 80)} · {t(item['location'], 80)}" for item in row["evidence"][:3])
            more = row["evidence_count"] - min(3, len(row["evidence"]))
            body.append([chip(row["severity"]), f"<b>{t(row['title'], 140)}</b>", t(row["element_name"], 120),
                         evidence + (f"<br/>y {more} más" if more > 0 else "")])
        story.append(table(["Severidad", "Amenaza", "Dónde", "Indicios (hallazgos abiertos)"], body, [19 * mm, 50 * mm, 38 * mm, WIDTH - 107 * mm]))
        story.append(Paragraph("Un indicio es un hallazgo abierto del código del componente relacionado con la amenaza: una señal para revisar, "
                               "no una confirmación.", STYLE["note"]))
    if data["patterns"]:
        pending_rules = sum(entry["count"] for entry in data["patterns"])
        story.append(h2(f"Patrones de las reglas ({len(data['patterns'])} patrones · {pending_rules} amenazas)"))
        body = [[chip(entry["severity"]),
                 f"<b>{t(entry['title'], 140)}</b><br/><font color=\"#636363\">{t(entry['category'], 60)}"
                 + (f" · CWE-{', CWE-'.join(str(value) for value in entry['cwe'][:3])}" if entry["cwe"] else "") + "</font>",
                 f"<b>{entry['count']}</b> · {t(entry['counts'], 80)}<br/>{t(entry['where'], 320)}",
                 t("; ".join(entry["mitigations"][:3]), 300)] for entry in data["patterns"]]
        story.append(table(["Severidad", "Patrón", "Afecta a", "Medida"], body, [19 * mm, 50 * mm, 55 * mm, WIDTH - 124 * mm]))
        story.append(Paragraph("La severidad es la peor entre los componentes del patrón (sube con Internet, datos sensibles o indicios). "
                               "El detalle por componente está en el panel.", STYLE["note"]))
    story.append(h2(f"Decisiones ({len(data['decided'])})"))
    if data["decided"]:
        body = [[t(row["title"], 120), t(row["element_name"], 100), t(STATUS[row["status"]], 20),
                 t((row.get("decision") or {}).get("reason") or "—", 240), t((row.get("decision") or {}).get("by") or "—", 40)]
                for row in data["decided"][:400]]
        story.append(table(["Amenaza", "Dónde", "Decisión", "Motivo", "Por"], body, [50 * mm, 36 * mm, 20 * mm, WIDTH - 128 * mm, 22 * mm]))
        if len(data["decided"]) > 400:
            story.append(Paragraph(f"Se muestran 400 de {len(data['decided'])} decisiones; todas están en el panel.", STYLE["note"]))
    else:
        story.append(Paragraph("Todavía no hay amenazas mitigadas, aceptadas ni descartadas: cada decisión se registra en el panel con su motivo.", STYLE["body"]))
    # Anexos
    if data["flows"]:
        story.append(h2("Anexo A · Flujos del diagrama"))
        body = [[str(data["number"][flow["id"]]), t(f"{data['components'][flow['source']]['name']} → {data['components'][flow['target']]['name']}", 140),
                 flow["protocol"].upper(), t(flow.get("name") or "—", 160) + (f'<br/><font color="#636363">{t(", ".join(data["labels"][item] for item in flow["data"]), 80)}</font>' if flow.get("data") else ""),
                 "sí" if flow.get("authenticated") else '<font color="#b71824">no</font>', "sí" if flow.get("encrypted") else '<font color="#b71824">no</font>']
                for flow in data["flows"]]
        story.append(table(["N.º", "Origen → destino", "Protocolo", "Qué viaja", "Autent.", "Cifrado"], body,
                           [10 * mm, 62 * mm, 18 * mm, WIDTH - 124 * mm, 17 * mm, 17 * mm]))
    story.append(h2("Anexo B · Componentes"))
    body = []
    for entry in data["by_component"]:
        component = entry["component"]
        exposure = ", ".join(value for value in ("Internet" if component.get("internet_facing") else "",
                                                 ", ".join(data["labels"][item] for item in component.get("data") or [])) if value)
        body.append([f"<b>{t(component['name'], 80)}</b><br/><font color=\"#636363\">{t(_kind(component, data['kinds']), 50)}"
                     + (f" · {t(component['technology'], 40)}" if component.get("technology") else "") + "</font>",
                     t(data["member_of"].get(component["id"], "—"), 60), t(exposure or "—", 90),
                     *[(f'<font color="{SEVERITY[level][1 if level == "critical" else 0].hexval().replace("0x", "#")}"><b>{entry["counts"][level]}</b></font>'
                        if entry["counts"][level] else '<font color="#636363">0</font>') for level in ORDER]])
    story.append(table(["Componente", "Frontera", "Exposición y datos", "Crít.", "Altas", "Medias", "Bajas"], body,
                       [54 * mm, 36 * mm, WIDTH - 146 * mm, 14 * mm, 14 * mm, 14 * mm, 14 * mm]))
    story += _methods_pdf(model, data)
    story += [h2("Método y cobertura"), *bullets([t(line, 600) for line in coverage(model, data)]),
              Spacer(1, 8), Paragraph(t(NOTE, 400) + " " + DISCLAIMER, STYLE["note"])]
    return build(story, title=f"Modelo de amenazas · {model['name']}", footer=f"Modelo de amenazas · {model['name'][:80]}", version=version,
                 author=str(model.get("updated_by") or "Tamandua"), subject="Modelo de amenazas")


def _methods_pdf(model: dict, data: dict) -> list:
    story = []
    notes = model.get("pasta") or {}
    if any(notes.values()):
        story.append(h2("Anexo C · PASTA"))
        for key, title in threat_methods.PASTA_STAGES:
            if notes.get(key):
                story += [Paragraph(t(title, 80), STYLE["h3"]), Paragraph(t(notes[key], 3000), STYLE["body"])]
    for index, tree in enumerate(model.get("attack_trees") or []):
        story.append(h2(f"Anexo D · Árbol de ataque · {tree['goal'][:90]}") if index == 0 else Paragraph(t(f"Árbol de ataque · {tree['goal']}", 120), STYLE["h3"]))
        lines = []
        for depth, node in _walk(tree):
            extra = [f"dificultad {LEVELS[node['difficulty']]}" if node.get("difficulty") else "",
                     f"sobre {_element_name(model, data, node['element'])}" if node.get("element") else "", "mitigado" if node.get("mitigated") else ""]
            gate = " (se necesitan todos)" if node["gate"] == "and" and node["has_children"] else ""
            lines.append(Paragraph("&nbsp;" * 6 * depth + "•&nbsp;&nbsp;" + t(node["text"], 200) + t(gate, 40)
                                   + (f' <font color="#636363">· {t(", ".join(value for value in extra if value), 160)}</font>' if any(extra) else ""),
                                   STYLE["body"]))
        story += lines
    mappings = model.get("attack_mappings") or []
    if mappings:
        status = {"relevant": "relevante", "mitigated": "mitigada", "not_applicable": "no aplica"}
        story.append(h2("Anexo E · MITRE ATT&CK"))
        body = []
        for item in mappings:
            name, _, tactics = threat_methods.TECHNIQUES[item["technique"]]
            body.append([f"<b>{t(item['technique'], 12)}</b> {t(name, 80)}", t(", ".join(threat_methods.TACTICS[tactic] for tactic in tactics), 80),
                         t(_element_name(model, data, item["element"]) if item.get("element") else "todo el sistema", 100), status[item["status"]],
                         t(item.get("note") or "—", 200)])
        story.append(table(["Técnica", "Táctica", "Elemento", "Estado", "Nota"], body, [46 * mm, 30 * mm, 38 * mm, 18 * mm, WIDTH - 132 * mm]))
        story.append(Paragraph("MITRE ATT&amp;CK® es una marca de The MITRE Corporation: https://attack.mitre.org", STYLE["note"]))
    return story


def _walk(tree: dict):
    children: dict = {}
    for node in tree["nodes"]:
        children.setdefault(node["parent"], []).append(node)

    def walk(parent, depth):
        for node in children.get(parent, []):
            yield depth, {**node, "has_children": bool(children.get(node["id"]))}
            yield from walk(node["id"], depth + 1)
    return walk(None, 0)


# ------------------------------------------------------------------ Markdown

def _cell(value) -> str:
    return " ".join(str(value or "").split()).replace("|", "\\|")


def to_markdown(model: dict, rows: list[dict]) -> str:
    """El mismo informe en Markdown (para un wiki, un ticket o un pull request)."""
    data = digest(model, rows)
    counts = data["severity"]
    names = {"critical": "Crítica", "high": "Alta", "medium": "Media", "low": "Baja"}
    lines = [f"# Modelo de amenazas · {model['name']}", "", model.get("description") or "", "",
             f"Enfoque: **{data['method_label']}** · actualizado {str(model.get('updated_at') or '')[:16].replace('T', ' ')} por {model.get('updated_by') or '—'} · "
             f"{len(data['components'])} componentes, {len(data['flows'])} flujos, {len(model.get('boundaries') or [])} fronteras.", "",
             "## Resumen", "",
             f"- **{len(data['pending'])} abiertas**: {counts['critical']} críticas, {counts['high']} altas, {counts['medium']} medias y {counts['low']} bajas.",
             f"- {data['rule_based']} salen de las reglas del enfoque y se reducen a **{len(data['patterns'])} patrones**; {len(data['team'])} las escribió el equipo.",
             (f"- {len(data['evidenced'])} con indicios en hallazgos abiertos de los análisis (señal para revisar, no confirmación); "
              if data["linked"] else "- No se buscaron indicios en los análisis: ningún componente tiene repositorio enlazado; ")
             + f"{len(data['decided'])} decididas (mitigadas, aceptadas o no aplican).", ""]
    if data["first"]:
        lines += ["## Qué atender primero", "", "| Severidad | Amenaza | Dónde | Qué hacer |", "|---|---|---|---|"]
        for source, item in data["first"]:
            where = item["where_short"] if source == "pattern" else (_element_name(model, data, item["element"]) if item["element"] else item["element_name"])
            title = f"{item['title']} (patrón en {item['count']})" if source == "pattern" else item["title"]
            lines.append(f"| {names[item['severity']]} | {_cell(title)} | {_cell(where)} | {_cell('; '.join(item['mitigations'][:2]) or '—')} |")
        lines.append("")
    if data["team"]:
        lines += [f"## Amenazas identificadas por el equipo ({len(data['team'])})", ""]
        for row in data["team"]:
            lines += [f"### {names[row['severity']]} · {row['title']}", "",
                      f"{row['element_name']} · {row['category']} · estado: **{STATUS[row['status']].lower()}**"
                      + (f" · responsable: {row['owner']}" if row.get("owner") else "")
                      + (f" · posibilidad {LEVELS[row['likelihood']]}" if row.get("likelihood") else "")
                      + (f" · impacto {LEVELS[row['impact']]}" if row.get("impact") else ""), ""]
            if row["why"]:
                lines += [row["why"], ""]
            if row["mitigations"]:
                lines += ["Mitigación: " + "; ".join(row["mitigations"]), ""]
    if data["evidenced"]:
        lines += [f"## Con indicios en los análisis ({len(data['evidenced'])})", "", "| Severidad | Amenaza | Dónde | Indicios |", "|---|---|---|---|"]
        for row in data["evidenced"]:
            evidence = "; ".join(f"{item['title']} en `{item['location']}`" for item in row["evidence"][:3])
            lines.append(f"| {names[row['severity']]} | {_cell(row['title'])} | {_cell(row['element_name'])} | {_cell(evidence)} |")
        lines.append("")
    if data["patterns"]:
        lines += [f"## Amenazas por patrón ({len(data['patterns'])} patrones)", "",
                  "Cada patrón se corrige con la misma medida en todos los componentes que lista.", "",
                  "| Severidad | Patrón | Afecta a | Medida |", "|---|---|---|---|"]
        for entry in data["patterns"]:
            cwe = f" · CWE-{', CWE-'.join(str(value) for value in entry['cwe'][:3])}" if entry["cwe"] else ""
            lines.append(f"| {names[entry['severity']]} | {_cell(entry['title'])} ({_cell(entry['category'])}{cwe}) | "
                         f"{entry['count']} ({entry['counts']}): {_cell(entry['where'])} | {_cell('; '.join(entry['mitigations'][:3]))} |")
        lines.append("")
    if data["decided"]:
        lines += [f"## Decisiones ({len(data['decided'])})", "", "| Amenaza | Dónde | Decisión | Motivo | Por |", "|---|---|---|---|---|"]
        for row in data["decided"]:
            decision = row.get("decision") or {}
            lines.append(f"| {_cell(row['title'])} | {_cell(row['element_name'])} | {STATUS[row['status']]} | {_cell(decision.get('reason') or '—')} | {_cell(decision.get('by') or '—')} |")
        lines.append("")
    if data["flows"]:
        lines += ["## Anexo A · Flujos del diagrama", "", "| N.º | Origen → destino | Protocolo | Qué viaja | Autenticado | Cifrado |", "|---|---|---|---|---|---|"]
        for flow in data["flows"]:
            lines.append(f"| {data['number'][flow['id']]} | {_cell(data['components'][flow['source']]['name'])} → {_cell(data['components'][flow['target']]['name'])} | "
                         f"{flow['protocol'].upper()} | {_cell(flow.get('name') or '—')} | {'sí' if flow.get('authenticated') else 'no'} | {'sí' if flow.get('encrypted') else 'no'} |")
        lines.append("")
    lines += ["## Anexo B · Componentes", "", "| Componente | Tipo | Frontera | Datos | Expuesto | Abiertas (C/A/M/B) |", "|---|---|---|---|---|---|"]
    for entry in data["by_component"]:
        component = entry["component"]
        lines.append(f"| {_cell(component['name'])} | {_cell(_kind(component, data['kinds']))} | {_cell(data['member_of'].get(component['id'], '—'))} | "
                     f"{_cell(', '.join(data['labels'][item] for item in component.get('data') or []) or '—')} | {'sí' if component.get('internet_facing') else 'no'} | "
                     f"{'/'.join(str(entry['counts'][level]) for level in ORDER)} |")
    lines.append("")
    notes = model.get("pasta") or {}
    if any(notes.values()):
        lines += ["## Anexo C · PASTA", ""]
        for key, title in threat_methods.PASTA_STAGES:
            if notes.get(key):
                lines += [f"### {title}", "", notes[key], ""]
    for tree in model.get("attack_trees") or []:
        lines += [f"## Anexo D · Árbol de ataque · {tree['goal']}", ""]
        for depth, node in _walk(tree):
            extra = [f"dificultad {LEVELS[node['difficulty']]}" if node.get("difficulty") else "",
                     f"sobre {_element_name(model, data, node['element'])}" if node.get("element") else "", "mitigado" if node.get("mitigated") else ""]
            gate = " (se necesitan todos)" if node["gate"] == "and" and node["has_children"] else ""
            lines.append(f"{'  ' * depth}- {node['text']}{gate}" + (f" · {', '.join(item for item in extra if item)}" if any(extra) else ""))
        lines.append("")
    mappings = model.get("attack_mappings") or []
    if mappings:
        status = {"relevant": "relevante", "mitigated": "mitigada", "not_applicable": "no aplica"}
        lines += ["## Anexo E · MITRE ATT&CK", "", "| Técnica | Táctica | Elemento | Estado | Nota |", "|---|---|---|---|---|"]
        for item in mappings:
            name, _, tactics = threat_methods.TECHNIQUES[item["technique"]]
            element = _element_name(model, data, item["element"]) if item.get("element") else "todo el sistema"
            lines.append(f"| {item['technique']} {name} | {', '.join(threat_methods.TACTICS[tactic] for tactic in tactics)} | "
                         f"{_cell(element)} | {status[item['status']]} | {_cell(item.get('note') or '')} |")
        lines += ["", "MITRE ATT&CK® es una marca de The MITRE Corporation: https://attack.mitre.org", ""]
    lines += ["## Método y cobertura", "", *(f"- {line}" for line in coverage(model, data)), "", f"> {NOTE} {DISCLAIMER}", ""]
    return "\n".join(lines)

