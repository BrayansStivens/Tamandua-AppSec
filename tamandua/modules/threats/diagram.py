"""Diagrama del modelo de amenazas: colocación automática, colores y dibujo (SVG y PDF).

La colocación es la misma que la del editor del panel (web/src/features/threats/threat-layout.ts); si cambia
una, cambia la otra. Principios, para que un humano lo entienda y lo quiera editar:
- Columnas según el recorrido de los datos, no según el tipo: lo que entra desde Internet a la izquierda,
  lo que recibe datos a su derecha y los terceros al final. Los flujos de vuelta (respuestas, webhooks)
  no empujan columnas: cuenta la distancia a los actores.
- Cada frontera es un bloque que contiene a sus componentes; los bloques nunca se solapan.
- Dentro de cada columna, cada bloque se coloca a la altura de aquello con lo que habla (menos cruces).
- Rejilla de 8 px, pilas de 5 como mucho (más se reparten en columnas) y etiquetas cortas: número de
  flujo y protocolo. Lo que viaja por cada flujo está en la tabla del informe, con el mismo número.

El dibujo se describe una sola vez (una lista de primitivas) y se pinta en SVG o en PDF: el diagrama del
informe y el que se exporta son idénticos. Todo texto del modelo se escapa en el SVG y en el PDF se dibuja
como texto plano, nunca como marcado.
"""

from __future__ import annotations

import html
import math

from tamandua.shared.i18n import default_locale, localize, msg, t

# Paleta: los tokens del panel (web/src/index.css, modo claro). (tinta ≥ 4,5:1 sobre blanco, relleno suave)
COLORS = {
    "neutral": ("#525252", "#f7f7f7"),
    "brand": ("#7342d3", "#f1ecfb"),
    "info": ("#00649e", "#e6f4fb"),
    "success": ("#006e42", "#e6f5ef"),
    "warning": ("#8a4c00", "#fdf5e6"),
    "attention": ("#a34100", "#fef0e6"),
    "danger": ("#b71824", "#fce9ea"),
}
COLOR_NAMES = {"neutral": msg("threats.colors.neutral"), "brand": msg("threats.colors.brand"), "info": msg("threats.colors.info"),
               "success": msg("threats.colors.success"), "warning": msg("threats.colors.warning"),
               "attention": msg("threats.colors.attention"), "danger": msg("threats.colors.danger")}
# Sin color elegido, cada componente toma el de su papel; la leyenda lo explica.
KIND_COLOR = {"actor": "neutral", "external": "neutral", "web_app": "brand", "api": "info", "service": "info", "function": "info",
              "database": "success", "cache": "success", "queue": "success", "storage": "success", "identity": "warning"}
LEGEND = [("brand", msg("threats.diagram.legend_clients")), ("info", msg("threats.diagram.legend_services")),
          ("success", msg("threats.diagram.legend_data")), ("warning", msg("threats.diagram.legend_identity")),
          ("neutral", msg("threats.diagram.legend_actors"))]
INK, MUTED, LINE, WHITE = "#171717", "#636363", "#c7c7c7", "#ffffff"
FONT = "Helvetica, Arial, sans-serif"

NODE_W, NODE_H, DRAW_H = 184, 88, 72
GAP_X, GAP_INNER, GAP_GRID, GAP_Y, PAD, HEADER, SNAP = 136, 112, 40, 40, 32, 44, 8
MAX_STACK = 5
LAYERS = {"actor": 0, "web_app": 1, "identity": 3, "api": 2, "service": 2, "function": 2, "cache": 3, "queue": 3,
          "database": 3, "storage": 3, "external": 4}
PROCESSES = {"web_app", "api", "service", "function"}
STORES = {"database", "cache", "queue", "storage"}


def base_kind(component: dict) -> str:
    return (component.get("custom_base") or "service") if component["kind"] == "custom" else component["kind"]


def layer(component: dict) -> int:
    return LAYERS.get(base_kind(component), 2)


def node_size(component: dict) -> tuple[float, float]:
    size = component.get("size") or {}
    return size.get("width") or NODE_W, size.get("height") or NODE_H


def color_of(item: dict, *, boundary: bool = False) -> str:
    if item.get("color") in COLORS:
        return item["color"]
    return "neutral" if boundary else KIND_COLOR.get(base_kind(item), "neutral")


def is_manual(component: dict) -> bool:
    """A chosen color that differs from the role's color: it needs its own legend entry."""
    return component.get("color") in COLORS and component["color"] != KIND_COLOR.get(base_kind(component), "neutral")


def legend_tones(model: dict) -> tuple[list[str], list[str]]:
    """Legend tones in use: (role colors, in LEGEND order; manual colors, in palette order). Same as legendTones in threat-colors.ts."""
    components = model.get("components", [])
    automatic = {color_of(item) for item in components if not is_manual(item)}
    manual = {item["color"] for item in components if is_manual(item)}
    return [tone for tone, _ in LEGEND if tone in automatic], [tone for tone in COLORS if tone in manual]


def _snap(value: float) -> float:
    # Como Math.round del editor (la mitad, hacia arriba), no el redondeo al par de round().
    return math.floor(value / SNAP + 0.5) * SNAP


# ------------------------------------------------------------------ colocación

def _inner_ranks(ids: list[str], edges: list[tuple[str, str]], seed) -> dict[str, int]:
    """Columnas dentro de una frontera: el papel de cada componente, empujado por los flujos internos."""
    rank = {item: seed(item) for item in ids}
    known = set(ids)
    forward = [(a, b) for a, b in edges if a != b and a in known and b in known and seed(a) <= seed(b)]
    for _ in ids:
        changed = False
        for a, b in forward:
            if rank[b] < rank[a] + 1:
                rank[b], changed = rank[a] + 1, True
        if not changed:
            break
    levels = sorted(set(rank.values()))
    return {item: levels.index(rank[item]) for item in ids}


def _group_ranks(ids: list[str], edges: list[tuple[str, str]], seed: dict[str, int], sinks: set[str]) -> dict[str, int]:
    """Columna de cada bloque según el recorrido de los datos.

    Primero, a cuántos saltos está cada bloque de los actores (lo que entra desde fuera). Un flujo cuenta
    «hacia delante» si se aleja de los actores (o, a la misma distancia, va de un papel anterior a uno
    posterior: aplicación → datos). Los que vuelven (respuestas, webhooks, ciclos) no empujan columnas.
    Con los de delante, cada bloque va una columna a la derecha del último que le envía datos. Lo que
    nada alimenta (una cadena de CI) se acerca a su destino y los terceros que solo reciben van al final."""
    targets: dict[str, list[str]] = {item: [] for item in ids}
    for a, b in edges:
        if b not in targets[a]:
            targets[a].append(b)
    fed = {b for _, b in edges}
    starts = [item for item in ids if seed[item] == 0] or [item for item in ids if item not in fed] or ids[:1]
    distance = {item: 0 for item in starts}
    queue = list(starts)
    while queue:
        item = queue.pop(0)
        for other in targets[item]:
            if other not in distance:
                distance[other] = distance[item] + 1
                queue.append(other)
    for item in ids:
        distance.setdefault(item, -1)  # inalcanzable desde los actores: una fuente propia (CI, tareas)
    # Orden estricto (distancia, papel medio, orden del modelo): cada flujo entre bloques va hacia delante o
    # hacia atrás, nunca «de lado». Así dos bloques que se hablan no comparten columna (flechas verticales
    # que atraviesan componentes).
    key = {item: (distance[item], seed[item], index) for index, item in enumerate(ids)}
    forward = [(a, b) for a in ids for b in targets[a] if key[a] < key[b]]
    incoming: dict[str, list[str]] = {item: [] for item in ids}
    outgoing: dict[str, list[str]] = {item: [] for item in ids}
    for a, b in forward:
        incoming[b].append(a)
        outgoing[a].append(b)
    rank: dict[str, int] = {}
    for item in sorted(ids, key=key.get):  # el orden estricto es topológico para los flujos de delante
        rank[item] = max((rank[source] + 1 for source in incoming[item]), default=0)
    for item in sorted(ids, key=key.get, reverse=True):
        if seed[item] > 0 and not incoming[item] and outgoing[item]:
            rank[item] = max(0, min(rank[other] for other in outgoing[item]) - 1)
        elif seed[item] > 0 and not incoming[item] and not outgoing[item]:
            rank[item] = min(1, max(rank.values(), default=0))
    for item in ids:  # terceros que solo reciben: la última columna, como en cualquier diagrama de flujo de datos
        if item in sinks and incoming[item] and not outgoing[item]:
            rank[item] = max([rank[other] for other in ids if other not in sinks] + [rank[item] - 1]) + 1
    levels = sorted(set(rank.values()))
    return {item: levels.index(rank[item]) for item in ids}


def _stacks(column: list[dict]) -> list[list[dict]]:
    """Una pila de más de MAX_STACK componentes se reparte en columnas parejas (una rejilla)."""
    if len(column) <= MAX_STACK:
        return [column]
    parts = math.ceil(len(column) / MAX_STACK)
    size = math.ceil(len(column) / parts)
    return [column[start:start + size] for start in range(0, len(column), size)]


def _group(boundary: str | None, members: list[dict], flows: list[dict]) -> dict:
    if boundary is None:
        return {"id": f"c:{members[0]['id']}", "boundary": None, "members": members, "cols": [members], "gaps": [0]}
    ids = [item["id"] for item in members]
    by_id = {item["id"]: item for item in members}
    inner = _inner_ranks(ids, [(f["source"], f["target"]) for f in flows if f["source"] in by_id and f["target"] in by_id],
                         lambda item: layer(by_id[item]))
    columns: dict[int, list[dict]] = {}
    for item in members:
        columns.setdefault(inner[item["id"]], []).append(item)
    cols, gaps = [], []
    for key in sorted(columns):
        stacks = _stacks(sorted(columns[key], key=layer))
        cols += stacks
        gaps += [GAP_GRID] * (len(stacks) - 1) + [GAP_INNER]
    return {"id": f"b:{boundary}", "boundary": boundary, "members": members, "cols": cols, "gaps": gaps}


def _measure(group: dict) -> None:
    widths = [max(node_size(item)[0] for item in column) for column in group["cols"]]
    heights = [sum(node_size(item)[1] for item in column) + GAP_Y * (len(column) - 1) for column in group["cols"]]
    inner_w = sum(widths) + sum(group["gaps"][:-1])
    inner_h = max(heights + [NODE_H])
    group.update(widths=widths, heights=heights, inner_w=inner_w, inner_h=inner_h)
    if group["boundary"] is None:
        group["width"], group["height"] = node_size(group["members"][0])
    else:
        group["width"], group["height"] = inner_w + PAD * 2, HEADER + inner_h + PAD


def _place(columns: list[list[dict]]) -> tuple[dict, dict]:
    nodes: dict = {}
    boxes: dict = {}
    heights = [sum(group["height"] for group in column) + GAP_Y * 1.5 * (len(column) - 1) for column in columns]
    tallest = max(heights + [0])
    x = 40.0
    for column, column_h in zip(columns, heights):
        y = 40 + (tallest - column_h) / 2
        width = max(group["width"] for group in column)
        for group in column:
            gx = x + (width - group["width"]) / 2
            if group["boundary"] is None:
                nodes[group["members"][0]["id"]] = {"x": _snap(gx), "y": _snap(y)}
            else:
                boxes[group["boundary"]] = {"x": _snap(gx), "y": _snap(y), "width": group["width"], "height": group["height"]}
                cx = _snap(gx) + PAD
                for members, col_w, col_h, gap in zip(group["cols"], group["widths"], group["heights"], group["gaps"]):
                    cy = _snap(y) + HEADER + (group["inner_h"] - col_h) / 2
                    for item in members:
                        nodes[item["id"]] = {"x": _snap(cx + (col_w - node_size(item)[0]) / 2), "y": _snap(cy)}
                        cy += node_size(item)[1] + GAP_Y
                    cx += col_w + gap
            y += group["height"] + GAP_Y * 1.5
        x += width + GAP_X
    return nodes, boxes


def auto_layout(model: dict) -> dict:
    components = {item["id"]: item for item in model.get("components", [])}
    flows = [f for f in model.get("flows", []) if f["source"] in components and f["target"] in components]
    groups, group_of, placed = [], {}, set()
    for boundary in model.get("boundaries", []):
        members = [components[member] for member in boundary["components"] if member in components and member not in placed]
        if not members:
            continue
        placed.update(item["id"] for item in members)
        groups.append(_group(boundary["id"], members, flows))
    for item in model.get("components", []):
        if item["id"] not in placed:
            groups.append(_group(None, [item], flows))
    for group in groups:
        for item in group["members"]:
            group_of[item["id"]] = group["id"]
    # Papel del bloque: la media de sus componentes (0 = solo actores). Una frontera de datos con un servicio
    # de configuración sigue siendo «datos».
    seed = {group["id"]: sum(layer(item) for item in group["members"]) / len(group["members"]) for group in groups}
    sinks = {group["id"] for group in groups if all(base_kind(item) == "external" for item in group["members"])}
    between = [(group_of[f["source"]], group_of[f["target"]]) for f in flows if group_of[f["source"]] != group_of[f["target"]]]
    ids = [group["id"] for group in groups]
    rank = _group_ranks(ids, between, seed, sinks)
    for group in groups:
        _measure(group)
    by_id = {group["id"]: group for group in groups}
    columns: list[list[dict]] = [[] for _ in range(max(rank.values(), default=-1) + 1)]
    for group in sorted(groups, key=lambda g: (seed[g["id"]], ids.index(g["id"]))):
        columns[rank[group["id"]]].append(group)
    columns = [column for column in columns if column]
    neighbours: dict[str, list[str]] = {item: [] for item in components}
    for f in flows:
        neighbours[f["source"]].append(f["target"])
        neighbours[f["target"]].append(f["source"])

    # Menos cruces: cada bloque (y cada componente dentro de su bloque) a la altura media de sus vecinos.
    nodes, boxes = _place(columns) if columns else ({}, {})
    for _ in range(4):
        centre = {key: point["y"] + node_size(components[key])[1] / 2 for key, point in nodes.items()}
        for column in columns:
            def outside(group: dict) -> float:
                own = {item["id"] for item in group["members"]}
                around = [centre[other] for item in group["members"] for other in neighbours[item["id"]] if other not in own]
                return sum(around) / len(around) if around else sum(centre[item["id"]] for item in group["members"]) / len(group["members"])
            column.sort(key=outside)
            for group in column:
                if group["boundary"] is None:
                    continue
                for stack in group["cols"]:
                    stack.sort(key=lambda item: (sum(centre[other] for other in neighbours[item["id"]]) / len(neighbours[item["id"]])
                                                 if neighbours[item["id"]] else centre[item["id"]]))
        nodes, boxes = _place(columns)
    del by_id
    # Fronteras vacías: al final, listas para arrastrar componentes dentro.
    right = max([box["x"] + box["width"] for box in boxes.values()] + [point["x"] + NODE_W for point in nodes.values()] + [0]) + GAP_X
    empty_y = 40
    for boundary in model.get("boundaries", []):
        if boundary["id"] not in boxes:
            boxes[boundary["id"]] = {"x": _snap(right), "y": empty_y, "width": NODE_W + PAD * 2, "height": HEADER + NODE_H + PAD}
            empty_y += NODE_H + HEADER + PAD + GAP_Y
    return {"nodes": nodes, "boundaries": boxes}


def fit_box(box: dict, members: list[tuple[dict, tuple[float, float]]]) -> dict:
    """Una caja siempre contiene a sus componentes, aunque llegue pequeña de un JSON."""
    if not members:
        return box
    left = min([box["x"]] + [point["x"] - PAD for point, _ in members])
    top = min([box["y"]] + [point["y"] - HEADER for point, _ in members])
    right = max([box["x"] + box["width"]] + [point["x"] + size[0] + PAD for point, size in members])
    bottom = max([box["y"] + box["height"]] + [point["y"] + size[1] + PAD for point, size in members])
    return {"x": left, "y": top, "width": right - left, "height": bottom - top}


def layout(model: dict) -> dict:
    """Respeta cada posición dibujada, coloca solo lo que no la tiene y ajusta cada caja a sus componentes."""
    result = auto_layout(model)
    for component in model.get("components", []):
        if component.get("position"):
            result["nodes"][component["id"]] = dict(component["position"])
    sizes = {item["id"]: node_size(item) for item in model.get("components", [])}
    for boundary in model.get("boundaries", []):
        box = dict(boundary.get("box") or result["boundaries"].get(boundary["id"]) or {"x": 40, "y": 40, "width": 320, "height": 220})
        members = [(result["nodes"][member], sizes[member]) for member in boundary["components"] if member in result["nodes"] and member in sizes]
        result["boundaries"][boundary["id"]] = fit_box(box, members)
    return result


# ------------------------------------------------------------------ flechas y etiquetas (igual que React Flow)

def _offset(distance: float) -> float:
    return 0.5 * distance if distance >= 0 else 0.25 * 25 * math.sqrt(-distance)


def _control(side: str, x1: float, y1: float, x2: float, y2: float) -> tuple[float, float]:
    if side == "left":
        return x1 - _offset(x1 - x2), y1
    if side == "right":
        return x1 + _offset(x2 - x1), y1
    if side == "top":
        return x1, y1 - _offset(y1 - y2)
    return x1, y1 + _offset(y2 - y1)


def _anchor(rect: dict, side: str) -> tuple[float, float]:
    x, y, w, h = rect["x"], rect["y"], rect["width"], rect["height"]
    return {"left": (x, y + h / 2), "right": (x + w, y + h / 2), "top": (x + w / 2, y), "bottom": (x + w / 2, y + h)}[side]


def sides(a: dict, b: dict) -> tuple[str, str]:
    """Qué lado de cada componente mira al otro (por sus centros): las flechas no cruzan por dentro de las cajas."""
    dx = (b["x"] + b["width"] / 2) - (a["x"] + a["width"] / 2)
    dy = (b["y"] + b["height"] / 2) - (a["y"] + a["height"] / 2)
    if abs(dx) >= abs(dy):
        return ("right", "left") if dx >= 0 else ("left", "right")
    return ("bottom", "top") if dy >= 0 else ("top", "bottom")


LANE = 14  # separación entre flujos que unen los mismos dos componentes (ida y vuelta, o varios)


def lanes(flows: list[dict]) -> dict[str, float]:
    """Desplazamiento de cada flujo: los que comparten extremos (en cualquier sentido) van en carriles paralelos."""
    groups: dict[frozenset, list[str]] = {}
    for flow in flows:
        groups.setdefault(frozenset((flow["source"], flow["target"])), []).append(flow["id"])
    return {identifier: (index - (len(members) - 1) / 2) * LANE for members in groups.values() for index, identifier in enumerate(members)}


def _shift(point: tuple[float, float], side: str, offset: float) -> tuple[float, float]:
    return (point[0], point[1] + offset) if side in ("left", "right") else (point[0] + offset, point[1])


def _curve(a: dict, b: dict, offset: float = 0) -> tuple[tuple[float, float], ...]:
    source_side, target_side = sides(a, b)
    start, end = _shift(_anchor(a, source_side), source_side, offset), _shift(_anchor(b, target_side), target_side, offset)
    c1 = _control(source_side, *start, *end)
    c2 = _control(target_side, *end, *start)
    return start, c1, c2, end


def _point(curve, t: float) -> tuple[float, float]:
    (sx, sy), (ax, ay), (bx, by), (tx, ty) = curve
    u = 1 - t
    return (u ** 3 * sx + 3 * u * u * t * ax + 3 * u * t * t * bx + t ** 3 * tx,
            u ** 3 * sy + 3 * u * u * t * ay + 3 * u * t * t * by + t ** 3 * ty)


LABEL_H = 18          # alto dibujado de la etiqueta
LABEL_ROOM = 20       # alto con el que se buscan huecos (igual que el editor)
SPOTS = (0.5, 0.4, 0.6, 0.3, 0.7, 0.78, 0.22, 0.85, 0.15)


def _overlap(a: dict, b: dict) -> float:
    return (max(0, min(a["x"] + a["width"], b["x"] + b["width"]) - max(a["x"], b["x"]))
            * max(0, min(a["y"] + a["height"], b["y"] + b["height"]) - max(a["y"], b["y"])))


def label_width(text: str) -> float:
    return min(132, len(text) * 6 + 14)


def label_spots(edges: list[tuple[str, tuple, str, float]], rects: list[dict]) -> dict[str, tuple[float, float]]:
    """Etiqueta de cada flujo en el primer punto de su curva que no pisa componentes ni otras etiquetas.
    Igual que labelSpots del editor: primero los flujos cortos (tienen menos sitio donde elegir)."""
    placed: list[dict] = []
    spots: dict[str, tuple[float, float]] = {}
    for key, curve, text, _ in sorted(edges, key=lambda edge: edge[3]):
        width = label_width(text) + 8
        best = (math.inf, _point(curve, 0.5), None)
        for spot in SPOTS:
            x, y = _point(curve, spot)
            box = {"x": x - width / 2, "y": y - (LABEL_ROOM + 6) / 2, "width": width, "height": LABEL_ROOM + 6}
            cost = sum(_overlap(box, item) * 4 for item in rects) + sum(_overlap(box, item) for item in placed) + abs(spot - 0.5)
            if cost < best[0]:
                best = (cost, (x, y), box)
            if cost < 1:
                break
        spots[key] = best[1]
        if best[2]:
            placed.append(best[2])
    return spots


# ------------------------------------------------------------------ escena

def _wrap(text: str, width: float, size: float, lines: int = 2, bold: bool = True) -> list[str]:
    """Parte un nombre en como mucho `lines` renglones que caben en `width` (medida aproximada de Helvetica)."""
    per_line = max(6, int(width / (size * (0.6 if bold else 0.53))))
    words, rows, current = str(text).split(), [], ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if len(candidate) <= per_line or not current:
            current = candidate
        else:
            rows.append(current)
            current = word
    if current:
        rows.append(current)
    rows = [row if len(row) <= per_line else row[:per_line - 1] + "…" for row in rows]
    if len(rows) > lines:
        rows = rows[:lines]
        rows[-1] = (rows[-1][:per_line - 1].rstrip() + "…")
    return rows or [""]


def flow_label(number: int, flow: dict) -> str:
    return f"{number} · {flow['protocol'].upper()}"


def scene(model: dict, kinds: dict[str, str] | None = None, *, locale: str | None = None) -> dict:
    """El diagrama como primitivas: {"bounds": (x, y, w, h), "items": [...]}. Lo pintan to_svg y to_drawing."""
    locale = locale or default_locale()
    kinds = kinds or {}
    geometry = layout(model)
    components = {item["id"]: item for item in model.get("components", [])}
    rects = {}
    for key, point in geometry["nodes"].items():
        if key in components:
            width, height = node_size(components[key])
            drawn = min(height, DRAW_H) if not (components[key].get("size") or {}).get("height") else height
            rects[key] = {"x": point["x"], "y": point["y"], "width": width, "height": drawn}
    items: list[dict] = []
    for boundary in model.get("boundaries", []):
        box = geometry["boundaries"].get(boundary["id"])
        if not box:
            continue
        ink, fill = COLORS[color_of(boundary, boundary=True)]
        items += [{"t": "rect", "x": box["x"], "y": box["y"], "w": box["width"], "h": box["height"], "rx": 16, "fill": fill,
                   "opacity": 0.55, "stroke": ink, "sw": 1.5, "dash": (8, 6)},
                  {"t": "text", "x": box["x"] + 14, "y": box["y"] + 24, "text": boundary["name"][:80], "size": 12.5, "bold": True, "fill": ink}]
    # Flujos: curvas como las del editor, numeradas en el orden del modelo (la tabla del informe usa el mismo número).
    curves = []
    offsets = lanes(model.get("flows", []))
    for number, flow in enumerate(model.get("flows", []), start=1):
        a, b = rects.get(flow["source"]), rects.get(flow["target"])
        if not a or not b:
            continue
        curves.append((flow, number, _curve(a, b, offsets.get(flow["id"], 0)), math.hypot(b["x"] - a["x"], b["y"] - a["y"])))
    spots = label_spots([(flow["id"], curve, flow_label(number, flow), length) for flow, number, curve, length in curves], list(rects.values()))
    curves = [(flow, number, curve) for flow, number, curve, _ in curves]
    for flow, number, curve in curves:
        plain = not flow.get("encrypted")
        stroke = COLORS["danger"][0] if plain else MUTED
        start, c1, c2, end = curve
        dx, dy = end[0] - c2[0], end[1] - c2[1]
        if math.hypot(dx, dy) < 1e-6:
            dx, dy = end[0] - start[0], end[1] - start[1]
        norm = math.hypot(dx, dy) or 1
        ux, uy = dx / norm, dy / norm
        base = (end[0] - ux * 9, end[1] - uy * 9)
        names = f"{components[flow['source']]['name']} → {components[flow['target']]['name']}"
        tip = f"{number}. {names} · {flow['protocol'].upper()}" + (f" · {flow['name']}" if flow.get("name") else "") + (f" · {t('threats.diagram.unencrypted_flow', locale)}" if plain else "")
        items += [{"t": "curve", "points": (start, c1, c2, base), "stroke": stroke, "sw": 1.4, "dash": (5, 4) if plain else None, "tip": tip},
                  {"t": "poly", "points": (end, (base[0] - uy * 4.5, base[1] + ux * 4.5), (base[0] + uy * 4.5, base[1] - ux * 4.5)), "fill": stroke}]
    for flow, number, curve in curves:
        x, y = spots[flow["id"]]
        text = flow_label(number, flow)
        width = label_width(text) - 10
        plain = not flow.get("encrypted")
        items += [{"t": "rect", "x": x - width / 2, "y": y - LABEL_H / 2, "w": width, "h": LABEL_H, "rx": 9, "fill": WHITE,
                   "stroke": COLORS["danger"][0] if plain else LINE, "sw": 1},
                  {"t": "text", "x": x, "y": y + 3.6, "text": text, "size": 10, "bold": True, "fill": COLORS["danger"][0] if plain else MUTED,
                   "anchor": "middle"}]
    # Componentes: forma según su papel (proceso redondeado, almacén entre dos líneas, el resto rectángulo).
    for key, rect in rects.items():
        item = components[key]
        role = base_kind(item)
        ink, fill = COLORS[color_of(item)]
        x, y, w, h = rect["x"], rect["y"], rect["width"], rect["height"]
        if role in STORES:
            items += [{"t": "rect", "x": x, "y": y, "w": w, "h": h, "rx": 0, "fill": fill, "stroke": None, "sw": 0},
                      {"t": "line", "x1": x, "y1": y, "x2": x + w, "y2": y, "stroke": ink, "sw": 2},
                      {"t": "line", "x1": x, "y1": y + h, "x2": x + w, "y2": y + h, "stroke": ink, "sw": 2}]
        else:
            items.append({"t": "rect", "x": x, "y": y, "w": w, "h": h, "rx": h / 2 if role in PROCESSES else 10, "fill": fill,
                          "stroke": ink, "sw": 1.5, "dash": (5, 3) if role == "external" else None})
        name = _wrap(item["name"], w - 24, 12.5)
        detail = (item.get("technology") or item.get("custom_kind") or kinds.get(item["kind"]) or "")[:60]
        flags = [t(key, locale) for key, on in (("threats.diagram.flag_internet", item.get("internet_facing")),
                                                ("threats.diagram.flag_sensitive", set(item.get("data") or []) & {"pii", "credentials", "payment"}),
                                                ("threats.diagram.flag_encrypted", item.get("encrypted_at_rest") and role in STORES)) if on]
        block = len(name) * 14 + (13 if detail else 0) + (12 if flags else 0)
        cursor = y + (h - block) / 2 + 11
        for row in name:
            items.append({"t": "text", "x": x + w / 2, "y": cursor, "text": row, "size": 12.5, "bold": True, "fill": INK, "anchor": "middle"})
            cursor += 14
        if detail:
            items.append({"t": "text", "x": x + w / 2, "y": cursor - 1, "text": _wrap(detail, w - 24, 10, 1, bold=False)[0], "size": 10,
                          "fill": ink, "anchor": "middle"})
            cursor += 13
        if flags:
            items.append({"t": "text", "x": x + w / 2, "y": cursor - 1, "text": " · ".join(flags), "size": 9, "fill": MUTED, "anchor": "middle"})
    # Límites, título arriba y leyenda abajo.
    extents = [(r["x"], r["y"], r["x"] + r["width"], r["y"] + r["height"]) for r in rects.values()]
    extents += [(box["x"], box["y"], box["x"] + box["width"], box["y"] + box["height"]) for box in geometry["boundaries"].values()]
    left = min((item[0] for item in extents), default=0) - 32
    top = min((item[1] for item in extents), default=0) - 64
    right = max((item[2] for item in extents), default=720) + 32
    bottom = max((item[3] for item in extents), default=420) + 76
    width, height = max(560, right - left), max(300, bottom - top)
    # Leyenda: los colores automáticos que se usan y los tipos de línea; si no cabe en una fila, sigue en otra.
    # A manual color shows the team's label, or a placeholder so that every color on the diagram is explained.
    automatic, manual = legend_tones(model)
    labels, names = model.get("legend") or {}, dict(LEGEND)
    entries = [("swatch", tone, localize(names[tone], locale)) for tone in automatic]
    entries += [("swatch", tone, (labels.get(tone) or "").strip()[:40] or t("threats.diagram.legend_custom", locale)) for tone in manual]
    entries += [("line", None, t("threats.diagram.legend_encrypted", locale)), ("dashed", None, t("threats.diagram.legend_unencrypted", locale)),
                ("note", None, t("threats.diagram.legend_note", locale))]
    rows, row, used_w = [], [], 0.0
    for kind, tone, text in entries:
        entry_w = (0 if kind == "note" else 38) + len(text) * 6.2 + 24
        if row and used_w + entry_w > width - 48:
            rows.append(row)
            row, used_w = [], 0.0
        row.append((kind, tone, text))
        used_w += entry_w
    rows.append(row)
    height += 22 * (len(rows) - 1)
    items.insert(0, {"t": "rect", "x": left, "y": top, "w": width, "h": height, "rx": 0, "fill": WHITE, "stroke": None, "sw": 0})
    items.insert(1, {"t": "text", "x": left + 24, "y": top + 36, "text": model["name"][:120], "size": 20, "bold": True, "fill": INK})
    ly = top + height - 34 - 22 * (len(rows) - 1)
    for row in rows:
        lx = left + 24
        for kind, tone, text in row:
            if kind == "swatch":
                ink, fill = COLORS[tone]
                items += [{"t": "rect", "x": lx, "y": ly - 10, "w": 22, "h": 14, "rx": 4, "fill": fill, "stroke": ink, "sw": 1.2},
                          {"t": "text", "x": lx + 30, "y": ly + 1, "text": text, "size": 11, "fill": INK}]
                lx += 30 + len(text) * 6.2 + 24
            elif kind in ("line", "dashed"):
                colour = MUTED if kind == "line" else COLORS["danger"][0]
                items += [{"t": "line", "x1": lx, "y1": ly - 3, "x2": lx + 30, "y2": ly - 3, "stroke": colour, "sw": 1.4,
                           "dash": (5, 4) if kind == "dashed" else None},
                          {"t": "text", "x": lx + 38, "y": ly + 1, "text": text, "size": 11, "fill": INK}]
                lx += 38 + len(text) * 6.2 + 24
            else:
                items.append({"t": "text", "x": lx, "y": ly + 1, "text": text, "size": 11, "fill": MUTED})
        ly += 22
    return {"bounds": (left, top, width, height), "items": items}


# ------------------------------------------------------------------ pintores

def _svg_attrs(item: dict) -> str:
    stroke = f' stroke="{item["stroke"]}" stroke-width="{item["sw"]:g}"' if item.get("stroke") else ""
    dash = f' stroke-dasharray="{item["dash"][0]:g} {item["dash"][1]:g}"' if item.get("dash") else ""
    return stroke + dash


def to_svg(model: dict, kinds: dict[str, str] | None = None, *, locale: str | None = None) -> str:
    """El diagrama como SVG autónomo: sin scripts ni recursos externos, con el texto escapado."""
    drawn = scene(model, kinds, locale=locale)
    left, top, width, height = drawn["bounds"]
    escape = lambda value: html.escape(str(value), quote=True)
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{left:g} {top:g} {width:g} {height:g}" width="{width:g}" height="{height:g}" '
             f'role="img" aria-label="{escape(t("threats.diagram.aria_label", locale, name=model["name"]))}" font-family="{FONT}">']
    for item in drawn["items"]:
        kind = item["t"]
        if kind == "rect":
            opacity = f' fill-opacity="{item["opacity"]:g}"' if item.get("opacity") else ""
            parts.append(f'<rect x="{item["x"]:g}" y="{item["y"]:g}" width="{item["w"]:g}" height="{item["h"]:g}" rx="{item["rx"]:g}" '
                         f'fill="{item["fill"]}"{opacity}{_svg_attrs(item) if item.get("stroke") else ""}/>')
        elif kind == "line":
            parts.append(f'<line x1="{item["x1"]:g}" y1="{item["y1"]:g}" x2="{item["x2"]:g}" y2="{item["y2"]:g}"{_svg_attrs(item)}/>')
        elif kind == "curve":
            (sx, sy), (ax, ay), (bx, by), (tx, ty) = item["points"]
            parts.append(f'<path d="M{sx:.1f},{sy:.1f} C{ax:.1f},{ay:.1f} {bx:.1f},{by:.1f} {tx:.1f},{ty:.1f}" fill="none"{_svg_attrs(item)}>'
                         f'<title>{escape(item["tip"])}</title></path>')
        elif kind == "poly":
            points = " ".join(f"{x:.1f},{y:.1f}" for x, y in item["points"])
            parts.append(f'<polygon points="{points}" fill="{item["fill"]}"/>')
        elif kind == "text":
            anchor = f' text-anchor="{item["anchor"]}"' if item.get("anchor") else ""
            weight = ' font-weight="700"' if item.get("bold") else ""
            parts.append(f'<text x="{item["x"]:g}" y="{item["y"]:g}"{anchor} font-size="{item["size"]:g}"{weight} fill="{item["fill"]}">'
                         f'{escape(item["text"])}</text>')
    parts.append("</svg>")
    return "\n".join(parts)


def to_drawing(model: dict, max_width: float, max_height: float, kinds: dict[str, str] | None = None, *, locale: str | None = None):
    """El mismo diagrama como dibujo vectorial de ReportLab, escalado para caber en (max_width, max_height)."""
    from reportlab.graphics.shapes import Drawing, Group, Line, Path, Polygon, Rect, String
    from reportlab.lib import colors

    drawn = scene(model, kinds, locale=locale)
    left, top, width, height = drawn["bounds"]
    scale = min(max_width / width, max_height / height, 1.0)
    flip = lambda y: top + height - y  # SVG crece hacia abajo; ReportLab, hacia arriba (ya queda en [0, alto])
    group = Group(transform=(scale, 0, 0, scale, -left * scale, 0))
    colour = lambda value: colors.HexColor(value) if value else None
    for item in drawn["items"]:
        kind = item["t"]
        dash = list(item["dash"]) if item.get("dash") else None
        if kind == "rect":
            shape = Rect(item["x"], flip(item["y"] + item["h"]), item["w"], item["h"], rx=item["rx"], ry=item["rx"],
                         fillColor=colour(item["fill"]), strokeColor=colour(item.get("stroke")), strokeWidth=item.get("sw") or 0,
                         strokeDashArray=dash)
            if item.get("opacity"):
                shape.fillOpacity = item["opacity"]
            group.add(shape)
        elif kind == "line":
            group.add(Line(item["x1"], flip(item["y1"]), item["x2"], flip(item["y2"]), strokeColor=colour(item["stroke"]),
                           strokeWidth=item["sw"], strokeDashArray=dash))
        elif kind == "curve":
            (sx, sy), (ax, ay), (bx, by), (tx, ty) = item["points"]
            path = Path(fillColor=None, strokeColor=colour(item["stroke"]), strokeWidth=item["sw"], strokeDashArray=dash)
            path.moveTo(sx, flip(sy))
            path.curveTo(ax, flip(ay), bx, flip(by), tx, flip(ty))
            group.add(path)
        elif kind == "poly":
            group.add(Polygon([value for x, y in item["points"] for value in (x, flip(y))], fillColor=colour(item["fill"]), strokeColor=None))
        elif kind == "text":
            group.add(String(item["x"], flip(item["y"]), item["text"], fontName="Helvetica-Bold" if item.get("bold") else "Helvetica",
                             fontSize=item["size"], fillColor=colour(item["fill"]), textAnchor=item.get("anchor") or "start"))
    drawing = Drawing(width * scale, height * scale)
    group.transform = (scale, 0, 0, scale, -left * scale, 0)
    drawing.add(group)
    return drawing
