"""Revisión de pull requests: qué hallazgos introduce un PR y cómo contarlo en GitHub.

Un PR no se juzga por todo lo que hay en el repositorio sino por lo que añade.
Se escanea el commit de cabeza con los mismos motores y se cruza con dos cosas:

* la **línea base**, el último escaneo completo del repositorio (rama principal):
  una huella que ya estaba allí es preexistente, no culpa del PR;
* el **diff**: un hallazgo de código o secreto cuenta si cae en una línea añadida
  o modificada; uno de dependencias, si el PR toca el manifiesto que lo declara.

Sin línea base se cuenta solo lo que cae en líneas cambiadas, y se dice.
"""

from __future__ import annotations

import re

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
GATES = ("critical", "high", "medium", "never")


def changed_lines(files: list[dict]) -> dict[str, set[int] | None]:
    """Líneas añadidas o modificadas por fichero. None: sin parche (binario o enorme), se trata entero."""
    result: dict[str, set[int] | None] = {}
    for item in files:
        name = item.get("filename")
        if not isinstance(name, str) or item.get("status") == "removed":
            continue
        patch = item.get("patch")
        if not isinstance(patch, str):
            result[name] = None
            continue
        lines: set[int] = set()
        current = 0
        for raw in patch.splitlines():
            header = HUNK.match(raw)
            if header:
                current = int(header.group(1))
                continue
            if raw.startswith("+") and not raw.startswith("+++"):
                lines.add(current)
                current += 1
            elif raw.startswith("-") and not raw.startswith("---"):
                continue
            elif not raw.startswith("\\"):
                current += 1
        result[name] = lines
    return result


def _touches(finding: dict, changed: dict[str, set[int] | None]) -> bool:
    path = finding.get("path")
    if path not in changed:
        return False
    if finding.get("scanner") == "sca":
        return True  # el manifiesto o el lockfile cambió
    lines = changed[path]
    return lines is None or finding.get("line") in lines


def classify(findings: list[dict], changed: dict[str, set[int] | None], baseline: set[str] | None) -> dict:
    """Separa lo que introduce el PR de lo que ya existía en el código que toca."""
    introduced, preexisting = [], []
    for finding in findings:
        if not _touches(finding, changed):
            continue
        if baseline is not None and finding["fingerprint"] in baseline:
            preexisting.append(finding)
        else:
            introduced.append(finding)
    return {"introduced": introduced, "preexisting": preexisting}


def verdict(introduced: list[dict], gate: str = "high") -> dict:
    """Estado del commit: falla si el PR introduce algo de la severidad del umbral o peor."""
    counts = {level: sum(1 for item in introduced if item["severity"] == level) for level in SEVERITY_ORDER}
    if gate == "never":
        blocking = 0
    else:
        limit = SEVERITY_ORDER.index(gate)
        blocking = sum(count for level, count in counts.items() if SEVERITY_ORDER.index(level) <= limit)
    label = {"critical": "crítica", "high": "alta o superior", "medium": "media o superior", "low": "baja o superior"}.get(gate, gate)
    if blocking:
        description = f"{blocking} {'hallazgo nuevo' if blocking == 1 else 'hallazgos nuevos'} de severidad {label}"
    elif introduced:
        description = f"{len(introduced)} {'hallazgo nuevo' if len(introduced) == 1 else 'hallazgos nuevos'} por debajo del umbral"
    else:
        description = "Sin hallazgos nuevos en el código que cambia"
    return {"state": "failure" if blocking else "success", "description": description, "counts": counts, "blocking": blocking}


def _cell(value, limit: int = 120) -> str:
    """Texto de celda seguro: una línea, sin backticks ni barras que rompan la tabla o abran Markdown."""
    text = " ".join(str(value or "").split()).replace("`", "'").replace("|", "/")
    if len(text) > limit:
        text = text[:limit].rsplit(" ", 1)[0].rstrip(",.;:") + "…"  # corta en palabra, no a mitad
    return text


SEVERITY_LABEL = {"critical": "Crítica", "high": "Alta", "medium": "Media", "low": "Baja", "info": "Info"}
GATE_LABEL = {"critical": "crítica", "high": "alta o superior", "medium": "media o superior", "never": "nunca bloquea"}


def _plural(count: int, one: str, many: str) -> str:
    return f"{count} {one if count == 1 else many}"


def _rows(findings: list[dict], limit: int = 25) -> list[str]:
    lines = ["| Severidad | Hallazgo | Ubicación | Corrección |", "|---|---|---|---|"]
    from tamandua.modules.findings.fix_guide import attach
    ordered = attach([dict(item) for item in sorted(findings, key=lambda item: SEVERITY_ORDER.index(item["severity"]) if item["severity"] in SEVERITY_ORDER else 9)])
    for finding in ordered[:limit]:
        package = finding.get("package") or {}
        line = finding.get("line") if isinstance(finding.get("line"), int) else 0
        where = (f"`{_cell(package.get('name'), 60)}` {_cell(package.get('version'), 30)}" if package.get("name")
                 else f"`{_cell(finding.get('path'), 80)}:{line}`")
        # Solo un comando que actualiza de verdad (con su versión); «reinstala» o «instala -r» no dicen a qué.
        commands = [item for item in (finding.get("fix") or {}).get("commands") or [] if item.get("label") == "Actualiza"]
        fix = (f"`{_cell(commands[0]['code'], 120)}`" if commands and "`" not in commands[0]["code"]
               else f"Actualizar a `{_cell(package['fixed_version'], 30)}`" if package.get("fixed_version")
               else _cell(finding.get("remediation"), 140))
        lines.append(f"| {SEVERITY_LABEL.get(finding['severity'], finding['severity'])} | {_cell(finding['title'], 80)} | {where} | {fix} |")
    if len(ordered) > limit:
        lines.append(f"| | … y {len(ordered) - limit} más en el panel | | |")
    return lines


def render_comment(pull: dict, outcome: dict, *, run_id: str, baseline_run: str | None, panel_url: str | None,
                   gate: str = "high", tools: list[dict] | None = None) -> str:
    """Comentario en Markdown de GitHub. Nunca incluye valores de secretos: solo regla, fichero y línea."""
    introduced, preexisting, state = outcome["introduced"], outcome["preexisting"], outcome["verdict"]
    commit = f"`{pull['head_sha'][:7]}`"
    lines = ["## Revisión de seguridad", ""]
    if state["blocking"]:
        lines += ["> [!CAUTION]",
                  f"> **{_plural(state['blocking'], 'hallazgo nuevo bloquea', 'hallazgos nuevos bloquean')} este PR** "
                  f"(severidad {GATE_LABEL.get(gate, gate)}).",
                  "> Corrígelo antes de mergear: el estado `tamandua` se recalcula en cada push."]
    elif introduced:
        lines += ["> [!WARNING]", f"> **{_plural(len(introduced), 'hallazgo nuevo', 'hallazgos nuevos')}** por debajo del umbral de bloqueo.",
                  "> Revísalos antes de mergear. No bloquean el PR."]
    else:
        lines += ["> [!TIP]", f"> **Este PR no introduce hallazgos** en el código que cambia (commit {commit}). No hay nada que hacer aquí."]
    if introduced:
        lines += ["", f"### Requieren atención ({len(introduced)})", "", *_rows(introduced)]
    if preexisting:
        lines += ["", "<details>", f"<summary>{_plural(len(preexisting), 'hallazgo preexistente', 'hallazgos preexistentes')} "
                  "en el código que toca este PR, ya presentes en la rama principal</summary>", "", *_rows(preexisting, 15), "", "</details>"]
    engines = ", ".join(f"{item['name'].capitalize()} {item['version']}" for item in (tools or []) if item.get("status") in ("completed", "partial"))
    basis = ("comparado con el último escaneo de la rama principal" if baseline_run
             else "sin escaneo previo de la rama principal: cuenta todo lo que cae en líneas cambiadas")
    where = f"[en el panel]({panel_url})" if panel_url else "en el panel de Tamandua"
    lines += ["", f"<sub>Commit {commit} · {basis} · bloquea desde severidad {GATE_LABEL.get(gate, gate)}"
              + (f" · {engines}" if engines else "") + f". Detalle, triage y exportación a Jira {where} (ejecución `{run_id[:12]}`). "
              "Los secretos se citan por regla y ubicación; su valor nunca se publica.</sub>"]
    return "\n".join(lines)


def render_unused_comment(new: list[dict], before: list[dict], ecosystems: list[str]) -> str:
    """Informativo: dependencias declaradas que el código no usa, separando las que añade el PR."""
    def table(items: list[dict]) -> list[str]:
        rows = ["| Paquete | Ecosistema | Declarada en |", "|---|---|---|"]
        rows += [f"| `{_cell(item['name'], 60)}` | {item['ecosystem']} | `{_cell(item['manifest'], 80)}:{int(item['line'])}` |" for item in items[:30]]
        if len(items) > 30:
            rows.append(f"| … y {len(items) - 30} más | | |")
        return rows
    lines = ["## Dependencias no utilizadas", ""]
    if new:
        lines += ["> [!WARNING]", f"> **{_plural(len(new), 'dependencia nueva no se usa', 'dependencias nuevas no se usan')}** en el código.",
                  "> Quítalas si sobran, o ignora el aviso si se cargan de una forma que no se ve en el código.", "",
                  f"### Añadidas en este PR ({len(new)})", "", *table(new)]
    else:
        lines += ["> [!TIP]", "> **Este PR no agrega dependencias sin usar.** No hay nada que hacer aquí."]
    if before:
        lines += ["", "<details>", f"<summary>{_plural(len(before), 'dependencia preexistente sin uso', 'dependencias preexistentes sin uso')}, "
                  "anteriores a este PR</summary>", "", *table(before), "", "</details>"]
    projects = ", ".join(f"`{item}`" for item in ecosystems) or "sin manifiestos reconocidos"
    lines += ["", f"<sub>Informativo: no bloquea el merge. Proyecto {projects}, {_plural(len(new), 'dependencia nueva', 'dependencias nuevas')} sin uso en el PR. "
              "Se revisan las dependencias de ejecución; cuenta como uso un import o una mención en configuración, scripts o Dockerfile. "
              "Una dependencia declarada y no usada entra igual en el build y en el análisis de vulnerabilidades.</sub>"]
    return "\n".join(lines)
