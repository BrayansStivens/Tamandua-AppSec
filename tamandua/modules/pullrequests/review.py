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

from tamandua.shared.i18n import default_locale, msg, t, text

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
    if blocking:
        description = msg("pulls.verdict.blocking", count=blocking, gate=GATE_LABEL.get(gate, gate))
    elif introduced:
        description = msg("pulls.verdict.below", count=len(introduced))
    else:
        description = msg("pulls.verdict.clean")
    return {"state": "failure" if blocking else "success", "description": description, "counts": counts, "blocking": blocking}


def _cell(value, limit: int = 120) -> str:
    """Texto de celda seguro: una línea, sin backticks ni barras que rompan la tabla o abran Markdown."""
    text = " ".join(str(value or "").split()).replace("`", "'").replace("|", "/")
    if len(text) > limit:
        text = text[:limit].rsplit(" ", 1)[0].rstrip(",.;:") + "…"  # corta en palabra, no a mitad
    return text


SEVERITY_LABEL = {"critical": msg("pulls.severity.critical"), "high": msg("pulls.severity.high"), "medium": msg("pulls.severity.medium"),
                  "low": msg("pulls.severity.low"), "info": msg("pulls.severity.info")}
GATE_LABEL = {"critical": msg("pulls.gate.critical"), "high": msg("pulls.gate.high"), "medium": msg("pulls.gate.medium"),
              "low": msg("pulls.gate.low"), "never": msg("pulls.gate.never")}


def _rows(findings: list[dict], locale: str | None = None, limit: int = 25) -> list[str]:
    locale = locale or default_locale()
    lines = [t("pulls.table.header", locale), "|---|---|---|---|"]
    from tamandua.modules.findings.fix_guide import attach
    ordered = attach([dict(item) for item in sorted(findings, key=lambda item: SEVERITY_ORDER.index(item["severity"]) if item["severity"] in SEVERITY_ORDER else 9)])
    for finding in ordered[:limit]:
        package = finding.get("package") or {}
        line = finding.get("line") if isinstance(finding.get("line"), int) else 0
        where = (f"`{_cell(package.get('name'), 60)}` {_cell(package.get('version'), 30)}" if package.get("name")
                 else f"`{_cell(finding.get('path'), 80)}:{line}`")
        # Solo un comando que actualiza de verdad (con su versión); «reinstala» o «instala -r» no dicen a qué.
        commands = [item for item in (finding.get("fix") or {}).get("commands") or [] if item.get("action") == "update"]
        fix = (f"`{_cell(commands[0]['code'], 120)}`" if commands and "`" not in commands[0]["code"]
               else t("pulls.table.update_to", locale, version=_cell(package["fixed_version"], 30)) if package.get("fixed_version")
               else _cell(text(finding.get("remediation"), locale), 140))
        severity = text(SEVERITY_LABEL.get(finding["severity"], finding["severity"]), locale)
        lines.append(f"| {severity} | {_cell(text(finding['title'], locale), 80)} | {where} | {fix} |")
    if len(ordered) > limit:
        lines.append(f"| | {t('pulls.table.more', locale, count=len(ordered) - limit)} | | |")
    return lines


def render_comment(pull: dict, outcome: dict, *, run_id: str, baseline_run: str | None, panel_url: str | None,
                   gate: str = "high", tools: list[dict] | None = None, locale: str | None = None) -> str:
    """Comentario en Markdown de GitHub. Nunca incluye valores de secretos: solo regla, fichero y línea.

    A PR comment is read by the whole team: it speaks TAMANDUA_DEFAULT_LOCALE unless told otherwise."""
    locale = locale or default_locale()
    introduced, preexisting, state = outcome["introduced"], outcome["preexisting"], outcome["verdict"]
    commit = f"`{pull['head_sha'][:7]}`"
    gate_label = text(GATE_LABEL.get(gate, gate), locale)
    lines = [t("pulls.comment.heading", locale), ""]
    if state["blocking"]:
        lines += ["> [!CAUTION]", "> " + t("pulls.comment.blocking", locale, count=state["blocking"], gate=gate_label),
                  "> " + t("pulls.comment.blocking_hint", locale)]
    elif introduced:
        lines += ["> [!WARNING]", "> " + t("pulls.comment.below", locale, count=len(introduced)), "> " + t("pulls.comment.below_hint", locale)]
    else:
        lines += ["> [!TIP]", "> " + t("pulls.comment.clean", locale, commit=commit)]
    if introduced:
        lines += ["", t("pulls.comment.attention", locale, count=len(introduced)), "", *_rows(introduced, locale)]
    if preexisting:
        lines += ["", "<details>", f"<summary>{t('pulls.comment.preexisting', locale, count=len(preexisting))}</summary>", "",
                  *_rows(preexisting, locale, 15), "", "</details>"]
    engines = ", ".join(f"{item['name'].capitalize()} {item['version']}" for item in (tools or []) if item.get("status") in ("completed", "partial"))
    basis = t("pulls.comment.basis_baseline", locale) if baseline_run else t("pulls.comment.basis_none", locale)
    where = t("pulls.comment.where_link", locale, url=panel_url) if panel_url else t("pulls.comment.where_plain", locale)
    lines += ["", t("pulls.comment.footer", locale, commit=commit, basis=basis, gate=gate_label, engines=f" · {engines}" if engines else "",
                    where=where, run=run_id[:12])]
    return "\n".join(lines)


def render_unused_comment(new: list[dict], before: list[dict], ecosystems: list[str], locale: str | None = None) -> str:
    """Informativo: dependencias declaradas que el código no usa, separando las que añade el PR."""
    locale = locale or default_locale()

    def table(items: list[dict]) -> list[str]:
        rows = [t("pulls.unused.header", locale), "|---|---|---|"]
        rows += [f"| `{_cell(item['name'], 60)}` | {item['ecosystem']} | `{_cell(item['manifest'], 80)}:{int(item['line'])}` |" for item in items[:30]]
        if len(items) > 30:
            rows.append(f"| {t('pulls.unused.more', locale, count=len(items) - 30)} | | |")
        return rows
    lines = [t("pulls.unused.heading", locale), ""]
    if new:
        lines += ["> [!WARNING]", "> " + t("pulls.unused.new", locale, count=len(new)), "> " + t("pulls.unused.new_hint", locale), "",
                  t("pulls.unused.added", locale, count=len(new)), "", *table(new)]
    else:
        lines += ["> [!TIP]", "> " + t("pulls.unused.clean", locale)]
    if before:
        lines += ["", "<details>", f"<summary>{t('pulls.unused.before', locale, count=len(before))}</summary>", "", *table(before), "", "</details>"]
    projects = ", ".join(f"`{item}`" for item in ecosystems) or t("pulls.unused.no_manifests", locale)
    lines += ["", t("pulls.unused.footer", locale, projects=projects, count=len(new))]
    return "\n".join(lines)
