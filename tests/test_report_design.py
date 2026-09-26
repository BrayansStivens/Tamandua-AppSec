"""Informes y diagrama con el sistema de diseño: concisos, agrupados por acción y con colores de la paleta."""

import base64
import json
import re
import unittest
import xml.etree.ElementTree as ET
import zlib
from pathlib import Path

from tamandua.modules.threats import diagram as threat_diagram
from tamandua.modules.threats import model as tm
from tamandua.modules.threats import report as threat_report
from tamandua.modules.reporting.audit import render_audit_pdf, validate_options
from tamandua.modules.findings.remediation import action, fix_groups
from tamandua.modules.reporting.technical import render_technical_pdf
from test_threat_model import model

EXAMPLE = Path(__file__).resolve().parents[1] / "web/src/examples/threat-models/stride.json"


def advisory(identifier: str, severity: str, fixed: str | None, *, kev: bool = False, name: str = "pillow", version: str = "10.3.0") -> dict:
    return {"fingerprint": identifier.lower().ljust(64, "0")[:64], "scanner": "sca", "severity": severity, "rule_id": identifier,
            "cve": [identifier], "title": f"{name} {version}: {name}: fallo {identifier}", "path": "backend/poetry.lock", "line": 1,
            "kev": "2026-01-01" if kev else None, "epss": {"score": 0.1}, "remediation": "Actualiza.",
            "package": {"name": name, "version": version, "ecosystem": "pypi", "fixed_version": fixed}}


def code(identifier: str, severity: str) -> dict:
    return {"fingerprint": identifier.ljust(64, "0")[:64], "scanner": "sast", "severity": severity, "rule_id": "py.sql", "title": "Injection: sql",
            "path": "app/db.py", "line": 12, "reason": "SQL concatenado", "remediation": "Usa parámetros del driver. Y el ORM cuando puedas.", "cwe": [89]}


def pages(pdf: bytes) -> int:
    return len(re.findall(rb"/Type\s*/Page[^s]", pdf))


def text(pdf: bytes) -> str:
    """Texto aproximado de un PDF de ReportLab (flujos comprimidos), para comprobar qué dice."""
    chunks = []
    for stream in re.findall(rb"stream\r?\n(.*?)endstream", pdf, re.S):
        stream = stream.strip()
        try:
            raw = base64.a85decode(stream.removesuffix(b"~>")) if stream.endswith(b"~>") else stream
            chunks.append(zlib.decompress(raw).decode("latin-1"))
        except (ValueError, zlib.error):
            continue
    return "".join(chunks)


class RemediationTests(unittest.TestCase):
    def test_advisories_of_a_package_close_with_one_update(self):
        findings = [advisory("CVE-1", "high", "11.0.0"), advisory("CVE-2", "critical", "12.3.0"), advisory("CVE-3", "medium", "9.9.0"),
                    code("a", "high"), code("b", "high")]
        groups = fix_groups(findings)
        self.assertEqual(len(groups), 3)  # un paquete + dos hallazgos de código
        package = next(entry for entry in groups if entry["kind"] == "package")
        self.assertEqual((package["severity"], package["target"], package["complete"], len(package["items"])), ("critical", "12.3.0", True, 3))
        self.assertEqual(action(package), "Actualizar pillow a 12.3.0 (cierra los 3)")
        self.assertEqual(len(fix_groups(findings, by_rule=True)), 2)  # la misma regla en dos sitios: un patrón

    def test_exploited_first_and_partial_fixes_are_said(self):
        groups = fix_groups([advisory("CVE-9", "critical", "2.0"), advisory("CVE-5", "medium", None, kev=True, name="lib", version="1.0"),
                             advisory("CVE-6", "high", "1.5", name="lib", version="1.0")])
        self.assertEqual(groups[0]["name"], "lib")  # explotación activa antes que severidad
        self.assertIn("cierra 1 de 2", action(groups[0]))
        self.assertEqual(action(fix_groups([advisory("CVE-7", "low", None)])[0], short=True),
                         "Sin versión corregida: evaluar alcanzabilidad, mitigar o sustituir")
        self.assertEqual(action(fix_groups([code("c", "low")])[0], short=True), "Usa parámetros del driver.")


class ReportTests(unittest.TestCase):
    def record(self, findings):
        return {"id": "r" * 32, "type": "repository_scan", "created_at": "2026-09-25T10:00:00+00:00", "findings": findings,
                "source": {"name": "org/<b>app</b>", "branch": "main"},
                "steps": [{"name": "Trivy 0.74.0", "status": "completed", "tool": {"version": "0.74.0"}},
                          {"name": "Opengrep", "status": "inconclusive", "detail": "sin reglas"}]}

    def test_a_package_with_many_advisories_is_one_row(self):
        many = [advisory(f"CVE-2026-{index:04d}", "high", f"12.{index}.0") for index in range(120)]
        pdf = render_audit_pdf(self.record(many), many, validate_options({"framework": "soc2", "detail": "all"}, default_by="ana"), version="t")
        self.assertLessEqual(pages(pdf), 4)  # antes, una fila y un bloque por aviso: decenas de páginas
        self.assertIn("120 vulnerabilidades", text(pdf))

    def test_technical_report_puts_actions_first_and_says_what_was_not_analysed(self):
        findings = [*(advisory(f"CVE-{index}", "high", "12.0.0") for index in range(40)), code("a", "critical"), code("b", "medium")]
        pdf = render_technical_pdf(self.record(findings), version="t")
        content = text(pdf)
        self.assertTrue(pdf.startswith(b"%PDF-"))
        for expected in ("Qu\\351 hacer primero", "Actualizar pillow a 12.0.0 \\(cierra los 40\\)", "Cobertura incompleta", "Anexo"):
            self.assertIn(expected, content)
        self.assertIn("(org/) Tj (<) Tj (b) Tj (>) Tj (app)", content)  # el nombre es dato: se ve tal cual, no se interpreta
        self.assertLessEqual(pages(pdf), 5)

    def test_markdown_report_renders_in_the_requested_language(self):
        from tamandua.modules.runs.store import render_repository_report
        findings = [{**advisory("CVE-1", "high", "12.0.0"), "ghsa": [], "reason": "", "kev": None}, code("a", "critical")]
        record = {**self.record(findings), "status": "completed", "owasp_coverage": [], "limitations": [],
                  "steps": [{"name": "Opengrep", "status": "completed", "detail": ""}],
                  "source": {"name": "org/app", "provider": "github", "sha256": "abc"},
                  "summary": {"files": 1, "dependencies": 1, "severities": {"high": 1, "critical": 1}, "priorities": {}}}
        english, spanish = render_repository_report(record, locale="en"), render_repository_report(record, locale="es")
        self.assertIn("## Executive summary", english)
        self.assertIn("### What to do first", english)
        self.assertNotIn("Resumen ejecutivo", english)
        self.assertIn("## Resumen ejecutivo", spanish)


class DiagramTests(unittest.TestCase):
    def test_colors_come_from_the_palette_and_are_validated(self):
        current = model(components=[{**item, "color": "danger"} if item["id"] == "api" else item for item in model()["components"]])
        self.assertEqual(next(item for item in current["components"] if item["id"] == "api")["color"], "danger")
        with self.assertRaises(tm.ModelError):
            model(components=[{**item, "color": "#ff0000"} if item["id"] == "api" else item for item in model()["components"]])
        with self.assertRaises(tm.ModelError):
            model(boundaries=[{**model()["boundaries"][0], "color": "url(javascript:x)"}])
        svg = tm.to_svg(current)
        ET.fromstring(svg)
        self.assertIn(threat_diagram.COLORS["danger"][0], svg)
        self.assertIn("1 · HTTPS", svg)          # flujos numerados como en la tabla del informe
        self.assertIn("Actores y terceros", svg)  # leyenda de los colores automáticos que se usan

    def test_data_flows_left_to_right_and_back_flows_do_not_push_columns(self):
        example = tm.from_portable(json.loads(EXAMPLE.read_text(encoding="utf-8")))
        layout = threat_diagram.auto_layout(example)
        kinds = {item["id"]: threat_diagram.base_kind(item) for item in example["components"]}
        actors = [layout["nodes"][key]["x"] for key, kind in kinds.items() if kind == "actor"]
        others = [layout["nodes"][key]["x"] for key, kind in kinds.items() if kind not in ("actor",)]
        self.assertLess(max(actors), min(others))
        for point in layout["nodes"].values():  # rejilla de 8 px: fácil de retocar a mano
            self.assertEqual((point["x"] % 8, point["y"] % 8), (0, 0))


class ThreatReportTests(unittest.TestCase):
    def test_rule_threats_are_grouped_into_patterns_with_their_components(self):
        current = {**model(), "id": "0" * 24, "updated_by": "ana", "updated_at": "2026-09-25T10:00:00+00:00"}
        rows = tm.threats(current)
        data = threat_report.digest(current, rows)
        self.assertEqual(sum(entry["count"] for entry in data["patterns"]), sum(1 for row in rows if row["framework"] != "manual" and row["status"] in ("open", "evidenced")))
        self.assertEqual(len({entry["rule"] for entry in data["patterns"]}), len(data["patterns"]))
        markdown = threat_report.to_markdown(current, rows)
        self.assertLess(markdown.index("## Resumen"), markdown.index("## Amenazas por patrón"))
        self.assertIn("## Anexo A · Flujos del diagrama", markdown)
        pdf = threat_report.render_pdf(current, rows, version="t")
        self.assertTrue(pdf.startswith(b"%PDF-"))
        self.assertIn("Patrones de las reglas", text(pdf))


if __name__ == "__main__":
    unittest.main()


class LaneTests(unittest.TestCase):
    def test_flows_between_the_same_components_get_parallel_lanes(self):
        flows = [{"id": "ida", "source": "a", "target": "b"}, {"id": "vuelta", "source": "b", "target": "a"}, {"id": "otro", "source": "a", "target": "c"}]
        self.assertEqual(threat_diagram.lanes(flows), {"ida": -7.0, "vuelta": 7.0, "otro": 0.0})
