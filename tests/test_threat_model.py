"""Threat modeling: validation, proposal from the inventory, STRIDE, evidence, decisions and exports."""

import ast
import json
import os
import tempfile
import unittest
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from tamandua.modules.threats import model as tm
from tamandua.modules.identity.auth import Users
from tamandua.modules.scanning.inventory import collect
from tamandua.modules.runs.store import save_repository_scan
from test_auth import PASSWORD, HttpCase
from test_dashboard import _finding, _scan

REPO = "github:org/shop"


def model(**overrides):
    base = {"name": "Tienda", "components": [
        {"id": "usuario", "name": "Usuario", "kind": "actor", "internet_facing": True},
        {"id": "api", "name": "API", "kind": "api", "internet_facing": True, "authenticates": True, "asset": REPO},
        {"id": "db", "name": "PostgreSQL", "kind": "database", "data": ["pii", "credentials"]},
        {"id": "stripe", "name": "Stripe", "kind": "external", "data": ["payment"]}],
        "flows": [{"id": "f1", "source": "usuario", "target": "api", "protocol": "https", "data": ["credentials"]},
                  {"id": "f2", "source": "api", "target": "db", "protocol": "sql", "data": ["pii"], "authenticated": True},
                  {"id": "f3", "source": "api", "target": "stripe", "protocol": "https", "data": ["payment"], "authenticated": True},
                  {"id": "f4", "source": "stripe", "target": "api", "protocol": "https", "data": ["payment"]}],
        "boundaries": [{"id": "internet", "name": "Internet", "components": ["usuario", "stripe"]},
                       {"id": "app", "name": "Aplicación", "components": ["api"]},
                       {"id": "datos", "name": "Datos", "components": ["db"]}]}
    base.update(overrides)
    return tm.validate(base, known_assets={REPO})


class ModelTests(unittest.TestCase):
    def test_every_ui_json_example_is_importable(self):
        examples = Path(__file__).resolve().parents[1] / "web/src/examples/threat-models"
        methods = ("stride", "linddun", "pasta", "attack_trees", "attack", "custom")
        self.assertEqual({path.name for path in (examples / "en").glob("*.json")}, {f"{method}.json" for method in methods})
        self.assertEqual({path.name for path in (examples / "es").glob("*.json")}, {f"{method}.json" for method in methods})
        for locale in ("en", "es"):
            for method in methods:
                with self.subTest(locale=locale, method=method):
                    document = json.loads((examples / locale / f"{method}.json").read_text(encoding="utf-8"))
                    imported = tm.from_portable(document)
                    self.assertEqual(imported["methodology"], method)
                    # The examples show every component type, a custom one included, and no positions.
                    self.assertEqual(len(imported["components"]), 13)
                    self.assertEqual(len(imported["flows"]), 13)
                    self.assertIn("custom", {item["kind"] for item in imported["components"]})
                    self.assertTrue(all(item["position"] is None for item in imported["components"]))
        # Same ids in both languages: only the text differs.
        ids = lambda doc: {key: [item["id"] for item in doc["model"].get(key) or []] for key in ("components", "flows", "boundaries", "manual_threats", "attack_trees")}
        for method in methods:
            with self.subTest(method=method, check="same ids"):
                english, spanish = (json.loads((examples / locale / f"{method}.json").read_text(encoding="utf-8")) for locale in ("en", "es"))
                self.assertEqual(ids(english), ids(spanish))

    def test_validation_rejects_dangling_and_unknown(self):
        good = model()
        bad_flow = {**good, "flows": [{"id": "x", "source": "api", "target": "nope", "protocol": "https"}]}
        for payload in (bad_flow, {**good, "components": good["components"] + [dict(good["components"][0])]},
                        {**good, "components": [{**good["components"][1], "asset": "github:otro/repo"}]},
                        {**good, "boundaries": good["boundaries"] + [{"id": "b2", "name": "Otra", "components": ["api"]}]}):
            with self.assertRaises(tm.ModelError):
                tm.validate(payload, known_assets={REPO})

    def test_rules_fire_on_the_right_elements(self):
        rows = tm.threats(model())
        fired = {(row["rule"], row["element"]) for row in rows}
        self.assertIn(("TM-I03", "db"), fired)          # credentials in a store
        self.assertIn(("TM-I02", "db"), fired)          # sensitive and unencrypted at rest
        self.assertIn(("TM-S03", "api"), fired)         # Stripe webhook into the API
        self.assertIn(("TM-I05", "f3"), fired)          # payment data to a third party
        self.assertIn(("TM-E02", "api"), fired)         # calls out: SSRF
        self.assertNotIn(("TM-S01", "api"), fired)      # authenticates: "no authentication" doesn't apply
        self.assertIn(("TM-T04", "f2"), fired)          # unencrypted SQL crossing from "Aplicación" to "Datos"
        flows = [{**flow, "encrypted": True} if flow["id"] == "f2" else flow for flow in model()["flows"]]
        self.assertNotIn(("TM-T04", "f2"), {(row["rule"], row["element"]) for row in tm.threats(model(flows=flows))})
        encrypted = model(components=[*model()["components"][:2], {**model()["components"][2], "encrypted_at_rest": True}, model()["components"][3]])
        self.assertNotIn(("TM-I02", "db"), {(row["rule"], row["element"]) for row in tm.threats(encrypted)})

    def test_evidence_from_code_and_dependencies_is_attributed_separately(self):
        xss = {**_finding("a" * 64, cwe=(79,)), "scanner": "sast", "package": None}
        dep = _finding("b" * 64, cwe=(79,))
        rows = {row["rule"]: row for row in tm.threats(model(), {REPO: [xss, dep]}) if row["element"] == "api"}
        self.assertEqual(rows["TM-T01"]["status"], "evidenced")
        self.assertEqual([item["fingerprint"] for item in rows["TM-T01"]["evidence"]], ["a" * 64])
        self.assertEqual([item["fingerprint"] for item in rows["TM-T02"]["evidence"]], ["b" * 64])

    def test_process_evidence_comes_only_from_its_own_repository(self):
        other = "github:org/front"
        current = tm.validate({**model(), "components": model()["components"] + [
            {"id": "front", "name": "Front", "kind": "web_app", "internet_facing": True, "asset": other}],
            "flows": model()["flows"] + [{"id": "f9", "source": "front", "target": "api", "protocol": "https", "data": ["pii"], "authenticated": True}]},
            known_assets={REPO, other})
        xss = {**_finding("d" * 64, cwe=(79,)), "scanner": "sast", "package": None}
        rows = tm.threats(current, {other: [xss]})
        by = {(row["rule"], row["element"]): row for row in rows}
        self.assertEqual(by[("TM-T01", "front")]["status"], "evidenced")
        self.assertEqual(by[("TM-T01", "api")]["status"], "open")   # the API doesn't inherit the front end's findings

    def test_in_a_monorepo_evidence_comes_only_from_the_component_folder(self):
        current = tm.validate({**model(), "components": model()["components"] + [
            {"id": "front", "name": "Front", "kind": "web_app", "internet_facing": True, "asset": REPO, "path": "./frontend"}],
            "flows": model()["flows"] + [{"id": "f9", "source": "front", "target": "api", "protocol": "https", "data": ["pii"], "authenticated": True}]},
            known_assets={REPO})
        front = next(item for item in current["components"] if item["id"] == "front")
        self.assertEqual(front["path"], "frontend/")
        backend = {**_finding("e" * 64, cwe=(79,)), "scanner": "sast", "package": None, "path": "backend/app.py"}
        ui = {**_finding("f" * 64, cwe=(79,)), "scanner": "sast", "package": None, "path": "frontend/src/app.ts"}
        by = {(row["rule"], row["element"]): row for row in tm.threats(current, {REPO: [backend, ui]})}
        self.assertEqual([item["fingerprint"] for item in by[("TM-T01", "front")]["evidence"]], ["f" * 64])
        self.assertEqual(by[("TM-T01", "front")]["evidence_scope"], [{"asset": REPO, "path": "frontend/"}])
        # The API has no folder: it takes the whole repository and says so.
        self.assertEqual(by[("TM-T01", "api")]["evidence_scope"], [{"asset": REPO, "path": None}])
        self.assertEqual(by[("TM-T01", "api")]["evidence_count"], 2)

    def test_folders_and_canvas_positions_are_validated(self):
        for folder in ("../etc", "a/../b", "a;b"):
            bad = [{**item, "path": folder} if item["id"] == "api" else item for item in model()["components"]]
            with self.subTest(folder=folder), self.assertRaises(tm.ModelError):
                model(components=bad)
        placed = model(components=[{**item, "position": {"x": 10.26, "y": -4}} for item in model()["components"]],
                       boundaries=[{**model()["boundaries"][0], "box": {"x": 0, "y": 0, "width": 300, "height": 200}}])
        self.assertEqual(placed["components"][0]["position"], {"x": 10.3, "y": -4})
        self.assertEqual(placed["boundaries"][0]["box"], {"x": 0, "y": 0, "width": 300, "height": 200})
        odd = [{**item, "position": {"x": "1", "y": 2}} if item["id"] == "usuario" else item for item in model()["components"]]
        self.assertIsNone(model(components=odd)["components"][0]["position"])
        self.assertEqual(tm._layout(placed)["nodes"]["usuario"], {"x": 10.3, "y": -4})  # the exports use what was drawn
        partly_placed = model(components=[{**item, "position": {"x": 777, "y": 88}} if item["id"] == "api" else item
                                          for item in model()["components"]])
        self.assertEqual(tm._layout(partly_placed)["nodes"]["api"], {"x": 777, "y": 88})
        self.assertIn("usuario", tm._layout(partly_placed)["nodes"])

    def test_linddun_looks_at_privacy_not_security(self):
        rows = tm.threats(model(methodology="linddun"))
        fired = {(row["rule"], row["element"]) for row in rows}
        self.assertIn(("PV-Dd02", "db"), fired)          # personal data unencrypted at rest
        self.assertIn(("PV-L01", "db"), fired)
        self.assertIn(("PV-U01", "api"), fired)          # collects the user's personal data
        self.assertFalse([row for row in rows if row["rule"].startswith("TM-")])
        self.assertEqual({row["framework"] for row in rows}, {"linddun"})
        self.assertIn("Divulgación de datos", {row["category"] for row in rows})

    def test_team_written_threats_live_in_every_methodology(self):
        manual = [{"id": "robo-sesion", "title": "Robo de sesión desde un Wi-Fi público", "category": "Sesión", "element": "f1",
                   "severity": "high", "scenario": "Un atacante en la misma red...", "likelihood": "medium", "impact": "high", "owner": "ana"}]
        for method in ("stride", "custom", "attack_trees"):
            rows = tm.threats(model(methodology=method, manual_threats=manual))
            own = [row for row in rows if row["framework"] == "manual"]
            self.assertEqual((len(own), own[0]["element_name"], own[0]["owner"]), (1, "Usuario → API", "ana"), method)
        self.assertEqual({row["framework"] for row in tm.threats(model(methodology="custom", manual_threats=manual))}, {"manual"})
        with self.assertRaises(tm.ModelError):
            model(manual_threats=[{**manual[0], "element": "no-existe"}])
        with self.assertRaises(tm.ModelError):
            model(methodology="inventado")

    def test_attack_trees_and_attack_mappings_are_validated_and_reported(self):
        tree = {"id": "cuenta", "goal": "Entrar en la cuenta de otro usuario", "nodes": [
            {"id": "a", "parent": None, "text": "Robar la contraseña", "gate": "or"},
            {"id": "b", "parent": "a", "text": "Phishing", "difficulty": "low"},
            {"id": "c", "parent": None, "text": "Saltarse el segundo factor", "gate": "and", "element": "api", "mitigated": True}]}
        mappings = [{"technique": "T1110", "element": "api", "status": "relevant", "note": "Sin límite de intentos"},
                    {"technique": "T1110", "element": "api"}]  # duplicate: ignored
        current = model(methodology="attack", attack_trees=[tree], attack_mappings=mappings,
                        pasta={"objectives": "Que nadie pague por otro"})
        self.assertEqual(len(current["attack_mappings"]), 1)
        report = tm.to_markdown({**current, "updated_at": "", "updated_by": "x"}, tm.threats(current))
        for text in ("Enfoque: **MITRE ATT&CK**", "T1110 Brute Force", "Acceso a credenciales", "attack.mitre.org",
                     "Entrar en la cuenta de otro usuario", "  - Phishing", "mitigado", "Que nadie pague por otro"):
            self.assertIn(text, report)
        for bad in ({**tree, "nodes": [{"id": "a", "parent": "b", "text": "x"}, {"id": "b", "parent": "a", "text": "y"}]},
                    {**tree, "nodes": [{"id": "a", "parent": "zz", "text": "x"}]}):
            with self.assertRaises(tm.ModelError):
                model(attack_trees=[bad])
        with self.assertRaises(tm.ModelError):
            model(attack_mappings=[{"technique": "T9999"}])
        with self.assertRaises(tm.ModelError):
            model(pasta={"inventada": "x"})

    def test_a_project_starts_without_repositories_and_links_them_later(self):
        blank = tm.validate({"name": "Plataforma", "components": [], "flows": [], "boundaries": []}, known_assets={REPO})
        self.assertEqual(blank["repositories"], [])
        linked = tm.validate({**blank, "repositories": [REPO, REPO]}, known_assets={REPO})
        self.assertEqual(linked["repositories"], [REPO])
        with self.assertRaises(tm.ModelError):
            tm.validate({**blank, "repositories": ["github:ajeno/repo"]}, known_assets={REPO})
        # A repository that uses a component is part of the project even if nobody added it by hand.
        self.assertEqual(model()["repositories"], [REPO])

    def test_proposals_merge_into_what_the_team_already_drew(self):
        other = "github:org/pagos"
        drawn = tm.validate({**model(), "components": [{**item, "position": {"x": 100 + index * 300, "y": 90}} for index, item in enumerate(model()["components"])],
                             "boundaries": [{**item, "box": {"x": 60 + index * 300, "y": 40, "width": 256, "height": 200}} for index, item in enumerate(model()["boundaries"])]},
                            known_assets={REPO, other})
        proposal = tm.validate({"name": "x", "components": [
            {"id": "usuario", "name": "Usuario", "kind": "actor", "internet_facing": True},
            {"id": "pagos", "name": "API de pagos", "kind": "api", "asset": other, "authenticates": True},
            {"id": "pg", "name": "PostgreSQL", "kind": "database", "data": ["pii"]}],
            "flows": [{"id": "a", "source": "usuario", "target": "pagos", "protocol": "https"},
                      {"id": "b", "source": "pagos", "target": "pg", "protocol": "sql", "authenticated": True}],
            "boundaries": [{"id": "aplicacion", "name": "Aplicación", "components": ["pagos"]}]}, known_assets={REPO, other})
        merged, added = tm.merge_proposal(drawn, proposal)
        self.assertEqual(added, {"components": 1, "flows": 2})      # "Usuario" and "PostgreSQL" already existed
        names = [item["name"] for item in merged["components"]]
        self.assertEqual(names.count("Usuario"), 1)
        self.assertEqual(names.count("PostgreSQL"), 1)
        new = next(item for item in merged["components"] if item["name"] == "API de pagos")
        app = next(item for item in merged["boundaries"] if item["name"] == "Aplicación")
        self.assertIn(new["id"], app["components"])
        box = app["box"]
        self.assertTrue(box["x"] <= new["position"]["x"] <= box["x"] + box["width"])
        self.assertTrue(box["y"] <= new["position"]["y"] <= box["y"] + box["height"])     # inside its drawn boundary
        self.assertIn(("usuario", new["id"]), {(flow["source"], flow["target"]) for flow in merged["flows"]})
        self.assertEqual(tm.validate(merged, known_assets={REPO, other})["repositories"], [REPO, other])

    def test_imported_positions_that_do_not_fit_their_boundaries_are_relaid(self):
        base = {"name": "CRM", "components": [
            {"id": "front", "name": "Frontend", "kind": "actor", "position": {"x": 60, "y": 180}},
            {"id": "api", "name": "API", "kind": "api", "position": {"x": 410, "y": 180}},
            {"id": "db", "name": "PostgreSQL", "kind": "database", "position": {"x": 710, "y": 280}},
            {"id": "gcp", "name": "GCP", "kind": "service", "position": {"x": 710, "y": 60}}],
            "flows": [{"id": "a", "source": "front", "target": "api", "protocol": "https"},
                      {"id": "b", "source": "api", "target": "db", "protocol": "sql"},
                      {"id": "c", "source": "api", "target": "gcp", "protocol": "https"}],
            # Boxes that don't fit (the database spills out) and that overlap each other.
            "boundaries": [{"id": "backend", "name": "Backend", "components": ["api", "db"], "box": {"x": 350, "y": 120, "width": 450, "height": 380}},
                           {"id": "nube", "name": "Nube", "components": ["gcp"], "box": {"x": 660, "y": 20, "width": 200, "height": 120}}]}
        imported = tm.from_portable({"format": "tamandua-threat-model", "version": 1, "model": base})
        self.assertTrue(imported.get("relayout"))
        self.assertTrue(all(item["position"] is None for item in imported["components"]))
        coherent = {**base, "components": [{**item, "position": None} for item in base["components"]],
                    "boundaries": [{**item, "box": None} for item in base["boundaries"]]}
        self.assertFalse(tm.from_portable({"format": "tamandua-threat-model", "version": 1, "model": coherent}).get("relayout"))

    def test_automatic_layout_keeps_members_inside_and_boxes_apart(self):
        import glob
        for path in sorted(glob.glob(str(Path(__file__).parents[1] / "web/src/examples/threat-models/*/*.json"))):
            current = tm.from_portable(json.loads(Path(path).read_text(encoding="utf-8")))
            layout = tm._layout(current)
            nodes, boxes = layout["nodes"], layout["boundaries"]
            sizes = {item["id"]: tm._node_size(item) for item in current["components"]}
            self.assertEqual(len({item["kind"] for item in current["components"]}), 12, path)   # every kind is covered
            for boundary in current["boundaries"]:
                box = boxes[boundary["id"]]
                for member in boundary["components"]:
                    point, (width, height) = nodes[member], sizes[member]
                    self.assertTrue(box["x"] <= point["x"] and point["x"] + width <= box["x"] + box["width"], (path, member))
                    self.assertTrue(box["y"] <= point["y"] and point["y"] + height <= box["y"] + box["height"], (path, member))
            ids = list(boxes)
            for index, first in enumerate(ids):
                for second in ids[index + 1:]:
                    a, b = boxes[first], boxes[second]
                    self.assertFalse(a["x"] < b["x"] + b["width"] and b["x"] < a["x"] + a["width"]
                                     and a["y"] < b["y"] + b["height"] and b["y"] < a["y"] + a["height"], (path, first, second))
            self.assertTrue(tm.geometry_fits({**current, "components": [{**item, "position": nodes[item["id"]]} for item in current["components"]],
                                              "boundaries": [{**item, "box": boxes[item["id"]]} for item in current["boundaries"]]}), path)

    def test_several_repositories_name_their_processes(self):
        inventory = {"packages": {"pypi": ["fastapi"]}}
        draft = tm.suggest("S", [{"id": "github:o/a", "name": "o/a", "inventory": inventory, "findings": []},
                                 {"id": "github:o/b", "name": "o/b", "inventory": inventory, "findings": []}])
        self.assertEqual(sorted(item["name"] for item in draft["components"] if item["kind"] == "api"), ["API Python · a", "API Python · b"])

    def test_severity_is_graded_not_flat(self):
        levels = {row["severity"] for row in tm.threats(model())}
        self.assertGreater(len(levels), 1)

    def test_suggestion_from_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "package.json").write_text(json.dumps({"dependencies": {"next": "15", "@prisma/client": "5", "stripe": "14", "next-auth": "4"}}))
            (root / "docker-compose.yml").write_text("services:\n  cache:\n    image: redis:7-alpine\n")
            inventory = collect(root)
        self.assertIn("next", inventory["packages"]["npm"])
        self.assertEqual(inventory["services"], ["redis"])
        draft = tm.validate(tm.suggest("Tienda", [{"id": REPO, "name": "org/shop", "inventory": inventory, "findings": []}]), known_assets={REPO})
        kinds = sorted(item["kind"] for item in draft["components"])
        self.assertEqual(kinds, ["actor", "cache", "database", "external", "identity", "web_app"])
        self.assertTrue(all(item["origin"] == "suggested" for item in draft["components"]))
        self.assertEqual(next(item for item in draft["components"] if item["kind"] == "external")["data"], ["payment"])

    def test_live_inventory_from_github_manifests(self):
        from tamandua.modules.scanning import inventory
        files = [("pyproject.toml", b'[project]\ndependencies = ["fastapi>=0.110", "psycopg[binary]", "sqlalchemy", "stripe"]\n'),
                 ("crates/api/Cargo.toml", b'[dependencies]\naxum = "0.7"\nsqlx = { version = "0.8" }\n'),
                 ("../../escape/package.json", b'{"dependencies": {"express": "4"}}')]
        with patch("tamandua.modules.integrations.github.installation_repository", return_value={"id": REPO, "name": "org/shop", "branch": "main"}), \
                patch("tamandua.modules.integrations.github.repository_manifests", return_value=files) as fetch:
            found = inventory.live(REPO, installation_id=7)
        self.assertEqual(fetch.call_args.args[1:], ("org/shop", "main"))
        self.assertNotIn("npm", found["packages"])  # the path that left the directory was ignored
        self.assertEqual(found["found_in"]["axum"], "crates/api/Cargo.toml")
        draft = tm.suggest("Tienda", [{"id": REPO, "name": "org/shop", "inventory": found, "findings": []}])
        by_name = {item["name"]: item for item in draft["components"]}
        self.assertEqual(by_name["PostgreSQL"]["technology"], "PostgreSQL vía sqlalchemy")
        self.assertNotIn("Base de datos (ORM)", by_name)
        self.assertIn("pyproject.toml", by_name["API Python"]["description"])
        self.assertIn("API Rust", by_name)

    def test_exports(self):
        current = {**model(), "id": "0" * 24, "updated_by": "ana"}
        rows = tm.threats(current)
        dragon = tm.to_threat_dragon(current, rows)
        cells = dragon["detail"]["diagrams"][0]["cells"]
        self.assertEqual({cell["shape"] for cell in cells}, {"trust-boundary-box", "actor", "process", "store", "flow"})
        self.assertEqual(sum(len(cell["data"].get("threats", [])) for cell in cells), len(rows))
        ast.parse(tm.to_pytm(current))
        self.assertIn("## Amenazas", tm.to_markdown(current, rows))

    def test_custom_components_and_selected_tools(self):
        custom = model(methodology="custom", custom_modules=["stride", "linddun", "trees"],
                       components=[*model()["components"], {"id": "motor", "name": "Motor de pagos", "kind": "custom",
                       "custom_kind": "Motor de reglas", "custom_base": "api", "internet_facing": True,
                       "authenticates": False, "data": ["pii"]}])
        self.assertEqual(custom["components"][-1]["custom_kind"], "Motor de reglas")
        self.assertEqual(custom["custom_modules"], ["stride", "linddun", "trees"])
        rows = tm.threats(custom)
        self.assertEqual({row["framework"] for row in rows}, {"stride", "linddun"})
        self.assertIn(("TM-S01", "motor"), {(row["rule"], row["element"]) for row in rows})
        self.assertIn(("PV-Nr01", "motor"), {(row["rule"], row["element"]) for row in rows})
        self.assertIn("Motor de reglas", tm.to_markdown(custom, rows))
        ast.parse(tm.to_pytm(custom))
        self.assertIn("motor", {cell["id"] for cell in tm.to_threat_dragon(custom, rows)["detail"]["diagrams"][0]["cells"]})
        with self.assertRaises(tm.ModelError):
            model(methodology="custom", custom_modules=["inventado"])
        with self.assertRaises(tm.ModelError):
            model(components=[{"id": "x", "name": "X", "kind": "custom", "custom_kind": "X", "custom_base": "inventado"}])

    def test_svg_export_escapes_labels_and_keeps_layout(self):
        current = model(components=[{**item, "name": '<script>alert("x")</script>', "position": {"x": 120, "y": 80}} if item["id"] == "api"
                                    else {**item, "position": {"x": 350 + index * 210, "y": 100}} for index, item in enumerate(model()["components"])],
                        boundaries=[])
        svg = tm.to_svg(current)
        root = ET.fromstring(svg)
        self.assertEqual(root.tag, "{http://www.w3.org/2000/svg}svg")
        self.assertIn('&lt;script&gt;', svg)
        self.assertNotIn('<script>', svg)
        self.assertIn('x="120" y="80"', svg)

    def test_legend_labels_manual_colors(self):
        painted = [{**item, "color": "danger"} if item["id"] in ("api", "db") else item for item in model()["components"]]
        current = model(components=painted, legend={"danger": "  Alcance   PCI ", "info": "sin uso"})
        self.assertEqual(current["legend"], {"danger": "Alcance PCI"})  # trimmed; colors no component uses are dropped
        self.assertEqual(model()["legend"], {})  # a model without a legend is still valid
        self.assertEqual(model(legend=None)["legend"], {})
        # A chosen color equal to the role's color is explained by the role's entry, not a custom one.
        same = model(components=[{**item, "color": "success"} if item["id"] == "db" else item for item in model()["components"]],
                     legend={"success": "Datos"})
        self.assertEqual(same["legend"], {})
        self.assertEqual(model(components=painted, legend={"danger": "   "})["legend"], {})
        for legend in ({"red": "Rojo"}, ["danger"], "danger", {"danger": 5}, {"danger": "x" * 41}, {"danger": "a\x00b"}):
            with self.subTest(legend=legend), self.assertRaises(tm.ModelError):
                model(components=painted, legend=legend)
        self.assertEqual(len(model(components=painted, legend={"danger": "x" * 40})["legend"]["danger"]), 40)
        # The portable format carries the legend; documents from before it existed import without one.
        document = json.loads(json.dumps(tm.to_portable(current)))
        self.assertEqual(document["model"]["legend"], {"danger": "Alcance PCI"})
        self.assertEqual(tm.from_portable(document)["legend"], {"danger": "Alcance PCI"})
        self.assertNotIn("legend", tm.to_portable(model())["model"])
        del document["model"]["legend"]
        self.assertEqual(tm.from_portable(document)["legend"], {})
        with self.assertRaises(tm.ModelError):
            tm.from_portable({**document, "model": {**document["model"], "legend": {"purple": "x"}}})

    def test_svg_legend_lists_roles_in_use_and_manual_colors(self):
        painted = [{**item, "color": "danger"} if item["id"] == "api" else item for item in model()["components"]]
        svg = tm.to_svg(model(components=painted, legend={"danger": '<b>"PCI" & co</b>'}), locale="en")
        ET.fromstring(svg)
        self.assertIn("&lt;b&gt;&quot;PCI&quot; &amp; co&lt;/b&gt;", svg)
        self.assertNotIn("<b>", svg)
        self.assertIn(">Data<", svg)
        self.assertNotIn("APIs, services and jobs", svg)  # the only API is painted red
        unlabeled = tm.to_svg(model(components=painted), locale="es")
        self.assertIn(">Color personalizado<", unlabeled)
        self.assertNotIn("Color personalizado", tm.to_svg(model(), locale="es"))

    def test_portable_json_round_trip_detaches_assets(self):
        original = model(methodology="custom", custom_modules=["stride", "trees", "manual"],
                         repository_refs=["grupo/por-conectar"])
        document = tm.to_portable(original, {REPO: {"name": "org/shop"}})
        self.assertEqual(document["format"], "tamandua-threat-model")
        self.assertEqual(document["model"]["components"][1]["asset_ref"], "org/shop")
        self.assertEqual(set(document["model"]["repository_refs"]), {"org/shop", "grupo/por-conectar"})
        imported = tm.from_portable(json.loads(json.dumps(document)))
        self.assertEqual(imported["methodology"], "custom")
        self.assertEqual(imported["custom_modules"], ["stride", "trees", "manual"])
        self.assertEqual(imported["components"][1]["asset"], None)
        self.assertEqual(imported["components"][1]["asset_ref"], "org/shop")
        self.assertEqual(imported["repositories"], [])
        self.assertEqual(imported["flows"], original["flows"])
        self.assertEqual(tm.to_portable(imported)["model"]["repository_refs"], document["model"]["repository_refs"])
        simple = tm.from_portable({**document["model"], "repositories": ["sin/crear"]})
        self.assertIn("sin/crear", simple["repository_refs"])
        for invalid in ({"format": "otro", "version": 1, "model": document["model"]},
                        {**document["model"], "flows": [{"id": "x", "source": "inexistente", "target": "api", "protocol": "https"}]}):
            with self.assertRaises(tm.ModelError):
                tm.from_portable(invalid)

    def test_portable_import_checks_method_specific_sections(self):
        tree = {"id": "cuenta", "goal": "Entrar", "nodes": [{"id": "ruta", "parent": None, "text": "Robar sesión"}]}
        mapping = {"technique": "T1190", "element": "api"}
        base = model(methodology="custom", custom_modules=["manual", "trees", "attack", "pasta"],
                     attack_trees=[tree], attack_mappings=[mapping], pasta={"objectives": "Proteger cuentas"})
        complete = tm.to_portable(base)["model"]
        self.assertEqual(len(tm.from_portable(complete)["attack_trees"]), 1)
        for method, forbidden, section in (("stride", "árboles", "attack_trees"),
                                           ("linddun", "técnicas", "attack_mappings"),
                                           ("attack_trees", "etapas", "pasta"),
                                           ("attack", "árboles", "attack_trees")):
            document = {**tm.to_portable(model(methodology=method))["model"], section: complete[section]}
            with self.subTest(method=method), self.assertRaisesRegex(tm.ModelError, forbidden):
                tm.from_portable(document)
            current = model(methodology=method, attack_trees=[tree], attack_mappings=[mapping], pasta={"objectives": "Proteger cuentas"})
            exported = tm.to_portable(current)["model"]
            self.assertNotIn(section, exported)
            self.assertNotIn("custom_modules", exported)
            tm.from_portable(exported)
        with self.assertRaisesRegex(tm.ModelError, "árboles"):
            tm.from_portable({**complete, "custom_modules": ["manual", "attack", "pasta"]})


class RouteTests(HttpCase):
    def test_suggest_edit_decide_and_export(self):
        with patch.dict(os.environ, {"TAMANDUA_REQUIRE_TOTP": "none"}):
            Users(self.data_dir).create("operadora", PASSWORD, role="admin")
            _, _, cookies = self.post("/api/auth/login", "login", {"username": "operadora", "password": PASSWORD})
            cookie = cookies[0].split("; ")[0]
            scan = _scan("org/shop", [{**_finding("c" * 64, cwe=(89,)), "scanner": "sast", "package": None}], datetime.now(timezone.utc).isoformat())
            scan["source"]["id"] = REPO
            stored = save_repository_scan(self.data_dir, {**scan, "inventory": {"packages": {"npm": ["express", "pg"]}, "services": []}})
            for artifact in ("report.md", "report.pdf", "report-soc2.pdf", "report-iso27001.pdf",
                             "findings.sarif", "tickets.json"):
                status, content = self.call("GET", f"/api/runs/{stored['id']}/{artifact}", headers={"Cookie": cookie})[:2]
                self.assertEqual(status, 200, artifact)
                if artifact.endswith(".pdf"):
                    self.assertTrue(content.startswith(b"%PDF-"), artifact)
            status, created, _ = self.post("/api/threat-models", "save-threat-model", {"name": "Tienda", "suggest": [REPO]}, cookie)
            self.assertEqual(status, 200, created)
            self.assertIn("database", {item["kind"] for item in created["model"]["components"]})
            evidenced = [row for row in created["threats"] if row["status"] == "evidenced"]
            self.assertEqual([row["rule"] for row in evidenced], ["TM-T01"])
            model_id, threat = created["model"]["id"], evidenced[0]["id"]
            status, decided, _ = self.post("/api/threat-models/decide", "threat-decision",
                                           {"id": model_id, "threat": threat, "status": "mitigated", "reason": "Consultas parametrizadas desde el ORM"}, cookie)
            self.assertEqual(next(row for row in decided["threats"] if row["id"] == threat)["status"], "mitigated")
            painted = [{**item, "color": "danger"} if index == 0 else item for index, item in enumerate(decided["model"]["components"])]
            status, saved, _ = self.post("/api/threat-models", "save-threat-model", {"id": model_id, "model": {
                **decided["model"], "name": "Tienda v2", "components": painted, "legend": {"danger": "Alcance PCI"}}}, cookie)
            self.assertEqual(status, 200)
            self.assertEqual(saved["model"]["legend"], {"danger": "Alcance PCI"})
            self.assertIn("Alcance PCI", self.call("GET", f"/api/threat-models/{model_id}/diagram.svg", headers={"Cookie": cookie})[1].decode())
            for artifact in ("threat-dragon.json", "tm.py", "report.md", "report.pdf", "diagram.svg", "model.json"):
                self.assertEqual(self.call("GET", f"/api/threat-models/{model_id}/{artifact}", headers={"Cookie": cookie})[0], 200)
            status, pdf = self.call("GET", f"/api/threat-models/{model_id}/report.pdf", headers={"Cookie": cookie})[:2]
            self.assertEqual(status, 200)
            self.assertTrue(pdf.startswith(b"%PDF-"))
            # A threat model isn't SOC 2 or ISO evidence: those reports are about the findings.
            self.assertEqual(self.call("GET", f"/api/threat-models/{model_id}/report-soc2.pdf", headers={"Cookie": cookie})[0], 404)
            for artifact in ("report.md", "report.pdf", "report-soc2.pdf", "report-iso27001.pdf", "findings.sarif", "tickets.json", "record.json"):
                status, body = self.call("GET", f"/api/assets/export?key={REPO}&status=all&artifact={artifact}", headers={"Cookie": cookie})[:2]
                self.assertEqual(status, 200, (artifact, str(body)[:300]))
                if artifact.endswith(".pdf"):
                    self.assertTrue(body.startswith(b"%PDF-"), artifact)
            portable = tm.to_portable(decided["model"], {REPO: {"name": "org/shop"}})
            before = len(tm.list_models(self.data_dir))
            status, preview, _ = self.post("/api/threat-models/validate", "validate-threat-model", portable, cookie)
            self.assertEqual(status, 200, preview)
            self.assertEqual(preview["name"], decided["model"]["name"])
            self.assertEqual(preview["components"], len(decided["model"]["components"]))
            self.assertEqual(len(tm.list_models(self.data_dir)), before)
            status, imported, _ = self.post("/api/threat-models/import", "import-threat-model", portable, cookie)
            self.assertEqual(status, 200, imported)
            self.assertNotEqual(imported["model"]["id"], model_id)
            self.assertEqual(imported["model"]["repositories"], [])
            self.assertIn("org/shop", imported["model"]["repository_refs"])
            bad = {**portable, "model": {**portable["model"], "methodology": "stride", "custom_modules": None,
                                         "attack_trees": [{"id": "ruta", "goal": "Entrar", "nodes": []}]}}
            bad["model"].pop("custom_modules")
            status, validation_error, _ = self.post("/api/threat-models/validate", "validate-threat-model", bad, cookie)
            self.assertEqual(status, 400)
            self.assertIn("árboles de ataque", validation_error["error"])
            status, rejected, _ = self.post("/api/threat-models/import", "import-threat-model", bad, cookie)
            self.assertEqual(status, 400)
            self.assertIn("árboles de ataque", rejected["error"])
            status, listing, _ = self.call("GET", "/api/threat-models", headers={"Cookie": cookie})
            self.assertIn("Tienda v2", [item["name"] for item in listing["models"]])


if __name__ == "__main__":
    unittest.main()
