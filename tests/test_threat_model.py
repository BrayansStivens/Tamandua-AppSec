"""Modelado de amenazas: validación, propuesta desde el inventario, STRIDE, evidencia, decisiones y exportaciones."""

import ast
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from appsec_agent import threat_model as tm
from appsec_agent.auth import Users
from appsec_agent.inventory import collect
from appsec_agent.store import save_repository_scan
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
        self.assertIn(("TM-I03", "db"), fired)          # credenciales en un almacén
        self.assertIn(("TM-I02", "db"), fired)          # sensible y sin cifrar en reposo
        self.assertIn(("TM-S03", "api"), fired)         # webhook de Stripe hacia la API
        self.assertIn(("TM-I05", "f3"), fired)          # datos de pago a un tercero
        self.assertIn(("TM-E02", "api"), fired)         # llama hacia fuera: SSRF
        self.assertNotIn(("TM-S01", "api"), fired)      # autentica: no aplica «sin autenticación»
        self.assertIn(("TM-T04", "f2"), fired)          # SQL sin cifrar cruzando de Aplicación a Datos
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
        self.assertEqual(by[("TM-T01", "api")]["status"], "open")   # la API no hereda los hallazgos del front

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
        from appsec_agent import inventory
        files = [("pyproject.toml", b'[project]\ndependencies = ["fastapi>=0.110", "psycopg[binary]", "sqlalchemy", "stripe"]\n'),
                 ("crates/api/Cargo.toml", b'[dependencies]\naxum = "0.7"\nsqlx = { version = "0.8" }\n'),
                 ("../../escape/package.json", b'{"dependencies": {"express": "4"}}')]
        with patch("appsec_agent.github_app.installation_repositories", return_value=[{"id": REPO, "name": "org/shop", "branch": "main"}]), \
                patch("appsec_agent.github_app.repository_manifests", return_value=files) as fetch:
            found = inventory.live(REPO, installation_id=7)
        self.assertEqual(fetch.call_args.args[1:], ("org/shop", "main"))
        self.assertNotIn("npm", found["packages"])  # la ruta que salía del directorio se ignoró
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


class RouteTests(HttpCase):
    def test_suggest_edit_decide_and_export(self):
        with patch.dict(os.environ, {"APPSEC_AGENT_REQUIRE_TOTP": "none"}):
            Users(self.data_dir).create("operadora", PASSWORD, role="admin")
            _, _, cookies = self.post("/api/auth/login", "login", {"username": "operadora", "password": PASSWORD})
            cookie = cookies[0].split("; ")[0]
            scan = _scan("org/shop", [{**_finding("c" * 64, cwe=(89,)), "scanner": "sast", "package": None}], datetime.now(timezone.utc).isoformat())
            scan["source"]["id"] = REPO
            save_repository_scan(self.data_dir, {**scan, "inventory": {"packages": {"npm": ["express", "pg"]}, "services": []}})
            status, created, _ = self.post("/api/threat-models", "save-threat-model", {"name": "Tienda", "suggest": [REPO]}, cookie)
            self.assertEqual(status, 200, created)
            self.assertIn("database", {item["kind"] for item in created["model"]["components"]})
            evidenced = [row for row in created["threats"] if row["status"] == "evidenced"]
            self.assertEqual([row["rule"] for row in evidenced], ["TM-T01"])
            model_id, threat = created["model"]["id"], evidenced[0]["id"]
            status, decided, _ = self.post("/api/threat-models/decide", "threat-decision",
                                           {"id": model_id, "threat": threat, "status": "mitigated", "reason": "Consultas parametrizadas desde el ORM"}, cookie)
            self.assertEqual(next(row for row in decided["threats"] if row["id"] == threat)["status"], "mitigated")
            status, _, _ = self.post("/api/threat-models", "save-threat-model", {"id": model_id, "model": {**decided["model"], "name": "Tienda v2"}}, cookie)
            self.assertEqual(status, 200)
            for artifact in ("threat-dragon.json", "tm.py", "report.md"):
                self.assertEqual(self.call("GET", f"/api/threat-models/{model_id}/{artifact}", headers={"Cookie": cookie})[0], 200)
            status, listing, _ = self.call("GET", "/api/threat-models", headers={"Cookie": cookie})
            self.assertEqual(listing["models"][0]["name"], "Tienda v2")


if __name__ == "__main__":
    unittest.main()
