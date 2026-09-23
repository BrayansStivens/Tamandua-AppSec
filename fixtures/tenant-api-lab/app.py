"""Laboratorio local con fallos intencionales y controles corregidos.

Nunca exponer este servidor a una red externa ni usar datos reales.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
from urllib.parse import parse_qs
from wsgiref.simple_server import make_server


TOKENS = {
    "token-alice": ("alice", "tenant-a"),
    "token-bob": ("bob", "tenant-b"),
    "token-admin": ("admin", "tenant-a"),
}


class TenantLab:
    def __init__(self, vulnerable: bool):
        self.vulnerable = vulnerable
        self.users = {
            "alice": {"name": "alice", "tenant": "tenant-a", "role": "member", "support_pin": "1111"},
            "bob": {"name": "bob", "tenant": "tenant-b", "role": "member", "support_pin": "2222"},
            "admin": {"name": "admin", "tenant": "tenant-a", "role": "admin", "support_pin": "3333"},
        }
        self.db = sqlite3.connect(":memory:")
        self.db.execute("CREATE TABLE documents (id INTEGER PRIMARY KEY, title TEXT, tenant TEXT)")
        self.db.executemany(
            "INSERT INTO documents VALUES (?, ?, ?)",
            [(1, "Roadmap A", "tenant-a"), (2, "Budget B", "tenant-b")],
        )

    @staticmethod
    def _json(start_response, status: str, payload: dict):
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        start_response(status, [("Content-Type", "application/json"), ("Content-Length", str(len(body)))])
        return [body]

    def __call__(self, environ, start_response):
        method = environ["REQUEST_METHOD"]
        path = environ["PATH_INFO"]
        token = environ.get("HTTP_AUTHORIZATION", "").removeprefix("Bearer ")
        principal = TOKENS.get(token)
        if principal is None:
            return self._json(start_response, "401 Unauthorized", {"error": "unauthorized"})
        username, tenant = principal
        user = self.users[username]

        if method == "GET" and path.startswith("/api/documents/"):
            raw_id = path.rsplit("/", 1)[-1]
            if not raw_id.isdecimal():
                return self._json(start_response, "404 Not Found", {"error": "not_found"})
            row = self.db.execute("SELECT id, title, tenant FROM documents WHERE id = ?", (int(raw_id),)).fetchone()
            if row is None or (not self.vulnerable and row[2] != tenant):
                return self._json(start_response, "404 Not Found", {"error": "not_found"})
            return self._json(start_response, "200 OK", {"id": row[0], "title": row[1], "tenant": row[2]})

        if method == "POST" and path == "/api/admin/reports":
            if not self.vulnerable and user["role"] != "admin":
                return self._json(start_response, "403 Forbidden", {"error": "forbidden"})
            return self._json(start_response, "200 OK", {"report": "synthetic-admin-report"})

        if method == "GET" and path == "/api/me":
            payload = dict(user) if self.vulnerable else {"name": username, "tenant": tenant, "role": user["role"]}
            return self._json(start_response, "200 OK", payload)

        if method == "PATCH" and path == "/api/me":
            try:
                size = int(environ.get("CONTENT_LENGTH") or "0")
                if size < 0 or size > 1024:
                    return self._json(start_response, "413 Content Too Large", {"error": "body_too_large"})
                data = json.loads(environ["wsgi.input"].read(size))
                if not isinstance(data, dict):
                    raise ValueError("body must be an object")
            except (ValueError, json.JSONDecodeError):
                return self._json(start_response, "400 Bad Request", {"error": "invalid_json"})
            if self.vulnerable:
                user.update({key: value for key, value in data.items() if key in user})
            elif isinstance(data.get("name"), str):
                user["name"] = data["name"]
            return self._json(start_response, "200 OK", {"name": user["name"], "role": user["role"]})

        if method == "GET" and path == "/api/search":
            query = parse_qs(environ.get("QUERY_STRING", "")).get("q", [""])[0]
            try:
                if self.vulnerable:
                    # Vulnerabilidad deliberada: interpolación SQL en el fixture de evaluación.
                    rows = self.db.execute(
                        f"SELECT id, title, tenant FROM documents WHERE title LIKE '%{query}%' AND tenant = '{tenant}'"
                    ).fetchall()
                else:
                    rows = self.db.execute(
                        "SELECT id, title, tenant FROM documents WHERE title LIKE ? AND tenant = ?",
                        (f"%{query}%", tenant),
                    ).fetchall()
            except sqlite3.Error:
                return self._json(start_response, "400 Bad Request", {"error": "invalid_query"})
            return self._json(
                start_response,
                "200 OK",
                {"documents": [{"id": row[0], "title": row[1], "tenant": row[2]} for row in rows]},
            )

        return self._json(start_response, "404 Not Found", {"error": "not_found"})


def main():
    parser = argparse.ArgumentParser(description="Fixture local de seguridad; solo loopback")
    parser.add_argument("--variant", choices=("vulnerable", "fixed"), required=True)
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    with make_server("127.0.0.1", args.port, TenantLab(args.variant == "vulnerable")) as server:
        print(f"tenant-api-lab {args.variant} en http://127.0.0.1:{server.server_port}", flush=True)
        server.serve_forever()


if __name__ == "__main__":
    main()
