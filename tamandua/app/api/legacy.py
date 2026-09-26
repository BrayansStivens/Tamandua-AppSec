"""Anticorrupción: las rutas que aún no se han migrado a FastAPI las atiende el router clásico, en memoria.

Patrón *strangler fig*: FastAPI va delante; lo que no conoce se lo pasa al manejador de siempre (la misma tubería de
seguridad, los mismos límites de cuerpo) y devuelve su respuesta tal cual. Cada ruta migrada se borra de routes_*.py.
"""

from __future__ import annotations

import io
from email.message import Message

from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import Response

HOP = {"server", "date", "connection", "transfer-encoding"}


def _call(handler_class, *, method: str, target: str, headers: list[tuple[str, str]], body: bytes, client: str, port: int):
    handler = handler_class.__new__(handler_class)
    handler.server = type("Server", (), {"server_port": port})()
    handler.client_address = (client, 0)
    handler.request_version = "HTTP/1.1"
    handler.command, handler.path = method, target
    handler.requestline = f"{method} {target} HTTP/1.1"
    handler.rfile, handler.wfile = io.BytesIO(body), io.BytesIO()
    message = Message()  # cabeceras sin distinguir mayúsculas, como las de http.server
    for name, value in headers:
        message[name] = value
    handler.headers = message
    getattr(handler, f"do_{method}")()
    head, _, content = handler.wfile.getvalue().partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    status = int(lines[0].split()[1])
    raw = [(name.strip().lower(), value.strip()) for name, _, value in (line.partition(":") for line in lines[1:]) if name]
    return status, [(name, value) for name, value in raw if name not in HOP], content


async def forward(request: Request) -> Response:
    target = request.url.path + (f"?{request.url.query}" if request.url.query else "")
    status, headers, content = await run_in_threadpool(
        _call, request.app.state.handler, method=request.method, target=target, headers=list(request.headers.items()),
        body=await request.body(), client=request.client.host if request.client else "127.0.0.1", port=request.app.state.port)
    response = Response(content=content, status_code=status)
    response.raw_headers = [(name.encode("latin-1"), value.encode("latin-1")) for name, value in headers]
    response.headers["x-tamandua-legacy"] = "1"  # para no registrar dos veces en el log (el clásico ya lo hizo)
    return response
