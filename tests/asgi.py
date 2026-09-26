"""Cliente de pruebas sobre la aplicación ASGI completa (FastAPI + router clásico detrás), sin socket."""

from starlette.testclient import TestClient

from tamandua.app.api import create_app

PORT = 8766


def client_for(data_dir, handler) -> TestClient:
    app = create_app(data_dir, port=PORT, handler=handler)
    return TestClient(app, base_url=f"http://127.0.0.1:{PORT}", client=("127.0.0.1", 10000), follow_redirects=False)


def request(client: TestClient, method: str, path: str, body: str | bytes | None = None, headers: dict | None = None):
    client.cookies.clear()  # cada petición lleva solo la cookie que la prueba indique
    return client.request(method, path, content=body, headers=headers or {})


def raw(client: TestClient, method: str, path: str, body: str | bytes | None = None, headers: dict | None = None) -> bytes:
    """La respuesta como bytes HTTP (línea de estado, cabeceras con Mayúsculas, cuerpo), como la leían las pruebas antiguas."""
    response = request(client, method, path, body, headers)
    lines = [f"HTTP/1.1 {response.status_code} {response.reason_phrase}"]
    lines += [f"{'-'.join(part.capitalize() for part in name.split('-'))}: {value}" for name, value in response.headers.multi_items()]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + response.content
