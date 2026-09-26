"""Arranque del panel: el estado compartido (auth, cola, log) y el servidor uvicorn."""

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlsplit

from tamandua.shared import log as logging_setup
from tamandua.app import data_migrations as migrations
from tamandua.app.api.security import State, public_url
from tamandua.modules.identity.auth import Authenticator
from tamandua.modules.runs.jobs import ScanJobs


def embedded_worker() -> bool:
    """Un solo proceso (por defecto): el servidor ejecuta también los análisis. En compose, un servicio `worker` aparte
    los ejecuta y el API corre con APPSEC_AGENT_EMBEDDED_WORKER=0 (sin Docker)."""
    return os.environ.get("APPSEC_AGENT_EMBEDDED_WORKER", "1").lower() not in ("0", "false", "no", "off")


def build_state(data_dir: Path, *, watch_pull_requests: bool = False, worker: bool | None = None) -> State:
    migrations.upgrade(data_dir)  # antes de que nada lea: una actualización convierte los datos viejos una sola vez
    embedded = embedded_worker() if worker is None else worker
    state = State(data_dir=data_dir, log=logging_setup.configure(data_dir), jobs=ScanJobs(data_dir, worker=embedded),
                  auth=Authenticator(data_dir))
    if watch_pull_requests and embedded:
        from tamandua.app.worker import start_periodic
        start_periodic(data_dir, state.jobs)
    return state


LOOPBACK = ("127.0.0.1", "localhost", "::1", "[::1]")


def transport_check(port: int) -> str | None:
    """Motivo para no arrancar, o None. HTTP en claro solo si el panel no sale de esta máquina.

    La contraseña, la cookie de sesión y los tokens que se pegan en Integraciones viajan en
    cada petición: servirlos por HTTP a la red los expone a cualquiera en el camino.
    """
    url = public_url(port)
    parts = urlsplit(url)
    if parts.scheme == "https":
        return None
    if parts.scheme == "http" and (parts.hostname or "") in LOOPBACK:
        return None
    if os.environ.get("APPSEC_AGENT_ALLOW_INSECURE_HTTP", "").strip() == "1":
        return None
    return (f"APPSEC_AGENT_PUBLIC_URL={url} expone el panel por HTTP en claro. Usa HTTPS "
            "(APPSEC_AGENT_TLS_CERT/APPSEC_AGENT_TLS_KEY o un proxy como Caddy delante) o, solo en una red "
            "de confianza y bajo tu responsabilidad, APPSEC_AGENT_ALLOW_INSECURE_HTTP=1.")


def serve(data_dir: Path, port: int, bind: str | None = None) -> None:
    if port < 0 or port > 65535:
        raise ValueError("Puerto fuera de rango")
    problem = transport_check(port)
    if problem:
        raise SystemExit(problem)
    # Fuera de un contenedor se escucha solo en loopback; dentro, en todas las interfaces del contenedor.
    address = bind or os.environ.get("APPSEC_AGENT_BIND", "127.0.0.1")
    state = build_state(data_dir, watch_pull_requests=True)
    from tamandua.app.api import create_app
    import uvicorn
    app = create_app(data_dir, port=port, state=state)
    cert, key = os.environ.get("APPSEC_AGENT_TLS_CERT", "").strip(), os.environ.get("APPSEC_AGENT_TLS_KEY", "").strip()
    print(f"Panel: {public_url(port)} (escuchando en {address}:{port}{', TLS' if cert else ''})", flush=True)
    code = state.auth.setup_code()
    if code:
        # Directo a la consola y no al log en fichero: solo quien ve la consola del servidor puede reclamarlo.
        print("\n" + "=" * 64 + "\n  Primer arranque: crea el administrador en el panel con este código\n"
              f"      {code}\n  (solo sirve una vez y solo mientras no haya usuarios)\n" + "=" * 64 + "\n", flush=True)
    # Sin cabecera Server, sin confiar en X-Forwarded-* (el host permitido lo decide APPSEC_AGENT_ALLOWED_ORIGINS)
    # y con los mismos límites de TLS que antes (1.2 como mínimo).
    uvicorn.run(app, host=address, port=port, log_level="warning", access_log=False, server_header=False, proxy_headers=False,
                ssl_certfile=cert or None, ssl_keyfile=key or None, timeout_keep_alive=5)
    print("Panel detenido.", flush=True)
