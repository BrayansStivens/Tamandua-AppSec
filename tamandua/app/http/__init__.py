"""API HTTP del panel. Importar los módulos de rutas los registra en la tabla."""

from __future__ import annotations

import os
from http.server import ThreadingHTTPServer
from pathlib import Path

from tamandua.shared import log as logging_setup
from tamandua.app import data_migrations as migrations
from tamandua.modules.identity.auth import Authenticator
from tamandua.modules.runs.jobs import ScanJobs
from tamandua.app.http import routes_auth  # noqa: F401 — registran sus rutas
from tamandua.app.http import routes_cra  # noqa: F401 — registran sus rutas
from tamandua.app.http import routes_cves  # noqa: F401 — registran sus rutas
from tamandua.app.http import routes_prs  # noqa: F401 — registran sus rutas
from tamandua.app.http import routes_runs  # noqa: F401 — registran sus rutas
from tamandua.app.http import routes_sources  # noqa: F401 — registran sus rutas
from tamandua.app.http import routes_threats  # noqa: F401 — registran sus rutas
from tamandua.app.http.core import ROUTES, PREFIXES, State, allowed_origins, build_handler, public_url

__all__ = ["make_handler", "serve", "allowed_origins", "public_url", "ROUTES", "PREFIXES"]


def make_handler(data_dir: Path, *, watch_pull_requests: bool = False):
    migrations.upgrade(data_dir)  # antes de que nada lea: una actualización convierte los datos viejos una sola vez
    state = State(data_dir=data_dir, log=logging_setup.configure(data_dir), jobs=ScanJobs(data_dir),
                  auth=Authenticator(data_dir))
    if watch_pull_requests:
        from tamandua.modules.integrations.installations import github_installations
        from tamandua.modules.pullrequests.watch import Watcher
        Watcher(data_dir, state.jobs, lambda: github_installations(data_dir)).start()
        from tamandua.modules.intel.cve_db import Syncer
        Syncer(data_dir).start()
        # Una vez al día, las dependencias ya analizadas contra los avisos publicados después (sin conexión).
        from tamandua.modules.intel.advisory_watch import Watcher as AdvisoryWatcher
        AdvisoryWatcher(data_dir).start()
    return build_handler(state)


LOOPBACK = ("127.0.0.1", "localhost", "::1", "[::1]")


def transport_check(port: int) -> str | None:
    """Motivo para no arrancar, o None. HTTP en claro solo si el panel no sale de esta máquina.

    La contraseña, la cookie de sesión y los tokens que se pegan en Integraciones viajan en
    cada petición: servirlos por HTTP a la red los expone a cualquiera en el camino.
    """
    from urllib.parse import urlsplit
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
    handler = make_handler(data_dir, watch_pull_requests=True)
    with ThreadingHTTPServer((address, port), handler) as server:
        cert, key = os.environ.get("APPSEC_AGENT_TLS_CERT", "").strip(), os.environ.get("APPSEC_AGENT_TLS_KEY", "").strip()
        if cert or key:
            import ssl
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(cert, key)
            server.socket = context.wrap_socket(server.socket, server_side=True)
        print(f"Panel: {public_url(server.server_port)} (escuchando en {address}:{server.server_port}"
              f"{', TLS' if cert else ''})", flush=True)
        code = handler.state.auth.setup_code()
        if code:
            # Directo a la consola y no al log en fichero: solo quien ve la consola del servidor puede reclamarlo.
            print("\n" + "=" * 64 + "\n  Primer arranque: crea el administrador en el panel con este código\n"
                  f"      {code}\n  (solo sirve una vez y solo mientras no haya usuarios)\n" + "=" * 64 + "\n", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("Panel detenido.", flush=True)
