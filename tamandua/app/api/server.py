"""Panel start-up: the shared state (auth, queue, log) and the uvicorn server."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

from tamandua.shared import log as logging_setup, settings
from tamandua.app import data_migrations as migrations, wiring
from tamandua.app.api.security import State, public_url
from tamandua.modules.identity.auth import Authenticator
from tamandua.modules.runs import periodic
from tamandua.modules.runs.jobs import ScanJobs
from tamandua.shared.i18n import t


def embedded_worker() -> bool:
    """Single process (the default): the server also runs the scans. In compose, a separate `worker` service runs
    them and the API runs with TAMANDUA_EMBEDDED_WORKER=0 (no Docker)."""
    return settings.flag("TAMANDUA_EMBEDDED_WORKER")


def build_state(data_dir: Path, *, watch_pull_requests: bool = False, worker: bool | None = None) -> State:
    wiring.configure()
    migrations.upgrade(data_dir)  # before anything reads: an upgrade converts old data exactly once
    embedded = embedded_worker() if worker is None else worker
    state = State(data_dir=data_dir, log=logging_setup.configure(data_dir), jobs=ScanJobs(data_dir, worker=embedded),
                  auth=Authenticator(data_dir))
    if watch_pull_requests and embedded and not periodic.external():
        from tamandua.app.worker import start_periodic
        start_periodic(data_dir, state.jobs)
    return state


LOOPBACK = ("127.0.0.1", "localhost", "::1", "[::1]")


def transport_check(port: int) -> str | None:
    """Reason not to start, or None. Plain HTTP only if the panel never leaves this machine.

    The password, the session cookie and the tokens pasted into Integrations travel with every
    request: serving them over HTTP on the network exposes them to anyone along the way.
    """
    url = public_url(port)
    parts = urlsplit(url)
    if parts.scheme == "https":
        return None
    if parts.scheme == "http" and (parts.hostname or "") in LOOPBACK:
        return None
    if settings.flag("TAMANDUA_ALLOW_INSECURE_HTTP"):
        return None
    return t("cli.server.insecure_http", url=url)


def proxy_settings() -> dict:
    """Uvicorn settings for the client address. Direct (default): the TCP peer, X-Forwarded-* ignored.

    Behind a reverse proxy every request comes from the proxy: sign-in throttling per client and the audit log would
    see one address for everybody (one attacker could lock everyone out). `TAMANDUA_FORWARDED_ALLOW_IPS` lists the
    proxies whose X-Forwarded-For is believed; set it only when the API is reachable through that proxy alone.
    """
    trusted = settings.text("TAMANDUA_FORWARDED_ALLOW_IPS")
    return {"proxy_headers": True, "forwarded_allow_ips": trusted} if trusted else {"proxy_headers": False}


def serve(data_dir: Path, port: int, bind: str | None = None) -> None:
    if port < 0 or port > 65535:
        raise ValueError(t("cli.server.port_out_of_range"))
    problem = transport_check(port)
    if problem:
        raise SystemExit(problem)
    # Outside a container, listen on loopback only; inside one, on all of the container's interfaces.
    address = bind or settings.text("TAMANDUA_BIND")
    state = build_state(data_dir, watch_pull_requests=True)
    from tamandua.app.api import create_app
    import uvicorn
    app = create_app(data_dir, port=port, state=state)
    cert, key = settings.text("TAMANDUA_TLS_CERT"), settings.text("TAMANDUA_TLS_KEY")
    print(t("cli.server.listening_tls" if cert else "cli.server.listening", url=public_url(port), address=f"{address}:{port}"), flush=True)
    code = state.auth.setup_code()
    if code:
        # Straight to the console, not the log file: only someone who can see the server console can claim it.
        print("\n" + "=" * 64 + f"\n  {t('cli.server.setup_code')}\n      {code}\n  {t('cli.server.setup_code_hint')}\n" + "=" * 64 + "\n",
              flush=True)
    # No Server header; X-Forwarded-For only from trusted proxies (the allowed Host is always decided by
    # TAMANDUA_ALLOWED_ORIGINS, never by forwarded headers); same TLS floor as before (1.2).
    uvicorn.run(app, host=address, port=port, log_level="warning", access_log=False, server_header=False, **proxy_settings(),
                ssl_certfile=cert or None, ssl_keyfile=key or None, timeout_keep_alive=5)
    print(t("cli.server.stopped"), flush=True)
