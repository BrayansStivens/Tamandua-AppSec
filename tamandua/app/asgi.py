"""The app as an ASGI object, for platforms that import it instead of running `tamandua serve` (Vercel's Python
runtime, or any ASGI server: `uvicorn tamandua.app.asgi:app`).

Everything comes from the environment: TAMANDUA_DATABASE_URL, TAMANDUA_MASTER_KEY, TAMANDUA_PUBLIC_URL and
TAMANDUA_ALLOWED_ORIGINS at least. This process never runs scans (a worker elsewhere does) and never starts periodic
tasks. The data folder only holds caches that rebuild themselves (TAMANDUA_DATA_DIR, or the system's temporary folder).
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from tamandua.app.api import create_app
from tamandua.app.api.server import build_state, transport_check
from tamandua.shared import settings
from tamandua.shared.i18n import t, text

PORT = 443  # only used when TAMANDUA_PUBLIC_URL is missing, which the checks below refuse


def _build():
    problems = [text(problem) for problem in settings.problems()]
    if not settings.is_set("TAMANDUA_PUBLIC_URL"):
        problems.append(t("cli.settings.missing", name="TAMANDUA_PUBLIC_URL"))
    insecure = transport_check(PORT)
    if insecure:
        problems.append(insecure)
    if problems:
        raise RuntimeError("\n".join([t("cli.settings.header"), *problems]))
    data_dir = Path(settings.text("TAMANDUA_DATA_DIR") or Path(tempfile.gettempdir()) / "tamandua")
    data_dir.mkdir(parents=True, exist_ok=True)
    state = build_state(data_dir, watch_pull_requests=False, worker=False)
    code = state.auth.setup_code()
    if code:
        print(f"{t('cli.server.setup_code')}: {code}", flush=True)  # in the platform's logs, like on a server's console
    return create_app(data_dir, port=PORT, state=state)


app = _build()
