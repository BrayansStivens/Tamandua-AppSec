"""Vercel entry point: the API and the panel as one Python function (see docs/deploy.md). Scans run on a worker
elsewhere; this only imports the ASGI app."""

from tamandua.app.asgi import app  # noqa: F401
