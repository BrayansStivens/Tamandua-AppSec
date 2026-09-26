"""Compatibilidad: el panel vive en ``tamandua.app.http`` (tabla de rutas y manejadores por área)."""

from tamandua.app.http import allowed_origins, make_handler, public_url, serve

__all__ = ["allowed_origins", "make_handler", "public_url", "serve"]
