"""Compatibilidad: el panel vive en ``appsec_agent.api`` (tabla de rutas y manejadores por área)."""

from .api import allowed_origins, make_handler, public_url, serve

__all__ = ["allowed_origins", "make_handler", "public_url", "serve"]
