"""Rutas del proyecto y de la configuración, en un solo sitio (antes cada módulo calculaba la suya)."""

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]  # raíz del repositorio (o /app en el contenedor)
RULES_DIR = ROOT / "rules"
FIXTURES_DIR = ROOT / "fixtures"
# Configuración y secretos (almacén cifrado). Las pruebas lo redirigen a un temporal con patch.object(paths, "CONFIG_DIR", …).
CONFIG_DIR = Path(os.environ.get("APPSEC_AGENT_CONFIG_DIR") or Path.home() / ".config" / "appsec-agent")
