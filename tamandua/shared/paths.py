"""Project and configuration paths in one place (each module used to compute its own)."""

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]  # repository root (or /app in the container)
RULES_DIR = ROOT / "rules"
FIXTURES_DIR = ROOT / "fixtures"
# Config and secrets (encrypted vault). Tests redirect it to a temp dir with patch.object(paths, "CONFIG_DIR", …).
CONFIG_DIR = Path(os.environ.get("TAMANDUA_CONFIG_DIR") or Path.home() / ".config" / "tamandua")
