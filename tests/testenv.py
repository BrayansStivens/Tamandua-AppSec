"""What a test that empties the environment must keep: the test database and the temporary configuration folder."""

import os

KEEP = ("TAMANDUA_DATABASE_URL", "TAMANDUA_DB_ISOLATE", "TAMANDUA_CONFIG_DIR")


def base(**extra) -> dict:
    return {**{name: os.environ[name] for name in KEEP if name in os.environ}, **extra}
