"""Locations of local state."""

from __future__ import annotations

import os
from pathlib import Path

STATE_DIR_ENV = "PIISAFE_HOME"
DB_FILE = "piisafe.db"
POLICY_SEARCH = ("piisafe.yaml", "piisafe.yml", ".piisafe.yaml")


def default_state_dir() -> Path:
    env = os.environ.get(STATE_DIR_ENV)
    return Path(env).expanduser() if env else Path.home() / ".piisafe"


def find_policy_file(start: Path | None = None) -> Path | None:
    """Look for a policy file in the working directory."""
    base = start or Path.cwd()
    for name in POLICY_SEARCH:
        p = base / name
        if p.is_file():
            return p
    return None
