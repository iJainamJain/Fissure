"""Optional on-device settings persistence for the GUI.

Stores GUI preferences (and, only if the user opts in, API keys) in a JSON file
under the user's home directory. This is a local convenience, not a secret store:
keys are saved in plaintext, readable by this OS user. The file lives outside the
repo and is created with owner-only permissions on a best-effort basis.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

CONFIG_DIR = Path.home() / ".fissure"
CONFIG_PATH = CONFIG_DIR / "config.json"

# Keys that hold secrets — only written when the user opts into "remember".
SECRET_FIELDS = ("gemini_api_key", "anthropic_api_key")


def load_config() -> dict[str, Any]:
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


def save_config(data: dict[str, Any]) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")
    try:  # best-effort owner-only perms (mainly meaningful on POSIX)
        os.chmod(CONFIG_PATH, 0o600)
    except OSError:
        pass


def clear_secrets() -> None:
    """Remove stored API keys but keep non-secret preferences."""
    data = load_config()
    changed = False
    for field in SECRET_FIELDS:
        if field in data:
            del data[field]
            changed = True
    data["remember_keys"] = False
    if changed or CONFIG_PATH.exists():
        save_config(data)
