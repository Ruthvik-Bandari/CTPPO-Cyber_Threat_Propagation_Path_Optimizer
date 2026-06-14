"""
CLI client configuration (Phase B / B5b)
========================================

Stores the API key + API base URL in ``~/.ctppo/config.json`` (override the location with
``CTPPO_CONFIG``). Environment variables ``CTPPO_API_KEY`` / ``CTPPO_API_URL`` take
precedence over the file, which is convenient for CI where secrets come from the
environment rather than a written-out config.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Optional

DEFAULT_API_URL = "http://localhost:8000"


def config_path() -> Path:
    override = os.environ.get("CTPPO_CONFIG")
    if override:
        return Path(override)
    return Path.home() / ".ctppo" / "config.json"


def load_config() -> dict:
    """Config from the file, with env vars taking precedence (CI-friendly)."""
    data: dict = {}
    path = config_path()
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            data = {}
    if os.environ.get("CTPPO_API_KEY"):
        data["api_key"] = os.environ["CTPPO_API_KEY"]
    if os.environ.get("CTPPO_API_URL"):
        data["api_url"] = os.environ["CTPPO_API_URL"]
    data.setdefault("api_url", DEFAULT_API_URL)
    return data


def save_config(api_key: str, api_url: Optional[str] = None) -> Path:
    """Write the config file (0600 perms — it holds a secret) and return its path."""
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"api_key": api_key, "api_url": api_url or DEFAULT_API_URL}
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)   # rw for owner only
    except OSError:
        pass
    return path
