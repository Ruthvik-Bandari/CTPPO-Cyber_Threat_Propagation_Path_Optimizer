"""
CLI configuration (open-source, local-first, no-auth)
=====================================================

The CLI talks to a local CTPPO API with no credentials. The only setting is the API base
URL, which defaults to ``http://localhost:8000`` and can be overridden by the ``CTPPO_API_URL``
environment variable or a ``--api-url`` flag.
"""

from __future__ import annotations

import os

DEFAULT_API_URL = "http://localhost:8000"


def resolve_api_url(override: str = "") -> str:
    """API base URL: explicit flag override, else ``CTPPO_API_URL`` env, else the default."""
    return override or os.environ.get("CTPPO_API_URL") or DEFAULT_API_URL
