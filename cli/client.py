"""
CTPPO API client used by the CLI (open-source, local-first, no-auth)
====================================================================

Thin httpx wrapper over the local CTPPO API. No authentication: requests carry no
``X-API-Key`` / ``Authorization`` header. ``http_client`` can be injected (e.g. an httpx
client over an ASGI transport) so the CLI is testable in-process without a running server.
"""

from __future__ import annotations

from typing import List, Optional

import httpx


class CtppoError(Exception):
    """A user-facing CLI/API error with a clean message."""


class CtppoClient:
    def __init__(self, api_url: str, http_client: Optional[httpx.Client] = None) -> None:
        self._http = http_client or httpx.Client(base_url=api_url, timeout=30.0)

    def _request(self, method: str, path: str, **kwargs) -> dict:
        try:
            resp = self._http.request(method, path, **kwargs)
        except httpx.HTTPError as e:
            raise CtppoError(f"Could not reach the CTPPO API: {e}")
        if resp.status_code >= 400:
            raise CtppoError(f"API error {resp.status_code}: {resp.text[:200]}")
        return resp.json()

    def create_instance(self, name: str, prompt: str = "",
                        files: Optional[List[dict]] = None, target_spec: Optional[dict] = None) -> dict:
        return self._request("POST", "/api/instances", json={
            "name": name, "prompt": prompt,
            "files": files or [], "target_spec": target_spec or {},
        })
