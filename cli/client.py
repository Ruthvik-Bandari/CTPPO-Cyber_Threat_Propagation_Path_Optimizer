"""
CTPPO API client used by the CLI (Phase B / B5b)
================================================

Thin httpx wrapper that authenticates with the B5a API key via the ``X-API-Key`` header.
``http_client`` can be injected (e.g. an httpx client over an ASGI transport) so the CLI
is testable in-process against the API without a running server.
"""

from __future__ import annotations

from typing import List, Optional

import httpx


class CtppoError(Exception):
    """A user-facing CLI/API error with a clean message."""


class CtppoClient:
    def __init__(self, api_url: str, api_key: str, http_client: Optional[httpx.Client] = None) -> None:
        if not api_key:
            raise CtppoError("No API key configured. Run `ctppo-cli configure --api-key ...` first.")
        self._key = api_key
        self._http = http_client or httpx.Client(base_url=api_url, timeout=30.0)

    def _request(self, method: str, path: str, **kwargs) -> dict:
        try:
            resp = self._http.request(method, path, headers={"X-API-Key": self._key}, **kwargs)
        except httpx.HTTPError as e:
            raise CtppoError(f"Could not reach the CTPPO API: {e}")
        if resp.status_code == 401:
            raise CtppoError("Authentication failed — the API key is invalid or revoked.")
        if resp.status_code == 403:
            raise CtppoError("No active subscription for this key. Activate a product key in the dashboard.")
        if resp.status_code >= 400:
            raise CtppoError(f"API error {resp.status_code}: {resp.text[:200]}")
        return resp.json()

    def whoami(self) -> dict:
        return self._request("GET", "/api/auth/whoami")["user"]

    def subscription_status(self) -> dict:
        return self._request("GET", "/api/subscription/status")

    def create_instance(self, name: str, prompt: str = "",
                        files: Optional[List[dict]] = None, target_spec: Optional[dict] = None) -> dict:
        return self._request("POST", "/api/instances", json={
            "name": name, "prompt": prompt,
            "files": files or [], "target_spec": target_spec or {},
        })
