"""
Server-side session store for CTPPO auth (Phase B / B1)
=======================================================

Server-side sessions (not stateless-JWT-only) so logout is a real, server-side
revocation. A session is an opaque id → {email, created_at}, with a TTL.

Backend resolution (honest, run-anywhere):
- If ``REDIS_URL`` is set AND the ``redis`` client is importable AND the server answers
  PING → use **Redis** (production / shared, survives restarts, multi-process).
- Otherwise → a clearly-labeled **in-memory** fallback for local dev/tests. It does NOT
  survive a restart and is not shared across processes; ``backend_name`` reports which is
  active so this is never mistaken for the real thing.

Also issues single-use password-reset tokens (token → email, consumed on use).
"""

from __future__ import annotations

import json
import os
import secrets
import threading
import time
from typing import Dict, Optional, Tuple

SESSION_TTL_SECONDS = 7 * 24 * 3600       # 7 days, matches the old refresh-token horizon
RESET_TTL_SECONDS = 30 * 60               # 30 minutes for a password-reset link
_SESSION_PREFIX = "sess:"
_RESET_PREFIX = "reset:"


class _MemoryBackend:
    """Process-local TTL store. Dev/test only — labeled, not for production."""

    name = "memory"

    def __init__(self) -> None:
        self._data: Dict[str, Tuple[str, float]] = {}
        self._lock = threading.Lock()

    def setex(self, key: str, ttl: int, value: str) -> None:
        with self._lock:
            self._data[key] = (value, time.time() + ttl)

    def get(self, key: str) -> Optional[str]:
        with self._lock:
            item = self._data.get(key)
            if item is None:
                return None
            value, expires_at = item
            if time.time() >= expires_at:
                self._data.pop(key, None)
                return None
            return value

    def delete(self, key: str) -> bool:
        with self._lock:
            return self._data.pop(key, None) is not None


class _RedisBackend:
    """Thin wrapper over a redis-py client (str keys/values)."""

    name = "redis"

    def __init__(self, client) -> None:
        self._client = client

    def setex(self, key: str, ttl: int, value: str) -> None:
        self._client.setex(key, ttl, value)

    def get(self, key: str) -> Optional[str]:
        val = self._client.get(key)
        return val.decode("utf-8") if isinstance(val, (bytes, bytearray)) else val

    def delete(self, key: str) -> bool:
        return bool(self._client.delete(key))


def _make_backend(redis_url: Optional[str], force_memory: bool):
    if force_memory or not redis_url:
        return _MemoryBackend()
    try:
        import redis  # type: ignore
        client = redis.Redis.from_url(redis_url, socket_connect_timeout=2)
        client.ping()
        return _RedisBackend(client)
    except Exception as e:  # unreachable server / missing client → honest fallback
        print(f"[session_store] Redis unavailable ({e}); using in-memory fallback (dev only).")
        return _MemoryBackend()


class SessionStore:
    """Create / read / revoke sessions and issue single-use reset tokens."""

    def __init__(self, redis_url: Optional[str] = None, force_memory: bool = False) -> None:
        url = redis_url if redis_url is not None else os.environ.get("REDIS_URL")
        self._backend = _make_backend(url, force_memory)

    @property
    def backend_name(self) -> str:
        return self._backend.name

    # --- sessions ---------------------------------------------------------
    def create_session(self, email: str, ttl_seconds: int = SESSION_TTL_SECONDS) -> str:
        session_id = secrets.token_urlsafe(32)
        payload = json.dumps({"email": email.lower(), "created_at": time.time()})
        self._backend.setex(_SESSION_PREFIX + session_id, ttl_seconds, payload)
        return session_id

    def get_session(self, session_id: str) -> Optional[dict]:
        if not session_id:
            return None
        raw = self._backend.get(_SESSION_PREFIX + session_id)
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except (ValueError, TypeError):
            return None

    def delete_session(self, session_id: str) -> bool:
        """Revoke a session (logout). Returns True if a session was removed."""
        if not session_id:
            return False
        return self._backend.delete(_SESSION_PREFIX + session_id)

    # --- password-reset tokens -------------------------------------------
    def create_reset_token(self, email: str, ttl_seconds: int = RESET_TTL_SECONDS) -> str:
        token = secrets.token_urlsafe(32)
        self._backend.setex(_RESET_PREFIX + token, ttl_seconds, email.lower())
        return token

    def consume_reset_token(self, token: str) -> Optional[str]:
        """Return the email for a valid token and invalidate it (single use)."""
        if not token:
            return None
        email = self._backend.get(_RESET_PREFIX + token)
        if email is None:
            return None
        self._backend.delete(_RESET_PREFIX + token)
        return email
