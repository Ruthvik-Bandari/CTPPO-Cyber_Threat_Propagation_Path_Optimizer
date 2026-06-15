"""
Canonical in-memory user store for CTPPO auth (Phase B / B1)
============================================================

One user store, replacing the three scattered ``USERS_DB`` dicts the prototype had
(server_secure, subscription.py, and the Postgres-only database.py). It is **dict-like**
on purpose so the existing server_secure code (`USERS_DB[email]`, `email in USERS_DB`,
`USERS_DB.get(...)`) keeps working unchanged via a single import swap, while the new
session-auth router uses the same object through its convenience methods.

Emails are normalized to lowercase so lookups are case-insensitive. B2 will reconcile
this with the database/subscription layer (back it with Postgres in production).
"""

from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import Dict, Optional


class UserStore:
    """Dict-like store of user records keyed by lowercased email."""

    def __init__(self, persistence=None) -> None:
        self._users: Dict[str, dict] = {}
        self._p = persistence
        if self._p:
            self._users = dict(self._p.load())

    # --- dict-like surface (keeps existing server_secure code working) ----
    def __contains__(self, email: str) -> bool:
        return isinstance(email, str) and email.lower() in self._users

    def __getitem__(self, email: str) -> dict:
        return self._users[email.lower()]

    def __setitem__(self, email: str, value: dict) -> None:
        self._users[email.lower()] = value
        if self._p:
            self._p.upsert(email.lower(), value)

    def get(self, email: str, default=None):
        if not isinstance(email, str):
            return default
        return self._users.get(email.lower(), default)

    # --- convenience API for the auth router ------------------------------
    def create_user(self, email: str, name: str, password_hash: str, role: str = "user") -> Optional[dict]:
        key = email.lower()
        if key in self._users:
            return None
        record = {
            "id": f"usr_{secrets.token_hex(4)}",
            "email": key,
            "name": name,
            "password_hash": password_hash,
            "totp_secret": None,
            "is_2fa_enabled": False,
            "role": role,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        self._users[key] = record
        if self._p:
            self._p.upsert(key, record)
        return record

    def set_password(self, email: str, password_hash: str) -> bool:
        user = self._users.get(email.lower())
        if not user:
            return False
        user["password_hash"] = password_hash
        if self._p:
            self._p.upsert(email.lower(), user)
        return True


def public_view(user: dict) -> dict:
    """A user record with secret fields stripped, safe to return over the API."""
    return {
        "id": user.get("id"),
        "email": user.get("email"),
        "name": user.get("name"),
        "role": user.get("role", "user"),
        "is_2fa_enabled": user.get("is_2fa_enabled", False),
        "created_at": user.get("created_at"),
    }
