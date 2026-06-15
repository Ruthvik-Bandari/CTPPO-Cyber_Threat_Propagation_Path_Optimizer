"""
API-key store for CTPPO (Phase B / B5a)
=======================================

Long-lived API keys for non-interactive clients (the B5 pip CLI / CI). A key is issued to
a user, embedded in their client config, and used to authenticate requests — it resolves
back to the owning user, who remains subject to the subscription gate (so a key is only as
live as its subscription).

Security: the raw key is shown **once** at creation and never stored; only its SHA-256 hash
is kept. A single SHA-256 is appropriate here (unlike passwords) because keys are
high-entropy random tokens, not guessable secrets. Canonical in-memory store (run-anywhere).
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

KEY_PREFIX = "ctppo_"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class ApiKeyStore:
    def __init__(self, persistence=None) -> None:
        self._by_hash: Dict[str, dict] = {}      # sha256(raw) -> record
        self._id_to_hash: Dict[str, str] = {}     # key_id -> sha256(raw)
        self._p = persistence
        if self._p:
            for h, rec in self._p.load().items():
                self._by_hash[h] = rec
                self._id_to_hash[rec["id"]] = h

    def issue(self, owner: str, name: str = "default") -> Tuple[str, dict]:
        """Create a key for ``owner``. Returns (raw_key, record). The raw key is the only
        time the secret is available — only its hash is stored."""
        raw = KEY_PREFIX + secrets.token_urlsafe(32)
        key_id = "key_" + secrets.token_hex(6)
        record = {
            "id": key_id,
            "owner": owner.lower(),
            "name": name,
            "prefix": raw[:14],            # ctppo_ + 8 chars, for display only
            "created_at": _now(),
            "last_used_at": None,
        }
        key_hash = _hash_key(raw)
        self._by_hash[key_hash] = record
        self._id_to_hash[key_id] = key_hash
        if self._p:
            self._p.upsert(key_hash, record)
        return raw, record

    def resolve(self, raw: str) -> Optional[str]:
        """Validate a raw key; return the owner email (and stamp last_used) or None."""
        if not raw or not raw.startswith(KEY_PREFIX):
            return None
        key_hash = _hash_key(raw)
        record = self._by_hash.get(key_hash)
        if not record:
            return None
        record["last_used_at"] = _now()
        if self._p:
            self._p.upsert(key_hash, record)
        return record["owner"]

    def list_for(self, owner: str) -> List[dict]:
        """Key metadata for ``owner`` — never the raw key or its hash."""
        out = []
        for record in self._by_hash.values():
            if record["owner"] == owner.lower():
                out.append({k: record[k] for k in ("id", "name", "prefix", "created_at", "last_used_at")})
        return out

    def revoke(self, owner: str, key_id: str) -> bool:
        """Revoke one of the owner's keys. Returns True if a key was removed."""
        key_hash = self._id_to_hash.get(key_id)
        if not key_hash:
            return False
        record = self._by_hash.get(key_hash)
        if not record or record["owner"] != owner.lower():
            return False
        del self._by_hash[key_hash]
        del self._id_to_hash[key_id]
        if self._p:
            self._p.delete(key_hash)
        return True


# Default process-wide API-key store shared by the API (persistent when CTPPO_DB_URL is set).
from persistence import default_persistence  # noqa: E402
api_keys = ApiKeyStore(persistence=default_persistence("api_keys"))
