"""
Canonical subscription + product-key store for CTPPO (Phase B / B2)
===================================================================

ONE subscription store, replacing the three former copies of this logic (a dead
``subscription.py`` module, plus two duplicate in-line blocks in server_secure.py). It
holds product keys and per-user activations in memory (run-anywhere; B-phase can back it
with Postgres via api/database.py). Owners bypass the gate entirely.

A user's "dashboard unlocked" gate (product design §2) = ``check_subscription`` returning
``has_subscription`` True, i.e. an activated, non-expired key (or an owner account).
"""

from __future__ import annotations

import os
import secrets
import string
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

_DEFAULT_OWNERS = ["bandari.ru@northeastern.edu", "ruthvik299@gmail.com"]
# Owners need no subscription. Overridable via OWNER_EMAILS (comma-separated).
OWNER_EMAILS = [e.strip().lower() for e in os.environ.get("OWNER_EMAILS", "").split(",") if e.strip()] \
    or _DEFAULT_OWNERS


def is_owner(email: str) -> bool:
    return isinstance(email, str) and email.lower() in OWNER_EMAILS


def _generate_key() -> str:
    """A unique-looking product key: CTPPO-XXXX-XXXX-XXXX-XXXX."""
    chars = string.ascii_uppercase + string.digits
    segments = ["".join(secrets.choice(chars) for _ in range(4)) for _ in range(4)]
    return f"CTPPO-{'-'.join(segments)}"


def _parse_iso(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


class SubscriptionStore:
    """Product keys + activations, keyed by lowercased email."""

    def __init__(self, persistence=None) -> None:
        self._keys: Dict[str, dict] = {}
        self._activations: Dict[str, dict] = {}
        self._p = persistence
        if self._p:
            for k, v in self._p.load().items():
                if k.startswith("key:"):
                    self._keys[k[4:]] = v
                elif k.startswith("act:"):
                    self._activations[k[4:]] = v

    # --- product keys -----------------------------------------------------
    def create_product_key(self, subscription_type: str = "individual",
                           validity_days: int = 365, created_by: str = "admin") -> dict:
        key = _generate_key()
        while key in self._keys:
            key = _generate_key()
        self._keys[key] = {
            "key": key,
            "subscription_type": subscription_type,
            "validity_days": validity_days,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "created_by": created_by,
            "is_activated": False,
            "activated_by": None,
            "expires_at": None,
        }
        if self._p:
            self._p.upsert("key:" + key, self._keys[key])
        return self._keys[key]

    def validate_product_key(self, key: str) -> dict:
        kd = self._keys.get(key)
        if not kd:
            return {"valid": False, "error": "Invalid product key", "code": "INVALID_KEY"}
        if kd["is_activated"]:
            return {"valid": False, "error": "This product key has already been activated",
                    "code": "ALREADY_ACTIVATED", "activated_by": kd["activated_by"]}
        return {"valid": True, "subscription_type": kd["subscription_type"],
                "validity_days": kd["validity_days"]}

    def revoke_key(self, key: str) -> bool:
        kd = self._keys.pop(key, None)
        if kd is None:
            return False
        if self._p:
            self._p.delete("key:" + key)
        # also drop any activation that used this key
        for email, act in list(self._activations.items()):
            if act.get("key") == key:
                self._activations.pop(email, None)
                if self._p:
                    self._p.delete("act:" + email)
        return True

    def list_keys(self) -> List[dict]:
        return [
            {"key": kd["key"], "subscription_type": kd["subscription_type"],
             "validity_days": kd["validity_days"], "created_at": kd["created_at"],
             "used": kd["is_activated"], "used_by": kd["activated_by"]}
            for kd in self._keys.values()
        ]

    # --- activations / gating --------------------------------------------
    def activate(self, key: str, email: str) -> dict:
        """Activate a product key for ``email`` (single use). Owners need no key."""
        if is_owner(email):
            return {"success": True, "is_owner": True, "subscription_type": "owner",
                    "message": "Owner account - no activation required", "expires_at": None}
        validation = self.validate_product_key(key)
        if not validation["valid"]:
            return {"success": False, "error": validation["error"], "code": validation.get("code")}
        kd = self._keys[key]
        expires_at = datetime.now(timezone.utc) + timedelta(days=kd["validity_days"])
        kd["is_activated"] = True
        kd["activated_by"] = email.lower()
        kd["expires_at"] = expires_at.isoformat()
        self._activations[email.lower()] = {
            "key": key,
            "subscription_type": kd["subscription_type"],
            "activated_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": expires_at.isoformat(),
        }
        if self._p:
            self._p.upsert("key:" + key, kd)
            self._p.upsert("act:" + email.lower(), self._activations[email.lower()])
        return {"success": True, "subscription_type": kd["subscription_type"],
                "expires_at": expires_at.isoformat(), "days_remaining": kd["validity_days"]}

    def check_subscription(self, email: str) -> dict:
        """Gating check. Owners always active; otherwise an activated, non-expired key."""
        if is_owner(email):
            return {"has_subscription": True, "is_owner": True,
                    "subscription_type": "owner", "expires_at": None, "status": "active"}
        act = self._activations.get(email.lower())
        if not act:
            return {"has_subscription": False, "is_owner": False, "status": "no_subscription"}
        expires_at = _parse_iso(act["expires_at"])
        now = datetime.now(timezone.utc)
        if now > expires_at:
            return {"has_subscription": False, "is_owner": False,
                    "subscription_type": act["subscription_type"],
                    "expires_at": act["expires_at"], "status": "expired"}
        return {"has_subscription": True, "is_owner": False,
                "subscription_type": act["subscription_type"],
                "expires_at": act["expires_at"],
                "days_remaining": (expires_at - now).days, "status": "active"}

    def list_activations(self) -> List[dict]:
        return [
            {"email": email, "subscription_type": a["subscription_type"],
             "activated_at": a.get("activated_at"), "expires_at": a["expires_at"]}
            for email, a in self._activations.items()
        ]


# Default process-wide subscription store shared by the API (persistent when CTPPO_DB_URL is set).
from persistence import default_persistence  # noqa: E402
subscriptions = SubscriptionStore(persistence=default_persistence("subscriptions"))
