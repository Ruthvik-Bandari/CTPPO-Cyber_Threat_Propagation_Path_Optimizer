"""
Password hashing for CTPPO auth (Phase B / B1)
==============================================

Uses **bcrypt** if it is installed (the roadmap target), otherwise falls back to
**PBKDF2-HMAC-SHA256** from the standard library — salted, iterated, and honest. This
replaces the prototype's unsalted `hashlib.sha256`, which is unsafe for passwords.

The stored hash is self-describing (`scheme$...`) so `verify_password` selects the right
algorithm without extra state. No third-party dependency is required for the fallback.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os

# PBKDF2 work factor. 600k SHA-256 iterations matches current OWASP guidance.
_PBKDF2_ITERS = 600_000
_PBKDF2_PREFIX = "pbkdf2_sha256"
_BCRYPT_PREFIX = "bcrypt"

try:                       # bcrypt is preferred when available; the API still runs without it.
    import bcrypt as _bcrypt
except Exception:          # pragma: no cover - depends on the environment
    _bcrypt = None


def hash_password(password: str) -> str:
    """Hash a plaintext password into a self-describing, salted string."""
    if not password:
        raise ValueError("password must not be empty")
    if _bcrypt is not None:
        digest = _bcrypt.hashpw(password.encode("utf-8"), _bcrypt.gensalt()).decode("utf-8")
        return f"{_BCRYPT_PREFIX}${digest}"
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _PBKDF2_ITERS)
    return (
        f"{_PBKDF2_PREFIX}${_PBKDF2_ITERS}$"
        f"{base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"
    )


def verify_password(password: str, stored: str) -> bool:
    """Constant-time check of a plaintext password against a stored hash."""
    if not password or not stored:
        return False
    if stored.startswith(_BCRYPT_PREFIX + "$"):
        if _bcrypt is None:
            return False
        try:
            return _bcrypt.checkpw(password.encode("utf-8"), stored[len(_BCRYPT_PREFIX) + 1:].encode("utf-8"))
        except Exception:
            return False
    if stored.startswith(_PBKDF2_PREFIX + "$"):
        try:
            _, iters, b64salt, b64hash = stored.split("$")
            salt = base64.b64decode(b64salt)
            expected = base64.b64decode(b64hash)
            dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iters))
            return hmac.compare_digest(dk, expected)
        except Exception:
            return False
    return False


def scheme() -> str:
    """Which hashing scheme new hashes will use (for diagnostics/logging)."""
    return _BCRYPT_PREFIX if _bcrypt is not None else _PBKDF2_PREFIX
