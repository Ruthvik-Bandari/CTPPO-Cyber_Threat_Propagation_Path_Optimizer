"""
Tests for the B1 auth core: password hashing + server-side session store.

Runs fully offline against the in-memory session backend (no Redis, no fastapi).
Run with: python3 tests/api/test_session_store.py
"""

import sys
from pathlib import Path

# api/ modules use sibling imports (e.g. `from database import ...`), so put api/ on path.
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "api"))

from passwords import hash_password, verify_password, scheme  # noqa: E402
from session_store import SessionStore  # noqa: E402


def _store():
    # force_memory keeps the test independent of any REDIS_URL in the environment.
    return SessionStore(force_memory=True)


def test_password_hash_is_salted_and_not_plaintext():
    h = hash_password("hunter2-correct-horse")
    assert h != "hunter2-correct-horse"
    assert "hunter2" not in h
    # Salt => two hashes of the same password differ.
    assert hash_password("hunter2-correct-horse") != h


def test_password_verify_roundtrip():
    h = hash_password("S3cur3-Passw0rd!")
    assert verify_password("S3cur3-Passw0rd!", h) is True
    assert verify_password("wrong-password", h) is False
    assert verify_password("", h) is False
    assert verify_password("anything", "") is False


def test_password_scheme_is_strong():
    # Either bcrypt (if installed) or the salted PBKDF2 fallback — never plain sha256.
    assert scheme() in ("bcrypt", "pbkdf2_sha256")


def test_session_create_and_get_roundtrip():
    s = _store()
    sid = s.create_session("User@Example.com")
    data = s.get_session(sid)
    assert data is not None
    assert data["email"] == "user@example.com"   # normalized to lowercase


def test_session_unknown_id_returns_none():
    s = _store()
    assert s.get_session("does-not-exist") is None
    assert s.get_session("") is None


def test_logout_revokes_session():
    s = _store()
    sid = s.create_session("a@b.com")
    assert s.get_session(sid) is not None
    assert s.delete_session(sid) is True
    assert s.get_session(sid) is None              # revoked server-side
    assert s.delete_session(sid) is False          # already gone


def test_session_ttl_expiry():
    s = _store()
    sid = s.create_session("a@b.com", ttl_seconds=-1)   # already expired
    assert s.get_session(sid) is None


def test_reset_token_is_single_use():
    s = _store()
    token = s.create_reset_token("reset@me.com")
    assert s.consume_reset_token(token) == "reset@me.com"
    assert s.consume_reset_token(token) is None    # cannot be reused
    assert s.consume_reset_token("bogus") is None


def test_reset_token_expiry():
    s = _store()
    token = s.create_reset_token("a@b.com", ttl_seconds=-1)
    assert s.consume_reset_token(token) is None


def test_backend_is_memory_when_forced():
    assert _store().backend_name == "memory"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"PASS  {fn.__name__}")
    print(f"\n{len(fns)} tests passed.")
