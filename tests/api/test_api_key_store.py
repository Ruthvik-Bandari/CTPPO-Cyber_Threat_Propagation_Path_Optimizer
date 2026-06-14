"""
Tests for the B5a API-key store — pure Python, no fastapi/Redis.

Run with: python3 tests/api/test_api_key_store.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "api"))

from api_key_store import ApiKeyStore, KEY_PREFIX, _hash_key  # noqa: E402

A = "alice@example.com"
B = "bob@example.com"


def test_issue_returns_raw_and_record():
    s = ApiKeyStore()
    raw, rec = s.issue(A, "ci")
    assert raw.startswith(KEY_PREFIX)
    assert rec["owner"] == A and rec["name"] == "ci"
    assert rec["prefix"] == raw[:14]


def test_resolve_valid_and_invalid():
    s = ApiKeyStore()
    raw, _ = s.issue(A)
    assert s.resolve(raw) == A
    assert s.resolve(KEY_PREFIX + "wrong") is None
    assert s.resolve("not-a-ctppo-key") is None
    assert s.resolve("") is None


def test_raw_key_is_not_stored_only_hash():
    s = ApiKeyStore()
    raw, _ = s.issue(A)
    # the store holds the hash, never the raw secret
    assert _hash_key(raw) in s._by_hash
    assert raw not in s._by_hash


def test_list_returns_metadata_without_secret():
    s = ApiKeyStore()
    raw, _ = s.issue(A, "ci")
    keys = s.list_for(A)
    assert len(keys) == 1
    k = keys[0]
    assert set(k.keys()) == {"id", "name", "prefix", "created_at", "last_used_at"}
    assert raw not in str(k) and _hash_key(raw) not in str(k)


def test_list_is_owner_scoped():
    s = ApiKeyStore()
    s.issue(A); s.issue(A); s.issue(B)
    assert len(s.list_for(A)) == 2 and len(s.list_for(B)) == 1


def test_revoke_invalidates_key():
    s = ApiKeyStore()
    raw, rec = s.issue(A)
    assert s.revoke(A, rec["id"]) is True
    assert s.resolve(raw) is None              # no longer valid
    assert s.revoke(A, rec["id"]) is False     # already gone


def test_cannot_revoke_another_users_key():
    s = ApiKeyStore()
    raw, rec = s.issue(A)
    assert s.revoke(B, rec["id"]) is False     # Bob can't revoke Alice's key
    assert s.resolve(raw) == A                  # still valid


def test_resolve_stamps_last_used():
    s = ApiKeyStore()
    raw, rec = s.issue(A)
    assert rec["last_used_at"] is None
    s.resolve(raw)
    assert s.list_for(A)[0]["last_used_at"] is not None


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"PASS  {fn.__name__}")
    print(f"\n{len(fns)} tests passed.")
