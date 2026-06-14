"""
Tests for the B2 canonical subscription + product-key store.

Pure-Python, no Redis/fastapi. Run with: python3 tests/api/test_subscription_store.py
"""

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "api"))

from subscription_store import SubscriptionStore, is_owner, OWNER_EMAILS  # noqa: E402


def _store():
    return SubscriptionStore()


def test_create_and_validate_key():
    s = _store()
    kd = s.create_product_key("individual", 30)
    assert kd["key"].startswith("CTPPO-")
    v = s.validate_product_key(kd["key"])
    assert v["valid"] is True and v["subscription_type"] == "individual"


def test_validate_unknown_key():
    s = _store()
    v = s.validate_product_key("CTPPO-XXXX-XXXX-XXXX-XXXX")
    assert v["valid"] is False and v["code"] == "INVALID_KEY"


def test_activate_then_subscription_active():
    s = _store()
    key = s.create_product_key("individual", 365)["key"]
    res = s.activate(key, "user@example.com")
    assert res["success"] is True
    sub = s.check_subscription("user@example.com")
    assert sub["has_subscription"] is True and sub["status"] == "active"
    assert 360 <= sub["days_remaining"] <= 365


def test_double_activation_rejected():
    s = _store()
    key = s.create_product_key("individual", 30)["key"]
    assert s.activate(key, "a@b.com")["success"] is True
    second = s.activate(key, "c@d.com")
    assert second["success"] is False and second["code"] == "ALREADY_ACTIVATED"


def test_check_subscription_none_for_unactivated_user():
    s = _store()
    sub = s.check_subscription("nobody@example.com")
    assert sub["has_subscription"] is False and sub["status"] == "no_subscription"


def test_expired_subscription_detected():
    s = _store()
    key = s.create_product_key("individual", 30)["key"]
    s.activate(key, "exp@example.com")
    # Force the activation into the past to exercise the expiry branch deterministically.
    past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    s._activations["exp@example.com"]["expires_at"] = past
    sub = s.check_subscription("exp@example.com")
    assert sub["has_subscription"] is False and sub["status"] == "expired"


def test_owner_bypasses_gate_without_key():
    owner = OWNER_EMAILS[0]
    assert is_owner(owner) is True
    s = _store()
    sub = s.check_subscription(owner)
    assert sub["has_subscription"] is True and sub["is_owner"] is True
    act = s.activate("no-key-needed", owner)
    assert act["success"] is True and act["is_owner"] is True


def test_revoke_key_clears_activation():
    s = _store()
    key = s.create_product_key("enterprise", 365)["key"]
    s.activate(key, "rev@example.com")
    assert s.revoke_key(key) is True
    assert s.check_subscription("rev@example.com")["has_subscription"] is False
    assert s.revoke_key(key) is False        # already gone


def test_list_activations_includes_activated_at():
    # Regression: the old admin endpoint KeyError'd because activations lacked activated_at.
    s = _store()
    key = s.create_product_key("individual", 365)["key"]
    s.activate(key, "list@example.com")
    acts = s.list_activations()
    assert len(acts) == 1 and acts[0]["activated_at"] is not None
    keys = s.list_keys()
    assert keys[0]["used"] is True and keys[0]["used_by"] == "list@example.com"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"PASS  {fn.__name__}")
    print(f"\n{len(fns)} tests passed.")
