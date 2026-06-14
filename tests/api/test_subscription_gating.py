"""
B2 integration: session-based subscription gating on the real server_secure app.

Boots the actual FastAPI app and drives the gate end-to-end. Requires the API deps
(fastapi, sqlalchemy, pyotp, qrcode, email-validator) installed in Phase B.

Run with: python3 tests/api/test_subscription_gating.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "api"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import server_secure  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

ADMIN_SECRET = "ctppo-admin-2026"
_counter = {"n": 0}


def _client():
    return TestClient(server_secure.app)


def _new_email():
    _counter["n"] += 1
    return f"b2user{_counter['n']}@example.com"


def _signup(c, email):
    r = c.post("/api/auth/signup", json={"email": email, "password": "password123", "name": "B2"})
    assert r.status_code == 200, r.text


def test_status_and_protected_require_auth():
    c = _client()
    assert c.get("/api/subscription/status").status_code == 401
    assert c.post("/api/subscription/activate", json={"product_key": "x"}).status_code == 401


def test_unsubscribed_user_is_gated_then_activates():
    c = _client()
    email = _new_email()
    _signup(c, email)
    # no subscription yet
    assert c.get("/api/subscription/status").json()["has_subscription"] is False
    # a product endpoint is blocked with 403 (auth OK, subscription missing)
    assert c.get("/api/model/info").status_code == 403
    # mint + activate a key for this session user
    key = server_secure.subscriptions.create_product_key("individual", 365)["key"]
    act = c.post("/api/subscription/activate", json={"product_key": key})
    assert act.status_code == 200 and act.json()["success"] is True
    # now subscribed; the gate opens (no longer 403)
    assert c.get("/api/subscription/status").json()["has_subscription"] is True
    assert c.get("/api/model/info").status_code != 403


def test_activate_invalid_key_rejected():
    c = _client()
    _signup(c, _new_email())
    r = c.post("/api/subscription/activate", json={"product_key": "CTPPO-0000-0000-0000-0000"})
    assert r.status_code == 400


def test_activate_already_used_key_rejected():
    key = server_secure.subscriptions.create_product_key("individual", 365)["key"]
    c1 = _client(); _signup(c1, _new_email())
    assert c1.post("/api/subscription/activate", json={"product_key": key}).status_code == 200
    c2 = _client(); _signup(c2, _new_email())
    assert c2.post("/api/subscription/activate", json={"product_key": key}).status_code == 400


def test_owner_bypasses_gate_without_key():
    c = _client()
    owner = server_secure.OWNER_EMAILS[0]
    _signup(c, owner)
    assert c.get("/api/subscription/status").json()["has_subscription"] is True
    assert c.get("/api/model/info").status_code != 403   # owner never gated


def test_admin_generate_key_requires_secret():
    c = _client()
    assert c.post("/api/admin/generate-key", json={"admin_secret": "wrong"}).status_code == 401
    r = c.post("/api/admin/generate-key", json={"admin_secret": ADMIN_SECRET, "subscription_type": "enterprise"})
    assert r.status_code == 200 and r.json()["product_key"].startswith("CTPPO-")


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"PASS  {fn.__name__}")
    print(f"\n{len(fns)} tests passed.")
