"""
HTTP-level tests for the B1 session-auth router, in isolation.

Mounts ``create_auth_router`` on a throwaway FastAPI app with fresh in-memory stores
(no Redis, no server_secure, no DB), and drives the full flow with the FastAPI
TestClient. Requires fastapi + httpx (installed in Phase B).

Run with: python3 tests/api/test_auth_routes.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "api"))

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from auth_routes import create_auth_router, SESSION_COOKIE  # noqa: E402
from session_store import SessionStore  # noqa: E402
from user_store import UserStore  # noqa: E402


def _client():
    app = FastAPI()
    app.include_router(create_auth_router(UserStore(), SessionStore(force_memory=True)))
    return TestClient(app)


def test_signup_sets_session_and_returns_user():
    c = _client()
    r = c.post("/api/auth/signup", json={"email": "a@b.com", "password": "password123", "name": "A"})
    assert r.status_code == 200, r.text
    assert r.json()["user"]["email"] == "a@b.com"
    assert SESSION_COOKIE in r.cookies          # session cookie issued


def test_duplicate_signup_rejected():
    c = _client()
    body = {"email": "a@b.com", "password": "password123", "name": "A"}
    assert c.post("/api/auth/signup", json=body).status_code == 200
    assert c.post("/api/auth/signup", json=body).status_code == 400


def test_me_requires_session():
    c = _client()
    assert c.get("/api/auth/me").status_code == 401


def test_signup_then_me_then_logout_flow():
    c = _client()
    c.post("/api/auth/signup", json={"email": "a@b.com", "password": "password123", "name": "A"})
    me = c.get("/api/auth/me")
    assert me.status_code == 200 and me.json()["user"]["email"] == "a@b.com"
    # logout revokes the session server-side; /me then fails
    out = c.post("/api/auth/logout")
    assert out.status_code == 200 and out.json()["revoked"] is True
    assert c.get("/api/auth/me").status_code == 401


def test_login_wrong_password_rejected():
    c = _client()
    c.post("/api/auth/signup", json={"email": "a@b.com", "password": "password123", "name": "A"})
    c.post("/api/auth/logout")
    assert c.post("/api/auth/login", json={"email": "a@b.com", "password": "WRONG"}).status_code == 401
    ok = c.post("/api/auth/login", json={"email": "a@b.com", "password": "password123"})
    assert ok.status_code == 200


def test_forgot_then_reset_password_flow():
    c = _client()
    c.post("/api/auth/signup", json={"email": "a@b.com", "password": "oldpassword1", "name": "A"})
    c.post("/api/auth/logout")
    # forgot-password returns a dev token (email delivery stubbed)
    fr = c.post("/api/auth/forgot-password", json={"email": "a@b.com"})
    assert fr.status_code == 200
    token = fr.json().get("dev_reset_token")
    assert token, "dev reset token expected in dev mode"
    # reset, then old password must fail and new one must work
    rr = c.post("/api/auth/reset-password", json={"token": token, "new_password": "brandnewpass2"})
    assert rr.status_code == 200
    assert c.post("/api/auth/login", json={"email": "a@b.com", "password": "oldpassword1"}).status_code == 401
    assert c.post("/api/auth/login", json={"email": "a@b.com", "password": "brandnewpass2"}).status_code == 200


def test_reset_token_is_single_use_over_http():
    c = _client()
    c.post("/api/auth/signup", json={"email": "a@b.com", "password": "oldpassword1", "name": "A"})
    token = c.post("/api/auth/forgot-password", json={"email": "a@b.com"}).json()["dev_reset_token"]
    assert c.post("/api/auth/reset-password", json={"token": token, "new_password": "newpass12345"}).status_code == 200
    # reused token rejected
    assert c.post("/api/auth/reset-password", json={"token": token, "new_password": "another123456"}).status_code == 400


def test_forgot_password_unknown_email_is_generic():
    c = _client()
    r = c.post("/api/auth/forgot-password", json={"email": "nobody@nowhere.com"})
    assert r.status_code == 200
    assert "dev_reset_token" not in r.json()     # no token for non-existent account


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"PASS  {fn.__name__}")
    print(f"\n{len(fns)} tests passed.")
