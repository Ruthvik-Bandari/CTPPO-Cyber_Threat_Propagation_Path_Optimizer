"""
HTTP tests for the B5a API-key routes + key-based authentication.

Isolated tests mount the key router with a fake user dependency. The real-app tests boot
server_secure and prove the end-to-end CLI auth path: issue a key over a session, then use
it (via X-API-Key, with no cookie) to reach a protected endpoint; revoked/bogus keys fail.

Run with: python3 tests/api/test_api_key_routes.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "api"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from fastapi import FastAPI, Request  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from api_key_store import ApiKeyStore  # noqa: E402
from api_key_routes import create_api_key_router  # noqa: E402


def _fake_user(request: Request) -> dict:
    return {"email": request.headers.get("X-Test-User", "default@example.com")}


def _client():
    app = FastAPI()
    app.include_router(create_api_key_router(ApiKeyStore(), _fake_user))
    return TestClient(app)


ALICE = {"X-Test-User": "alice@example.com"}


def test_issue_returns_raw_key_once():
    c = _client()
    r = c.post("/api/keys", json={"name": "ci"}, headers=ALICE)
    assert r.status_code == 200
    body = r.json()
    assert body["api_key"].startswith("ctppo_") and body["name"] == "ci"


def test_list_shows_metadata_not_secret():
    c = _client()
    raw = c.post("/api/keys", json={"name": "ci"}, headers=ALICE).json()["api_key"]
    keys = c.get("/api/keys", headers=ALICE).json()["keys"]
    assert len(keys) == 1 and "api_key" not in keys[0]
    assert raw not in str(keys[0])               # raw secret never listed


def test_revoke_key():
    c = _client()
    kid = c.post("/api/keys", json={"name": "ci"}, headers=ALICE).json()["id"]
    assert c.delete(f"/api/keys/{kid}", headers=ALICE).status_code == 200
    assert c.delete(f"/api/keys/{kid}", headers=ALICE).status_code == 404


def _subscribed_session():
    """A real-app TestClient signed in as a fresh subscribed user."""
    import server_secure
    c = TestClient(server_secure.app)
    email = f"b5key{_subscribed_session.n}@example.com"
    _subscribed_session.n += 1
    c.post("/api/auth/signup", json={"email": email, "password": "password123", "name": "K"})
    key = server_secure.subscriptions.create_product_key("individual", 365)["key"]
    c.post("/api/subscription/activate", json={"product_key": key})
    return c


_subscribed_session.n = 0


def test_real_app_key_management_requires_auth():
    import server_secure
    assert TestClient(server_secure.app).post("/api/keys", json={"name": "x"}).status_code == 401


def test_real_app_key_authenticates_protected_endpoint():
    import server_secure
    session = _subscribed_session()
    raw = session.post("/api/keys", json={"name": "ci"}).json()["api_key"]
    # A fresh client with NO cookie, authenticating purely via the API key.
    cli = TestClient(server_secure.app)
    r = cli.get("/api/model/info", headers={"X-API-Key": raw})
    assert r.status_code != 401 and r.status_code != 403     # authed + subscribed
    assert cli.get("/api/model/info", headers={"X-API-Key": "ctppo_bogus"}).status_code == 401


def test_real_app_revoked_key_stops_working():
    import server_secure
    session = _subscribed_session()
    issued = session.post("/api/keys", json={"name": "ci"}).json()
    raw, kid = issued["api_key"], issued["id"]
    cli = TestClient(server_secure.app)
    assert cli.get("/api/model/info", headers={"X-API-Key": raw}).status_code != 401
    assert session.delete(f"/api/keys/{kid}").status_code == 200
    assert cli.get("/api/model/info", headers={"X-API-Key": raw}).status_code == 401   # revoked


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"PASS  {fn.__name__}")
    print(f"\n{len(fns)} tests passed.")
