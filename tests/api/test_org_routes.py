"""
HTTP tests for the B4 organization / RBAC router.

Most tests mount the router in isolation with a header-driven fake user dependency to
exercise org CRUD + RBAC. A final test boots the real server_secure app to confirm the
router is mounted and subscription-gated.

Run with: python3 tests/api/test_org_routes.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "api"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from fastapi import FastAPI, Request  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from org_store import OrgStore  # noqa: E402
from org_routes import create_org_router  # noqa: E402


def _fake_user(request: Request) -> dict:
    return {"email": request.headers.get("X-Test-User", "default@example.com")}


def _client():
    app = FastAPI()
    app.include_router(create_org_router(OrgStore(), _fake_user))
    return TestClient(app)


ADMIN = {"X-Test-User": "admin@corp.com"}
BOB = {"X-Test-User": "bob@corp.com"}
OUT = {"X-Test-User": "outsider@other.com"}


def test_create_org_and_my_org():
    c = _client()
    r = c.post("/api/orgs", json={"name": "Acme", "seats": 5}, headers=ADMIN)
    assert r.status_code == 200 and r.json()["members"]["admin@corp.com"] == "admin"
    me = c.get("/api/orgs/me", headers=ADMIN).json()
    assert me["role"] == "admin" and me["org"]["name"] == "Acme"


def test_admin_adds_member_and_member_can_view():
    c = _client()
    oid = c.post("/api/orgs", json={"name": "Acme"}, headers=ADMIN).json()["id"]
    assert c.post(f"/api/orgs/{oid}/members", json={"email": "bob@corp.com"}, headers=ADMIN).status_code == 200
    members = c.get(f"/api/orgs/{oid}/members", headers=BOB).json()["members"]
    assert {m["email"] for m in members} == {"admin@corp.com", "bob@corp.com"}


def test_non_admin_cannot_add_member():
    c = _client()
    oid = c.post("/api/orgs", json={"name": "Acme"}, headers=ADMIN).json()["id"]
    c.post(f"/api/orgs/{oid}/members", json={"email": "bob@corp.com"}, headers=ADMIN)
    r = c.post(f"/api/orgs/{oid}/members", json={"email": "carol@corp.com"}, headers=BOB)
    assert r.status_code == 403


def test_outsider_cannot_view_org():
    c = _client()
    oid = c.post("/api/orgs", json={"name": "Acme"}, headers=ADMIN).json()["id"]
    assert c.get(f"/api/orgs/{oid}/members", headers=OUT).status_code == 404


def test_seat_limit_over_http():
    c = _client()
    oid = c.post("/api/orgs", json={"name": "Acme", "seats": 2}, headers=ADMIN).json()["id"]
    assert c.post(f"/api/orgs/{oid}/members", json={"email": "bob@corp.com"}, headers=ADMIN).status_code == 200
    r = c.post(f"/api/orgs/{oid}/members", json={"email": "carol@corp.com"}, headers=ADMIN)
    assert r.status_code == 400 and "Seat" in r.json()["detail"]


def test_set_role_and_remove_member():
    c = _client()
    oid = c.post("/api/orgs", json={"name": "Acme"}, headers=ADMIN).json()["id"]
    c.post(f"/api/orgs/{oid}/members", json={"email": "bob@corp.com"}, headers=ADMIN)
    assert c.put(f"/api/orgs/{oid}/members/bob@corp.com", json={"role": "admin"}, headers=ADMIN).status_code == 200
    assert c.delete(f"/api/orgs/{oid}/members/bob@corp.com", headers=ADMIN).status_code == 200
    members = c.get(f"/api/orgs/{oid}/members", headers=ADMIN).json()["members"]
    assert {m["email"] for m in members} == {"admin@corp.com"}


def test_real_app_orgs_mounted_and_gated():
    import server_secure
    rc = TestClient(server_secure.app)
    assert rc.post("/api/orgs", json={"name": "x"}).status_code == 401   # needs auth
    email = "b4admin@example.com"
    rc.post("/api/auth/signup", json={"email": email, "password": "password123", "name": "B4"})
    key = server_secure.subscriptions.create_product_key("enterprise", 365)["key"]
    assert rc.post("/api/subscription/activate", json={"product_key": key}).status_code == 200
    org = rc.post("/api/orgs", json={"name": "RealCorp", "seats": 10})
    assert org.status_code == 200 and org.json()["members"][email] == "admin"
    assert rc.get("/api/orgs/me").json()["role"] == "admin"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"PASS  {fn.__name__}")
    print(f"\n{len(fns)} tests passed.")
