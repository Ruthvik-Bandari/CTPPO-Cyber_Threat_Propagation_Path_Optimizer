"""
HTTP tests for the B3 instance CRUD router.

Most tests mount the router in isolation with a fake header-driven user dependency
(no auth/subscription machinery needed) to exercise CRUD + owner-scoping. A final test
boots the real server_secure app to confirm the router is mounted and subscription-gated.

Run with: python3 tests/api/test_instance_routes.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "api"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from fastapi import FastAPI, Request  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from instance_store import InstanceStore  # noqa: E402
from instance_routes import create_instance_router  # noqa: E402


def _fake_user(request: Request) -> dict:
    # Simulate the logged-in user via a header so we can test multiple owners.
    return {"email": request.headers.get("X-Test-User", "default@example.com")}


def _client():
    app = FastAPI()
    app.include_router(create_instance_router(InstanceStore(), _fake_user))
    return TestClient(app)


ALICE = {"X-Test-User": "alice@example.com"}
BOB = {"X-Test-User": "bob@example.com"}


def test_create_and_list():
    c = _client()
    r = c.post("/api/instances", json={"name": "scan1", "prompt": "p", "target_spec": {"url": "x"}}, headers=ALICE)
    assert r.status_code == 200 and r.json()["name"] == "scan1"
    lst = c.get("/api/instances", headers=ALICE).json()["instances"]
    assert len(lst) == 1 and lst[0]["owner"] == "alice@example.com"


def test_get_own_instance():
    c = _client()
    iid = c.post("/api/instances", json={"name": "s"}, headers=ALICE).json()["id"]
    assert c.get(f"/api/instances/{iid}", headers=ALICE).status_code == 200


def test_owner_isolation_get_and_list():
    c = _client()
    iid = c.post("/api/instances", json={"name": "alice-only"}, headers=ALICE).json()["id"]
    # Bob cannot see Alice's instance, and his list is empty
    assert c.get(f"/api/instances/{iid}", headers=BOB).status_code == 404
    assert c.get("/api/instances", headers=BOB).json()["instances"] == []


def test_update_instance():
    c = _client()
    iid = c.post("/api/instances", json={"name": "old"}, headers=ALICE).json()["id"]
    r = c.put(f"/api/instances/{iid}", json={"name": "new", "status": "ready"}, headers=ALICE)
    assert r.status_code == 200 and r.json()["name"] == "new" and r.json()["status"] == "ready"
    # Bob cannot update Alice's instance
    assert c.put(f"/api/instances/{iid}", json={"name": "hax"}, headers=BOB).status_code == 404


def test_delete_instance():
    c = _client()
    iid = c.post("/api/instances", json={"name": "tmp"}, headers=ALICE).json()["id"]
    assert c.delete(f"/api/instances/{iid}", headers=BOB).status_code == 404   # not owner
    assert c.delete(f"/api/instances/{iid}", headers=ALICE).status_code == 200
    assert c.get(f"/api/instances/{iid}", headers=ALICE).status_code == 404


def test_create_with_file_metadata():
    c = _client()
    r = c.post("/api/instances", json={
        "name": "withfiles",
        "files": [{"name": "scan.json", "size": 50, "content_type": "application/json"}],
    }, headers=ALICE)
    f = r.json()["files"][0]
    assert f["ext"] == "json" and f["scanned_at"]


def test_real_app_instances_are_mounted_and_gated():
    import server_secure
    rc = TestClient(server_secure.app)
    # unauthenticated -> 401
    assert rc.get("/api/instances").status_code == 401
    # subscribed user: signup + activate, then full CRUD works on the real app
    email = "b3int@example.com"
    rc.post("/api/auth/signup", json={"email": email, "password": "password123", "name": "B3"})
    key = server_secure.subscriptions.create_product_key("individual", 365)["key"]
    assert rc.post("/api/subscription/activate", json={"product_key": key}).status_code == 200
    created = rc.post("/api/instances", json={"name": "real", "prompt": "go"})
    assert created.status_code == 200
    assert any(i["id"] == created.json()["id"] for i in rc.get("/api/instances").json()["instances"])


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"PASS  {fn.__name__}")
    print(f"\n{len(fns)} tests passed.")
