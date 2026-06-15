"""
Persistence tests — each store survives a 'restart' when backed by SQL.

A fresh store instance pointed at the same SQLite file must load what a prior instance wrote
(write-through + load-on-start). Also asserts the in-memory default (persistence=None) stays
isolated. No DB server needed — uses a temp SQLite file.

Run with: python3 tests/api/test_persistence.py
"""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "api"))

from persistence import persistence_for  # noqa: E402
from user_store import UserStore  # noqa: E402
from instance_store import InstanceStore  # noqa: E402
from api_key_store import ApiKeyStore  # noqa: E402
from org_store import OrgStore  # noqa: E402
from subscription_store import SubscriptionStore  # noqa: E402


def _url():
    d = tempfile.mkdtemp(prefix="ctppo_persist_")
    return f"sqlite:///{d}/store.db"


def test_user_store_persists():
    url = _url()
    s1 = UserStore(persistence=persistence_for(url, "users"))
    s1.create_user("a@x.com", "Ada", "hash123")
    s2 = UserStore(persistence=persistence_for(url, "users"))
    assert "a@x.com" in s2
    assert s2.get("a@x.com")["name"] == "Ada"
    assert s2.get("a@x.com")["password_hash"] == "hash123"


def test_instance_store_persists():
    url = _url()
    s1 = InstanceStore(persistence=persistence_for(url, "instances"))
    inst = s1.create("a@x.com", "scan", "prompt")
    s2 = InstanceStore(persistence=persistence_for(url, "instances"))
    got = s2.get(inst["id"], "a@x.com")
    assert got is not None and got["name"] == "scan"
    # delete write-through
    assert s2.delete(inst["id"], "a@x.com") is True
    s3 = InstanceStore(persistence=persistence_for(url, "instances"))
    assert s3.get(inst["id"], "a@x.com") is None


def test_api_key_store_persists():
    url = _url()
    s1 = ApiKeyStore(persistence=persistence_for(url, "keys"))
    raw, rec = s1.issue("a@x.com", "ci")
    s2 = ApiKeyStore(persistence=persistence_for(url, "keys"))
    assert s2.resolve(raw) == "a@x.com"
    assert any(k["id"] == rec["id"] for k in s2.list_for("a@x.com"))


def test_org_store_persists():
    url = _url()
    s1 = OrgStore(persistence=persistence_for(url, "orgs"))
    org = s1.create_org("Acme", "admin@x.com", 5)
    s1.add_member(org["id"], "admin@x.com", "bob@x.com", "member")
    s2 = OrgStore(persistence=persistence_for(url, "orgs"))
    loaded = s2.org_for_user("admin@x.com")
    assert loaded is not None and loaded["name"] == "Acme"
    assert s2.org_for_user("bob@x.com") is not None       # _user_org rebuilt on load
    assert loaded["members"]["bob@x.com"] == "member"


def test_subscription_store_persists():
    url = _url()
    s1 = SubscriptionStore(persistence=persistence_for(url, "subs"))
    kd = s1.create_product_key("individual", 30)
    s1.activate(kd["key"], "a@x.com")
    s2 = SubscriptionStore(persistence=persistence_for(url, "subs"))
    assert s2.check_subscription("a@x.com")["has_subscription"] is True
    # revoke write-through removes both key + activation
    assert s2.revoke_key(kd["key"]) is True
    s3 = SubscriptionStore(persistence=persistence_for(url, "subs"))
    assert s3.check_subscription("a@x.com")["has_subscription"] is False


def test_in_memory_default_is_isolated():
    a = UserStore()  # no persistence
    a.create_user("x@y.com", "X", "h")
    b = UserStore()
    assert "x@y.com" not in b  # separate in-memory state, nothing shared


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"PASS  {fn.__name__}")
    print(f"\n{len(fns)} tests passed.")
