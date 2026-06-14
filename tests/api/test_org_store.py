"""
Tests for the B4 organization / RBAC store — pure Python, no fastapi/Redis.

Run with: python3 tests/api/test_org_store.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "api"))

from org_store import OrgStore, OrgError  # noqa: E402

ADMIN = "admin@corp.com"
BOB = "bob@corp.com"
CAROL = "carol@corp.com"
OUT = "outsider@other.com"


def _raises(status, fn):
    try:
        fn()
    except OrgError as e:
        assert e.status == status, f"expected {status}, got {e.status}: {e.detail}"
        return
    raise AssertionError(f"expected OrgError({status}) but none raised")


def test_create_makes_creator_admin():
    s = OrgStore()
    org = s.create_org("Acme", ADMIN, seats=5)
    assert org["members"][ADMIN] == "admin"
    assert s.org_for_user(ADMIN)["id"] == org["id"]


def test_cannot_create_two_orgs():
    s = OrgStore()
    s.create_org("Acme", ADMIN)
    _raises(400, lambda: s.create_org("Beta", ADMIN))


def test_admin_adds_member():
    s = OrgStore()
    org = s.create_org("Acme", ADMIN, seats=5)
    s.add_member(org["id"], ADMIN, BOB)
    assert org["members"][BOB] == "member"
    assert s.org_for_user(BOB)["id"] == org["id"]


def test_non_admin_cannot_add_member():
    s = OrgStore()
    org = s.create_org("Acme", ADMIN, seats=5)
    s.add_member(org["id"], ADMIN, BOB)            # Bob is a member
    _raises(403, lambda: s.add_member(org["id"], BOB, CAROL))


def test_seat_allotment_enforced():
    s = OrgStore()
    org = s.create_org("Acme", ADMIN, seats=2)     # admin fills 1 of 2 seats
    s.add_member(org["id"], ADMIN, BOB)            # 2 of 2
    _raises(400, lambda: s.add_member(org["id"], ADMIN, CAROL))   # exhausted


def test_cannot_add_user_already_in_an_org():
    s = OrgStore()
    o1 = s.create_org("Acme", ADMIN, seats=5)
    s.create_org("Beta", BOB, seats=5)             # Bob admins his own org
    _raises(400, lambda: s.add_member(o1["id"], ADMIN, BOB))


def test_set_role_and_last_admin_protection():
    s = OrgStore()
    org = s.create_org("Acme", ADMIN, seats=5)
    s.add_member(org["id"], ADMIN, BOB)
    s.set_role(org["id"], ADMIN, BOB, "admin")     # promote
    assert org["members"][BOB] == "admin"
    # now two admins: demoting the original is allowed
    s.set_role(org["id"], BOB, ADMIN, "member")
    assert org["members"][ADMIN] == "member"
    # Bob is now the last admin — cannot be demoted
    _raises(400, lambda: s.set_role(org["id"], BOB, BOB, "member"))


def test_remove_member_and_last_admin_protection():
    s = OrgStore()
    org = s.create_org("Acme", ADMIN, seats=5)
    s.add_member(org["id"], ADMIN, BOB)
    s.remove_member(org["id"], ADMIN, BOB)
    assert BOB not in org["members"] and s.org_for_user(BOB) is None
    _raises(400, lambda: s.remove_member(org["id"], ADMIN, ADMIN))   # last admin
    _raises(404, lambda: s.remove_member(org["id"], ADMIN, "ghost@x.com"))


def test_member_can_view_outsider_cannot():
    s = OrgStore()
    org = s.create_org("Acme", ADMIN, seats=5)
    s.add_member(org["id"], ADMIN, BOB)
    assert len(s.list_members(org["id"], BOB)) == 2      # member can view
    _raises(404, lambda: s.list_members(org["id"], OUT))  # outsider can't see it


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"PASS  {fn.__name__}")
    print(f"\n{len(fns)} tests passed.")
