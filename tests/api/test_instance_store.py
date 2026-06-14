"""
Tests for the B3 instance (workspace) store — pure Python, no fastapi/Redis.

Run with: python3 tests/api/test_instance_store.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "api"))

from instance_store import InstanceStore  # noqa: E402

A = "alice@example.com"
B = "bob@example.com"


def test_create_and_get():
    s = InstanceStore()
    inst = s.create(A, "My scan", prompt="check web app", target_spec={"url": "https://x"})
    assert inst["id"].startswith("inst_")
    assert inst["owner"] == A and inst["status"] == "draft"
    assert s.get(inst["id"], A)["name"] == "My scan"


def test_get_is_owner_scoped():
    s = InstanceStore()
    inst = s.create(A, "secret")
    assert s.get(inst["id"], B) is None        # Bob cannot read Alice's instance


def test_list_only_returns_owner_instances():
    s = InstanceStore()
    s.create(A, "a1"); s.create(A, "a2"); s.create(B, "b1")
    assert len(s.list_for(A)) == 2
    assert len(s.list_for(B)) == 1


def test_update_changes_fields_and_timestamp():
    s = InstanceStore()
    inst = s.create(A, "orig", prompt="p1")
    created = inst["updated_at"]
    updated = s.update(inst["id"], A, name="renamed", prompt="p2")
    assert updated["name"] == "renamed" and updated["prompt"] == "p2"
    assert updated["updated_at"] >= created


def test_update_wrong_owner_is_none():
    s = InstanceStore()
    inst = s.create(A, "x")
    assert s.update(inst["id"], B, name="hacked") is None
    assert s.get(inst["id"], A)["name"] == "x"   # unchanged


def test_delete_owner_scoped():
    s = InstanceStore()
    inst = s.create(A, "x")
    assert s.delete(inst["id"], B) is False      # Bob cannot delete Alice's
    assert s.delete(inst["id"], A) is True
    assert s.get(inst["id"], A) is None
    assert s.delete(inst["id"], A) is False      # already gone


def test_files_get_metadata_scan():
    s = InstanceStore()
    inst = s.create(A, "withfiles", files=[{"name": "report.PDF", "size": 1234, "content_type": "application/pdf"}])
    f = inst["files"][0]
    assert f["ext"] == "pdf" and f["size"] == 1234 and f["scanned_at"]


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"PASS  {fn.__name__}")
    print(f"\n{len(fns)} tests passed.")
