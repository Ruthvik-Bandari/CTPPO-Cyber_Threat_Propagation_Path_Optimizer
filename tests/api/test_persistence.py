"""
Persistence test — the instance store survives a 'restart' when backed by SQL.

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
from instance_store import InstanceStore  # noqa: E402


def _url():
    d = tempfile.mkdtemp(prefix="ctppo_persist_")
    return f"sqlite:///{d}/store.db"


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


def test_in_memory_default_is_isolated():
    a = InstanceStore()  # no persistence
    inst = a.create("x@y.com", "s")
    b = InstanceStore()
    assert b.get(inst["id"], "x@y.com") is None  # separate in-memory state, nothing shared


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"PASS  {fn.__name__}")
    print(f"\n{len(fns)} tests passed.")
