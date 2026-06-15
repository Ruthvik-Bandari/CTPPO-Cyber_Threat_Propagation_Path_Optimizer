"""Tests for the emulated ground-truth testbed (C2)."""

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
logging.disable(logging.CRITICAL)

from evaluation.emulated_testbed import run, _enumerate_paths  # noqa: E402


def test_enumerate_paths_finds_all_simple_paths():
    adj = {"s": ["a", "b"], "a": ["g"], "b": ["g"]}
    paths = set(_enumerate_paths(adj, "s", "g"))
    assert paths == {("s", "a", "g"), ("s", "b", "g")}


def test_engine_front_is_sound_on_all_topologies():
    res = run()
    # Every returned path is a real, independently-enumerated exploitable path.
    assert res["all_sound"] is True
    assert abs(res["mean_soundness"] - 1.0) < 1e-9


def test_single_goal_networks_have_full_goal_coverage():
    res = run()
    for r in res["rows"]:
        assert r["front_size"] >= 1
        if r["reachable_goals"] == 1:
            assert abs(r["goal_coverage"] - 1.0) < 1e-9


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"PASS  {fn.__name__}")
    print(f"\n{len(fns)} tests passed.")
