"""Tests for D2 (runtime vs graph size + tractability ceiling)."""

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
logging.disable(logging.CRITICAL)

from evaluation.d2_scalability import (  # noqa: E402
    scaled_network, realistic_scaling, worstcase_ceiling, epsilon_extends_ceiling,
)
from core.network_builder import build_network  # noqa: E402
from core.threat_data import ThreatDataProvider  # noqa: E402


def test_scaled_network_size_and_connectivity():
    spec = scaled_network(12, seed=0)
    assert len(spec.hosts) == 12
    assert spec.hosts[0].internet_facing and spec.hosts[-1].is_goal
    g = build_network(spec, provider=ThreatDataProvider(offline=True))
    assert g.num_nodes > 12 and g.num_edges >= 11      # backbone connectivity at minimum


def test_realistic_scaling_grows_and_stays_fast():
    rows = realistic_scaling(sizes=(10, 30), reps=1)
    assert rows[1]["nodes"] > rows[0]["nodes"]          # bigger graph
    assert all(r["median_ms"] >= 0 for r in rows)
    assert all(r["mean_front"] >= 1 for r in rows)


def test_worstcase_front_grows_with_k():
    res = worstcase_ceiling(ks=range(3, 7), budget_ms=1e9)   # huge budget → run all, no early stop
    fronts = [r["exact_front"] for r in res["rows"]]
    assert fronts == sorted(fronts) and fronts[-1] > fronts[0]   # monotonically growing front
    assert res["rows"][-1]["labels"] > res["rows"][0]["labels"]


def test_worstcase_ceiling_detected_with_tiny_budget():
    res = worstcase_ceiling(ks=range(3, 12), budget_ms=50.0)    # small budget → ceiling found early
    assert res["ceiling_k"] is not None


def test_epsilon_extends_ceiling_reduces_runtime_and_front():
    rows = epsilon_extends_ceiling(k=8, epsilons=(0.0, 0.5))
    exact, approx = rows[0], rows[1]
    assert approx["front"] <= exact["front"]
    assert approx["labels"] <= exact["labels"]


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"PASS  {fn.__name__}")
    print(f"\n{len(fns)} tests passed.")
