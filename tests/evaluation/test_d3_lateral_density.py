"""Tests for D3 (lateral-edge density handling)."""

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
logging.disable(logging.CRITICAL)

from evaluation.d3_lateral_density import (  # noqa: E402
    dense_network, edge_growth_vs_size, budget_handling,
)
from core.network_builder import build_network  # noqa: E402
from core.threat_data import ThreatDataProvider  # noqa: E402


def test_full_mesh_has_more_edges_than_sparse():
    prov = ThreatDataProvider(offline=True)
    sparse = build_network(dense_network(12, 0.1, seed=0), provider=prov)
    full = build_network(dense_network(12, 1.0, seed=0), provider=prov)
    assert full.num_edges > sparse.num_edges


def test_budget_bounds_edges_and_default_is_unbounded():
    prov = ThreatDataProvider(offline=True)
    spec = dense_network(20, 1.0, seed=0)
    unbounded = build_network(spec, provider=prov)
    budgeted = build_network(spec, provider=prov, max_lateral_per_host=3)
    assert budgeted.num_edges < unbounded.num_edges
    # default None reproduces the unbudgeted graph exactly
    assert build_network(spec, provider=prov, max_lateral_per_host=None).num_edges == unbounded.num_edges


def test_edge_growth_is_superlinear_front_stays_small():
    rows = edge_growth_vs_size(sizes=(10, 40), budget_k=4)
    small, big = rows[0], rows[1]
    # quadratic-ish: 4x hosts ⇒ much more than 4x edges, while budgeted stays near-linear
    assert big["edges_unbudgeted"] / small["edges_unbudgeted"] > 4.0
    assert big["edges_budgeted"] / small["edges_budgeted"] < big["edges_unbudgeted"] / small["edges_unbudgeted"]
    assert small["front"] >= 1 and big["front"] >= 1   # front stays small (no search explosion)


def test_budget_decision_cost_reported_and_monotone_edges():
    res = budget_handling(n_hosts=12, density=1.0, budgets=(None, 3, 2), n_seeds=6)
    rows = {str(r["budget"]): r for r in res["rows"]}
    assert rows["None"]["top_fix_unchanged_frac"] == 1.0          # vs itself
    assert rows["2"]["mean_edges"] <= rows["3"]["mean_edges"] <= rows["None"]["mean_edges"]
    for r in res["rows"]:
        assert 0.0 <= r["top_fix_unchanged_frac"] <= 1.0


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"PASS  {fn.__name__}")
    print(f"\n{len(fns)} tests passed.")
