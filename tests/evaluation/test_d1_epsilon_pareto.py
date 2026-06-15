"""Tests for D1 (ε-Pareto bounded-approximation fallback)."""

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
logging.disable(logging.CRITICAL)

import numpy as np  # noqa: E402

from algorithms.namoa_star import run_namoa_star  # noqa: E402
from algorithms.pareto_utils import ParetoSet, LabeledSolution, CostVector  # noqa: E402
from evaluation.d1_epsilon_pareto import (  # noqa: E402
    pareto_hard_graph, epsilon_sweep_hard, _internal_costs, approximation_factor, _max_depth,
)


def test_epsilon_zero_is_exact_and_positive_reduces_front():
    g = pareto_hard_graph(6)
    exact = run_namoa_star(g, epsilon=0.0)
    approx = run_namoa_star(g, epsilon=0.25)
    assert len(exact.pareto_paths) > 10           # the hard instance has a large exact front
    assert len(approx.pareto_paths) < len(exact.pareto_paths)   # ε prunes it


def test_paretoset_epsilon_dominance_prunes():
    # Exact: [1,2] and [2,1] are mutually non-dominated → both kept.
    exact = ParetoSet()
    exact.add(LabeledSolution("a", CostVector(np.array([1.0, 2.0]))))
    assert exact.add(LabeledSolution("b", CostVector(np.array([2.0, 1.0])))) is True
    # ε=0.0 keeps a near-tie; ε=0.5 lets [1,2] ε-dominate [1.2, 2.2].
    eps = ParetoSet(epsilon=0.5)
    eps.add(LabeledSolution("a", CostVector(np.array([1.0, 2.0]))))
    assert eps.is_dominated(CostVector(np.array([1.2, 2.2]))) is True
    assert eps.is_dominated(CostVector(np.array([0.5, 1.0]))) is False   # genuinely better


def test_compounded_bound_holds_on_hard_instance():
    res = epsilon_sweep_hard(k=6)
    assert res["exact_front"] > 10
    for r in res["rows"]:
        assert r["compounded_bound_holds"] is True       # (1+ε)^d always holds
        if r["epsilon"] > 0:
            assert r["front_size"] <= res["exact_front"]


def test_naive_1pe_bound_is_violated_documenting_compounding():
    # The whole point of the D1 correction: per-label ε compounds, so (1+ε) is NOT enough.
    res = epsilon_sweep_hard(k=7)
    violated = any(r["max_approx_factor"] > r["naive_bound_1pe"] + 1e-9
                   for r in res["rows"] if r["epsilon"] > 0)
    assert violated


def test_negative_epsilon_rejected():
    g = pareto_hard_graph(4)
    try:
        run_namoa_star(g, epsilon=-0.1)
        assert False, "expected ValueError"
    except ValueError:
        pass


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"PASS  {fn.__name__}")
    print(f"\n{len(fns)} tests passed.")
