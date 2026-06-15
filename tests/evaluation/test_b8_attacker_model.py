"""Tests for B8 (attacker-model sensitivity)."""

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
logging.disable(logging.CRITICAL)

from evaluation.b8_attacker_model import (  # noqa: E402
    attacker_construct, decision_sweep, scalar_optimal_path, ATTACKER_MODELS,
)


def test_attacker_models_include_single_objective_extremes():
    labels = {lab for lab, _ in ATTACKER_MODELS}
    assert {"min_time", "max_success", "min_impact"} <= labels


def test_construct_attacker_model_is_live():
    """Disjoint-route construct: single-objective attackers split AND the one recommended
    fix misses the stealth attacker — proving the attacker model genuinely matters."""
    c = attacker_construct()
    assert c["distinct_attacker_paths"] >= 2          # attackers diverge
    assert c["all_models_covered"] is False           # one fix can't cover disjoint routes
    assert c["coverage_by_model"]["min_impact"] is False
    assert c["coverage_by_model"]["min_time"] is True


def test_decision_sweep_metrics_in_range():
    res = decision_sweep(n=12)
    assert res["n_evaluated"] > 0
    assert 0.0 <= res["frac_nets_attacker_paths_diverge"] <= 1.0
    assert 0.0 <= res["overall_recommendation_coverage"] <= 1.0
    assert res["mean_distinct_attacker_paths"] >= 1.0


def test_scalar_optimal_handles_empty_front():
    assert scalar_optimal_path([], (1.0, 0.0, 0.0)) is None


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"PASS  {fn.__name__}")
    print(f"\n{len(fns)} tests passed.")
