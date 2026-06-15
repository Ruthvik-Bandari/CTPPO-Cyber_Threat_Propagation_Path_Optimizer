"""Tests for B7 (cost-combination semantics sensitivity)."""

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
logging.disable(logging.CRITICAL)

from evaluation.b7_combination_semantics import (  # noqa: E402
    impact_construct_validity, impact_combination, success_combination,
    illustrative_inversion, _prod, _noisy_or,
)
from core.network_builder import create_sample_multihost_network  # noqa: E402
from core.threat_data import ThreatDataProvider  # noqa: E402
from algorithms.namoa_star import run_namoa_star  # noqa: E402


def test_combine_impact_default_reproduces_max():
    g = create_sample_multihost_network(provider=ThreatDataProvider(offline=True))
    default = run_namoa_star(g)
    explicit_max = run_namoa_star(g, combine_impact="max")
    assert len(default.pareto_paths) == len(explicit_max.pareto_paths)


def test_impact_knob_is_live():
    """impact=sum must change the front vs max on a route with differing impact composition."""
    c = impact_construct_validity()
    assert c["knob_changes_impact_scores"] is True


def test_impact_combination_sweep_top_fix_in_range():
    res = impact_combination(n=12)
    assert res["n_evaluated"] > 0
    assert 0.0 <= res["top_fix_invariant_frac"] <= 1.0
    assert 0.0 <= res["mean_front_jaccard"] <= 1.0


def test_noisy_or_rewards_length_product_penalises():
    """The defining pathology: noisy-OR rises with hops, ∏ falls."""
    short = [0.8]
    long = [0.5, 0.5, 0.5, 0.5]
    assert _prod(short) > _prod(long)            # product prefers short
    assert _noisy_or(long) > _noisy_or(short)    # noisy-OR prefers long
    inv = illustrative_inversion()
    assert inv["prod_prefers_short"] and inv["noisyor_prefers_long"]


def test_success_combination_length_effect_signs():
    res = success_combination(n=20)
    # ∏ correlates negatively with path length; noisy-OR positively.
    assert res["spearman_prod_vs_length"] < 0
    assert res["spearman_noisyor_vs_length"] > 0


def test_invalid_combine_impact_rejected():
    g = create_sample_multihost_network(provider=ThreatDataProvider(offline=True))
    try:
        run_namoa_star(g, combine_impact="median")
        assert False, "expected ValueError"
    except ValueError:
        pass


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"PASS  {fn.__name__}")
    print(f"\n{len(fns)} tests passed.")
