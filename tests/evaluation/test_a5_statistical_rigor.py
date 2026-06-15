"""Tests for A5 (statistical rigor — bootstrap / Wilson CIs on the headline numbers)."""

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
logging.disable(logging.CRITICAL)

from evaluation.a5_statistical_rigor import (  # noqa: E402
    bootstrap_ci, wilson_ci, phase_c_rigor, sensitivity_rigor,
)


def test_bootstrap_ci_brackets_point_and_zero_width_on_constant():
    ci = bootstrap_ci([0.5, 0.5, 0.5, 0.5])
    assert ci["ci_lo"] == 0.5 == ci["ci_hi"]          # no spread in a constant sample
    ci2 = bootstrap_ci([0.1, 0.2, 0.3, 0.4, 0.5])
    assert ci2["ci_lo"] <= ci2["point"] <= ci2["ci_hi"]
    assert ci2["std"] is not None


def test_bootstrap_ci_handles_non_scalar_values_for_correlation():
    # (x, y) pairs with a custom statistic — std must be None, not a crash.
    pairs = [(1, 1), (2, 2), (3, 3), (4, 4)]
    ci = bootstrap_ci(pairs, statistic=lambda s: sum(x for x, _ in s))
    assert ci["std"] is None
    assert ci["n"] == 4


def test_wilson_ci_correct_at_extremes():
    # p = 1 must give a finite lower bound (< 1), not the degenerate [1, 1] a bootstrap would.
    perfect = wilson_ci(60, 60)
    assert perfect["point"] == 1.0
    assert 0.9 < perfect["ci_lo"] < 1.0          # finite lower bound, not [1, 1]
    assert perfect["ci_hi"] >= 0.999             # capped at ~1.0 (float, not exact equality)
    zero = wilson_ci(0, 40)
    assert zero["point"] == 0.0 and zero["ci_lo"] == 0.0 and zero["ci_hi"] < 0.15
    half = wilson_ci(50, 100)
    assert half["ci_lo"] < 0.5 < half["ci_hi"]


def test_phase_c_rigor_small_n():
    res = phase_c_rigor(n=15)
    assert res["n_evaluated"] > 0
    for key in ("divergence_rate", "recovery_pareto", "pareto_ge_rate"):
        ci = res[key]
        assert ci["ci_lo"] <= ci["point"] <= ci["ci_hi"]
    assert res["graph_nodes"]["min"] >= 1


def test_sensitivity_rigor_small_n():
    res = sensitivity_rigor(n=8)
    for key in ("b3_lateral_invariant", "b6_multiplier_invariant", "b8_recommendation_coverage"):
        ci = res[key]
        assert 0.0 <= ci["ci_lo"] <= ci["ci_hi"] <= 1.0
    assert res["b4_spearman_time_epss"]["n"] > 0


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"PASS  {fn.__name__}")
    print(f"\n{len(fns)} tests passed.")
