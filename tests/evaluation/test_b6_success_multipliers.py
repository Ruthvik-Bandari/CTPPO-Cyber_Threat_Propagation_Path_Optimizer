"""Tests for B6 (success-probability heuristic-multiplier sensitivity)."""

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
logging.disable(logging.CRITICAL)

from evaluation.b6_success_multipliers import (  # noqa: E402
    mechanism_sensitivity, decision_sensitivity, mixed_network, VARIANTS, ISOLATED,
)
from core.threat_data import ThreatDataProvider  # noqa: E402


def test_every_knob_is_live():
    """Each multiplier must measurably move a single edge's success probability —
    otherwise an 'invariant' decision result would be a meaningless artifact."""
    m = mechanism_sensitivity()
    assert m["ac_swing"] > 0.3          # AC factor on a high-existence edge
    assert m["floor_swing_when_binds"] > 0.5   # KEV floor when it binds (low/missing-EPSS KEV)
    assert m["prior_swing"] > 0.3       # EPSS-missing prior


def test_kev_floor_inert_on_real_kev_at_default():
    """Honesty check: the shipped 0.90 floor does not bind on real (high-EPSS) KEV CVEs."""
    m = mechanism_sensitivity()
    assert m["floor_swing_real_kev_default"] == 0.0


def test_mixed_network_exercises_all_pools():
    """A generated network must draw from all three pools so every knob participates."""
    _spec, counts = mixed_network(0)
    assert counts.get("kev", 0) >= 1
    assert counts.get("nonkev", 0) >= 1
    assert counts.get("missing", 0) >= 1


def test_decision_sweep_runs_and_metrics_in_range():
    res = decision_sensitivity(n=10)
    assert res["n_evaluated"] > 0
    assert 0.0 <= res["top_fix_invariant_frac"] <= 1.0
    # the pool guarantee should hold across the evaluated nets
    for g in ("kev", "nonkev", "missing"):
        assert res["pool_presence_frac"][g] == 1.0
    for s in res["per_variant"].values():
        assert 0.0 <= s["top_fix_agreement"] <= 1.0
        assert s["max_magnitude_ratio"] >= 1.0


def test_isolated_variants_exist_in_grid():
    labels = {lab for lab, _ in VARIANTS}
    for variants in ISOLATED.values():
        assert set(variants) <= labels


def test_deterministic_across_runs():
    a = decision_sensitivity(n=8)
    b = decision_sensitivity(n=8)
    assert a["n_evaluated"] == b["n_evaluated"]
    assert a["top_fix_invariant_frac"] == b["top_fix_invariant_frac"]


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"PASS  {fn.__name__}")
    print(f"\n{len(fns)} tests passed.")
