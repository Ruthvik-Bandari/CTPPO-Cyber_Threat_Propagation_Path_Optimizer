"""Tests for the B1 EPSS marginal-vs-conditional sensitivity study."""

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
logging.disable(logging.CRITICAL)

from evaluation.b1_epss_conditional import run, REGIMES, _cond  # noqa: E402


def test_cond_transform_direction():
    assert _cond(0.1, True, 0.5, 1.0) > 0.1      # KEV edge raised toward 1 (γ<1)
    assert abs(_cond(0.1, False, 0.5, 1.0) - 0.1) < 1e-12  # non-KEV at γ=1 unchanged


def test_uniform_conditioning_is_ranking_invariant():
    # Analytic guarantee: uniform γ → path prob (∏p)^γ → EXACT order preservation.
    res = run(n=30)
    assert res["n_networks"] > 0
    for label in ("uniform_mild", "uniform_strong"):
        assert abs(res["regimes"][label]["top1_stable_frac"] - 1.0) < 1e-9
        assert abs(res["regimes"][label]["order_stable_frac"] - 1.0) < 1e-9


def test_conditioning_raises_magnitude():
    res = run(n=30)
    for label, gk, gn in REGIMES:
        if gk < 1.0 or gn < 1.0:
            assert res["regimes"][label]["mean_reach_lift"] >= 1.0 - 1e-9


def test_deterministic_across_runs():
    a = run(n=20)
    b = run(n=20)
    assert (a["regimes"]["kev_strong"]["mean_reach_lift"]
            == b["regimes"]["kev_strong"]["mean_reach_lift"])
    assert (a["regimes"]["kev_strong"]["order_stable_frac"]
            == b["regimes"]["kev_strong"]["order_stable_frac"])


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"PASS  {fn.__name__}")
    print(f"\n{len(fns)} tests passed.")
