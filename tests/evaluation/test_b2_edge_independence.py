"""Tests for the B2 edge-independence (correlation) sensitivity study."""

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
logging.disable(logging.CRITICAL)

from evaluation.b2_edge_independence import run, _p_rho  # noqa: E402


def test_p_rho_endpoints():
    probs = [0.5, 0.2, 0.1]
    assert abs(_p_rho(probs, 0.0) - (0.5 * 0.2 * 0.1)) < 1e-12   # independent product
    assert abs(_p_rho(probs, 1.0) - min(probs)) < 1e-12          # fully comonotonic


def test_sweep_runs_and_ratios_sane():
    res = run(n=25)
    assert res["n_networks"] > 0 and res["n_paths"] > 0
    # min >= prod always, so every misestimation ratio is >= 1.
    assert res["mean_misestimation_ratio"] >= 1.0
    for r in res["misestimation_by_hops"].values():
        assert r >= 1.0 - 1e-9
    assert 0.0 <= res["top1_path_stable_frac"] <= 1.0
    assert 0.0 <= res["full_order_stable_frac"] <= 1.0


def test_independence_underestimates_multihop():
    res = run(n=40)
    h = res["misestimation_by_hops"]
    # 1-hop: product == min (single edge), ratio exactly 1.
    if 1 in h:
        assert abs(h[1] - 1.0) < 1e-6
    # at least one multi-hop bucket shows a real (>1) correlation effect.
    assert any(r > 1.0 for k, r in h.items() if k >= 2)


def test_deterministic_across_runs():
    a = run(n=20)
    b = run(n=20)
    assert a["mean_misestimation_ratio"] == b["mean_misestimation_ratio"]
    assert a["top1_path_stable_frac"] == b["top1_path_stable_frac"]


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"PASS  {fn.__name__}")
    print(f"\n{len(fns)} tests passed.")
