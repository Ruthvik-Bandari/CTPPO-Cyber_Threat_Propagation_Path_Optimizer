"""Tests for the B3 lateral-movement prior sensitivity sweep."""

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
logging.disable(logging.CRITICAL)

from evaluation.b3_lateral_sensitivity import run, PRIOR_GRID  # noqa: E402


def test_sweep_runs_and_metrics_in_range():
    res = run(n=20)
    assert res["n_evaluated"] > 0
    for k in ("top_fix_invariant_frac", "baseline_vs_flat_agreement",
              "baseline_vs_strong_agreement"):
        assert 0.0 <= res[k] <= 1.0


def test_grid_spans_flat_to_strong():
    labels = {lab for lab, _ in PRIOR_GRID}
    assert {"baseline", "flat", "strong_seg"} <= labels


def test_deterministic_across_runs():
    a = run(n=15)
    b = run(n=15)
    assert a["n_evaluated"] == b["n_evaluated"]
    assert a["top_fix_invariant_frac"] == b["top_fix_invariant_frac"]


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"PASS  {fn.__name__}")
    print(f"\n{len(fns)} tests passed.")
