"""Tests for B4 external grounding (KEV add-dates vs the time-to-exploit proxy).

Slow (under tests/evaluation/). Uses the cached KEV + NVD snapshots. Asserts the harness runs and
returns a well-formed Spearman CI on a non-trivial sample; the headline value (≈ +0.26, CI excludes
0) is data-dependent and reported in the doc, so here we only assert structure + bounds.
"""

from evaluation.b4_external_grounding import run, _spearman


def test_spearman_helper_monotone():
    # perfectly increasing → +1; perfectly inverted → -1
    assert _spearman([1, 2, 3, 4], [10, 20, 30, 40]) == 1.0
    assert _spearman([1, 2, 3, 4], [40, 30, 20, 10]) == -1.0


def test_external_grounding_runs_on_cached_feeds():
    res = run()
    assert res["n_pairs"] >= 50                       # KEV ∩ NVD cache is a real sample
    f = res["spearman_full"]
    assert f and -1.0 <= f["point"] <= 1.0
    assert f["ci_lo"] <= f["point"] <= f["ci_hi"]     # CI brackets the point estimate
    assert res["median_window_days"] >= 0
