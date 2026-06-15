"""Tests for D4 (incremental re-analysis / what-if patch)."""

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
logging.disable(logging.CRITICAL)

from evaluation.d4_incremental import (  # noqa: E402
    incremental_whatif, on_front_host_pairs, run,
)
from core.threat_data import ThreatDataProvider  # noqa: E402
from evaluation.phase_c_eval import random_network  # noqa: E402
from evaluation.baseline_comparison import build_graph  # noqa: E402
from algorithms.namoa_star import run_namoa_star  # noqa: E402


def test_on_front_pairs_subset_of_edges():
    prov = ThreatDataProvider(offline=True)
    hosts, vulns = random_network(0)
    g, em = build_graph(hosts, vulns, prov)
    res = run_namoa_star(g)
    pairs = on_front_host_pairs(em, res.pareto_paths)
    all_pairs = {(v.source, v.target) for v in vulns}
    assert pairs <= all_pairs                       # front pairs are real edges
    assert len(pairs) >= 1                          # a reachable front uses at least one edge


def test_incremental_matches_full_per_network():
    prov = ThreatDataProvider(offline=True)
    # On several seeds, every skipped (off-front) patch must match the full recompute exactly
    # (this only holds because NAMOA* now returns the COMPLETE front — the D4/parallel-edge fix).
    for seed in (0, 1, 2, 4, 7):
        rows = incremental_whatif(seed, prov)
        for r in rows:
            if r["skipped"]:
                assert r["match"] is True, f"off-front skip changed the front (seed {seed})"


def test_run_aggregate_exact_and_some_skips():
    res = run(n=25)
    assert res["n_candidates"] > 0
    assert res["match_rate_skipped"] == 1.0         # incremental == full on every skip
    assert res["match_rate_overall"] == 1.0
    assert 0.0 < res["skip_rate"] <= 1.0            # at least some patches are off-front
    assert res["speedup"] >= 1.0


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"PASS  {fn.__name__}")
    print(f"\n{len(fns)} tests passed.")
