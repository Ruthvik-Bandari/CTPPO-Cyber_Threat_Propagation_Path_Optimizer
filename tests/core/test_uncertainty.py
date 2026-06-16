"""Tests for Phase 6 — per-path reachability uncertainty bands (B1/B2 made operational).

Fast, offline. Verifies the band arithmetic, the invariant independence ≤ comonotone, and that the
independence bound equals the engine's reported SUCCESS_PROBABILITY (the band lower bound is the
engine's point value — consistency).
"""

import logging
from math import prod

from core.uncertainty import reachability_band, path_reachability_band, edge_success_probs
from core.identity_graph import build_identity_graph, create_ad_kill_chain_scenario
from algorithms.namoa_star import run_namoa_star
from core.logging_system import ResearchLogger

logging.disable(logging.CRITICAL)
QUIET = ResearchLogger("test_uncertainty", console_output=False)


def test_band_arithmetic():
    b = reachability_band([0.5, 0.4, 0.8])
    assert abs(b["independence"] - 0.16) < 1e-9      # ∏ = 0.5*0.4*0.8
    assert b["comonotone"] == 0.4                    # min
    assert abs(b["width_factor"] - 2.5) < 1e-3       # 0.4 / 0.16
    assert b["n_edges"] == 3


def test_band_empty():
    b = reachability_band([])
    assert b["independence"] == 0.0 and b["comonotone"] == 0.0 and b["n_edges"] == 0


def test_comonotone_upper_bounds_independence():
    # for any path, min pᵢ ≥ ∏ pᵢ (the band never inverts)
    g = build_identity_graph(create_ad_kill_chain_scenario(), logger=QUIET)
    result = run_namoa_star(g, logger=QUIET)
    for ids, _c in result.pareto_paths:
        b = path_reachability_band(g, ids)
        assert b["comonotone"] >= b["independence"] - 1e-9
        assert b["n_edges"] >= 1


def test_independence_matches_engine_success():
    # the band's lower bound (∏ pᵢ over path edges) == the engine's reported SUCCESS_PROBABILITY
    g = build_identity_graph(create_ad_kill_chain_scenario(), logger=QUIET)
    result = run_namoa_star(g, logger=QUIET)
    for ids, cost in result.pareto_paths:
        labels = list(getattr(cost, "labels", []))
        if "SUCCESS_PROBABILITY" not in labels:
            continue
        engine_success = float(cost.values[labels.index("SUCCESS_PROBABILITY")])
        indep = prod(edge_success_probs(g, ids))
        assert abs(indep - engine_success) < 1e-4
