"""Tests for Phase 5 / C4 — the path evidence grader ("model, not validator").

Fast, offline. Verifies edge-evidence classification (live/KEV/high-EPSS/heuristic/non-action)
and that recovered C1/C3 paths are graded heuristic-only (0% data-grounded) — operationalizing
the honest "model not validator" boundary.
"""

import logging

from evaluation.path_validator import (
    classify_edge_evidence, validate_path, PathValidation,
    LIVE_EXPLOITED, KEV, HIGH_EPSS, DATA_GROUNDED, HEURISTIC,
)
from core.identity_graph import build_identity_graph, create_ad_kill_chain_scenario
from core.misconfig_graph import build_misconfig_graph, create_misconfig_breach_scenario
from algorithms.namoa_star import run_namoa_star
from core.logging_system import ResearchLogger

logging.disable(logging.CRITICAL)
QUIET = ResearchLogger("test_validator", console_output=False)


def test_classify_kev():
    tier, _ = classify_edge_evidence({"cve_id": "CVE-2021-44228", "is_kev": True, "epss": 0.94})
    assert tier == KEV


def test_classify_high_epss_not_kev():
    tier, _ = classify_edge_evidence({"cve_id": "CVE-X", "is_kev": False, "epss": 0.8})
    assert tier == HIGH_EPSS


def test_classify_data_grounded_low_epss():
    tier, _ = classify_edge_evidence({"cve_id": "CVE-Y", "is_kev": False, "epss": 0.01})
    assert tier == DATA_GROUNDED


def test_classify_heuristic_technique():
    tier, _ = classify_edge_evidence({"attack_technique": "T1550.002", "heuristic": True,
                                      "data_grounded": False})
    assert tier == HEURISTIC


def test_classify_live_exploited_takes_precedence():
    tier, _ = classify_edge_evidence({"cve_id": "CVE-2021-41773", "is_kev": True},
                                     live_exploited_cves={"CVE-2021-41773"})
    assert tier == LIVE_EXPLOITED


def test_classify_non_action_edge():
    # a "reach" connector / entry / discovery edge carries no attacker-decision evidence
    tier, _ = classify_edge_evidence({"attack_technique": "", "heuristic": True})
    assert tier is None


def test_c1_path_is_heuristic_only():
    g = build_identity_graph(create_ad_kill_chain_scenario(), logger=QUIET)
    result = run_namoa_star(g, logger=QUIET)
    for path, _c in result.pareto_paths:
        pv = validate_path(g, path)
        assert pv.n_action_edges >= 1
        assert pv.grounded_fraction == 0.0
        assert pv.confidence_label == "heuristic-only"


def test_c3_path_is_heuristic_only():
    g = build_misconfig_graph(create_misconfig_breach_scenario(), logger=QUIET)
    result = run_namoa_star(g, logger=QUIET)
    for path, _c in result.pareto_paths:
        pv = validate_path(g, path)
        assert pv.grounded_fraction == 0.0


def test_confidence_label_thresholds():
    pv = PathValidation(edges=[{"tier": KEV, "rationale": ""}, {"tier": HEURISTIC, "rationale": ""}])
    assert pv.confidence_label == "mixed"
    assert abs(pv.grounded_fraction - 0.5) < 1e-9
