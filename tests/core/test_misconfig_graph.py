"""Tests for Phase 5 / C3 — misconfiguration (non-CVE weakness) modeling.

Offline, fast. Verifies the misconfig breach scenario builds with NO CVE anywhere, NAMOA*
recovers a weakness-chain path to the crown jewel, CWE ids ride the edges, and the misconfig
costs are honestly flagged heuristic (not data-grounded).
"""

import logging

from core.misconfig_graph import (
    build_misconfig_graph, create_misconfig_breach_scenario, _misconfig_cost,
    Misconfiguration, EdgeType,
)
from core.node_types import NodeType
from algorithms.namoa_star import run_namoa_star
from core.logging_system import ResearchLogger

logging.disable(logging.CRITICAL)
QUIET = ResearchLogger("test_misconfig", console_output=False)


def _graph():
    return build_misconfig_graph(create_misconfig_breach_scenario(), logger=QUIET)


def _cwes_on(graph, path):
    return [graph.get_node(n).metadata.get("cwe_id") for n in path
            if graph.get_node(n) and graph.get_node(n).node_type == NodeType.EXPLOIT
            and graph.get_node(n).metadata.get("cwe_id")]


def test_scenario_builds_with_goal_and_no_cve():
    g = _graph()
    assert g.entry_points and g.goal_nodes
    # No exploit node references a CVE — this is a misconfiguration-only chain.
    exploits = [g.get_node(n) for n in g.nodes if g.get_node(n).node_type == NodeType.EXPLOIT]
    assert all(not e.target_vulnerabilities for e in exploits)


def test_namoa_recovers_misconfig_chain():
    g = _graph()
    result = run_namoa_star(g, logger=QUIET)
    assert len(result.pareto_paths) >= 1
    for path, _cost in result.pareto_paths:
        cwes = _cwes_on(g, path)
        assert "CWE-798" in cwes               # every path starts with default creds (initial access)


def test_cwe_ids_present_on_exploit_nodes():
    g = _graph()
    exploits = [g.get_node(n) for n in g.nodes if g.get_node(n).node_type == NodeType.EXPLOIT]
    tagged = {e.metadata.get("cwe_id") for e in exploits if e.metadata.get("cwe_id")}
    assert {"CWE-798", "CWE-306", "CWE-732", "CWE-522"} <= tagged


def test_both_routes_to_db_are_on_the_front():
    # the thorough backup-pivot chain (CWE-522) and the fast direct-DB route should both be present
    g = _graph()
    result = run_namoa_star(g, logger=QUIET)
    all_cwes = [_cwes_on(g, p) for p, _ in result.pareto_paths]
    assert any("CWE-522" in c for c in all_cwes)              # backup → secrets-in-backup chain
    assert any(c.count("CWE-306") >= 2 for c in all_cwes)     # fast route ends in a 2nd CWE-306 (DB no-auth)


def test_misconfig_costs_flagged_heuristic_not_grounded():
    cost = _misconfig_cost(
        Misconfiguration("default-creds", "Default credentials", "CWE-798", "T1078"), 8.0)
    assert cost.metadata["heuristic"] is True
    assert cost.metadata["data_grounded"] is False
    assert cost.metadata["cwe_id"] == "CWE-798"


def test_misconfig_edge_types_registered():
    assert EdgeType.MISCONFIG_INITIAL_ACCESS == "misconfig_initial_access"
    assert EdgeType.MISCONFIG_MOVE == "misconfig_lateral_move"
