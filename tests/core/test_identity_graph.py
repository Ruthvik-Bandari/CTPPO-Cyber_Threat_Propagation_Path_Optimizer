"""Tests for Phase 5 / C1 — identity/credential/AD attack-graph modeling.

Offline, fast. Verifies the AD kill-chain scenario builds, NAMOA* recovers a credential
lateral path to the Domain Controller, ATT&CK technique IDs ride the edges, and the
credential costs are honestly flagged as heuristic (not data-grounded).
"""

import logging

from core.identity_graph import (
    build_identity_graph, create_ad_kill_chain_scenario, _identity_cost, Technique, EdgeType,
)
from core.node_types import NodeType, AssetType
from algorithms.namoa_star import run_namoa_star
from core.logging_system import ResearchLogger

logging.disable(logging.CRITICAL)
QUIET = ResearchLogger("test_identity", console_output=False)


def _graph():
    return build_identity_graph(create_ad_kill_chain_scenario(), logger=QUIET)


def _techniques_on(graph, path):
    return [graph.get_node(n).mitre_technique_id for n in path
            if graph.get_node(n) and graph.get_node(n).node_type == NodeType.EXPLOIT
            and graph.get_node(n).mitre_technique_id]


def test_scenario_builds_with_domain_controller_goal():
    g = _graph()
    assert g.entry_points and g.goal_nodes
    dc_assets = [g.get_node(n) for n in g.nodes
                 if g.get_node(n).node_type == NodeType.ASSET
                 and g.get_node(n).asset_type == AssetType.DOMAIN_CONTROLLER]
    assert len(dc_assets) == 1  # the DC crown jewel


def test_namoa_recovers_ad_credential_path():
    g = _graph()
    result = run_namoa_star(g, logger=QUIET)
    assert len(result.pareto_paths) >= 1
    for path, _cost in result.pareto_paths:
        techs = _techniques_on(g, path)
        assert "T1566.001" in techs            # every path starts with initial access (phish)
        assert any(t.startswith("T1") for t in techs)


def test_attack_techniques_present_on_exploit_nodes():
    g = _graph()
    exploits = [g.get_node(n) for n in g.nodes if g.get_node(n).node_type == NodeType.EXPLOIT]
    tagged = [e for e in exploits if e.mitre_technique_id]
    # the real techniques (excludes the internal "reach" connector with empty id)
    ids = {e.mitre_technique_id for e in tagged}
    assert {"T1566.001", "T1550.002", "T1558.003", "T1003.006", "T1021.001"} <= ids
    assert all(e.mitre_tactic for e in tagged)  # tactic also populated


def test_both_routes_to_dc_are_on_the_front():
    # the thorough credential chain (DCSync) and the fast RDP route should both be non-dominated
    g = _graph()
    result = run_namoa_star(g, logger=QUIET)
    all_techs = [set(_techniques_on(g, p)) for p, _ in result.pareto_paths]
    assert any("T1003.006" in t for t in all_techs)   # Kerberoast→DCSync route
    assert any("T1021.001" in t for t in all_techs)   # RDP route


def test_credential_costs_flagged_heuristic_not_grounded():
    cost = _identity_cost(Technique("T1550.002", "Pass the Hash", "lateral-movement"), 8.0)
    assert cost.metadata["heuristic"] is True
    assert cost.metadata["data_grounded"] is False
    assert cost.metadata["attack_technique"] == "T1550.002"


def test_identity_edge_types_registered():
    assert EdgeType.IDENTITY_INITIAL_ACCESS == "identity_initial_access"
    assert EdgeType.CREDENTIAL_MOVE == "credential_lateral_move"


def test_grounding_seam_flips_data_grounded_when_frequencies_given():
    # default: every credential cost is heuristic-flagged (no public frequency source bundled)
    from core.attack_graph import EdgeType as ET
    from core.node_types import NodeType
    g_default = _graph()
    move_edges = [e for e in g_default.edges.values()
                  if e.edge_type in (ET.IDENTITY_INITIAL_ACCESS, ET.CREDENTIAL_MOVE)]
    assert move_edges and all(e.cost_vector.metadata.get("data_grounded") is False for e in move_edges)

    # grounding seam: a (clearly SYNTHETIC, test-only) frequency map flips the touched edges to
    # data_grounded=True and uses the observed frequency as the success prior.
    freqs = {"T1566.001": 0.42, "T1550.002": 0.61}     # synthetic, not a real telemetry source
    g = build_identity_graph(create_ad_kill_chain_scenario(), logger=QUIET, frequencies=freqs)
    grounded = [e for e in g.edges.values()
                if e.cost_vector.metadata.get("attack_technique") in freqs]
    assert grounded and all(e.cost_vector.metadata.get("data_grounded") is True for e in grounded)
    assert all(e.cost_vector.metadata.get("grounding_source") == "observed technique frequency"
               for e in grounded)
    # untouched techniques stay heuristic
    untouched = [e for e in g.edges.values()
                 if e.cost_vector.metadata.get("attack_technique") == "T1003.006"]
    assert untouched and all(e.cost_vector.metadata.get("data_grounded") is False for e in untouched)
