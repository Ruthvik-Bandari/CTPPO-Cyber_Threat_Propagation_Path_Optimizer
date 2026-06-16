"""Tests for Phase 5 / C2 — cloud IAM permission-lateral-movement modeling.

Offline, fast. Verifies the AWS privesc scenario builds, NAMOA* recovers a cloud IAM lateral
path to account administrator, cloud ATT&CK technique IDs ride the edges, the provider is
recorded, and the cloud-IAM costs are honestly flagged heuristic (not data-grounded).
"""

import logging

from core.cloud_iam_graph import (
    build_cloud_iam_graph, create_aws_privesc_scenario, _cloud_cost, Technique, EdgeType,
)
from core.node_types import NodeType, AssetType
from algorithms.namoa_star import run_namoa_star
from core.logging_system import ResearchLogger

logging.disable(logging.CRITICAL)
QUIET = ResearchLogger("test_cloud_iam", console_output=False)


def _graph():
    return build_cloud_iam_graph(create_aws_privesc_scenario(), logger=QUIET)


def _techniques_on(graph, path):
    return [graph.get_node(n).mitre_technique_id for n in path
            if graph.get_node(n) and graph.get_node(n).node_type == NodeType.EXPLOIT
            and graph.get_node(n).mitre_technique_id]


def test_scenario_builds_with_account_admin_goal():
    g = _graph()
    assert g.entry_points and g.goal_nodes
    goal = g.get_node(next(iter(g.goal_nodes)))
    assert goal.goal_type == "cloud_account_takeover"


def test_namoa_recovers_cloud_iam_path():
    g = _graph()
    result = run_namoa_star(g, logger=QUIET)
    assert len(result.pareto_paths) >= 1
    for path, _cost in result.pareto_paths:
        techs = _techniques_on(g, path)
        assert "T1078.004" in techs            # every path starts with cloud initial access
        assert any(t.startswith("T1") for t in techs)


def test_cloud_attack_techniques_present_on_exploit_nodes():
    g = _graph()
    exploits = [g.get_node(n) for n in g.nodes if g.get_node(n).node_type == NodeType.EXPLOIT]
    tagged = [e for e in exploits if e.mitre_technique_id]
    ids = {e.mitre_technique_id for e in tagged}
    assert {"T1078.004", "T1651", "T1552.005", "T1098.003", "T1548.005"} <= ids
    assert all(e.mitre_tactic for e in tagged)  # tactic also populated


def test_both_routes_to_admin_are_on_the_front():
    # the thorough IMDS→AssumeRole chain and the fast direct-elevation route are both non-dominated
    g = _graph()
    result = run_namoa_star(g, logger=QUIET)
    all_techs = [set(_techniques_on(g, p)) for p, _ in result.pareto_paths]
    assert any("T1098.003" in t for t in all_techs)   # IMDS → CI role → admin chain
    assert any("T1548.005" in t for t in all_techs)   # direct elevation route


def test_cloud_provider_recorded_on_principals():
    g = _graph()
    instances = [g.get_node(n) for n in g.nodes
                 if g.get_node(n).node_type == NodeType.ASSET
                 and g.get_node(n).metadata.get("cloud_provider")]
    assert instances and all(a.metadata["cloud_provider"] == "aws" for a in instances)


def test_cloud_costs_flagged_heuristic_not_grounded():
    cost = _cloud_cost(Technique("T1552.005", "IMDS", "credential-access"), 8.0)
    assert cost.metadata["heuristic"] is True
    assert cost.metadata["data_grounded"] is False
    assert cost.metadata["attack_technique"] == "T1552.005"


def test_cloud_edge_types_registered():
    assert EdgeType.CLOUD_INITIAL_ACCESS == "cloud_initial_access"
    assert EdgeType.CLOUD_IAM_MOVE == "cloud_iam_lateral_move"
