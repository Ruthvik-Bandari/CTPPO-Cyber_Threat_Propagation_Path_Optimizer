"""Tests for GNN-refined edge costs feeding NAMOA* (roadmap A1).

Verifies the wiring: NAMOA* runs on GNN-refined success-probabilities, the
rule-vs-GNN ablation both produce Pareto fronts reaching the same goals, and the
blend is a correct, clamped convex combination. Does NOT assert the (untrained)
GNN improves anything — that is A3.
"""

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

logging.disable(logging.CRITICAL)

import torch  # noqa: E402

from core.logging_system import ResearchLogger  # noqa: E402
from core.attack_graph import create_sample_enterprise_graph  # noqa: E402
from core.edge_costs import CostType  # noqa: E402
from core.cost_model import refine_success_probability  # noqa: E402
from algorithms.namoa_star import run_namoa_star  # noqa: E402
from ml.gnn.model import ExploitabilityGNN  # noqa: E402
from ml.gnn.features import graph_features, FEATURE_DIM  # noqa: E402
from ml.gnn.refine import gnn_exploitability_scores, refine_graph_costs  # noqa: E402

_LOG = ResearchLogger("TestGNNCostA1", console_output=False)


def _success_probs(graph):
    return {eid: e.cost_vector.get_component(CostType.SUCCESS_PROBABILITY).expected_value()
            for eid, e in graph.edges.items()}


def test_blend_is_convex_and_clamped():
    assert refine_success_probability(0.8, 0.2, weight=0.0) == 0.8   # pure rule
    assert refine_success_probability(0.8, 0.2, weight=1.0) == 0.2   # pure GNN
    assert abs(refine_success_probability(0.8, 0.2, weight=0.5) - 0.5) < 1e-9
    assert refine_success_probability(2.0, 2.0, weight=0.5) == 1.0   # clamped to [0,1]


def test_scores_in_range_and_cover_all_nodes():
    graph = create_sample_enterprise_graph(logger=_LOG)
    scores = gnn_exploitability_scores(graph)
    assert set(scores) == set(graph.nodes)
    assert all(0.0 <= s <= 1.0 for s in scores.values())


def test_namoa_runs_on_gnn_refined_costs():
    graph = create_sample_enterprise_graph(logger=_LOG)

    # Rule-based arm
    front_rule = run_namoa_star(graph, logger=_LOG).pareto_paths
    assert front_rule, "rule-based NAMOA* should find Pareto-optimal paths"
    before = _success_probs(graph)

    # GNN arm on the same graph (fixed seed -> deterministic untrained model so the
    # test does not depend on whether an A3 checkpoint is present on disk)
    torch.manual_seed(0)
    model = ExploitabilityGNN(in_features=FEATURE_DIM)
    n_refined = refine_graph_costs(graph, model=model)
    assert n_refined == graph.num_edges, "every edge has a success-prob component to refine"

    after = _success_probs(graph)
    assert any(abs(after[eid] - before[eid]) > 1e-6 for eid in before), \
        "refinement should change at least one edge's success probability"

    front_gnn = run_namoa_star(graph, logger=_LOG).pareto_paths
    assert front_gnn, "GNN-refined NAMOA* should also find Pareto-optimal paths"

    # Comparable fronts: both reach the same goal nodes (same graph instance)
    goals_rule = {path[-1] for path, _ in front_rule}
    goals_gnn = {path[-1] for path, _ in front_gnn}
    assert goals_rule == goals_gnn


if __name__ == "__main__":
    test_blend_is_convex_and_clamped()
    test_scores_in_range_and_cover_all_nodes()
    test_namoa_runs_on_gnn_refined_costs()
    print("3 tests passed.")
