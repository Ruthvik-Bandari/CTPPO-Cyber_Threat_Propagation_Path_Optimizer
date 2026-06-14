"""GNN -> cost-model bridge: refine edge success-probabilities with the GNN.

Runs ``ExploitabilityGNN`` over an attack graph's topology to predict per-node
exploitability, then rewrites each edge's SUCCESS_PROBABILITY by blending the
rule-based prior with the GNN score of the node the edge leads into. NAMOA* then
searches on the GNN-refined costs. This is the GNN arm of the rule-vs-GNN ablation
(docs/RESEARCH/02_COST_MODEL_SPEC.md §3); ``weight=0`` recovers the rule baseline.

The GNN is sized to the graph and, until trained on real attack-graph data
(roadmap A3), its scores are NOT yet meaningful — this module is the wiring, not
a claim that the GNN improves anything.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict, Optional

import torch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.edge_costs import CostType, create_probability_cost
from core.cost_model import refine_success_probability
from ml.gnn.model import ExploitabilityGNN
from ml.gnn.data import attack_graph_to_features


def gnn_exploitability_scores(graph, model: Optional[ExploitabilityGNN] = None,
                              checkpoint: Optional[str] = None) -> Dict[str, float]:
    """Per-node exploitability in [0, 1], keyed by node id.

    If ``model`` is None a fresh GNN is sized to the graph's node-type features
    (and optionally loaded from ``checkpoint``).
    """
    x, adj_norm, node_ids = attack_graph_to_features(graph)
    if model is None:
        model = ExploitabilityGNN(in_features=x.shape[1])
        if checkpoint:
            model.load_state_dict(torch.load(checkpoint, map_location="cpu"))
    model.eval()
    with torch.no_grad():
        scores = model(x, adj_norm)
    return {nid: float(scores[i]) for i, nid in enumerate(node_ids)}


def refine_graph_costs(graph, model: Optional[ExploitabilityGNN] = None,
                       checkpoint: Optional[str] = None,
                       weight: Optional[float] = None) -> int:
    """Refine each edge's SUCCESS_PROBABILITY with its target node's GNN score.

    Mutates ``graph`` in place; returns the number of edges refined. Each refined
    edge records (rule, gnn, blended) values under ``cost_vector.metadata`` so the
    refinement is auditable. Other objectives (time, impact) are left untouched.
    """
    scores = gnn_exploitability_scores(graph, model=model, checkpoint=checkpoint)
    refined = 0
    for edge in graph.edges.values():
        comp = edge.cost_vector.get_component(CostType.SUCCESS_PROBABILITY)
        gnn = scores.get(edge.target_id)
        if comp is None or gnn is None:
            continue
        p_rule = comp.expected_value()
        p_new = (refine_success_probability(p_rule, gnn) if weight is None
                 else refine_success_probability(p_rule, gnn, weight))
        edge.cost_vector.components[CostType.SUCCESS_PROBABILITY] = create_probability_cost(p_new)
        edge.cost_vector.metadata.setdefault("gnn_refined", {})["success_probability"] = {
            "p_rule": round(p_rule, 4),
            "gnn_exploitability": round(gnn, 4),
            "p_refined": round(p_new, 4),
        }
        refined += 1
    graph._nx_dirty = True
    return refined
