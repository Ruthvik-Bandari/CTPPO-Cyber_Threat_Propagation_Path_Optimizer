"""
E2 — Does the GNN refiner move the ENGINE-level decision? (Phase 5)
==================================================================

A3 already measured the GNN at the **per-node** level: on CTPPO's own synthetic graphs it only
*matches* EPSS ranking (improves calibration RMSE, no AUC lift), and on the real PIGNN AD dataset
message-passing adds **+0.07 ROC-AUC** over a topology-blind MLP (`A3_GNN_ABLATION.md`,
`A3_PIGNN_VALIDATION.md`). But the project's working principle is that *the decisive test is the
multi-objective NAMOA* path decision, not per-node AUC*.

So this asks the **engine-level** question directly: when the trained A3 GNN
(`models/exploitability_gnn.pt`) is wired into the engine via `refine_graph_costs`, does it change
the **Pareto-critical top fix** (the prioritization decision) vs the rule baseline, and how far does
it move each edge's success probability? If it barely moves the decision, the GNN is **exploratory**
at the engine level and correctly stays default-off; the one real lift is the topology task (PIGNN).

Reuses the real-CVE network generator (`baseline_study.network`, real EPSS/KEV) and the canonical
`build_graph` / `pareto_critical_vulns` from the Phase-C harness. Executes the real checkpoint.

Author: CTPPO
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from statistics import mean
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from algorithms.namoa_star import run_namoa_star
from core.threat_data import ThreatDataProvider
from core.logging_system import ResearchLogger
from evaluation.baseline_comparison import build_graph, pareto_critical_vulns
from evaluation.baseline_study import network

logging.disable(logging.CRITICAL)
QUIET = ResearchLogger("e2_gnn", console_output=False)

N_NETWORKS = 60


def _top_fix(graph, edge_map):
    crit = pareto_critical_vulns(edge_map, run_namoa_star(graph, logger=QUIET).pareto_paths)
    return crit.most_common(1)[0][0] if crit else None


def _refined_deltas(graph) -> List[float]:
    """|p_refined - p_rule| for every edge the GNN actually refined (recorded in metadata)."""
    out = []
    for edge in graph.edges.values():
        rec = (edge.cost_vector.metadata or {}).get("gnn_refined", {}).get("success_probability")
        if rec:
            out.append(abs(rec["p_refined"] - rec["p_rule"]))
    return out


def run(n: int = N_NETWORKS, provider: ThreatDataProvider = None) -> Dict:
    from ml.gnn.refine import refine_graph_costs, DEFAULT_CHECKPOINT
    provider = provider or ThreatDataProvider()

    changed = 0
    evaluated = 0
    all_deltas: List[float] = []
    front_rule: List[int] = []
    front_gnn: List[int] = []

    for seed in range(n):
        hosts, vulns = network(seed, "neutral", provider)

        g_rule, em_rule = build_graph(hosts, vulns, provider)
        if not g_rule.goal_nodes or not g_rule.entry_points:
            continue
        rule_top = _top_fix(g_rule, em_rule)
        front_rule.append(len(run_namoa_star(g_rule, logger=QUIET).pareto_paths))

        g_gnn, em_gnn = build_graph(hosts, vulns, provider)
        refine_graph_costs(g_gnn, provider=provider)        # mutate in place, real checkpoint
        gnn_top = _top_fix(g_gnn, em_gnn)
        front_gnn.append(len(run_namoa_star(g_gnn, logger=QUIET).pareto_paths))
        all_deltas += _refined_deltas(g_gnn)

        evaluated += 1
        if rule_top != gnn_top:
            changed += 1

    return {
        "checkpoint": str(DEFAULT_CHECKPOINT),
        "checkpoint_exists": DEFAULT_CHECKPOINT.exists(),
        "n_evaluated": evaluated,
        "decision_change_rate": changed / evaluated if evaluated else 0.0,
        "decisions_changed": changed,
        "mean_edge_success_delta": mean(all_deltas) if all_deltas else 0.0,
        "max_edge_success_delta": max(all_deltas) if all_deltas else 0.0,
        "mean_front_size_rule": mean(front_rule) if front_rule else 0.0,
        "mean_front_size_gnn": mean(front_gnn) if front_gnn else 0.0,
    }


if __name__ == "__main__":
    res = run()
    print(f"E2 — GNN engine-level effect ({res['n_evaluated']} real-CVE nets, neutral)\n")
    print(f"  checkpoint: {res['checkpoint']} (exists={res['checkpoint_exists']})")
    print(f"  Pareto top-fix CHANGED by GNN refinement: {res['decisions_changed']}/"
          f"{res['n_evaluated']} = {res['decision_change_rate']*100:.1f}%")
    print(f"  per-edge success-prob movement: mean {res['mean_edge_success_delta']:.3f}, "
          f"max {res['max_edge_success_delta']:.3f}")
    print(f"  mean Pareto front size: rule {res['mean_front_size_rule']:.2f} -> "
          f"gnn {res['mean_front_size_gnn']:.2f}")
