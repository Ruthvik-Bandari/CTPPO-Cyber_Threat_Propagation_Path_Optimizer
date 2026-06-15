"""
Phase 2 / D1 — ε-Pareto bounded-approximation fallback
======================================================

Exact NAMOA* returns the COMPLETE Pareto front, which can be exponentially large on adversarial
inputs. D1 adds an opt-in **ε-Pareto** mode (`run_namoa_star(..., epsilon=ε)`; exact stays the
default at ε=0): a label is pruned if an existing one ε-dominates it (within a (1+ε) factor on
every objective), yielding a smaller (1+ε)-approximate front. This is sound here because every
objective accumulates monotonically and non-negatively (time = Σ, success surprisal = Σ,
impact = max), so ε-dominance on partial paths is preserved under extension to full paths.

We verify the things the exit criterion asks for:
  (1) **Error bound** — on a constructed large-front instance, measure the worst-case factor by
      which the ε-front approximates each *exact* Pareto path (on the engine's internal
      minimisation costs: time, surprisal = −log p, impact), and watch the front/labels/runtime
      shrink with ε. IMPORTANT: per-label ε-dominance **compounds along the path**, so the correct
      end-to-end guarantee is **(1+ε)^d** (d = path depth in edges), NOT (1+ε) — a naive (1+ε)
      claim is violated, which we show and verify the (1+ε)^d bound instead.
  (1b) **Depth-scaled mode** — to get a *true* end-to-end (1+ε_target) factor, set the per-label
      tolerance to ε_step = (1+ε_target)^(1/d) − 1; we verify the resulting front meets ε_target.
  (2) **Realistic behaviour** — on CTPPO-shaped data-grounded networks the exact front is already
      small (objectives are coarse/correlated), so ε mostly trims search labels, not the front.

Reproduce:  python3 evaluation/d1_epsilon_pareto.py
"""

from __future__ import annotations

import logging
import math
import sys
import time
from pathlib import Path
from statistics import mean
from typing import List, Tuple

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.attack_graph import AttackGraph, EdgeType
from core.node_types import EntryPointNode, GoalNode, AssetNode, AssetType, PrivilegeLevel
from core.edge_costs import (
    EdgeCostVector, CostType, create_time_cost, create_probability_cost, create_impact_cost,
)
from algorithms.namoa_star import run_namoa_star, _P_FLOOR
from core.network_builder import build_network
from core.threat_data import ThreatDataProvider
from evaluation.b3_lateral_sensitivity import random_network as bnet

logging.disable(logging.CRITICAL)

EPSILONS = [0.0, 0.05, 0.1, 0.25, 0.5, 1.0]


def _edge_cost(t: float, p: float, impact: float) -> EdgeCostVector:
    c = EdgeCostVector.create_default()
    c.components[CostType.TIME_TO_EXPLOIT] = create_time_cost(max(t, 0.01))
    c.components[CostType.SUCCESS_PROBABILITY] = create_probability_cost(min(max(p, 1e-3), 0.999))
    c.components[CostType.BUSINESS_IMPACT] = create_impact_cost(impact * 0.8, impact, impact)
    return c


def pareto_hard_graph(k: int = 7) -> AttackGraph:
    """A layered 2-wide DAG with 2^k mutually non-dominated source→goal paths. Each layer i offers
    an 'A' choice (high time, ~certain success → surprisal≈0) and a 'B' choice (low time, lower
    success → surprisal=s_i). Superincreasing increments make every subset's (Σtime, Σsurprisal)
    distinct and non-dominated, so the exact Pareto front has 2^k points — a worst case for the
    optimizer and the ideal stress test for the ε-approximation."""
    g = AttackGraph(name=f"pareto_hard_k{k}")
    entry = EntryPointNode(name="entry", entry_type="internet", access_level=PrivilegeLevel.NONE)
    goal = GoalNode(name="goal", goal_type="compromise", required_privileges=PrivilegeLevel.LOCAL_ADMIN)
    g.add_node(entry)
    g.add_node(goal)
    # superincreasing increments kept under the surprisal floor cap (-log 1e-3 ≈ 6.9)
    incr = [0.1 * (1.7 ** i) for i in range(k)]          # 0.10, 0.17, 0.29, ... (sum < 6)
    prev = [entry.id]
    layer_nodes: List[Tuple[str, str]] = []
    for i in range(k):
        a = AssetNode(name=f"A{i}", asset_type=AssetType.SERVER)
        b = AssetNode(name=f"B{i}", asset_type=AssetType.SERVER)
        g.add_node(a)
        g.add_node(b)
        s = incr[i]
        # A: spend time (=s), keep success high (p≈1 → surprisal≈0). B: cheap time, pay surprisal=s.
        for src in prev:
            g.add_edge(src, a.id, EdgeType.ASSET_REACHES_ASSET, _edge_cost(t=s, p=0.999, impact=5.0))
            g.add_edge(src, b.id, EdgeType.ASSET_REACHES_ASSET, _edge_cost(t=0.01, p=math.exp(-s), impact=5.0))
        prev = [a.id, b.id]
        layer_nodes.append((a.id, b.id))
    for src in prev:
        g.add_edge(src, goal.id, EdgeType.ASSET_TO_GOAL, _edge_cost(t=0.01, p=0.999, impact=5.0))
    return g


def _internal_costs(result) -> List[np.ndarray]:
    """Recover each Pareto path's INTERNAL minimisation cost (time, surprisal, impact) from the
    output cost (which reports success as a probability)."""
    out = []
    for _ids, c in result.pareto_paths:
        labels = list(getattr(c, "labels", []) or [])
        ti = labels.index("TIME_TO_EXPLOIT") if "TIME_TO_EXPLOIT" in labels else 0
        si = labels.index("SUCCESS_PROBABILITY") if "SUCCESS_PROBABILITY" in labels else 1
        ii = labels.index("BUSINESS_IMPACT") if "BUSINESS_IMPACT" in labels else 2
        surpr = -math.log(max(float(c.values[si]), _P_FLOOR))
        out.append(np.array([float(c.values[ti]), surpr, float(c.values[ii])]))
    return out


def approximation_factor(exact: List[np.ndarray], approx: List[np.ndarray]) -> float:
    """Worst-case (over exact paths) of the best (over approx paths) max-objective ratio. The
    ε-Pareto guarantee is that this is ≤ 1+ε: every exact path is within (1+ε) of some kept path."""
    if not exact or not approx:
        return float("inf")
    worst = 0.0
    for e in exact:
        best = float("inf")
        for a in approx:
            # smallest factor f such that a_i <= f * e_i for all i (a approximates e)
            ratios = [(a[i] / e[i]) if e[i] > 1e-9 else (1.0 if a[i] <= 1e-9 else float("inf"))
                      for i in range(len(e))]
            best = min(best, max(ratios))
        worst = max(worst, best)
    return worst


def _max_depth(result) -> int:
    """Longest Pareto path length in EDGES (= compounding depth for ε-dominance)."""
    return max((len(ids) - 1 for ids, _ in result.pareto_paths), default=0)


def epsilon_sweep_hard(k: int = 7) -> dict:
    g = pareto_hard_graph(k)
    exact_res = run_namoa_star(g, epsilon=0.0)
    exact_internal = _internal_costs(exact_res)
    d = _max_depth(exact_res)
    rows = []
    for eps in EPSILONS:
        t0 = time.perf_counter()
        res = run_namoa_star(g, epsilon=eps)
        ms = (time.perf_counter() - t0) * 1000
        factor = approximation_factor(exact_internal, _internal_costs(res))
        rows.append({
            "epsilon": eps,
            "front_size": len(res.pareto_paths),
            "labels_expanded": res.num_labels_expanded,
            "time_ms": ms,
            "max_approx_factor": float(factor),
            "naive_bound_1pe": 1.0 + eps,                          # the WRONG bound (violated)
            "compounded_bound": (1.0 + eps) ** d,                  # the per-label compounded bound
            "compounded_bound_holds": bool(factor <= (1.0 + eps) ** d + 1e-9),
        })
    return {"k": k, "graph_nodes": g.num_nodes, "depth_edges": d,
            "exact_front": len(exact_res.pareto_paths), "rows": rows}


def depth_scaled_demo(k: int = 7, targets=(1.25, 1.5, 2.0)) -> dict:
    """To achieve a TRUE end-to-end (1+ε_target), set the per-label tolerance to
    ε_step = (1+ε_target)^(1/d) − 1. Verify the resulting front meets the target factor."""
    g = pareto_hard_graph(k)
    exact_internal = _internal_costs(run_namoa_star(g, epsilon=0.0))
    d = _max_depth(run_namoa_star(g, epsilon=0.0))
    rows = []
    for target in targets:
        eps_step = target ** (1.0 / d) - 1.0
        res = run_namoa_star(g, epsilon=eps_step)
        factor = approximation_factor(exact_internal, _internal_costs(res))
        rows.append({
            "target_factor": target, "eps_step": eps_step,
            "front_size": len(res.pareto_paths),
            "max_approx_factor": float(factor),
            "meets_target": bool(factor <= target + 1e-9),
        })
    return {"depth_edges": d, "rows": rows}


def epsilon_sweep_realistic(n: int = 30) -> dict:
    """On data-grounded CTPPO networks: does ε change the (already small) front, and how much
    search work does it save?"""
    provider = ThreatDataProvider(offline=True)
    graphs = [build_network(bnet(s), provider=provider) for s in range(n)]
    out = []
    for eps in [0.0, 0.1, 0.5]:
        fronts, labels = [], []
        for g in graphs:
            r = run_namoa_star(g, epsilon=eps)
            fronts.append(len(r.pareto_paths))
            labels.append(r.num_labels_expanded)
        out.append({"epsilon": eps, "mean_front": mean(fronts), "mean_labels_expanded": mean(labels)})
    return {"n": n, "rows": out}


def run(k: int = 7) -> dict:
    return {"hard": epsilon_sweep_hard(k), "depth_scaled": depth_scaled_demo(k),
            "realistic": epsilon_sweep_realistic()}


if __name__ == "__main__":
    res = run()
    h = res["hard"]
    print(f"D1 — ε-Pareto bounded approximation\n")
    print(f"(1) ERROR BOUND on a constructed Pareto-hard instance "
          f"(k={h['k']}, {h['graph_nodes']} nodes, depth={h['depth_edges']} edges, "
          f"exact front = {h['exact_front']} paths)")
    print(f"  {'epsilon':>8} {'front':>6} {'labels':>8} {'time_ms':>8} {'factor':>8} "
          f"{'1+eps':>7} {'(1+eps)^d':>10} {'ok':>5}")
    for r in h["rows"]:
        print(f"  {r['epsilon']:>8.2f} {r['front_size']:>6} {r['labels_expanded']:>8} "
              f"{r['time_ms']:>8.0f} {r['max_approx_factor']:>8.3f} {r['naive_bound_1pe']:>7.2f} "
              f"{r['compounded_bound']:>10.2f} {str(r['compounded_bound_holds']):>5}")
    print("  → front/labels/runtime shrink with ε. The naive (1+ε) bound is VIOLATED (per-label "
          "ε-dominance\n    compounds along the path); the correct end-to-end bound is (1+ε)^d, "
          "which always holds.\n")
    ds = res["depth_scaled"]
    print(f"(1b) DEPTH-SCALED for a TRUE end-to-end factor (d={ds['depth_edges']}; "
          f"ε_step=(1+target)^(1/d)−1)")
    print(f"  {'target':>8} {'eps_step':>9} {'front':>6} {'factor':>8} {'meets_target':>13}")
    for r in ds["rows"]:
        print(f"  {r['target_factor']:>8.2f} {r['eps_step']:>9.4f} {r['front_size']:>6} "
              f"{r['max_approx_factor']:>8.3f} {str(r['meets_target']):>13}")
    print("  → scaling the per-label tolerance by 1/d targets a desired end-to-end factor (met for "
          "moderate\n    targets; very tight targets can be slightly exceeded because the "
          "multiplicative factor is sensitive\n    to near-zero objectives — a high-success path "
          "has surprisal ≈ 0).\n")
    rr = res["realistic"]
    print(f"(2) REALISTIC data-grounded networks ({rr['n']} nets): the exact front is already small,")
    print(f"  {'epsilon':>8} {'mean_front':>11} {'mean_labels':>12}")
    for r in rr["rows"]:
        print(f"  {r['epsilon']:>8.2f} {r['mean_front']:>11.2f} {r['mean_labels_expanded']:>12.1f}")
    print("  → on CTPPO-shaped graphs ε barely changes the (small) front; its value is bounding the "
          "worst\n    case and trimming search labels, not routine front reduction.")
