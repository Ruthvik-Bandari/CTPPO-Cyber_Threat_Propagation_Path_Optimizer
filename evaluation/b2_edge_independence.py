"""
Phase 1 / B2 — Edge-independence (correlation) sensitivity
==========================================================

Path success probability is computed as the PRODUCT of per-edge success probabilities
(`algorithms/namoa_star`: success accumulates as Σ−log pᵢ = −log ∏pᵢ). That assumes edge
successes are **independent**. Real attackers are correlated: shared skill, tooling, and CVE
families mean that succeeding on one hop makes succeeding on similar hops more likely. The
critique: this systematically misestimates multi-hop probability — at minimum, test sensitivity.

We model correlation with a single interpretable knob ρ ∈ [0,1] (a mixture of the independent
product and the fully-comonotonic "shared attacker capability" model):

    P_ρ(path) = (1 − ρ) · ∏ pᵢ  +  ρ · min pᵢ

- ρ = 0 → ∏ pᵢ  (the engine's current independence assumption)
- ρ = 1 → min pᵢ (fully correlated: a path is as likely as its single hardest step)

Since min pᵢ ≥ ∏ pᵢ, positive correlation RAISES multi-hop success probability — increasingly for
longer paths. We measure (a) the magnitude of that misestimation by hop count, and (b) whether it
changes the DECISION (the most-likely path / its ranking), which is what actually matters for
remediation. Edge probabilities stay data-grounded (real EPSS/KEV/CVSS).

Reproduce:  python3 evaluation/b2_edge_independence.py
"""

from __future__ import annotations

import logging
import random
import sys
from collections import defaultdict
from math import prod
from pathlib import Path
from statistics import mean
from typing import List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.threat_data import ThreatDataProvider
from evaluation.baseline_comparison import HostSpec, VulnSpec, build_graph
from evaluation.emulated_testbed import _enumerate_paths, _edge_vals
from evaluation.b3_lateral_sensitivity import _CVE_POOL

logging.disable(logging.CRITICAL)

RHO_GRID = [0.0, 0.25, 0.5, 0.75, 1.0]


def random_hostnet(seed: int) -> Tuple[List[HostSpec], List[VulnSpec]]:
    """A seeded host-level network (internet → intermediate hosts → crown jewel) as a random
    forward DAG, so multiple multi-hop paths of varying length compete. Each edge is one
    exploit with a real CVE (varied EPSS/KEV → varied per-edge success probability)."""
    rng = random.Random(seed)
    k = rng.randint(3, 5)
    ids = ["internet"] + [f"h{i}" for i in range(k)] + ["crown"]
    hosts = ([HostSpec("internet", is_entry=True)]
             + [HostSpec(f"h{i}") for i in range(k)]
             + [HostSpec("crown", is_goal=True)])
    vulns: List[VulnSpec] = []
    used = set()
    for i in range(len(ids)):
        for j in range(i + 1, len(ids)):
            if rng.random() < 0.5:
                cve, _vec, score = rng.choice(_CVE_POOL)
                vulns.append(VulnSpec(f"{cve}@{ids[i]}->{ids[j]}", ids[i], ids[j], score,
                                      has_exploit=rng.random() < 0.6))
                used.add((i, j))
    # Backbone: guarantee internet→h0→…→crown so the crown is reachable.
    for i in range(len(ids) - 1):
        if (i, i + 1) not in used:
            cve, _vec, score = rng.choice(_CVE_POOL)
            vulns.append(VulnSpec(f"{cve}@{ids[i]}->{ids[i+1]}", ids[i], ids[i + 1], score, True))
    return hosts, vulns


def _path_edge_probs(path, edge_map, provider, cache) -> List[float]:
    probs = []
    for s, t in zip(path, path[1:]):
        v = edge_map.get((s, t))
        if v is None:
            return []
        _t, p, _i = _edge_vals(v, provider, cache)
        probs.append(p)
    return probs


def _p_rho(probs: List[float], rho: float) -> float:
    return (1 - rho) * prod(probs) + rho * min(probs)


def evaluate_network(seed: int, provider) -> Optional[dict]:
    hosts, vulns = random_hostnet(seed)
    graph, edge_map = build_graph(hosts, vulns, provider)
    adj = defaultdict(list)
    for (s, t) in edge_map:
        adj[s].append(t)
    entries, goals = list(graph.entry_points), list(graph.goal_nodes)
    paths = set()
    for e in entries:
        for g in goals:
            paths.update(_enumerate_paths(adj, e, g))
    paths = [p for p in paths if len(p) >= 2]
    if not paths:
        return None
    cache: dict = {}
    rows = []  # (hops, prod, min) — path node-ids are UUIDs, so use VALUES only (reproducible)
    for p in paths:
        probs = _path_edge_probs(p, edge_map, provider, cache)
        if probs:
            rows.append((len(probs), prod(probs), min(probs)))
    if not rows:
        return None
    multi = len(rows) >= 2
    # Value-based orderings (uuid-free → reproducible): rank by ∏ (ρ=0) vs by min (ρ=1).
    idx = list(range(len(rows)))
    order_indep = sorted(idx, key=lambda i: (-rows[i][1], -rows[i][2], rows[i][0]))
    order_corr = sorted(idx, key=lambda i: (-rows[i][2], -rows[i][1], rows[i][0]))
    return {
        "seed": seed,
        "path_rows": rows,                                  # (hops, prod, min)
        "multi": multi,
        "top1_stable": (order_indep[0] == order_corr[0]) if multi else None,
        "order_stable": (order_indep == order_corr) if multi else None,
    }


def run(n: int = 80) -> dict:
    provider = ThreatDataProvider(offline=True)
    rows = [r for r in (evaluate_network(s, provider) for s in range(n)) if r is not None]
    if not rows:
        return {"n_networks": 0}
    # (a) misestimation magnitude: min/∏ ratio per path, overall and by hop count
    by_hops = defaultdict(list)
    all_ratios = []
    for r in rows:
        for hops, pr, mn in r["path_rows"]:
            if pr > 0:
                ratio = mn / pr
                all_ratios.append(ratio)
                by_hops[hops].append(ratio)
    # (b) decision stability among networks with >=2 competing paths
    multi = [r for r in rows if r["multi"]]
    top1 = mean(1.0 if r["top1_stable"] else 0.0 for r in multi) if multi else 1.0
    order = mean(1.0 if r["order_stable"] else 0.0 for r in multi) if multi else 1.0
    return {
        "n_networks": len(rows),
        "n_multi_path_networks": len(multi),
        "n_paths": len(all_ratios),
        "mean_misestimation_ratio": mean(sorted(all_ratios)) if all_ratios else 1.0,
        "misestimation_by_hops": {h: mean(sorted(v)) for h, v in sorted(by_hops.items())},
        "top1_path_stable_frac": top1,         # most-likely path unchanged ρ=0 → ρ=1
        "full_order_stable_frac": order,       # entire path ranking unchanged ρ=0 → ρ=1
    }


if __name__ == "__main__":
    res = run()
    if not res.get("n_networks"):
        print("No evaluable networks."); raise SystemExit(1)
    print(f"Edge-independence sensitivity over {res['n_networks']} seeded host-level networks "
          f"({res['n_paths']} paths)\n")
    print(f"  mean misestimation ratio (min/∏, ρ=1 vs ρ=0): {res['mean_misestimation_ratio']:.2f}x")
    print("  by hop count (longer paths → larger correlation effect):")
    for h, r in res["misestimation_by_hops"].items():
        print(f"    {h}-hop paths : {r:.2f}x")
    print(f"\n  most-likely path UNCHANGED ρ=0→ρ=1 : {res['top1_path_stable_frac']:.1%} "
          f"(of {res['n_multi_path_networks']} multi-path nets)")
    print(f"  full path ranking UNCHANGED ρ=0→ρ=1 : {res['full_order_stable_frac']:.1%}")
    print("\nInterpretation: independence (∏ pᵢ) systematically UNDER-estimates correlated-attacker "
          "multi-hop\nsuccess (ratio grows with hops). Whether that changes the remediation DECISION "
          "is the\npractical question — measured by the path-ranking stability above.")
