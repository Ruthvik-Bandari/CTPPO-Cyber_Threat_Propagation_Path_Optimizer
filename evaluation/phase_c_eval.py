"""
Phase C evaluation: does multi-objective Pareto analysis pick a better fix than CVSS ranking?
============================================================================================

The core thesis test (docs/RESEARCH/04_ROADMAP_HANDOFF.md §C3): on multi-host attack graphs
with **data-grounded** edge costs (real EPSS/KEV via core/cost_model), compare which single
remediation each method recommends and how much it actually reduces attacker reachability.

Methods compared per network:
- **B1 — CVSS ranking:** fix the highest-CVSS vulnerability.
- **Proposed — Pareto-critical:** run NAMOA* to the crown jewel, fix the CVE that appears on
  the most Pareto-optimal paths (reuses evaluation/baseline_comparison primitives).
- **Oracle (upper bound):** the single vulnerability whose removal maximises reachability
  reduction (brute force). Lets us report what fraction of the achievable reduction each
  method recovers.

Reachability = the success probability of the most-likely-to-succeed Pareto path to the crown
jewel (cost vector's SUCCESS_PROBABILITY; 0 if the jewel becomes unreachable). A remediation's
"reduction" = baseline reachability − reachability after removing its chosen vulnerability.

Testbed: randomized synthetic multi-host networks (seeded → reproducible), each with a
guaranteed entry→crown chain plus random extra edges (some high-CVSS dead-ends, the realistic
case CVSS ranking gets wrong). Per-edge EPSS pulled from the real offline snapshot. This is a
synthetic-testbed result, not a claim about any specific production network — a container/VM
testbed and external datasets (C2) are the next step.

Run with: python3 evaluation/phase_c_eval.py
"""

from __future__ import annotations

import logging
import random
import sys
from pathlib import Path
from statistics import mean
from typing import Dict, List, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from algorithms.namoa_star import run_namoa_star
from core.threat_data import ThreatDataProvider
from evaluation.baseline_comparison import (
    HostSpec, VulnSpec, build_graph, cvss_ranking, pareto_critical_vulns,
)

logging.disable(logging.CRITICAL)  # silence NAMOA* per-search logs

N_NETWORKS = 300


def random_network(seed: int) -> Tuple[List[HostSpec], List[VulnSpec]]:
    """A reproducible random multi-host network with a guaranteed path to the crown jewel."""
    rng = random.Random(seed)
    k = rng.randint(2, 5)  # intermediate hosts
    hosts = [HostSpec("internet", is_entry=True)]
    hosts += [HostSpec(f"h{i}") for i in range(k)]
    hosts += [HostSpec("crown", is_goal=True)]
    ids = [h.id for h in hosts]

    vulns: List[VulnSpec] = []
    n = 0
    # Guaranteed chain internet -> h0 -> ... -> crown (moderate CVSS).
    chain = ["internet"] + [f"h{i}" for i in range(k)] + ["crown"]
    for a, b in zip(chain, chain[1:]):
        n += 1
        vulns.append(VulnSpec(f"CVE-{seed}-{n}", a, b,
                              cvss_score=round(rng.uniform(4.0, 9.0), 1),
                              has_exploit=rng.random() < 0.5))
    # Random extra edges, biased to HIGH CVSS — these include dead ends off the crown path.
    for _ in range(rng.randint(2, 6)):
        a, b = rng.sample(ids, 2)
        if a == "crown":  # crown is a sink
            continue
        n += 1
        vulns.append(VulnSpec(f"CVE-{seed}-{n}", a, b,
                              cvss_score=round(rng.uniform(6.0, 10.0), 1),
                              has_exploit=rng.random() < 0.4))
    return hosts, vulns


def reachability(hosts, vulns, provider) -> float:
    """Success probability of the best (most-likely) Pareto path to the crown jewel; 0 if none."""
    graph, _ = build_graph(hosts, vulns, provider)
    if not graph.goal_nodes or not graph.entry_points:
        return 0.0
    result = run_namoa_star(graph)
    best = 0.0
    for _ids, cost in result.pareto_paths:
        labels = list(getattr(cost, "labels", []))
        if "SUCCESS_PROBABILITY" in labels:
            best = max(best, float(cost.values[labels.index("SUCCESS_PROBABILITY")]))
    return best


def _without(vulns: List[VulnSpec], cve_id: str) -> List[VulnSpec]:
    return [v for v in vulns if v.cve_id != cve_id]


def evaluate_network(seed: int, provider) -> Dict:
    hosts, vulns = random_network(seed)
    p0 = reachability(hosts, vulns, provider)
    if p0 <= 0.0:
        return {}  # degenerate (no reachable crown) — excluded

    # B1: highest-CVSS vuln.
    cvss_top = cvss_ranking(vulns)[0].cve_id
    # Proposed: most path-critical CVE across the Pareto front.
    graph, edge_map = build_graph(hosts, vulns, provider)
    crit = pareto_critical_vulns(edge_map, run_namoa_star(graph).pareto_paths)
    pareto_top = crit.most_common(1)[0][0] if crit else cvss_top

    red_cvss = p0 - reachability(hosts, _without(vulns, cvss_top), provider)
    red_pareto = p0 - reachability(hosts, _without(vulns, pareto_top), provider)

    # Oracle: best single removal.
    red_oracle = max(p0 - reachability(hosts, _without(vulns, v.cve_id), provider) for v in vulns)

    return {
        "p0": p0,
        "diverge": cvss_top != pareto_top,
        "red_cvss": max(0.0, red_cvss),
        "red_pareto": max(0.0, red_pareto),
        "red_oracle": max(0.0, red_oracle),
    }


def run(n: int = N_NETWORKS) -> Dict:
    provider = ThreatDataProvider(offline=True)  # reproducible, no network
    rows = [r for r in (evaluate_network(s, provider) for s in range(n)) if r]
    m = len(rows)
    diverge = sum(r["diverge"] for r in rows)
    # Fraction of the oracle-achievable reduction each method recovers (when oracle > 0).
    rec = [(r["red_cvss"] / r["red_oracle"], r["red_pareto"] / r["red_oracle"])
           for r in rows if r["red_oracle"] > 1e-9]
    pareto_better = sum(1 for r in rows if r["red_pareto"] > r["red_cvss"] + 1e-9)
    pareto_ge = sum(1 for r in rows if r["red_pareto"] >= r["red_cvss"] - 1e-9)
    return {
        "n_evaluated": m,
        "mean_p0": mean(r["p0"] for r in rows),
        "divergence_rate": diverge / m,
        "mean_red_cvss": mean(r["red_cvss"] for r in rows),
        "mean_red_pareto": mean(r["red_pareto"] for r in rows),
        "mean_red_oracle": mean(r["red_oracle"] for r in rows),
        "recovery_cvss": mean(c for c, _ in rec) if rec else 0.0,
        "recovery_pareto": mean(p for _, p in rec) if rec else 0.0,
        "pareto_better_rate": pareto_better / m,
        "pareto_ge_rate": pareto_ge / m,
    }


if __name__ == "__main__":
    res = run()
    print(f"Phase C evaluation — {res['n_evaluated']} synthetic networks (seeded, real EPSS)\n")
    print(f"  mean baseline reachability (best-path success prob): {res['mean_p0']:.3f}")
    print(f"  top-fix divergence (CVSS-top != Pareto-top):         {res['divergence_rate']*100:.1f}%")
    print()
    print(f"  mean reachability reduction — CVSS fix:   {res['mean_red_cvss']:.3f}")
    print(f"  mean reachability reduction — Pareto fix: {res['mean_red_pareto']:.3f}")
    print(f"  mean reachability reduction — oracle:     {res['mean_red_oracle']:.3f}")
    print()
    print(f"  oracle reduction recovered — CVSS fix:    {res['recovery_cvss']*100:.1f}%")
    print(f"  oracle reduction recovered — Pareto fix:  {res['recovery_pareto']*100:.1f}%")
    print()
    print(f"  Pareto fix reduces reachability MORE than CVSS fix: {res['pareto_better_rate']*100:.1f}% of networks")
    print(f"  Pareto fix >= CVSS fix:                             {res['pareto_ge_rate']*100:.1f}% of networks")
