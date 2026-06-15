"""
Phase 1 / B1 — EPSS as a marginal vs a conditional
==================================================

EPSS predicts a **population base rate**: P(a CVE is exploited *somewhere* in the wild in 30 days).
The engine uses it as P(this attacker exploits this edge). But what you arguably want is a
**conditional**: P(exploit used | the attacker is already adjacent and targeting your crown jewel).
A motivated, adjacent attacker is plausibly more likely to use an available exploit than the
population rate — especially for **KEV** CVEs (known-exploited, already in attacker toolkits).

We model the conditional as a per-edge power transform of the success probability,
`p_cond = p ** γ` (γ ∈ (0,1]; γ=1 = EPSS as-is; γ<1 raises p toward 1), with a KEV-dependent γ so
known-exploited edges can be conditioned more strongly than the rest.

Two questions:
  1. **Does the marginal→conditional change affect the remediation RANKING, or only magnitude?**
     Analytic note: a *uniform* γ gives path prob (∏pᵢ)^γ — a monotone transform of the product —
     so it leaves the Pareto ranking **invariant** (magnitude only). We confirm this empirically,
     then test the case that can actually reorder: **KEV-dependent (non-uniform) conditioning.**

Edge probabilities stay data-grounded (real EPSS/KEV/CVSS). Reuses the B2 host-level generator.

Reproduce:  python3 evaluation/b1_epss_conditional.py
"""

from __future__ import annotations

import logging
import sys
from collections import defaultdict
from math import log, exp
from pathlib import Path
from statistics import mean
from typing import List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.threat_data import ThreatDataProvider
from evaluation.baseline_comparison import build_graph
from evaluation.emulated_testbed import _enumerate_paths, _edge_vals
from evaluation.b2_edge_independence import random_hostnet

logging.disable(logging.CRITICAL)

# (label, γ_kev, γ_non) — conditioning strength for KEV vs non-KEV edges. γ<1 raises p toward 1.
REGIMES: List[Tuple[str, float, float]] = [
    ("marginal (EPSS as-is)", 1.0, 1.0),    # baseline
    ("uniform_mild",          0.7, 0.7),    # uniform → ranking-invariant (analytic)
    ("uniform_strong",        0.4, 0.4),    # uniform → ranking-invariant
    ("kev_weighted",          0.3, 0.9),    # NON-uniform: KEV conditioned much more
    ("kev_strong",            0.15, 1.0),   # NON-uniform: only KEV conditioned
]


def _cond(p: float, kev: bool, g_kev: float, g_non: float) -> float:
    return p ** (g_kev if kev else g_non)


def _path_edges(path, edge_map, provider, cache) -> List[Tuple[float, bool]]:
    out = []
    for s, t in zip(path, path[1:]):
        v = edge_map.get((s, t))
        if v is None:
            return []
        _t, p, _i = _edge_vals(v, provider, cache)
        out.append((p, bool(v.has_exploit)))
    return out


def _ranking(rows, g_kev, g_non):
    """Value-based (uuid-free, deterministic) ranking of path indices by conditioned path
    log-probability Σ γ·log pᵢ. Log space avoids underflow AND makes UNIFORM conditioning exactly
    order-preserving (γ·Σlog p is a monotone scalar multiple), so the analytic invariance is exact."""
    logp = [sum((g_kev if kev else g_non) * log(max(p, 1e-12)) for p, kev in edges)
            for _hops, edges in rows]
    key = lambda i: (-logp[i], rows[i][0], tuple(sorted(p for p, _ in rows[i][1])))
    return sorted(range(len(rows)), key=key), logp


def evaluate_network(seed: int, provider) -> Optional[dict]:
    hosts, vulns = random_hostnet(seed)
    graph, edge_map = build_graph(hosts, vulns, provider)
    adj = defaultdict(list)
    for (s, t) in edge_map:
        adj[s].append(t)
    paths = set()
    for e in graph.entry_points:
        for g in graph.goal_nodes:
            paths.update(_enumerate_paths(adj, e, g))
    cache: dict = {}
    rows = []
    for p in paths:
        edges = _path_edges(p, edge_map, provider, cache)
        if edges:
            rows.append((len(edges), edges))
    if len(rows) < 2:
        return None                              # need competition for ranking questions
    base_rank, base_logp = _ranking(rows, 1.0, 1.0)
    base_top_log = base_logp[base_rank[0]]
    out = {"seed": seed, "regimes": {}}
    for label, gk, gn in REGIMES:
        rank, logp = _ranking(rows, gk, gn)
        out["regimes"][label] = {
            "top1_stable": rank[0] == base_rank[0],
            "order_stable": rank == base_rank,
            "reach_lift": exp(logp[rank[0]] - base_top_log),
        }
    return out


def run(n: int = 80) -> dict:
    provider = ThreatDataProvider(offline=True)
    rows = [r for r in (evaluate_network(s, provider) for s in range(n)) if r is not None]
    if not rows:
        return {"n_networks": 0}
    agg = {}
    for label, _gk, _gn in REGIMES:
        cells = [r["regimes"][label] for r in rows]
        agg[label] = {
            "top1_stable_frac": mean(1.0 if c["top1_stable"] else 0.0 for c in cells),
            "order_stable_frac": mean(1.0 if c["order_stable"] else 0.0 for c in cells),
            "mean_reach_lift": mean(sorted(c["reach_lift"] for c in cells)),
        }
    return {"n_networks": len(rows), "regimes": agg}


if __name__ == "__main__":
    res = run()
    if not res.get("n_networks"):
        print("No evaluable networks."); raise SystemExit(1)
    print(f"EPSS marginal→conditional sensitivity over {res['n_networks']} multi-path networks\n")
    print(f"  {'regime':<24} {'top1 stable':>12} {'order stable':>13} {'reach lift':>11}")
    for label, _gk, _gn in REGIMES:
        a = res["regimes"][label]
        print(f"  {label:<24} {a['top1_stable_frac']:>11.1%} {a['order_stable_frac']:>12.1%} "
              f"{a['mean_reach_lift']:>10.2f}x")
    print("\nInterpretation: UNIFORM conditioning (uniform_*) leaves the ranking 100% intact — it is a "
          "monotone\npower transform of the path product, so marginal-vs-conditional is magnitude-only "
          "there. KEV-dependent\n(non-uniform) conditioning is what can reorder the recommended fix — "
          "the size of that effect is the\nreal answer to 'does treating EPSS as a conditional change "
          "the decision?'")
