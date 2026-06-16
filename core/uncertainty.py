"""
Per-path reachability uncertainty bands (Phase 6)
=================================================

The Phase-1 cost-model studies (B1, B2) reached one clear recommendation: **report multi-hop
reachability as a range, not a point estimate.** Two sources of uncertainty drive it:

- **B2 — edge correlation.** The engine's success objective multiplies per-edge probabilities
  (∏ pᵢ), which assumes the edges are *independent*. B2 measured that independence
  **under-estimates** correlated multi-hop success by 4×–1440× (it grows with path length), with the
  perfectly-correlated (comonotone) case bounded by **min pᵢ** — a path's weakest edge. So the true
  reachability under unknown correlation lies in **[∏ pᵢ, min pᵢ]**: the independence product is the
  lower bound (what the engine reports as its point value), the weakest-link probability is the upper
  bound.
- **B1 — EPSS conditioning** raises magnitude 1.7×–3.5× but is order-invariant; it widens the band's
  scale, it does not reorder paths.

This module turns a recovered NAMOA* path into that **reachability band**, so the product can show a
range (and which edge is the band-defining bottleneck) instead of a single, falsely-precise number.
It changes **no** engine decision — it annotates the already-computed front (the B1–B8 lesson: bands
move magnitude, not the prioritization decision).

Author: CTPPO
"""

from __future__ import annotations

import sys
from math import prod
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.attack_graph import AttackGraph
from core.edge_costs import CostType


def edge_success_probs(graph: AttackGraph, path_ids: List[str]) -> List[float]:
    """Per-edge success probability along a path (representative edge per node pair)."""
    probs = []
    for u, v in zip(path_ids, path_ids[1:]):
        edge_id = graph.adjacency.get(u, {}).get(v)
        if edge_id is None:
            continue
        comp = graph.edges[edge_id].cost_vector.get_component(CostType.SUCCESS_PROBABILITY)
        if comp is not None:
            probs.append(float(comp.expected_value()))
    return probs


def reachability_band(probs: List[float]) -> Dict[str, float]:
    """Band for a path's reachability under unknown edge correlation.

    ``independence`` = ∏ pᵢ (the engine's point value, lower bound), ``comonotone`` = min pᵢ
    (perfectly-correlated upper bound, the weakest edge). ``width_factor`` = upper / lower.
    """
    if not probs:
        return {"independence": 0.0, "comonotone": 0.0, "width_factor": 1.0, "n_edges": 0}
    indep = float(prod(probs))
    como = float(min(probs))
    return {
        "independence": round(indep, 6),
        "comonotone": round(como, 6),
        "width_factor": round(como / indep, 3) if indep > 0 else float("inf"),
        "n_edges": len(probs),
    }


def path_reachability_band(graph: AttackGraph, path_ids: List[str]) -> Dict[str, float]:
    """Reachability band [∏ pᵢ, min pᵢ] for one recovered path."""
    return reachability_band(edge_success_probs(graph, path_ids))


def front_reachability_band(graph: AttackGraph, result) -> Optional[Dict[str, float]]:
    """The most-reachable path's band across a Pareto front (max independence estimate)."""
    bands = [path_reachability_band(graph, ids) for ids, _c in result.pareto_paths]
    return max(bands, key=lambda b: b["independence"], default=None)


if __name__ == "__main__":
    import logging
    logging.disable(logging.CRITICAL)
    from algorithms.namoa_star import run_namoa_star
    from core.logging_system import ResearchLogger
    from core.network_builder import create_sample_multihost_network

    QUIET = ResearchLogger("uncertainty", console_output=False)
    graph = create_sample_multihost_network(logger=QUIET)
    result = run_namoa_star(graph, logger=QUIET)
    print(f"{len(result.pareto_paths)} Pareto path(s)")
    for i, (ids, _c) in enumerate(result.pareto_paths, 1):
        b = path_reachability_band(graph, ids)
        print(f"  path {i}: reachability in [{b['independence']:.4f}, {b['comonotone']:.4f}]  "
              f"(×{b['width_factor']} wide, {b['n_edges']} edges)")
