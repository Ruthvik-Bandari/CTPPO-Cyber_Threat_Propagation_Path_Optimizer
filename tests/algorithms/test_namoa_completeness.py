"""Regression guard for NAMOA* Pareto-front COMPLETENESS, incl. parallel edges.

Background: ``AttackGraph`` is a multigraph — two CVEs can connect the same host pair (parallel
edges). A prior bug indexed edges only as ``adjacency[source][target] = edge_id`` (one per pair),
so ``get_outgoing_edges`` (and thus NAMOA*) could not traverse a second parallel edge, silently
dropping every path that used it → an INCOMPLETE Pareto front. Fixed by parallel-safe out/in edge
lists in ``core.attack_graph``. These tests pin the fix by comparing NAMOA* against an independent
brute-force enumeration of all simple paths.
"""

import logging
import sys
from itertools import count
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
logging.disable(logging.CRITICAL)

from algorithms.namoa_star import run_namoa_star
from core.attack_graph import AttackGraph, EdgeType
from core.node_types import EntryPointNode, GoalNode, AssetNode, AssetType, PrivilegeLevel
from core.edge_costs import (
    EdgeCostVector, CostType, create_time_cost, create_probability_cost, create_impact_cost,
)


def _edge(t, p, impact):
    c = EdgeCostVector.create_default()
    c.components[CostType.TIME_TO_EXPLOIT] = create_time_cost(max(t, 0.01))
    c.components[CostType.SUCCESS_PROBABILITY] = create_probability_cost(min(max(p, 1e-3), 0.999))
    c.components[CostType.BUSINESS_IMPACT] = create_impact_cost(impact, impact, impact)
    return c


def _brute_front(graph):
    """Independent ground truth: enumerate all simple entry→goal paths over ALL edges (parallels
    included), aggregate (time=Σ, surprisal=Σ−log p, impact=max), return the non-dominated set."""
    entry = next(iter(graph.entry_points))
    goal = next(iter(graph.goal_nodes))
    adj = {n: [] for n in graph.nodes}
    for e in graph.edges.values():
        adj[e.source_id].append((e.target_id, e))

    def dfs(node, visited, acc):
        if node == goal:
            yield acc
            return
        for tgt, e in adj[node]:
            if tgt in visited:
                continue
            ev = e.cost_vector.expected_values()
            yield from dfs(tgt, visited | {tgt}, acc + [(ev[CostType.TIME_TO_EXPLOIT],
                          ev[CostType.SUCCESS_PROBABILITY], ev[CostType.BUSINESS_IMPACT])])

    costs = set()
    for path in dfs(entry, {entry}, []):
        t = round(sum(e[0] for e in path), 4)
        s = round(float(np.prod([e[1] for e in path])), 6)      # cumulative success = ∏ p
        im = round(max((e[2] for e in path), default=0.0), 4)
        costs.add((t, s, im))

    def dom(a, b):       # a dominates b: time min, success MAX, impact min
        return (a[0] <= b[0] and a[1] >= b[1] and a[2] <= b[2]) and (
            a[0] < b[0] or a[1] > b[1] or a[2] < b[2])
    return {c for c in costs if not any(dom(o, c) for o in costs if o != c)}


def _namoa_front(graph):
    out = set()
    for _ids, cv in run_namoa_star(graph).pareto_paths:
        lab = list(cv.labels)
        out.add((round(float(cv.values[lab.index("TIME_TO_EXPLOIT")]), 4),
                 round(float(cv.values[lab.index("SUCCESS_PROBABILITY")]), 6),
                 round(float(cv.values[lab.index("BUSINESS_IMPACT")]), 4)))
    return out


def _parallel_edge_graph():
    """The minimal repro of the bug: two parallel edges h0→h1 with different impact, plus a direct
    entry→h1 route, so the true front has two incomparable paths (one via the low-impact parallel
    edge). The buggy single-edge index dropped the parallel edge and returned only one path."""
    g = AttackGraph(name="parallel_repro")
    ids = count()
    entry = EntryPointNode(name="entry", entry_type="net", access_level=PrivilegeLevel.NONE)
    h0 = AssetNode(name="h0", asset_type=AssetType.SERVER)
    h1 = AssetNode(name="h1", asset_type=AssetType.SERVER)
    goal = GoalNode(name="goal", goal_type="x", required_privileges=PrivilegeLevel.USER)
    for n in (entry, h0, h1, goal):
        g.add_node(n)
    g.add_edge(entry.id, h0.id, EdgeType.ASSET_REACHES_ASSET, _edge(10, 0.05, 5.0))
    g.add_edge(entry.id, h1.id, EdgeType.ASSET_REACHES_ASSET, _edge(10, 0.05, 6.1))   # direct
    # parallel h0->h1 edges (two CVEs): one low-impact (key), one high-impact
    g.add_edge(h0.id, h1.id, EdgeType.ASSET_REACHES_ASSET, _edge(5, 0.6, 5.6))
    g.add_edge(h0.id, h1.id, EdgeType.ASSET_REACHES_ASSET, _edge(5, 0.6, 6.3))
    g.add_edge(h1.id, goal.id, EdgeType.ASSET_REACHES_ASSET, _edge(10, 0.05, 4.8))
    return g


def test_parallel_edges_are_traversable():
    g = _parallel_edge_graph()
    # both parallel h0->h1 edges must be returned by get_outgoing_edges (the fix)
    h0 = next(n for n in g.nodes if g.nodes[n].name == "h0")
    h1 = next(n for n in g.nodes if g.nodes[n].name == "h1")
    h0_to_h1 = [e for e in g.get_outgoing_edges(h0) if e.target_id == h1]
    assert len(h0_to_h1) == 2, "parallel edges must both be traversable"


def test_namoa_front_complete_on_parallel_graph():
    g = _parallel_edge_graph()
    assert _namoa_front(g) == _brute_front(g)        # exact == complete true front


def test_namoa_complete_on_seeded_phase_c_graphs():
    """NAMOA* front must equal the brute-force Pareto front on data-grounded random graphs that
    DO contain parallel edges (the case the bug hit)."""
    from core.threat_data import ThreatDataProvider
    from evaluation.phase_c_eval import random_network
    from evaluation.baseline_comparison import build_graph
    provider = ThreatDataProvider(offline=True)
    checked = mismatches = 0
    for seed in range(40):
        hosts, vulns = random_network(seed)
        g, _ = build_graph(hosts, vulns, provider)
        if not g.goal_nodes or not g.entry_points:
            continue
        bf = _brute_front(g)
        if not bf:
            continue
        checked += 1
        if _namoa_front(g) != bf:
            mismatches += 1
    assert checked >= 20
    assert mismatches == 0, f"NAMOA* incomplete on {mismatches}/{checked} graphs"


def test_remove_parallel_edge_keeps_other_traversable():
    g = _parallel_edge_graph()
    h0 = next(n for n in g.nodes if g.nodes[n].name == "h0")
    h1 = next(n for n in g.nodes if g.nodes[n].name == "h1")
    one = g.get_outgoing_edges(h0)[0].id
    g.remove_edge(one)
    remaining = [e for e in g.get_outgoing_edges(h0) if e.target_id == h1]
    assert len(remaining) >= 1                       # the other parallel edge survives
    assert g.adjacency[h0].get(h1) in g.edges        # representative repointed, still valid


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"PASS  {fn.__name__}")
    print(f"\n{len(fns)} tests passed.")
