"""
Phase C2 — emulated multi-host testbed with ground-truth attack paths
=====================================================================

A live container/VM testbed is heavy infra; this is the runnable, no-Docker counterpart. We
hand-specify realistic multi-host networks (DMZ / app / data tiers, redundant paths, high-CVSS
dead ends) where the **ground-truth exploitable attack paths are known by construction** —
every entry→goal simple path over the exploit edges. We then validate the engine's NAMOA*
Pareto front against that ground truth, independently (no reimplementation of the engine's cost
accumulation):

- **Soundness (precision)**: every path the engine returns is a real exploitable entry→goal
  path. Expected 1.0 for a correct exact optimizer.
- **Goal coverage**: the front reaches every crown-jewel that is reachable at all. Expected 1.0.
- **Pareto recall (A3)**: of the *truly* non-dominated ground-truth paths (cost vectors
  re-computed independently here, not by the engine), what fraction does the front contain?
  This tests completeness — "does the front contain the path the attacker actually takes" —
  which soundness alone says nothing about.
- **Attacker recall (A3)**: is the single-objective optimum path (max success, min effort,
  min impact) present in the front — the route an attacker optimizing that objective would take?
- **Compression**: how many total exploitable paths the non-dominated front collapses to.

Reuses evaluation/baseline_comparison (HostSpec/VulnSpec/build_graph). Run:
  python3 evaluation/emulated_testbed.py
"""

from __future__ import annotations

import logging
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from algorithms.namoa_star import run_namoa_star
from core.cost_model import build_edge_cost, EdgeCostInputs
from core.edge_costs import CostType
from core.threat_data import ThreatDataProvider
from evaluation.baseline_comparison import HostSpec, VulnSpec, build_graph

logging.disable(logging.CRITICAL)


def _topologies() -> Dict[str, Tuple[List[HostSpec], List[VulnSpec]]]:
    """Named emulated networks (hosts + exploit edges). Goals are crown jewels."""
    return {
        "linear_chain": (
            [HostSpec("internet", is_entry=True), HostSpec("web"), HostSpec("app"), HostSpec("db", is_goal=True)],
            [VulnSpec("CVE-1", "internet", "web", 7.5, True),
             VulnSpec("CVE-2", "web", "app", 8.1, True),
             VulnSpec("CVE-3", "app", "db", 9.0, True)],
        ),
        "dual_path": (
            [HostSpec("internet", is_entry=True), HostSpec("web"), HostSpec("app"), HostSpec("db", is_goal=True)],
            [VulnSpec("CVE-1", "internet", "web", 7.0, True),
             VulnSpec("CVE-2", "internet", "app", 6.5, True),
             VulnSpec("CVE-3", "web", "db", 8.0, True),
             VulnSpec("CVE-4", "app", "db", 8.5, True)],
        ),
        "dmz_redundant_with_deadend": (
            [HostSpec("internet", is_entry=True), HostSpec("web1"), HostSpec("web2"),
             HostSpec("decoy"), HostSpec("app"), HostSpec("db", is_goal=True)],
            [VulnSpec("CVE-DEADEND", "internet", "decoy", 9.8, False),   # high CVSS, off-path
             VulnSpec("CVE-1", "internet", "web1", 7.0, True),
             VulnSpec("CVE-2", "internet", "web2", 6.8, False),
             VulnSpec("CVE-3", "web1", "app", 7.5, True),
             VulnSpec("CVE-4", "web2", "app", 7.2, True),
             VulnSpec("CVE-5", "app", "db", 8.9, True)],
        ),
        "diamond": (
            [HostSpec("internet", is_entry=True), HostSpec("a"), HostSpec("b"), HostSpec("c"),
             HostSpec("d", is_goal=True)],
            [VulnSpec("CVE-1", "internet", "a", 7.0, True),
             VulnSpec("CVE-2", "a", "b", 7.5, True),
             VulnSpec("CVE-3", "a", "c", 7.1, True),
             VulnSpec("CVE-4", "b", "d", 8.0, True),
             VulnSpec("CVE-5", "c", "d", 8.2, True)],
        ),
        "two_crown_jewels": (
            [HostSpec("internet", is_entry=True), HostSpec("dmz"),
             HostSpec("billing", is_goal=True), HostSpec("hr", is_goal=True)],
            [VulnSpec("CVE-1", "internet", "dmz", 7.4, True),
             VulnSpec("CVE-2", "dmz", "billing", 8.6, True),
             VulnSpec("CVE-3", "dmz", "hr", 8.0, True)],
        ),
    }


def _enumerate_paths(adj: Dict[str, List[str]], start: str, goal: str) -> List[Tuple[str, ...]]:
    out: List[Tuple[str, ...]] = []

    def dfs(node: str, path: List[str], seen: set) -> None:
        if node == goal:
            out.append(tuple(path))
            return
        for nxt in adj.get(node, []):
            if nxt not in seen:
                dfs(nxt, path + [nxt], seen | {nxt})

    dfs(start, [start], {start})
    return out


# --- independent cost re-computation (external check; mirrors the engine's objective senses) -
# minimize TIME (sum), MAXIMIZE SUCCESS (product of edge probs), minimize IMPACT (max along path).

def _edge_vals(v: VulnSpec, provider, cache: dict):
    if v.cve_id not in cache:
        cv = build_edge_cost(EdgeCostInputs(
            cve_id=v.cve_id, cvss_score=v.cvss_score, is_kev=v.has_exploit, asset_criticality=8.0,
        ), provider=provider)
        ev = cv.expected_values()
        cache[v.cve_id] = (ev[CostType.TIME_TO_EXPLOIT], ev[CostType.SUCCESS_PROBABILITY],
                           ev[CostType.BUSINESS_IMPACT])
    return cache[v.cve_id]


def _path_cost(path, edge_map, provider, cache):
    """(time=Σ, success=Π p, impact=max along path), accumulated independently of the engine."""
    time, succ, impact = 0.0, 1.0, 0.0
    for s, t in zip(path, path[1:]):
        v = edge_map.get((s, t))
        if v is None:
            return None
        et, ep, ei = _edge_vals(v, provider, cache)
        time += et
        succ *= ep
        impact = max(impact, ei)
    return (time, succ, impact)


def _dominates(a, b) -> bool:
    """a dominates b: no worse on any objective, strictly better on one
    (time lower=better, success higher=better, impact lower=better)."""
    no_worse = a[0] <= b[0] and a[1] >= b[1] and a[2] <= b[2]
    strictly = a[0] < b[0] or a[1] > b[1] or a[2] < b[2]
    return no_worse and strictly


def _true_nondominated(paths, costs) -> set:
    """Globally non-dominated ground-truth paths (across ALL goals — matches the engine, which
    returns one global Pareto front, so a globally-dominated goal's best path is excluded)."""
    nd = set()
    for i, pi in enumerate(paths):
        if costs[i] is None:
            continue
        if not any(j != i and costs[j] is not None and _dominates(costs[j], costs[i])
                   for j in range(len(paths))):
            nd.add(pi)
    return nd


def evaluate(name: str, hosts: List[HostSpec], vulns: List[VulnSpec], provider) -> dict:
    graph, edge_map = build_graph(hosts, vulns, provider)
    entries = list(graph.entry_points)
    goals = list(graph.goal_nodes)

    adj: Dict[str, List[str]] = defaultdict(list)
    for (s, t) in edge_map:
        adj[s].append(t)

    # Ground truth: all exploitable entry->goal simple paths (independent of the engine).
    truth = set()
    reachable_goals = set()
    for e in entries:
        for g in goals:
            paths = _enumerate_paths(adj, e, g)
            if paths:
                reachable_goals.add(g)
            truth.update(paths)

    result = run_namoa_star(graph)
    front = {tuple(pids) for pids, _ in result.pareto_paths}
    front_goals = {p[-1] for p in front}

    sound = sum(1 for p in front if p in truth)
    soundness = sound / len(front) if front else 1.0
    goal_coverage = (len(front_goals & reachable_goals) / len(reachable_goals)) if reachable_goals else 1.0

    # --- RECALL (A3): does the front CONTAIN the paths an attacker would actually take? ---
    cache: dict = {}
    truth_list = list(truth)
    costs = [_path_cost(p, edge_map, provider, cache) for p in truth_list]
    true_nd = _true_nondominated(truth_list, costs)
    # completeness recall: fraction of the truly non-dominated paths the engine returns
    pareto_recall = (len([p for p in true_nd if p in front]) / len(true_nd)) if true_nd else 1.0
    # attacker-optimum recall: for each objective, does the front contain a path achieving the
    # optimal value? Tie-aware — if several paths tie on an objective, any one in the front
    # counts (an attacker optimizing that objective could take any of them).
    valid = [(p, c) for p, c in zip(truth_list, costs) if c is not None]
    if valid:
        def _opt_in_front(k: int, maximize: bool) -> bool:
            vals = [c[k] for _, c in valid]
            best = max(vals) if maximize else min(vals)
            return any(p in front for p, c in valid if abs(c[k] - best) <= 1e-9)
        hits = [_opt_in_front(0, False),   # min time (least effort)
                _opt_in_front(1, True),    # max success probability
                _opt_in_front(2, False)]   # min impact (stealth)
        attacker_recall = sum(hits) / len(hits)
    else:
        attacker_recall = 1.0

    return {
        "name": name,
        "total_exploitable_paths": len(truth),
        "front_size": len(front),
        "reachable_goals": len(reachable_goals),
        "true_nondominated": len(true_nd),
        "soundness": soundness,
        "goal_coverage": goal_coverage,
        "pareto_recall": pareto_recall,
        "attacker_recall": attacker_recall,
        "compression": (len(truth) / len(front)) if front else 0.0,
    }


def run() -> dict:
    provider = ThreatDataProvider(offline=True)
    rows = [evaluate(name, h, v, provider) for name, (h, v) in _topologies().items()]
    n = len(rows)
    return {
        "rows": rows,
        "mean_soundness": sum(r["soundness"] for r in rows) / n,
        "mean_goal_coverage": sum(r["goal_coverage"] for r in rows) / n,
        "mean_pareto_recall": sum(r["pareto_recall"] for r in rows) / n,
        "mean_attacker_recall": sum(r["attacker_recall"] for r in rows) / n,
        "all_sound": all(abs(r["soundness"] - 1.0) < 1e-9 for r in rows),
        "all_goals_covered": all(abs(r["goal_coverage"] - 1.0) < 1e-9 for r in rows),
        "all_attacker_optima_present": all(abs(r["attacker_recall"] - 1.0) < 1e-9 for r in rows),
    }


if __name__ == "__main__":
    res = run()
    hdr = f"{'topology':<28} {'paths':>5} {'front':>5} {'tnd':>4} {'sound':>6} {'goalcov':>7} {'p-rec':>6} {'atk-rec':>7}"
    print(hdr)
    for r in res["rows"]:
        print(f"{r['name']:<28} {r['total_exploitable_paths']:>5} {r['front_size']:>5} "
              f"{r['true_nondominated']:>4} {r['soundness']:>6.2f} {r['goal_coverage']:>7.2f} "
              f"{r['pareto_recall']:>6.2f} {r['attacker_recall']:>7.2f}")
    print(f"\nmean soundness         : {res['mean_soundness']:.3f}  (precision: every returned path is real & exploitable)")
    print(f"mean goal coverage     : {res['mean_goal_coverage']:.3f}  (front reaches every reachable crown jewel)")
    print(f"mean Pareto recall     : {res['mean_pareto_recall']:.3f}  (front contains the truly non-dominated paths)")
    print(f"mean attacker recall   : {res['mean_attacker_recall']:.3f}  (front contains the per-objective optimum path)")
    print(f"all sound              : {res['all_sound']}")
    print(f"all goals covered      : {res['all_goals_covered']}")
    print(f"all attacker optima in front: {res['all_attacker_optima_present']}")
