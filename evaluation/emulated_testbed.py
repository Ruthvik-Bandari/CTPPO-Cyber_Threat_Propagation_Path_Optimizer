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
- **Goal coverage (recall)**: the front reaches every crown-jewel that is reachable at all.
  Expected 1.0.
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
    return {
        "name": name,
        "total_exploitable_paths": len(truth),
        "front_size": len(front),
        "reachable_goals": len(reachable_goals),
        "soundness": soundness,
        "goal_coverage": goal_coverage,
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
        "all_sound": all(abs(r["soundness"] - 1.0) < 1e-9 for r in rows),
        "all_goals_covered": all(abs(r["goal_coverage"] - 1.0) < 1e-9 for r in rows),
    }


if __name__ == "__main__":
    res = run()
    print(f"{'topology':<30} {'paths':>6} {'front':>6} {'sound':>6} {'goalcov':>8} {'compress':>9}")
    for r in res["rows"]:
        print(f"{r['name']:<30} {r['total_exploitable_paths']:>6} {r['front_size']:>6} "
              f"{r['soundness']:>6.2f} {r['goal_coverage']:>8.2f} {r['compression']:>8.2f}x")
    print(f"\nmean soundness     : {res['mean_soundness']:.3f}  (every returned path is a real exploitable path)")
    print(f"mean goal coverage : {res['mean_goal_coverage']:.3f}  (front reaches every reachable crown jewel)")
    print(f"all sound          : {res['all_sound']}")
    print(f"all goals covered  : {res['all_goals_covered']}")
