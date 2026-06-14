"""
Baseline Comparison: CVSS-only ranking vs. NAMOA* multi-objective Pareto paths
==============================================================================

Phase 4 groundwork (docs/RESEARCH/00_VISION.md). Tests the THESIS MECHANISM:

    Does multi-objective, data-grounded path analysis surface a different (and
    better-justified) remediation than ranking vulnerabilities by CVSS severity alone?

- **Baseline B1 — CVSS ranking:** "fix the highest-CVSS vulnerability first."
- **Proposed — NAMOA* Pareto:** find the Pareto-optimal attack paths to the crown-jewel
  asset (costs grounded in EPSS/KEV/CVSS via core/cost_model), then prioritise the
  vulnerabilities that actually lie on those paths.

`compare()` runs both and reports whether they diverge. The built-in scenario is an
*illustration*, not a generalisation claim — a general result needs the full datasets /
testbed (Phase 4). It shows a concrete network where the highest-CVSS bug is NOT on any
path to the crown jewel, so fixing it changes nothing, while the path-critical bugs have
lower CVSS.

Author: CTPPO
"""

from __future__ import annotations

import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.attack_graph import AttackGraph, EdgeType
from core.node_types import AssetNode, EntryPointNode, GoalNode, AssetType, PrivilegeLevel
from core.cost_model import build_edge_cost, EdgeCostInputs
from core.threat_data import ThreatDataProvider
from algorithms.namoa_star import run_namoa_star


@dataclass
class HostSpec:
    id: str
    is_entry: bool = False
    is_goal: bool = False          # crown-jewel / critical asset


@dataclass
class VulnSpec:
    cve_id: str
    source: str                    # host id
    target: str                    # host id
    cvss_score: float
    has_exploit: bool = False      # public exploit exists (KEV-like signal)


def cvss_ranking(vulns: List[VulnSpec]) -> List[VulnSpec]:
    """Baseline B1: vulnerabilities ranked by CVSS severity, highest first."""
    return sorted(vulns, key=lambda v: v.cvss_score, reverse=True)


def build_graph(hosts: List[HostSpec], vulns: List[VulnSpec],
                provider: ThreatDataProvider) -> Tuple[AttackGraph, Dict[Tuple[str, str], VulnSpec]]:
    """Build a canonical AttackGraph with data-grounded edge costs.

    Returns the graph and a map (src_node_id, tgt_node_id) -> VulnSpec so we can recover
    which vulnerability each path edge corresponds to.
    """
    graph = AttackGraph(name="eval_scenario")
    node_id: Dict[str, str] = {}
    for h in hosts:
        if h.is_entry:
            node = EntryPointNode(name=h.id, entry_type="network", access_level=PrivilegeLevel.NONE)
        elif h.is_goal:
            node = GoalNode(name=h.id, goal_type="critical_asset_compromise",
                            required_privileges=PrivilegeLevel.USER, value_to_attacker=9.0)
        else:
            node = AssetNode(name=h.id, asset_type=AssetType.SERVER, hostname=h.id,
                             criticality=5.0, network_zone="internal")
        graph.add_node(node)
        node_id[h.id] = node.id

    edge_map: Dict[Tuple[str, str], VulnSpec] = {}
    for v in vulns:
        if v.source not in node_id or v.target not in node_id:
            continue
        cost = build_edge_cost(EdgeCostInputs(
            cve_id=v.cve_id, cvss_score=v.cvss_score, is_kev=v.has_exploit,
            asset_criticality=8.0,
        ), provider=provider)
        s, t = node_id[v.source], node_id[v.target]
        graph.add_edge(s, t, EdgeType.ASSET_REACHES_ASSET, cost)
        edge_map[(s, t)] = v
    return graph, edge_map


def pareto_critical_vulns(edge_map: Dict[Tuple[str, str], VulnSpec],
                          pareto_paths) -> Counter:
    """Count how often each CVE appears as an edge across the Pareto-optimal paths."""
    counts: Counter = Counter()
    for path_ids, _cost in pareto_paths:
        for a, b in zip(path_ids, path_ids[1:]):
            v = edge_map.get((a, b))
            if v:
                counts[v.cve_id] += 1
    return counts


def compare(hosts: List[HostSpec], vulns: List[VulnSpec],
            provider: Optional[ThreatDataProvider] = None) -> Dict:
    """Run both approaches and report whether the recommended fix diverges."""
    provider = provider or ThreatDataProvider(offline=True)  # offline => reproducible
    ranked = cvss_ranking(vulns)
    cvss_top = ranked[0].cve_id if ranked else None

    graph, edge_map = build_graph(hosts, vulns, provider)
    result = run_namoa_star(graph)
    crit = pareto_critical_vulns(edge_map, result.pareto_paths)
    path_top = crit.most_common(1)[0][0] if crit else None

    return {
        "cvss_top": cvss_top,
        "cvss_order": [v.cve_id for v in ranked],
        "path_critical": path_top,
        "pareto_critical_counts": dict(crit),
        "num_pareto_paths": len(result.pareto_paths),
        "diverge": cvss_top is not None and path_top is not None and cvss_top != path_top,
    }


def illustrative_scenario() -> Tuple[List[HostSpec], List[VulnSpec]]:
    """A network where the highest-CVSS bug is a dead end, off any path to the crown jewel.

    internet --[CVE-DEADEND 9.8]--> web        (web has no route onward)
    internet --[CVE-ENTRY 7.0, exploited]--> app --[CVE-PIVOT 8.1, exploited]--> db(goal)
    """
    hosts = [
        HostSpec("internet", is_entry=True),
        HostSpec("web"),
        HostSpec("app"),
        HostSpec("db", is_goal=True),
    ]
    vulns = [
        VulnSpec("CVE-DEADEND", "internet", "web", cvss_score=9.8, has_exploit=False),
        VulnSpec("CVE-ENTRY", "internet", "app", cvss_score=7.0, has_exploit=True),
        VulnSpec("CVE-PIVOT", "app", "db", cvss_score=8.1, has_exploit=True),
    ]
    return hosts, vulns


if __name__ == "__main__":
    import logging
    logging.disable(logging.CRITICAL)  # quiet NAMOA* logs for the demo
    hosts, vulns = illustrative_scenario()
    out = compare(hosts, vulns)
    print("CVSS-only ranking (B1):      ", " > ".join(out["cvss_order"]))
    print("  -> would fix first:        ", out["cvss_top"])
    print(f"NAMOA* Pareto paths to crown jewel: {out['num_pareto_paths']}")
    print("  -> path-critical CVEs:     ", out["pareto_critical_counts"])
    print("  -> would fix first:        ", out["path_critical"])
    print()
    if out["diverge"]:
        print(f"DIVERGE: CVSS says fix {out['cvss_top']} (9.8), but it is a dead end. The real "
              f"path to the crown jewel runs through {out['path_critical']} — which CVSS ranks lower.")
    else:
        print("No divergence in this scenario.")
