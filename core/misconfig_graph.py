"""
Misconfiguration attack-graph builder (Phase 5, C3)
===================================================

C1 added identity/credential movement; C2 added cloud IAM. C3 closes the **non-CVE weakness**
gap: a huge fraction of real intrusions never touch a CVE at all — they walk in through
**misconfigurations**: default/weak credentials, services exposed with no authentication,
world-readable shares / overly permissive ACLs, secrets left in config or backups. These are
**CWE-class weaknesses, not CVEs**, so EPSS/KEV don't score them — but they are often the
*easiest* edges in the graph (a default password, once present, works with near-certainty).

This builds the **same canonical** ``core.attack_graph.AttackGraph`` (so it plugs straight into
NAMOA* and the rest of the engine), but the transitions are **misconfigurations** instead of CVE
exploits. Each edge carries its **CWE id** (and an ATT&CK technique id where one applies — e.g.
default creds → T1078 Valid Accounts) so a recovered path reads as a weakness chain.

**Honesty (read this).** Like the C1/C2 priors, misconfiguration exploit costs are **heuristic** —
there is no per-misconfig exploit-probability feed. They are documented priors (a calibration
target), flagged ``heuristic=True`` and ``data_grounded=False`` in every edge's metadata. The
honest nuance specific to misconfigs: their success priors are deliberately **high** (default
creds ≈ 0.95, exposed-no-auth ≈ 0.85) because the hard question is *presence*, not exploitability
— once the weakness is present, exploiting it is usually trivial. The grounded part is the
*structure* (which weakness gates which hop, recoverable from a scanner's config findings); the
contribution is the modeling capability + CWE provenance, not a data-grounded probability.

Author: CTPPO
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.attack_graph import AttackGraph, EdgeType
from core.node_types import (
    AssetNode, ExploitNode, EntryPointNode, GoalNode, AssetType, PrivilegeLevel,
)
from core.edge_costs import (
    EdgeCostVector, CostType,
    create_time_cost, create_probability_cost, create_impact_cost,
)
from core.logging_system import ResearchLogger, get_default_logger

# Misconfiguration edge relations (added to the canonical EdgeType string constants).
EdgeType.MISCONFIG_INITIAL_ACCESS = "misconfig_initial_access"
EdgeType.MISCONFIG_MOVE = "misconfig_lateral_move"


@dataclass
class Misconfiguration:
    """One misconfiguration / weakness used as an attacker transition. ``success``/``time`` are
    HEURISTIC priors (no per-misconfig data feed) — flagged as such in edge metadata. Success
    priors are deliberately high: the gating question for a misconfig is *presence*, not
    exploitability."""
    weakness_id: str           # stable slug, e.g. "default-creds"
    name: str                  # e.g. "Default administrator credentials"
    cwe_id: str = ""           # e.g. "CWE-798"
    mitre_technique_id: str = ""   # optional ATT&CK id where one applies (e.g. T1078)
    tactic: str = "initial-access"
    success: float = 0.85      # heuristic P(success) in [0,1] — high once present
    time: float = 2.0          # heuristic relative time (lower = faster)
    detection: float = 0.4     # heuristic detection difficulty (higher = stealthier)


@dataclass
class MisconfigHost:
    host_id: str
    name: str = ""
    asset_type: AssetType = AssetType.SERVER
    network_zone: str = "internal"
    criticality: float = 5.0
    internet_facing: bool = False      # attacker can land here via an exposed weakness
    is_goal: bool = False              # crown jewel


@dataclass
class MisconfigMove:
    """An attacker transition: reach ``dst_host`` from ``src_host`` (or from the attacker, when
    ``src_host`` is None = initial access) by exploiting ``weakness``."""
    dst_host: str
    weakness: Misconfiguration
    src_host: Optional[str] = None     # None => initial access from the internet attacker


@dataclass
class MisconfigScenario:
    name: str
    hosts: List[MisconfigHost] = field(default_factory=list)
    moves: List[MisconfigMove] = field(default_factory=list)


def _misconfig_cost(weakness: Misconfiguration, dst_criticality: float) -> EdgeCostVector:
    """Heuristic cost vector for a misconfiguration. NOT data-grounded (same discipline as the
    C1/C2 technique priors and the B3 lateral prior)."""
    cost = EdgeCostVector.create_default()
    cost.components[CostType.TIME_TO_EXPLOIT] = create_time_cost(max(weakness.time, 0.01))
    cost.components[CostType.SUCCESS_PROBABILITY] = create_probability_cost(weakness.success)
    impact = dst_criticality
    cost.components[CostType.BUSINESS_IMPACT] = create_impact_cost(
        impact * 0.7, impact, min(10.0, impact * 1.2))
    cost.metadata = {
        "weakness_id": weakness.weakness_id,
        "weakness_name": weakness.name,
        "cwe_id": weakness.cwe_id,
        "attack_technique": weakness.mitre_technique_id,
        "tactic": weakness.tactic,
        "detection_difficulty": weakness.detection,
        "heuristic": True,
        "data_grounded": False,
        "note": "misconfiguration prior (calibration target) — not a CVE/EPSS; success is high once present",
    }
    return cost


def build_misconfig_graph(
    scenario: MisconfigScenario,
    logger: Optional[ResearchLogger] = None,
) -> AttackGraph:
    """Build the canonical AttackGraph for a misconfiguration-driven attack scenario.

    Each move becomes ``src_asset --(weakness ExploitNode)--> dst_asset`` (or
    ``entry --> dst_asset`` for initial access). The ExploitNode carries the CWE id (in metadata)
    and the ATT&CK technique id where one applies; the move edge carries them too. Plugs into
    ``run_namoa_star``.
    """
    logger = logger or get_default_logger()
    graph = AttackGraph(name=scenario.name, logger=logger)

    entry = EntryPointNode(name="External Attacker", entry_type="exposed_misconfiguration",
                           access_level=PrivilegeLevel.NONE, detection_probability=0.2)
    graph.add_node(entry)

    asset_of: Dict[str, AssetNode] = {}
    for h in scenario.hosts:
        asset = AssetNode(
            name=h.name or h.host_id, asset_type=h.asset_type, hostname=h.host_id,
            criticality=h.criticality, network_zone=h.network_zone)
        graph.add_node(asset)
        asset_of[h.host_id] = asset
        if h.is_goal:
            goal = GoalNode(
                name=f"Compromise via {h.name or h.host_id}",
                goal_type="data_exfiltration", target_assets=[asset.id],
                required_privileges=PrivilegeLevel.LOCAL_ADMIN, value_to_attacker=h.criticality)
            graph.add_node(goal)
            graph.add_edge(asset.id, goal.id, EdgeType.ASSET_TO_GOAL)

    crit_of = {h.host_id: h.criticality for h in scenario.hosts}
    for mv in scenario.moves:
        if mv.dst_host not in asset_of:
            logger.warning("GRAPH", f"misconfig move references unknown host {mv.dst_host}")
            continue
        wk = mv.weakness
        exploit = ExploitNode(
            name=f"{wk.cwe_id or wk.weakness_id} {wk.name}"[:50],
            mitre_technique_id=wk.mitre_technique_id or None, mitre_tactic=wk.tactic,
            reliability=wk.success, detection_difficulty=wk.detection,
            required_privileges=PrivilegeLevel.NONE,
            gained_privileges=PrivilegeLevel.LOCAL_ADMIN)
        exploit.metadata["cwe_id"] = wk.cwe_id
        graph.add_node(exploit)
        cost = _misconfig_cost(wk, crit_of.get(mv.dst_host, 5.0))
        meta = {"weakness_id": wk.weakness_id, "cwe_id": wk.cwe_id, "tactic": wk.tactic, "heuristic": True}

        if mv.src_host is None:                       # initial access from the attacker
            graph.add_edge(entry.id, exploit.id, EdgeType.MISCONFIG_INITIAL_ACCESS, cost, metadata=meta)
            graph.add_edge(exploit.id, asset_of[mv.dst_host].id, EdgeType.ENTRY_TO_ASSET,
                           _misconfig_cost(Misconfiguration("", "reach", "", "", wk.tactic, 0.99, 0.1), 1.0))
        else:
            if mv.src_host not in asset_of:
                logger.warning("GRAPH", f"misconfig move from unknown host {mv.src_host}")
                continue
            graph.add_edge(asset_of[mv.src_host].id, exploit.id, EdgeType.MISCONFIG_MOVE, cost, metadata=meta)
            graph.add_edge(exploit.id, asset_of[mv.dst_host].id, EdgeType.ASSET_REACHES_ASSET,
                           _misconfig_cost(Misconfiguration("", "reach", "", "", wk.tactic, 0.99, 0.1),
                                           crit_of.get(mv.dst_host, 5.0)))

    logger.info("GRAPH", f"Built misconfiguration scenario '{scenario.name}'",
                {"hosts": len(scenario.hosts), "nodes": graph.num_nodes, "edges": graph.num_edges,
                 "goals": len(graph.goal_nodes)})
    return graph


def create_misconfig_breach_scenario() -> MisconfigScenario:
    """A misconfiguration-only breach chain — no CVE anywhere, the way many real breaches happen:

        Internet --default admin creds on exposed panel (CWE-798)--> DMZ web host
        DMZ web --internal service exposed, no auth (CWE-306)--> app server
        app --world-readable backup share (CWE-732)--> backup server
        backup --DB password left in backup (CWE-522)--> database (GOAL)

    Plus a fast/loud alternate: straight from the app server to the database via a DB exposed
    with no authentication to the app tier (CWE-306) — fewer hops, lower success/louder — so the
    front has a real choice and NAMOA* keeps both routes.
    """
    hosts = [
        MisconfigHost("dmz_web", "DMZ web host (admin panel)", AssetType.WEB_APPLICATION, "dmz",
                      4.0, internet_facing=True),
        MisconfigHost("app", "App server", AssetType.SERVER, "internal", 6.0),
        MisconfigHost("backup", "Backup server", AssetType.FILE_SERVER, "internal", 7.0),
        MisconfigHost("db", "Database", AssetType.DATABASE, "critical", 10.0, is_goal=True),
    ]
    moves = [
        MisconfigMove("dmz_web", Misconfiguration(
            "default-creds", "Default administrator credentials", "CWE-798", "T1078",
            "initial-access", success=0.90, time=1.0, detection=0.3)),
        MisconfigMove("app", Misconfiguration(
            "exposed-no-auth", "Internal service exposed with no auth", "CWE-306", "T1190",
            "lateral-movement", success=0.85, time=2.0, detection=0.5), src_host="dmz_web"),
        # Thorough route: pivot through the backup server (high success, more hops).
        MisconfigMove("backup", Misconfiguration(
            "world-readable-share", "World-readable backup share", "CWE-732", "T1135",
            "collection", success=0.90, time=2.5, detection=0.6), src_host="app"),
        MisconfigMove("db", Misconfiguration(
            "secrets-in-backup", "DB password left in backup file", "CWE-522", "T1552.001",
            "credential-access", success=0.95, time=1.5, detection=0.5), src_host="backup"),
        # Fast/loud alternate: DB exposed with no auth to the app tier (fewer hops, lower success).
        MisconfigMove("db", Misconfiguration(
            "db-no-auth", "Database exposed with no authentication", "CWE-306", "T1190",
            "lateral-movement", success=0.70, time=3.0, detection=0.2), src_host="app"),
    ]
    return MisconfigScenario("Misconfig-Breach", hosts=hosts, moves=moves)


if __name__ == "__main__":
    import logging
    logging.disable(logging.CRITICAL)
    from algorithms.namoa_star import run_namoa_star
    from core.node_types import NodeType

    graph = build_misconfig_graph(create_misconfig_breach_scenario(),
                                  logger=ResearchLogger("misconfig", console_output=False))
    result = run_namoa_star(graph, logger=ResearchLogger("misconfig", console_output=False))
    print(f"Misconfig breach: {graph.num_nodes} nodes, {graph.num_edges} edges, "
          f"{len(result.pareto_paths)} Pareto path(s)")
    for i, (path, cost) in enumerate(result.pareto_paths, 1):
        cwes = [graph.get_node(n).metadata.get("cwe_id") for n in path
                if graph.get_node(n) and graph.get_node(n).node_type == NodeType.EXPLOIT
                and graph.get_node(n).metadata.get("cwe_id")]
        print(f"  {i}. weaknesses: {' -> '.join(cwes)}  "
              f"[time={cost.values[0]:.1f} success={cost.values[1]:.3f} impact={cost.values[2]:.1f}]")
