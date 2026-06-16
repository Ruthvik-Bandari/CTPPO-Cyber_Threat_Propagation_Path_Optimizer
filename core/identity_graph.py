"""
Identity / Credential / Active-Directory attack-graph builder (Phase 5, C1)
===========================================================================

CTPPO's CVE-centric model (``core/network_builder``) captures *vulnerability*-driven lateral
movement. The biggest scope gap (critique C1) is **identity / credential** movement — the way
real intrusions actually pivot through a Windows/AD estate: phish a user, dump credentials,
pass-the-hash to the next host, escalate to Domain Admin via DCSync/Kerberoasting. None of that
is a CVE.

This builds the **same canonical** ``core.attack_graph.AttackGraph`` (so it plugs straight into
NAMOA* and the rest of the engine), but the transitions are **ATT&CK techniques** between hosts
rather than CVE exploits. Each edge carries its **MITRE ATT&CK technique ID** (on both the
``ExploitNode`` and the edge metadata) so a recovered path reads as a kill chain.

**Honesty (read this).** Unlike the CVE edges (EPSS/KEV-grounded), credential-technique costs
are **heuristic** — there is no per-technique exploit-probability feed. The success/time numbers
below are documented priors (a calibration target), flagged ``heuristic=True`` and
``data_grounded=False`` in every edge's metadata, exactly like the lateral-movement prior (B3).
The contribution is the *modeling capability* + ATT&CK provenance, not a data-grounded
probability for credential attacks.

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

# Identity/credential edge relations (added to the canonical EdgeType string constants).
EdgeType.IDENTITY_INITIAL_ACCESS = "identity_initial_access"
EdgeType.CREDENTIAL_MOVE = "credential_lateral_move"


@dataclass
class Technique:
    """One ATT&CK technique used as an attacker transition. ``success``/``time`` are HEURISTIC
    priors (no per-technique data feed) — flagged as such in edge metadata."""
    technique_id: str          # e.g. "T1550.002"
    name: str                  # e.g. "Pass the Hash"
    tactic: str                # e.g. "lateral-movement"
    success: float = 0.7       # heuristic P(success) in [0,1]
    time: float = 3.0          # heuristic relative time (lower = faster)
    detection: float = 0.5     # heuristic detection difficulty (higher = stealthier)


@dataclass
class IdentityHost:
    host_id: str
    name: str = ""
    asset_type: AssetType = AssetType.WORKSTATION
    network_zone: str = "internal"
    criticality: float = 5.0
    internet_facing: bool = False      # attacker can land here via initial access (e.g. phishing)
    is_goal: bool = False              # crown jewel (e.g. the Domain Controller)


@dataclass
class IdentityMove:
    """An attacker transition: reach ``dst_host`` from ``src_host`` (or from the attacker, when
    ``src_host`` is None = initial access) by performing ``technique``."""
    dst_host: str
    technique: Technique
    src_host: Optional[str] = None     # None => initial access from the internet attacker


@dataclass
class IdentityScenario:
    name: str
    hosts: List[IdentityHost] = field(default_factory=list)
    moves: List[IdentityMove] = field(default_factory=list)


def _identity_cost(tech: Technique, dst_criticality: float,
                   grounded_success: Optional[float] = None) -> EdgeCostVector:
    """Cost vector for a credential/identity technique.

    By default the success prior is the technique's heuristic ``success`` and the edge is flagged
    ``heuristic=True``/``data_grounded=False``. **Grounding seam:** if ``grounded_success`` is given
    (an observed technique frequency from detection telemetry / red-team data), it replaces the
    prior and the edge is flagged ``data_grounded=True``. No public frequency source is bundled, so
    the default is unchanged — see ``C1_GROUNDING_NOTE.md``."""
    cost = EdgeCostVector.create_default()
    cost.components[CostType.TIME_TO_EXPLOIT] = create_time_cost(max(tech.time, 0.01))
    grounded = grounded_success is not None
    cost.components[CostType.SUCCESS_PROBABILITY] = create_probability_cost(
        grounded_success if grounded else tech.success)
    impact = dst_criticality
    cost.components[CostType.BUSINESS_IMPACT] = create_impact_cost(
        impact * 0.7, impact, min(10.0, impact * 1.2))
    cost.metadata = {
        "attack_technique": tech.technique_id,
        "technique_name": tech.name,
        "tactic": tech.tactic,
        "detection_difficulty": tech.detection,
        "heuristic": not grounded,
        "data_grounded": grounded,
        "grounding_source": "observed technique frequency" if grounded else None,
        "note": ("credential/identity technique success grounded in observed frequency"
                 if grounded else
                 "credential/identity technique prior (calibration target) — not EPSS/CVE-grounded"),
    }
    return cost


def build_identity_graph(
    scenario: IdentityScenario,
    logger: Optional[ResearchLogger] = None,
    frequencies: Optional[Dict[str, float]] = None,
) -> AttackGraph:
    """Build the canonical AttackGraph for an identity/credential (AD) attack scenario.

    Each move becomes ``src_asset --(technique ExploitNode)--> dst_asset`` (or
    ``entry --> dst_asset`` for initial access). The ExploitNode carries the ATT&CK technique
    id/tactic; the move edge carries it in metadata too. Plugs into ``run_namoa_star``.

    ``frequencies`` (optional): a ``{ATT&CK technique id -> observed success frequency}`` map from
    detection-telemetry / red-team data. When provided, a move's success prior is replaced by the
    observed frequency and its edge is flagged ``data_grounded=True``. Default ``None`` keeps every
    credential cost heuristic-flagged (no public source bundled — see ``C1_GROUNDING_NOTE.md``).
    """
    frequencies = frequencies or {}
    logger = logger or get_default_logger()
    graph = AttackGraph(name=scenario.name, logger=logger)

    entry = EntryPointNode(name="External Attacker", entry_type="phishing",
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
                name=f"Domain compromise via {h.name or h.host_id}",
                goal_type="domain_dominance", target_assets=[asset.id],
                required_privileges=PrivilegeLevel.DOMAIN_ADMIN, value_to_attacker=h.criticality)
            graph.add_node(goal)
            graph.add_edge(asset.id, goal.id, EdgeType.ASSET_TO_GOAL)

    crit_of = {h.host_id: h.criticality for h in scenario.hosts}
    for mv in scenario.moves:
        if mv.dst_host not in asset_of:
            logger.warning("GRAPH", f"identity move references unknown host {mv.dst_host}")
            continue
        tech = mv.technique
        exploit = ExploitNode(
            name=f"{tech.technique_id} {tech.name}"[:50],
            mitre_technique_id=tech.technique_id, mitre_tactic=tech.tactic,
            reliability=tech.success, detection_difficulty=tech.detection,
            required_privileges=PrivilegeLevel.USER,
            gained_privileges=PrivilegeLevel.DOMAIN_ADMIN
            if crit_of.get(mv.dst_host, 0) >= 9 else PrivilegeLevel.LOCAL_ADMIN)
        graph.add_node(exploit)
        grounded_p = frequencies.get(tech.technique_id)
        cost = _identity_cost(tech, crit_of.get(mv.dst_host, 5.0), grounded_success=grounded_p)
        meta = {"attack_technique": tech.technique_id, "tactic": tech.tactic,
                "heuristic": grounded_p is None}

        if mv.src_host is None:                       # initial access from the attacker
            graph.add_edge(entry.id, exploit.id, EdgeType.IDENTITY_INITIAL_ACCESS, cost, metadata=meta)
            graph.add_edge(exploit.id, asset_of[mv.dst_host].id, EdgeType.ENTRY_TO_ASSET,
                           _identity_cost(Technique("", "reach", tech.tactic, 0.99, 0.1), 1.0))
        else:
            if mv.src_host not in asset_of:
                logger.warning("GRAPH", f"identity move from unknown host {mv.src_host}")
                continue
            graph.add_edge(asset_of[mv.src_host].id, exploit.id, EdgeType.CREDENTIAL_MOVE, cost, metadata=meta)
            graph.add_edge(exploit.id, asset_of[mv.dst_host].id, EdgeType.ASSET_REACHES_ASSET,
                           _identity_cost(Technique("", "reach", tech.tactic, 0.99, 0.1), crit_of.get(mv.dst_host, 5.0)))

    logger.info("GRAPH", f"Built identity/AD scenario '{scenario.name}'",
                {"hosts": len(scenario.hosts), "nodes": graph.num_nodes, "edges": graph.num_edges,
                 "goals": len(graph.goal_nodes)})
    return graph


def create_ad_kill_chain_scenario() -> IdentityScenario:
    """The canonical AD intrusion kill chain — recognizable to any red/blue teamer:

        Internet --phish(T1566.001)--> WS01 (workstation)
        WS01 --LSASS dump + Pass-the-Hash(T1003.001 / T1550.002)--> FILE01 (file server)
        FILE01 --Kerberoast a service acct(T1558.003)--> APP01 (app/SQL server)
        APP01 --DCSync(T1003.006)--> DC01 (Domain Controller, GOAL = Domain Admin)

    Plus a noisier alternate (RDP with a stolen password, T1021.001) so the front has a real
    choice and NAMOA* must pick the lower-cost credential chain.
    """
    hosts = [
        IdentityHost("ws01", "Workstation (phished user)", AssetType.WORKSTATION, "user", 4.0,
                     internet_facing=True),
        IdentityHost("file01", "File Server", AssetType.FILE_SERVER, "internal", 7.0),
        IdentityHost("app01", "App/SQL Server", AssetType.DATABASE, "internal", 8.0),
        IdentityHost("dc01", "Domain Controller", AssetType.DOMAIN_CONTROLLER, "critical", 10.0,
                     is_goal=True),
    ]
    moves = [
        IdentityMove("ws01", Technique("T1566.001", "Spearphishing Attachment", "initial-access",
                                       success=0.6, time=2.0, detection=0.4)),
        IdentityMove("file01", Technique("T1550.002", "Pass the Hash (after T1003.001 LSASS dump)",
                                         "lateral-movement", success=0.80, time=2.5, detection=0.6),
                     src_host="ws01"),
        # Thorough credential route: higher success but slower (Kerberoast → DCSync).
        IdentityMove("app01", Technique("T1558.003", "Kerberoasting", "credential-access",
                                        success=0.85, time=3.0, detection=0.7), src_host="file01"),
        IdentityMove("dc01", Technique("T1003.006", "DCSync", "credential-access",
                                       success=0.85, time=3.0, detection=0.5), src_host="app01"),
        # Fast but louder alternate: RDP straight to the DC with a cracked password.
        IdentityMove("dc01", Technique("T1021.001", "Remote Desktop Protocol", "lateral-movement",
                                       success=0.55, time=4.0, detection=0.2), src_host="file01"),
    ]
    return IdentityScenario("AD-KillChain", hosts=hosts, moves=moves)


if __name__ == "__main__":
    import logging
    logging.disable(logging.CRITICAL)
    from algorithms.namoa_star import run_namoa_star
    from core.node_types import NodeType

    graph = build_identity_graph(create_ad_kill_chain_scenario(),
                                 logger=ResearchLogger("identity", console_output=False))
    result = run_namoa_star(graph, logger=ResearchLogger("identity", console_output=False))
    print(f"AD scenario: {graph.num_nodes} nodes, {graph.num_edges} edges, "
          f"{len(result.pareto_paths)} Pareto path(s)")
    for i, (path, cost) in enumerate(result.pareto_paths, 1):
        techs = [graph.get_node(n).mitre_technique_id for n in path
                 if graph.get_node(n) and graph.get_node(n).node_type == NodeType.EXPLOIT
                 and graph.get_node(n).mitre_technique_id]
        print(f"  {i}. techniques: {' -> '.join(techs)}  "
              f"[time={cost.values[0]:.1f} success={cost.values[1]:.3f} impact={cost.values[2]:.1f}]")
