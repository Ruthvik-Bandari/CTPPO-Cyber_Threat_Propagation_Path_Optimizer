"""
Multi-Host Attack-Graph Builder
===============================

Builds a canonical ``AttackGraph`` for a *multi-host* network from a structured
topology spec — hosts, their vulnerabilities, and host-to-host reachability — so
NAMOA* can find attack paths that span lateral movement across hosts, not just the
single-site web template in ``scanners/website_analyzer.py``.

This is roadmap A5. It does NOT introduce a second graph/engine: it constructs the
one canonical ``core.attack_graph.AttackGraph`` and grounds the exploitation step of
each vulnerability in the real data cost model (``core.cost_model.build_edge_cost`` →
EPSS / CISA KEV / CVSS). The resulting graph plugs straight into ``run_namoa_star``
and ``ml.gnn.refine.refine_graph_costs`` (features are generic over the graph).

Graph shape per host (chained for lateral movement):

    EntryPoint --(entry)--> Asch_A --(has_vuln)--> Vuln_A --(enables)--> Exploit_A
        Exploit_A --(reaches: lateral)--> Asset_B  (for every B reachable from A)
        Asset_goal --(to_goal)--> Goal

So compromising host A (reaching its Exploit node) is what unlocks a pivot to any
host reachable from A. A goal host's asset connects directly to a Goal node —
controlling the crown-jewel host is the objective.

Honesty note: the vulnerability *exploitation* edges are data-grounded (EPSS/KEV/CVSS
via the cost model). The *lateral-movement* edges are a segmentation-aware heuristic
prior (same-zone pivots are easier than cross-zone), NOT empirical — the constants
below are calibration targets, flagged as such and recorded in each edge's metadata.

Author: CTPPO
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.attack_graph import AttackGraph, EdgeType
from core.node_types import (
    AssetNode, VulnerabilityNode, ExploitNode,
    EntryPointNode, GoalNode, AssetType, PrivilegeLevel,
)
from core.edge_costs import (
    EdgeCostVector, CostType,
    create_time_cost, create_probability_cost, create_impact_cost,
)
from core.cost_model import build_edge_cost, EdgeCostInputs
from core.logging_system import ResearchLogger, get_default_logger


# --- Lateral-movement heuristic priors (CALIBRATION TARGETS — not empirical) ---
# Segmentation makes cross-zone pivots harder/slower than same-zone ones. These are
# priors for the pivot step itself, kept on the same relative scales as the data
# cost model (time is relative-unitless, success is a probability). They are recorded
# in the edge metadata as heuristic so they are never mistaken for measured values.
_LATERAL_SUCCESS_SAME_ZONE = 0.80
_LATERAL_SUCCESS_CROSS_ZONE = 0.40
_LATERAL_TIME_SAME_ZONE = 2.0
_LATERAL_TIME_CROSS_ZONE = 5.0


@dataclass
class VulnSpec:
    """One vulnerability present on a host. EPSS/KEV are looked up from the threat
    provider by ``cve_id`` at build time; ``cvss_vector`` drives the CVSS sub-scores."""
    cve_id: Optional[str] = None
    name: str = ""
    cvss_vector: str = ""
    cvss_score: Optional[float] = None


@dataclass
class HostSpec:
    """A single host in the network."""
    host_id: str                                  # stable id used by ``reachability``
    name: str = ""
    asset_type: AssetType = AssetType.SERVER
    network_zone: str = "internal"
    criticality: float = 5.0                      # 0–10
    ip_address: str = ""
    vulnerabilities: List[VulnSpec] = field(default_factory=list)
    internet_facing: bool = False                 # attacker entry point reaches it
    is_goal: bool = False                         # crown jewel / objective


@dataclass
class NetworkSpec:
    """A multi-host network: hosts plus directed host-to-host reachability links.

    ``reachability`` is a list of ``(from_host_id, to_host_id)`` pairs meaning an
    attacker who has compromised ``from_host_id`` can pivot to ``to_host_id``.
    """
    name: str
    hosts: List[HostSpec] = field(default_factory=list)
    reachability: List[Tuple[str, str]] = field(default_factory=list)


def _entry_cost() -> EdgeCostVector:
    """Cost of an attacker reaching an internet-facing asset (cheap, high success)."""
    cost = EdgeCostVector.create_default()
    cost.components[CostType.TIME_TO_EXPLOIT] = create_time_cost(0.5, 0.1)
    cost.components[CostType.SUCCESS_PROBABILITY] = create_probability_cost(0.95)
    cost.components[CostType.BUSINESS_IMPACT] = create_impact_cost(0, 1, 2)
    return cost


def _discovery_cost() -> EdgeCostVector:
    """Cost of discovering a vulnerability on a reached asset (low, near-certain)."""
    cost = EdgeCostVector.create_default()
    cost.components[CostType.TIME_TO_EXPLOIT] = create_time_cost(1.0, 0.2)
    cost.components[CostType.SUCCESS_PROBABILITY] = create_probability_cost(0.9)
    cost.components[CostType.BUSINESS_IMPACT] = create_impact_cost(0, 0, 1)
    return cost


def _lateral_cost(same_zone: bool) -> EdgeCostVector:
    """Heuristic cost of pivoting from a compromised host to an adjacent one.

    Same-zone pivots are easier/faster than cross-zone (segmentation). Flagged as a
    heuristic prior in metadata — NOT data-grounded (see module note)."""
    cost = EdgeCostVector.create_default()
    t = _LATERAL_TIME_SAME_ZONE if same_zone else _LATERAL_TIME_CROSS_ZONE
    p = _LATERAL_SUCCESS_SAME_ZONE if same_zone else _LATERAL_SUCCESS_CROSS_ZONE
    cost.components[CostType.TIME_TO_EXPLOIT] = create_time_cost(t)
    cost.components[CostType.SUCCESS_PROBABILITY] = create_probability_cost(p)
    cost.components[CostType.BUSINESS_IMPACT] = create_impact_cost(0, 0, 1)
    cost.metadata = {
        "lateral_movement": True,
        "same_zone": same_zone,
        "heuristic": True,
        "note": "segmentation prior (calibration target) — not data-grounded",
    }
    return cost


def build_network(
    spec: NetworkSpec,
    provider=None,
    logger: Optional[ResearchLogger] = None,
) -> AttackGraph:
    """Build the canonical multi-host ``AttackGraph`` from ``spec``.

    Args:
        spec: the network topology (hosts, vulnerabilities, reachability).
        provider: optional ``ThreatDataProvider`` for EPSS/KEV lookups; passed to the
            data cost model. ``None`` => cost model falls back to CVSS-only (recorded).
        logger: research logger.

    Returns:
        An ``AttackGraph`` with entry points and goal nodes set, ready for
        ``run_namoa_star`` and ``refine_graph_costs``.
    """
    logger = logger or get_default_logger()
    graph = AttackGraph(name=spec.name, logger=logger)

    entry = EntryPointNode(
        name="Internet Attacker",
        entry_type="internet",
        access_level=PrivilegeLevel.NONE,
        detection_probability=0.1,
    )
    graph.add_node(entry)

    # Per-host asset / vulnerability / exploit nodes.
    asset_of: Dict[str, AssetNode] = {}
    exploits_of: Dict[str, List[ExploitNode]] = {}

    for host in spec.hosts:
        asset = AssetNode(
            name=host.name or host.host_id,
            asset_type=host.asset_type,
            ip_addresses=[host.ip_address] if host.ip_address else [],
            hostname=host.host_id,
            criticality=host.criticality,
            network_zone=host.network_zone,
        )
        graph.add_node(asset)
        asset_of[host.host_id] = asset
        exploits_of[host.host_id] = []

        if host.internet_facing:
            graph.add_edge(entry.id, asset.id, EdgeType.ENTRY_TO_ASSET, _entry_cost())

        for vspec in host.vulnerabilities:
            vuln = VulnerabilityNode(
                name=vspec.name or (vspec.cve_id or "vulnerability"),
                cve_id=vspec.cve_id,
                cvss_score=vspec.cvss_score if vspec.cvss_score is not None else 5.0,
                cvss_vector=vspec.cvss_vector,
            )
            graph.add_node(vuln)
            graph.add_edge(asset.id, vuln.id, EdgeType.ASSET_HAS_VULN, _discovery_cost())

            exploit = ExploitNode(
                name=f"Exploit: {vuln.name}"[:50],
                required_privileges=PrivilegeLevel.NONE,
                gained_privileges=PrivilegeLevel.LOCAL_ADMIN,
            )
            graph.add_node(exploit)
            exploit_cost = build_edge_cost(
                EdgeCostInputs(
                    cve_id=vspec.cve_id,
                    cvss_vector=vspec.cvss_vector,
                    cvss_score=vspec.cvss_score,
                    asset_criticality=host.criticality,
                ),
                provider=provider,
            )
            graph.add_edge(vuln.id, exploit.id, EdgeType.VULN_ENABLES_EXPLOIT, exploit_cost)
            exploits_of[host.host_id].append(exploit)

        if host.is_goal:
            goal = GoalNode(
                name=f"Compromise {host.name or host.host_id}",
                goal_type="host_compromise",
                target_assets=[asset.id],
                required_privileges=PrivilegeLevel.LOCAL_ADMIN,
                value_to_attacker=host.criticality,
            )
            graph.add_node(goal)
            graph.add_edge(asset.id, goal.id, EdgeType.ASSET_TO_GOAL)

    # Lateral movement: compromising a host (reaching one of its exploits) lets the
    # attacker pivot to any host reachable from it.
    zone_of = {h.host_id: h.network_zone for h in spec.hosts}
    lateral_edges = 0
    for from_id, to_id in spec.reachability:
        if from_id not in asset_of or to_id not in asset_of:
            logger.warning("GRAPH", f"reachability {from_id}->{to_id} references unknown host")
            continue
        same_zone = zone_of.get(from_id) == zone_of.get(to_id)
        for exploit in exploits_of.get(from_id, []):
            graph.add_edge(
                exploit.id, asset_of[to_id].id,
                EdgeType.ASSET_REACHES_ASSET, _lateral_cost(same_zone),
            )
            lateral_edges += 1

    logger.info(
        "GRAPH",
        f"Built multi-host network '{spec.name}'",
        {
            "hosts": len(spec.hosts),
            "nodes": graph.num_nodes,
            "edges": graph.num_edges,
            "lateral_edges": lateral_edges,
            "entry_points": len(graph.entry_points),
            "goals": len(graph.goal_nodes),
        },
    )
    return graph


def create_sample_multihost_network(
    provider=None,
    logger: Optional[ResearchLogger] = None,
) -> AttackGraph:
    """A small but realistic enterprise network for the ``analyze-network`` demo/tests.

    Internet -> DMZ web server -> internal app server -> critical-zone database (goal),
    with an internal workstation and file server providing alternate lateral paths.
    Vulnerabilities use real CVE ids + CVSS vectors so EPSS/KEV ground the cost model
    when a ``ThreatDataProvider`` is supplied.
    """
    LOG4SHELL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"   # CVE-2021-44228
    PROXYSHELL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # CVE-2021-34473
    SMBGHOST = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"    # CVE-2020-0796
    PRINTNIGHT = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"  # CVE-2021-34527

    spec = NetworkSpec(
        name="SampleMultiHostNetwork",
        hosts=[
            HostSpec(
                host_id="web01", name="WebServer (DMZ)",
                asset_type=AssetType.WEB_APPLICATION, network_zone="dmz",
                criticality=6.0, ip_address="10.0.1.10", internet_facing=True,
                vulnerabilities=[VulnSpec("CVE-2021-44228", "Log4Shell", LOG4SHELL, 10.0)],
            ),
            HostSpec(
                host_id="app01", name="AppServer",
                asset_type=AssetType.SERVER, network_zone="internal",
                criticality=7.0, ip_address="10.0.2.10",
                vulnerabilities=[VulnSpec("CVE-2021-34473", "ProxyShell", PROXYSHELL, 9.8)],
            ),
            HostSpec(
                host_id="ws01", name="Workstation",
                asset_type=AssetType.WORKSTATION, network_zone="internal",
                criticality=4.0, ip_address="10.0.2.50",
                vulnerabilities=[VulnSpec("CVE-2021-34527", "PrintNightmare", PRINTNIGHT, 8.8)],
            ),
            HostSpec(
                host_id="files01", name="FileServer",
                asset_type=AssetType.FILE_SERVER, network_zone="internal",
                criticality=8.0, ip_address="10.0.2.20",
                vulnerabilities=[VulnSpec("CVE-2020-0796", "SMBGhost", SMBGHOST, 10.0)],
            ),
            HostSpec(
                host_id="db01", name="DatabaseServer",
                asset_type=AssetType.DATABASE, network_zone="critical",
                criticality=10.0, ip_address="10.0.10.10", is_goal=True,
            ),
        ],
        reachability=[
            ("web01", "app01"),    # DMZ -> internal (cross-zone)
            ("ws01", "app01"),     # internal -> internal (same-zone)
            ("app01", "files01"),  # internal -> internal (same-zone)
            ("app01", "db01"),     # internal -> critical (cross-zone)
            ("files01", "db01"),   # internal -> critical (cross-zone)
        ],
    )
    return build_network(spec, provider=provider, logger=logger)


if __name__ == "__main__":
    from rich import print as rprint
    from algorithms.namoa_star import run_namoa_star

    graph = create_sample_multihost_network()
    rprint(graph.summary())
    result = run_namoa_star(graph)
    rprint(f"\nPareto-optimal multi-host attack paths: {len(result.pareto_paths)}")
