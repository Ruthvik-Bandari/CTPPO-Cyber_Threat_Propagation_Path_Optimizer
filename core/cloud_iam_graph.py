"""
Cloud IAM / permission-lateral-movement attack-graph builder (Phase 5, C2)
==========================================================================

C1 (``core/identity_graph``) added on-prem **identity/credential** movement (phish → PtH →
DCSync). C2 closes the matching gap for the **cloud control plane**: in AWS/Azure/GCP the lateral
path is not "exploit a CVE" and not even "pass a Windows hash" — it is **IAM permission abuse**:
land on a low-privilege principal (leaked access key), pivot to a workload (EC2/VM), steal its
attached role credentials from the **instance metadata service**, then chain ``AssumeRole`` /
``CreatePolicyVersion`` / ``PassRole`` up to account administrator. None of that is a CVE.

This builds the **same canonical** ``core.attack_graph.AttackGraph`` (so it plugs straight into
NAMOA* and the rest of the engine), but transitions are **cloud MITRE ATT&CK techniques** between
cloud principals/resources. Each edge carries its **ATT&CK technique ID + tactic** (on the
``ExploitNode`` and the edge metadata) so a recovered path reads as a cloud kill chain.

The ``Technique`` abstraction (id/name/tactic + heuristic success/time/detection priors) is shared
with C1 — a cloud IAM step is the same kind of object as a credential step. Provider is recorded
per principal; the scenario below is AWS, with the Azure/GCP equivalents noted in the docstring.

**Honesty (read this).** Exactly as in C1: cloud IAM technique costs are **heuristic** — there is
no per-technique exploit-probability feed (EPSS covers CVEs, not "can this principal
``iam:PassRole``"). The success/time numbers are documented priors (a calibration target), flagged
``heuristic=True`` and ``data_grounded=False`` in every edge's metadata. The grounded part is the
*structure* (which principal can reach which, via which technique); the contribution is the
modeling capability + ATT&CK provenance, not a data-grounded probability for cloud privesc.

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
from core.identity_graph import Technique          # shared ATT&CK-technique abstraction (C1)
from core.logging_system import ResearchLogger, get_default_logger

# Cloud IAM edge relations (added to the canonical EdgeType string constants).
EdgeType.CLOUD_INITIAL_ACCESS = "cloud_initial_access"
EdgeType.CLOUD_IAM_MOVE = "cloud_iam_lateral_move"


@dataclass
class CloudPrincipal:
    """A cloud IAM principal or resource the attacker can occupy/control: an IAM user, a role, a
    workload instance (EC2/VM), or a data resource. ``provider`` is aws|azure|gcp."""
    principal_id: str
    name: str = ""
    provider: str = "aws"
    principal_type: str = "iam_user"     # iam_user | role | instance | resource
    network_zone: str = "cloud"
    criticality: float = 5.0
    internet_facing: bool = False        # attacker can land here (e.g. leaked access key)
    is_goal: bool = False                # crown jewel (e.g. account administrator)

    def _asset_type(self) -> AssetType:
        return {
            "instance": AssetType.CLOUD_INSTANCE,
            "resource": AssetType.DATABASE,
        }.get(self.principal_type, AssetType.CLOUD_INSTANCE)


@dataclass
class CloudMove:
    """An attacker transition: reach ``dst`` from ``src`` (or from the attacker, when ``src`` is
    None = initial access) by performing cloud ATT&CK ``technique``."""
    dst: str
    technique: Technique
    src: Optional[str] = None            # None => initial access from the internet attacker


@dataclass
class CloudScenario:
    name: str
    provider: str = "aws"
    principals: List[CloudPrincipal] = field(default_factory=list)
    moves: List[CloudMove] = field(default_factory=list)


def _cloud_cost(tech: Technique, dst_criticality: float) -> EdgeCostVector:
    """Heuristic cost vector for a cloud IAM technique. NOT data-grounded (same discipline as the
    C1 credential prior and the B3 lateral prior)."""
    cost = EdgeCostVector.create_default()
    cost.components[CostType.TIME_TO_EXPLOIT] = create_time_cost(max(tech.time, 0.01))
    cost.components[CostType.SUCCESS_PROBABILITY] = create_probability_cost(tech.success)
    impact = dst_criticality
    cost.components[CostType.BUSINESS_IMPACT] = create_impact_cost(
        impact * 0.7, impact, min(10.0, impact * 1.2))
    cost.metadata = {
        "attack_technique": tech.technique_id,
        "technique_name": tech.name,
        "tactic": tech.tactic,
        "detection_difficulty": tech.detection,
        "heuristic": True,
        "data_grounded": False,
        "note": "cloud IAM technique prior (calibration target) — not EPSS/CVE-grounded",
    }
    return cost


def build_cloud_iam_graph(
    scenario: CloudScenario,
    logger: Optional[ResearchLogger] = None,
) -> AttackGraph:
    """Build the canonical AttackGraph for a cloud IAM privilege-escalation scenario.

    Each move becomes ``src_asset --(technique ExploitNode)--> dst_asset`` (or
    ``entry --> dst_asset`` for initial access). The ExploitNode carries the ATT&CK technique
    id/tactic; the move edge carries it in metadata too. Plugs into ``run_namoa_star``.
    """
    logger = logger or get_default_logger()
    graph = AttackGraph(name=scenario.name, logger=logger)

    entry = EntryPointNode(name="External Attacker", entry_type="cloud_credential_leak",
                           access_level=PrivilegeLevel.NONE, detection_probability=0.2)
    graph.add_node(entry)

    asset_of: Dict[str, AssetNode] = {}
    for p in scenario.principals:
        asset = AssetNode(
            name=p.name or p.principal_id, asset_type=p._asset_type(), hostname=p.principal_id,
            criticality=p.criticality, network_zone=p.network_zone)
        asset.metadata.update({"cloud_provider": p.provider, "principal_type": p.principal_type})
        graph.add_node(asset)
        asset_of[p.principal_id] = asset
        if p.is_goal:
            goal = GoalNode(
                name=f"Cloud account takeover via {p.name or p.principal_id}",
                goal_type="cloud_account_takeover", target_assets=[asset.id],
                required_privileges=PrivilegeLevel.ENTERPRISE_ADMIN, value_to_attacker=p.criticality)
            graph.add_node(goal)
            graph.add_edge(asset.id, goal.id, EdgeType.ASSET_TO_GOAL)

    crit_of = {p.principal_id: p.criticality for p in scenario.principals}
    for mv in scenario.moves:
        if mv.dst not in asset_of:
            logger.warning("GRAPH", f"cloud move references unknown principal {mv.dst}")
            continue
        tech = mv.technique
        exploit = ExploitNode(
            name=f"{tech.technique_id} {tech.name}"[:50],
            mitre_technique_id=tech.technique_id, mitre_tactic=tech.tactic,
            reliability=tech.success, detection_difficulty=tech.detection,
            required_privileges=PrivilegeLevel.USER,
            gained_privileges=PrivilegeLevel.ENTERPRISE_ADMIN
            if crit_of.get(mv.dst, 0) >= 9 else PrivilegeLevel.LOCAL_ADMIN)
        graph.add_node(exploit)
        cost = _cloud_cost(tech, crit_of.get(mv.dst, 5.0))
        meta = {"attack_technique": tech.technique_id, "tactic": tech.tactic, "heuristic": True}

        if mv.src is None:                            # initial access from the attacker
            graph.add_edge(entry.id, exploit.id, EdgeType.CLOUD_INITIAL_ACCESS, cost, metadata=meta)
            graph.add_edge(exploit.id, asset_of[mv.dst].id, EdgeType.ENTRY_TO_ASSET,
                           _cloud_cost(Technique("", "reach", tech.tactic, 0.99, 0.1), 1.0))
        else:
            if mv.src not in asset_of:
                logger.warning("GRAPH", f"cloud move from unknown principal {mv.src}")
                continue
            graph.add_edge(asset_of[mv.src].id, exploit.id, EdgeType.CLOUD_IAM_MOVE, cost, metadata=meta)
            graph.add_edge(exploit.id, asset_of[mv.dst].id, EdgeType.ASSET_REACHES_ASSET,
                           _cloud_cost(Technique("", "reach", tech.tactic, 0.99, 0.1), crit_of.get(mv.dst, 5.0)))

    logger.info("GRAPH", f"Built cloud IAM scenario '{scenario.name}'",
                {"principals": len(scenario.principals), "nodes": graph.num_nodes,
                 "edges": graph.num_edges, "goals": len(graph.goal_nodes)})
    return graph


def create_aws_privesc_scenario() -> CloudScenario:
    """A canonical AWS IAM privilege-escalation kill chain — recognizable to any cloud red teamer:

        Internet --leaked access key (T1078.004)--> low-priv IAM user
        IAM user --run command on a workload (T1651)--> EC2 instance (instance role attached)
        EC2 --steal role creds from IMDS (T1552.005)--> CI/CD role (broad permissions)
        CI/CD role --attach AdministratorAccess (T1098.003)--> Account Admin (GOAL)

    Plus a fast/loud alternate: straight from the EC2 instance role to Account Admin via a
    misconfigured elevation path (T1548.005 Temporary Elevated Cloud Access) — fewer hops, lower
    success/louder — so the front has a real choice and NAMOA* keeps both routes.

    Cross-cloud equivalents (same structure, different API names): Azure — Managed Identity +
    IMDS (169.254.169.254) → role assignment via ``Microsoft.Authorization/roleAssignments``;
    GCP — metadata server → ``iam.serviceAccounts.getAccessToken`` / ``actAs`` service-account
    impersonation. The ATT&CK technique IDs (T1078.004 / T1552.005 / T1098.003 / T1548.005) are
    cloud-provider-agnostic.
    """
    principals = [
        CloudPrincipal("iam_user", "Low-priv IAM user (leaked key)", "aws", "iam_user", "cloud",
                       4.0, internet_facing=True),
        CloudPrincipal("ec2_app", "EC2 app instance (instance role)", "aws", "instance", "cloud",
                       6.0),
        CloudPrincipal("ci_role", "CI/CD pipeline role", "aws", "role", "cloud", 8.0),
        CloudPrincipal("admin", "AWS Account Administrator", "aws", "role", "cloud", 10.0,
                       is_goal=True),
    ]
    moves = [
        CloudMove("iam_user", Technique("T1078.004", "Valid Accounts: Cloud Accounts",
                                        "initial-access", success=0.6, time=2.0, detection=0.4)),
        CloudMove("ec2_app", Technique("T1651", "Cloud Administration Command",
                                       "execution", success=0.80, time=2.5, detection=0.6),
                  src="iam_user"),
        # Thorough route: steal the instance role from IMDS, assume the broad CI role, then admin.
        CloudMove("ci_role", Technique("T1552.005", "Unsecured Credentials: Cloud Instance Metadata API",
                                       "credential-access", success=0.85, time=3.0, detection=0.7),
                  src="ec2_app"),
        CloudMove("admin", Technique("T1098.003", "Account Manipulation: Additional Cloud Roles",
                                     "privilege-escalation", success=0.85, time=3.0, detection=0.5),
                  src="ci_role"),
        # Fast/loud alternate: instance role elevates straight to account admin (misconfig).
        CloudMove("admin", Technique("T1548.005", "Abuse Elevation Control: Temporary Elevated Cloud Access",
                                     "privilege-escalation", success=0.55, time=4.0, detection=0.2),
                  src="ec2_app"),
    ]
    return CloudScenario("AWS-IAM-PrivEsc", provider="aws", principals=principals, moves=moves)


if __name__ == "__main__":
    import logging
    logging.disable(logging.CRITICAL)
    from algorithms.namoa_star import run_namoa_star
    from core.node_types import NodeType

    graph = build_cloud_iam_graph(create_aws_privesc_scenario(),
                                  logger=ResearchLogger("cloud_iam", console_output=False))
    result = run_namoa_star(graph, logger=ResearchLogger("cloud_iam", console_output=False))
    print(f"AWS IAM privesc: {graph.num_nodes} nodes, {graph.num_edges} edges, "
          f"{len(result.pareto_paths)} Pareto path(s)")
    for i, (path, cost) in enumerate(result.pareto_paths, 1):
        techs = [graph.get_node(n).mitre_technique_id for n in path
                 if graph.get_node(n) and graph.get_node(n).node_type == NodeType.EXPLOIT
                 and graph.get_node(n).mitre_technique_id]
        print(f"  {i}. techniques: {' -> '.join(techs)}  "
              f"[time={cost.values[0]:.1f} success={cost.values[1]:.3f} impact={cost.values[2]:.1f}]")
