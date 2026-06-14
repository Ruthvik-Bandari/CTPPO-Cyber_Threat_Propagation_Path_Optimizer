"""
Node Type Definitions for Attack Graphs
=======================================

This module defines the various node types used in attack graph representation:
- Assets (network devices, servers, workstations)
- Vulnerabilities (CVEs, misconfigurations)
- Exploits/Techniques (attack methods, MITRE ATT&CK techniques)
- Privilege States (user, root, system, domain admin)
- Business Impacts (data breach, service disruption)

Author: Ruthvik
Date: November 2025
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Union
from datetime import datetime
import uuid


class NodeType(Enum):
    """Enumeration of all node types in the attack graph"""
    ASSET = auto()
    VULNERABILITY = auto()
    EXPLOIT = auto()
    PRIVILEGE = auto()
    IMPACT = auto()
    ENTRY_POINT = auto()
    GOAL = auto()


class AssetType(Enum):
    """Types of network assets"""
    SERVER = "server"
    WORKSTATION = "workstation"
    ROUTER = "router"
    FIREWALL = "firewall"
    DATABASE = "database"
    WEB_APPLICATION = "web_application"
    IOT_DEVICE = "iot_device"
    CLOUD_INSTANCE = "cloud_instance"
    CONTAINER = "container"
    DOMAIN_CONTROLLER = "domain_controller"
    EMAIL_SERVER = "email_server"
    FILE_SERVER = "file_server"


class PrivilegeLevel(Enum):
    """Privilege levels in order of increasing access"""
    NONE = 0
    GUEST = 1
    USER = 2
    POWER_USER = 3
    LOCAL_ADMIN = 4
    ROOT = 5
    DOMAIN_USER = 6
    DOMAIN_ADMIN = 7
    ENTERPRISE_ADMIN = 8
    SYSTEM = 9


class ImpactCategory(Enum):
    """Categories of business impact"""
    CONFIDENTIALITY = "confidentiality"
    INTEGRITY = "integrity"
    AVAILABILITY = "availability"
    FINANCIAL = "financial"
    REPUTATIONAL = "reputational"
    REGULATORY = "regulatory"
    OPERATIONAL = "operational"


class CVSSSeverity(Enum):
    """CVSS severity ratings"""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class BaseNode(ABC):
    """
    Abstract base class for all node types.
    
    Each node has a unique identifier, type, and metadata.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    tags: Set[str] = field(default_factory=set)
    
    @property
    @abstractmethod
    def node_type(self) -> NodeType:
        """Return the type of this node"""
        pass
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert node to dictionary representation"""
        return {
            "id": self.id,
            "type": self.node_type.name,
            "name": self.name,
            "description": self.description,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
            "tags": list(self.tags)
        }
    
    def __hash__(self):
        return hash(self.id)
    
    def __eq__(self, other):
        if isinstance(other, BaseNode):
            return self.id == other.id
        return False


@dataclass
class AssetNode(BaseNode):
    """
    Represents a network asset (server, workstation, device, etc.)
    
    Attributes:
        asset_type: Type of asset (server, workstation, etc.)
        ip_address: IP address(es) of the asset
        hostname: Hostname of the asset
        os_info: Operating system information
        services: Running services and their versions
        criticality: Business criticality score (0-10)
        network_zone: Network zone (DMZ, internal, etc.)
    """
    asset_type: AssetType = AssetType.SERVER
    ip_addresses: List[str] = field(default_factory=list)
    hostname: str = ""
    os_info: Dict[str, str] = field(default_factory=dict)
    services: List[Dict[str, Any]] = field(default_factory=list)
    criticality: float = 5.0  # 0-10 scale
    network_zone: str = "internal"
    open_ports: List[int] = field(default_factory=list)
    installed_software: List[Dict[str, str]] = field(default_factory=list)
    
    @property
    def node_type(self) -> NodeType:
        return NodeType.ASSET
    
    def to_dict(self) -> Dict[str, Any]:
        base = super().to_dict()
        base.update({
            "asset_type": self.asset_type.value,
            "ip_addresses": self.ip_addresses,
            "hostname": self.hostname,
            "os_info": self.os_info,
            "services": self.services,
            "criticality": self.criticality,
            "network_zone": self.network_zone,
            "open_ports": self.open_ports
        })
        return base


@dataclass
class VulnerabilityNode(BaseNode):
    """
    Represents a vulnerability (CVE, misconfiguration, etc.)
    
    Attributes:
        cve_id: CVE identifier if applicable
        cvss_score: CVSS base score (0-10)
        cvss_vector: CVSS vector string
        affected_products: List of affected products/versions
        exploit_available: Whether public exploit exists
        patch_available: Whether patch is available
    """
    cve_id: Optional[str] = None
    cvss_score: float = 5.0
    cvss_vector: str = ""
    severity: CVSSSeverity = CVSSSeverity.MEDIUM
    affected_products: List[str] = field(default_factory=list)
    exploit_available: bool = False
    patch_available: bool = False
    published_date: Optional[datetime] = None
    cwe_ids: List[str] = field(default_factory=list)  # CWE weakness types
    attack_vector: str = "network"  # network, adjacent, local, physical
    attack_complexity: str = "low"  # low, high
    privileges_required: str = "none"  # none, low, high
    user_interaction: str = "none"  # none, required
    
    @property
    def node_type(self) -> NodeType:
        return NodeType.VULNERABILITY
    
    @property
    def exploitability_score(self) -> float:
        """Calculate exploitability based on CVSS components"""
        av_scores = {"network": 0.85, "adjacent": 0.62, "local": 0.55, "physical": 0.2}
        ac_scores = {"low": 0.77, "high": 0.44}
        pr_scores = {"none": 0.85, "low": 0.62, "high": 0.27}
        ui_scores = {"none": 0.85, "required": 0.62}
        
        return (
            8.22 *
            av_scores.get(self.attack_vector, 0.5) *
            ac_scores.get(self.attack_complexity, 0.5) *
            pr_scores.get(self.privileges_required, 0.5) *
            ui_scores.get(self.user_interaction, 0.5)
        )
    
    def to_dict(self) -> Dict[str, Any]:
        base = super().to_dict()
        base.update({
            "cve_id": self.cve_id,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "severity": self.severity.value if self.severity else "unknown",
            "exploit_available": self.exploit_available,
            "patch_available": self.patch_available,
            "exploitability_score": self.exploitability_score
        })
        return base


@dataclass
class ExploitNode(BaseNode):
    """
    Represents an exploit or attack technique.
    
    Attributes:
        exploit_db_id: Exploit-DB identifier
        mitre_technique_id: MITRE ATT&CK technique ID
        complexity: Technical complexity (1-10)
        reliability: Exploit reliability (0-1)
        required_privileges: Minimum privileges needed
        gained_privileges: Privileges gained on success
    """
    exploit_db_id: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    mitre_tactic: str = ""  # e.g., "initial-access", "privilege-escalation"
    complexity: float = 5.0  # 1-10, lower is easier
    reliability: float = 0.8  # 0-1, probability of success
    required_privileges: PrivilegeLevel = PrivilegeLevel.NONE
    gained_privileges: PrivilegeLevel = PrivilegeLevel.USER
    target_vulnerabilities: List[str] = field(default_factory=list)  # CVE IDs
    preconditions: List[str] = field(default_factory=list)
    postconditions: List[str] = field(default_factory=list)
    detection_difficulty: float = 0.5  # 0-1, higher is harder to detect
    
    @property
    def node_type(self) -> NodeType:
        return NodeType.EXPLOIT
    
    @property
    def success_probability(self) -> float:
        """Calculate overall success probability"""
        complexity_factor = 1.0 - (self.complexity / 10.0) * 0.5
        return self.reliability * complexity_factor
    
    def to_dict(self) -> Dict[str, Any]:
        base = super().to_dict()
        base.update({
            "exploit_db_id": self.exploit_db_id,
            "mitre_technique_id": self.mitre_technique_id,
            "mitre_tactic": self.mitre_tactic,
            "complexity": self.complexity,
            "reliability": self.reliability,
            "required_privileges": self.required_privileges.name,
            "gained_privileges": self.gained_privileges.name,
            "success_probability": self.success_probability
        })
        return base


@dataclass
class PrivilegeNode(BaseNode):
    """
    Represents a privilege state on an asset.
    
    Attributes:
        level: Privilege level (user, admin, root, etc.)
        asset_id: Asset where privilege is held
        scope: Scope of privilege (local, domain, etc.)
    """
    level: PrivilegeLevel = PrivilegeLevel.USER
    asset_id: str = ""
    scope: str = "local"  # local, domain, enterprise
    capabilities: List[str] = field(default_factory=list)
    persistence: bool = False  # Whether access is persistent
    
    @property
    def node_type(self) -> NodeType:
        return NodeType.PRIVILEGE
    
    @property
    def privilege_value(self) -> float:
        """Numerical value of privilege for comparison"""
        return self.level.value / PrivilegeLevel.SYSTEM.value
    
    def to_dict(self) -> Dict[str, Any]:
        base = super().to_dict()
        base.update({
            "level": self.level.name,
            "level_value": self.level.value,
            "asset_id": self.asset_id,
            "scope": self.scope,
            "capabilities": self.capabilities,
            "privilege_value": self.privilege_value
        })
        return base


@dataclass
class ImpactNode(BaseNode):
    """
    Represents a business impact.
    
    Attributes:
        category: Type of impact (confidentiality, availability, etc.)
        severity: Severity score (0-10)
        affected_assets: Assets that contribute to this impact
        business_service: Business service affected
        financial_impact: Estimated financial impact in dollars
    """
    category: ImpactCategory = ImpactCategory.CONFIDENTIALITY
    severity: float = 5.0  # 0-10
    affected_assets: List[str] = field(default_factory=list)
    business_service: str = ""
    financial_impact: float = 0.0  # Estimated $ impact
    recovery_time_hours: float = 24.0
    affected_users: int = 0
    regulatory_implications: List[str] = field(default_factory=list)  # e.g., ["GDPR", "HIPAA"]
    
    @property
    def node_type(self) -> NodeType:
        return NodeType.IMPACT
    
    @property
    def normalized_impact(self) -> float:
        """Normalized impact score combining multiple factors"""
        # Combine severity, financial impact, and user impact
        severity_component = self.severity / 10.0
        financial_component = min(1.0, self.financial_impact / 1_000_000)  # Cap at $1M
        user_component = min(1.0, self.affected_users / 10_000)  # Cap at 10k users
        
        return (severity_component * 0.4 + 
                financial_component * 0.4 + 
                user_component * 0.2)
    
    def to_dict(self) -> Dict[str, Any]:
        base = super().to_dict()
        base.update({
            "category": self.category.value if self.category else "unknown",
            "severity": self.severity,
            "business_service": self.business_service,
            "financial_impact": self.financial_impact,
            "recovery_time_hours": self.recovery_time_hours,
            "affected_users": self.affected_users,
            "normalized_impact": self.normalized_impact
        })
        return base


@dataclass
class EntryPointNode(BaseNode):
    """
    Represents an attacker entry point.
    
    Attributes:
        entry_type: Type of entry (internet, insider, physical)
        access_level: Initial access level gained
        detection_probability: Probability of detection at entry
    """
    entry_type: str = "internet"  # internet, insider, physical, supply_chain
    access_level: PrivilegeLevel = PrivilegeLevel.NONE
    detection_probability: float = 0.1
    reachable_assets: List[str] = field(default_factory=list)
    
    @property
    def node_type(self) -> NodeType:
        return NodeType.ENTRY_POINT
    
    def to_dict(self) -> Dict[str, Any]:
        base = super().to_dict()
        base.update({
            "entry_type": self.entry_type,
            "access_level": self.access_level.name,
            "detection_probability": self.detection_probability,
            "reachable_assets": self.reachable_assets
        })
        return base


@dataclass
class GoalNode(BaseNode):
    """
    Represents an attacker goal or objective.
    
    Attributes:
        goal_type: Type of goal (data_exfiltration, ransomware, etc.)
        target_assets: Assets that must be compromised
        required_privileges: Minimum privileges needed
        value_to_attacker: Value score for attacker (0-10)
    """
    goal_type: str = "data_exfiltration"
    target_assets: List[str] = field(default_factory=list)
    required_privileges: PrivilegeLevel = PrivilegeLevel.ROOT
    value_to_attacker: float = 8.0  # 0-10
    success_criteria: List[str] = field(default_factory=list)
    
    @property
    def node_type(self) -> NodeType:
        return NodeType.GOAL
    
    def to_dict(self) -> Dict[str, Any]:
        base = super().to_dict()
        base.update({
            "goal_type": self.goal_type,
            "target_assets": self.target_assets,
            "required_privileges": self.required_privileges.name,
            "value_to_attacker": self.value_to_attacker
        })
        return base


# Type alias for any node type
AnyNode = Union[AssetNode, VulnerabilityNode, ExploitNode, 
                PrivilegeNode, ImpactNode, EntryPointNode, GoalNode]


def create_node_from_dict(data: Dict[str, Any]) -> AnyNode:
    """Factory function to create a node from dictionary data"""
    node_type = NodeType[data.get("type", "ASSET")]
    
    type_mapping = {
        NodeType.ASSET: AssetNode,
        NodeType.VULNERABILITY: VulnerabilityNode,
        NodeType.EXPLOIT: ExploitNode,
        NodeType.PRIVILEGE: PrivilegeNode,
        NodeType.IMPACT: ImpactNode,
        NodeType.ENTRY_POINT: EntryPointNode,
        NodeType.GOAL: GoalNode
    }
    
    node_class = type_mapping[node_type]
    
    # Filter data to match dataclass fields
    import inspect
    valid_fields = {f.name for f in node_class.__dataclass_fields__.values()}
    filtered_data = {k: v for k, v in data.items() if k in valid_fields}
    
    return node_class(**filtered_data)


if __name__ == "__main__":
    # Test node creation
    from rich import print as rprint
    
    # Create sample nodes
    asset = AssetNode(
        name="WebServer01",
        asset_type=AssetType.WEB_APPLICATION,
        ip_addresses=["192.168.1.10"],
        criticality=8.0,
        services=[{"name": "Apache", "version": "2.4.51", "port": 80}]
    )
    
    vuln = VulnerabilityNode(
        name="Log4Shell",
        cve_id="CVE-2021-44228",
        cvss_score=10.0,
        severity=CVSSSeverity.CRITICAL,
        exploit_available=True,
        attack_vector="network",
        attack_complexity="low"
    )
    
    exploit = ExploitNode(
        name="Log4Shell RCE",
        mitre_technique_id="T1190",
        mitre_tactic="initial-access",
        reliability=0.95,
        complexity=3.0,
        gained_privileges=PrivilegeLevel.ROOT
    )
    
    impact = ImpactNode(
        name="Data Breach",
        category=ImpactCategory.CONFIDENTIALITY,
        severity=9.0,
        financial_impact=500000,
        affected_users=10000
    )
    
    rprint("[bold green]Sample Nodes Created:[/bold green]")
    rprint(f"Asset: {asset.to_dict()}")
    rprint(f"Vulnerability: {vuln.to_dict()}")
    rprint(f"Exploit: {exploit.to_dict()}")
    rprint(f"Impact: {impact.to_dict()}")
