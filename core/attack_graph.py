"""
Attack Graph Core Implementation
================================

This module provides the main AttackGraph class that represents the cyber
threat propagation network. It supports:
- Heterogeneous node types (assets, vulnerabilities, exploits, privileges, impacts)
- Multi-dimensional edge costs with probability distributions
- Dynamic graph updates (node/edge insertion, deletion, modification)
- Serialization/deserialization for persistence
- Integration with NetworkX for graph algorithms

Author: Ruthvik
Date: November 2025
"""

import json
import pickle
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple, Union
from datetime import datetime
import uuid

import networkx as nx
import numpy as np

from .node_types import (
    NodeType, BaseNode, AssetNode, VulnerabilityNode, ExploitNode,
    PrivilegeNode, ImpactNode, EntryPointNode, GoalNode, AnyNode,
    create_node_from_dict, AssetType, PrivilegeLevel, CVSSSeverity, ImpactCategory
)
from .edge_costs import (
    EdgeCostVector, PathCostVector, CostType, CostComponent,
    Distribution, create_time_cost, create_probability_cost, create_impact_cost
)
from .logging_system import ResearchLogger, get_default_logger, log_function


class EdgeType:
    """Edge type constants for attack graph relations"""
    # Asset-Vulnerability relations
    ASSET_HAS_VULN = "asset_has_vulnerability"
    
    # Vulnerability-Exploit relations
    VULN_ENABLES_EXPLOIT = "vulnerability_enables_exploit"
    
    # Exploit-Privilege relations
    EXPLOIT_GAINS_PRIV = "exploit_gains_privilege"
    EXPLOIT_REQUIRES_PRIV = "exploit_requires_privilege"
    
    # Asset-Privilege relations
    PRIV_ON_ASSET = "privilege_on_asset"
    
    # Network reachability
    ASSET_REACHES_ASSET = "asset_reaches_asset"
    
    # Privilege escalation
    PRIV_ESCALATES_TO = "privilege_escalates_to"
    
    # Impact relations
    ASSET_SUPPORTS_SERVICE = "asset_supports_service"
    COMPROMISE_CAUSES_IMPACT = "compromise_causes_impact"
    
    # Entry and goal relations
    ENTRY_TO_ASSET = "entry_point_to_asset"
    ASSET_TO_GOAL = "asset_to_goal"


@dataclass
class Edge:
    """
    Represents a directed edge in the attack graph.
    
    Attributes:
        source_id: ID of source node
        target_id: ID of target node
        edge_type: Type of relationship
        cost_vector: Multi-dimensional cost vector
        conditions: Conditions that must be met for this edge
        metadata: Additional edge metadata
    """
    source_id: str
    target_id: str
    edge_type: str
    cost_vector: EdgeCostVector = field(default_factory=EdgeCostVector.create_default)
    conditions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "edge_type": self.edge_type,
            "cost_vector": self.cost_vector.to_dict(),
            "conditions": self.conditions,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat()
        }


class AttackGraph:
    """
    Main attack graph class for cyber threat propagation modeling.
    
    This class provides:
    - Graph construction and manipulation
    - Node and edge management
    - Path enumeration
    - Integration with MOSP algorithms
    - Serialization and visualization support
    
    Attributes:
        nodes: Dictionary mapping node IDs to node objects
        edges: Dictionary mapping edge IDs to edge objects
        adjacency: Adjacency list for efficient traversal
        reverse_adjacency: Reverse adjacency for backward traversal
        graph: NetworkX DiGraph for algorithm integration
    """
    
    def __init__(
        self,
        name: str = "AttackGraph",
        logger: Optional[ResearchLogger] = None
    ):
        """
        Initialize an empty attack graph.
        
        Args:
            name: Name identifier for this graph
            logger: Research logger instance
        """
        self.name = name
        self.logger = logger or get_default_logger()
        
        # Node storage
        self.nodes: Dict[str, AnyNode] = {}
        self.nodes_by_type: Dict[NodeType, Set[str]] = {nt: set() for nt in NodeType}
        
        # Edge storage
        self.edges: Dict[str, Edge] = {}
        self.adjacency: Dict[str, Dict[str, str]] = {}  # source_id -> {target_id -> edge_id}
        self.reverse_adjacency: Dict[str, Dict[str, str]] = {}  # target_id -> {source_id -> edge_id}
        
        # NetworkX graph for algorithm integration
        self._nx_graph: Optional[nx.DiGraph] = None
        self._nx_dirty = True
        
        # Graph metadata
        self.metadata: Dict[str, Any] = {
            "created_at": datetime.now().isoformat(),
            "version": "1.0.0"
        }
        
        # Entry points and goals
        self.entry_points: Set[str] = set()
        self.goal_nodes: Set[str] = set()
        
        self.logger.info("GRAPH", f"Initialized attack graph: {name}")
    
    # =========================================================================
    # Node Operations
    # =========================================================================
    
    def add_node(self, node: AnyNode) -> str:
        """
        Add a node to the graph.
        
        Args:
            node: Node to add
            
        Returns:
            Node ID
        """
        if node.id in self.nodes:
            self.logger.warning("GRAPH", f"Node {node.id} already exists, updating")
        
        self.nodes[node.id] = node
        self.nodes_by_type[node.node_type].add(node.id)
        
        # Initialize adjacency entries
        if node.id not in self.adjacency:
            self.adjacency[node.id] = {}
        if node.id not in self.reverse_adjacency:
            self.reverse_adjacency[node.id] = {}
        
        # Track entry points and goals
        if node.node_type == NodeType.ENTRY_POINT:
            self.entry_points.add(node.id)
        elif node.node_type == NodeType.GOAL:
            self.goal_nodes.add(node.id)
        
        self._nx_dirty = True
        
        self.logger.debug(
            "GRAPH",
            f"Added node: {node.name} ({node.node_type.name})",
            {"node_id": node.id, "node_type": node.node_type.name}
        )
        
        return node.id
    
    def remove_node(self, node_id: str) -> bool:
        """
        Remove a node and all connected edges.
        
        Args:
            node_id: ID of node to remove
            
        Returns:
            True if removed, False if not found
        """
        if node_id not in self.nodes:
            return False
        
        node = self.nodes[node_id]
        
        # Remove all connected edges
        edges_to_remove = []
        for target_id, edge_id in self.adjacency.get(node_id, {}).items():
            edges_to_remove.append(edge_id)
        for source_id, edge_id in self.reverse_adjacency.get(node_id, {}).items():
            edges_to_remove.append(edge_id)
        
        for edge_id in edges_to_remove:
            self.remove_edge(edge_id)
        
        # Remove node
        del self.nodes[node_id]
        self.nodes_by_type[node.node_type].discard(node_id)
        self.entry_points.discard(node_id)
        self.goal_nodes.discard(node_id)
        
        if node_id in self.adjacency:
            del self.adjacency[node_id]
        if node_id in self.reverse_adjacency:
            del self.reverse_adjacency[node_id]
        
        self._nx_dirty = True
        
        self.logger.info("GRAPH", f"Removed node: {node_id}")
        
        return True
    
    def get_node(self, node_id: str) -> Optional[AnyNode]:
        """Get a node by ID"""
        return self.nodes.get(node_id)
    
    def get_nodes_by_type(self, node_type: NodeType) -> List[AnyNode]:
        """Get all nodes of a specific type"""
        return [self.nodes[nid] for nid in self.nodes_by_type[node_type]]
    
    # =========================================================================
    # Edge Operations
    # =========================================================================
    
    def add_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: str,
        cost_vector: Optional[EdgeCostVector] = None,
        conditions: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Add a directed edge to the graph.
        
        Args:
            source_id: Source node ID
            target_id: Target node ID
            edge_type: Type of relationship
            cost_vector: Multi-dimensional cost vector
            conditions: Edge traversal conditions
            metadata: Additional metadata
            
        Returns:
            Edge ID
        """
        if source_id not in self.nodes:
            raise ValueError(f"Source node {source_id} not found")
        if target_id not in self.nodes:
            raise ValueError(f"Target node {target_id} not found")
        
        edge = Edge(
            source_id=source_id,
            target_id=target_id,
            edge_type=edge_type,
            cost_vector=cost_vector or EdgeCostVector.create_default(),
            conditions=conditions or [],
            metadata=metadata or {}
        )
        
        self.edges[edge.id] = edge
        
        # Update adjacency lists
        if source_id not in self.adjacency:
            self.adjacency[source_id] = {}
        self.adjacency[source_id][target_id] = edge.id
        
        if target_id not in self.reverse_adjacency:
            self.reverse_adjacency[target_id] = {}
        self.reverse_adjacency[target_id][source_id] = edge.id
        
        self._nx_dirty = True
        
        self.logger.debug(
            "GRAPH",
            f"Added edge: {edge_type}",
            {
                "edge_id": edge.id,
                "source": source_id,
                "target": target_id,
                "costs": {k.name: v for k, v in edge.cost_vector.expected_values().items()}
            }
        )
        
        return edge.id
    
    def remove_edge(self, edge_id: str) -> bool:
        """Remove an edge by ID"""
        if edge_id not in self.edges:
            return False
        
        edge = self.edges[edge_id]
        
        # Update adjacency
        if edge.source_id in self.adjacency:
            self.adjacency[edge.source_id].pop(edge.target_id, None)
        if edge.target_id in self.reverse_adjacency:
            self.reverse_adjacency[edge.target_id].pop(edge.source_id, None)
        
        del self.edges[edge_id]
        self._nx_dirty = True
        
        return True
    
    def get_edge(self, source_id: str, target_id: str) -> Optional[Edge]:
        """Get edge between two nodes"""
        edge_id = self.adjacency.get(source_id, {}).get(target_id)
        if edge_id:
            return self.edges.get(edge_id)
        return None
    
    def get_outgoing_edges(self, node_id: str) -> List[Edge]:
        """Get all outgoing edges from a node"""
        return [
            self.edges[edge_id]
            for edge_id in self.adjacency.get(node_id, {}).values()
        ]
    
    def get_incoming_edges(self, node_id: str) -> List[Edge]:
        """Get all incoming edges to a node"""
        return [
            self.edges[edge_id]
            for edge_id in self.reverse_adjacency.get(node_id, {}).values()
        ]
    
    def get_successors(self, node_id: str) -> List[str]:
        """Get successor node IDs"""
        return list(self.adjacency.get(node_id, {}).keys())
    
    def get_predecessors(self, node_id: str) -> List[str]:
        """Get predecessor node IDs"""
        return list(self.reverse_adjacency.get(node_id, {}).keys())
    
    # =========================================================================
    # Graph Properties
    # =========================================================================
    
    @property
    def num_nodes(self) -> int:
        return len(self.nodes)
    
    @property
    def num_edges(self) -> int:
        return len(self.edges)
    
    def get_nx_graph(self) -> nx.DiGraph:
        """
        Get NetworkX DiGraph representation.
        
        The graph is cached and rebuilt only when dirty.
        """
        if self._nx_dirty or self._nx_graph is None:
            self._rebuild_nx_graph()
        return self._nx_graph
    
    def _rebuild_nx_graph(self):
        """Rebuild the NetworkX graph from internal representation"""
        G = nx.DiGraph()
        
        # Add nodes with attributes
        for node_id, node in self.nodes.items():
            G.add_node(node_id, **node.to_dict())
        
        # Add edges with attributes
        for edge_id, edge in self.edges.items():
            # Convert CostType keys to strings
            cost_values = {k.name: v for k, v in edge.cost_vector.expected_values().items()}
            G.add_edge(
                edge.source_id,
                edge.target_id,
                edge_id=edge_id,
                edge_type=edge.edge_type,
                **cost_values
            )
        
        self._nx_graph = G
        self._nx_dirty = False
        
        self.logger.debug("GRAPH", "Rebuilt NetworkX graph")
    
    # =========================================================================
    # Path Operations
    # =========================================================================
    
    def get_all_paths(
        self,
        source_id: str,
        target_id: str,
        max_length: Optional[int] = None,
        max_paths: int = 1000
    ) -> List[List[str]]:
        """
        Find all simple paths between source and target using NetworkX.

        A "simple path" means that no node is repeated. This is crucial for
        finding meaningful attack paths and avoiding infinite loops in cyclic graphs.
        
        Args:
            source_id: Source node ID
            target_id: Target node ID
            max_length: The maximum number of nodes in a path. If set, this acts
                        as a cutoff, which can significantly speed up the search
                        in large or dense graphs.
            max_paths: A safeguard to prevent returning an excessive number of
                       paths, which can consume a lot of memory. The search
                       will stop once this many paths have been found.
            
        Returns:
            List of paths, where each path is a list of node IDs.
        """
        G = self.get_nx_graph()
        
        paths = []
        try:
            for path in nx.all_simple_paths(G, source_id, target_id, cutoff=max_length):
                paths.append(path)
                if len(paths) >= max_paths:
                    break
        except nx.NetworkXNoPath:
            pass
        
        return paths
    
    def compute_path_cost(self, path: List[str]) -> PathCostVector:
        """
        Compute the cost vector for a path.
        
        Args:
            path: List of node IDs representing the path
            
        Returns:
            PathCostVector with aggregated costs
        """
        path_cost = PathCostVector()
        
        for i in range(len(path) - 1):
            edge = self.get_edge(path[i], path[i+1])
            if edge:
                path_cost.add_edge_cost(edge.cost_vector)
        
        return path_cost
    
    # =========================================================================
    # Attack-Specific Operations
    # =========================================================================
    
    def get_attack_paths_from_entry_points(
        self,
        max_length: int = 10
    ) -> Dict[Tuple[str, str], List[List[str]]]:
        """
        Get all attack paths from entry points to goals.
        
        Returns:
            Dictionary mapping (entry_id, goal_id) to list of paths
        """
        all_paths = {}
        
        for entry_id in self.entry_points:
            for goal_id in self.goal_nodes:
                paths = self.get_all_paths(entry_id, goal_id, max_length=max_length)
                if paths:
                    all_paths[(entry_id, goal_id)] = paths
        
        self.logger.info(
            "GRAPH",
            f"Found {sum(len(p) for p in all_paths.values())} attack paths",
            {"num_entry_points": len(self.entry_points), "num_goals": len(self.goal_nodes)}
        )
        
        return all_paths
    
    def get_reachable_assets(self, from_node_id: str) -> Set[str]:
        """Get all asset nodes reachable from a given node"""
        G = self.get_nx_graph()
        reachable = nx.descendants(G, from_node_id)
        return {
            nid for nid in reachable
            if nid in self.nodes_by_type[NodeType.ASSET]
        }
    
    def find_vulnerable_assets(self, cve_id: str) -> List[str]:
        """Find all assets vulnerable to a specific CVE"""
        vulnerable = []
        
        for vuln_id in self.nodes_by_type[NodeType.VULNERABILITY]:
            vuln = self.nodes[vuln_id]
            if isinstance(vuln, VulnerabilityNode) and vuln.cve_id == cve_id:
                # Find connected assets
                for pred_id in self.get_predecessors(vuln_id):
                    if pred_id in self.nodes_by_type[NodeType.ASSET]:
                        vulnerable.append(pred_id)
        
        return vulnerable
    
    # =========================================================================
    # Graph Statistics
    # =========================================================================
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive graph statistics"""
        G = self.get_nx_graph()
        
        stats = {
            "num_nodes": self.num_nodes,
            "num_edges": self.num_edges,
            "nodes_by_type": {
                nt.name: len(ids) for nt, ids in self.nodes_by_type.items()
            },
            "num_entry_points": len(self.entry_points),
            "num_goals": len(self.goal_nodes),
            "is_dag": nx.is_directed_acyclic_graph(G),
            "density": nx.density(G) if self.num_nodes > 0 else 0,
        }
        
        if self.num_nodes > 0:
            try:
                stats["avg_clustering"] = nx.average_clustering(G.to_undirected())
            except Exception:
                stats["avg_clustering"] = 0
            
            if nx.is_weakly_connected(G):
                stats["diameter"] = nx.diameter(G.to_undirected())
            else:
                stats["num_components"] = nx.number_weakly_connected_components(G)
        
        return stats
    
    # =========================================================================
    # Serialization
    # =========================================================================
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert graph to dictionary for serialization"""
        return {
            "name": self.name,
            "metadata": self.metadata,
            "nodes": {nid: node.to_dict() for nid, node in self.nodes.items()},
            "edges": {eid: edge.to_dict() for eid, edge in self.edges.items()},
            "entry_points": list(self.entry_points),
            "goal_nodes": list(self.goal_nodes)
        }
    
    def save_json(self, filepath: Union[str, Path]):
        """Save graph to JSON file"""
        filepath = Path(filepath)
        with open(filepath, 'w') as f:
            json.dump(self.to_dict(), f, indent=2, default=str)
        self.logger.info("GRAPH", f"Saved graph to {filepath}")
    
    def save_pickle(self, filepath: Union[str, Path]):
        """Save graph to pickle file"""
        filepath = Path(filepath)
        with open(filepath, 'wb') as f:
            pickle.dump(self, f)
        self.logger.info("GRAPH", f"Saved graph (pickle) to {filepath}")

    @classmethod
    def load_from_dataframes(
        cls,
        nodes_df: 'pd.DataFrame',
        edges_df: 'pd.DataFrame',
        name: str = "LoadedFromDataFrame",
        logger: Optional[ResearchLogger] = None
    ) -> 'AttackGraph':
        """
        Load graph from pandas DataFrames.

        Args:
            nodes_df: DataFrame containing node data. Must have 'id' and 'node_type' columns.
            edges_df: DataFrame containing edge data. Must have 'source_id' and 'target_id' columns.
            name: Name for the new graph.
            logger: Research logger instance.

        Returns:
            A new AttackGraph instance populated with data from the DataFrames.
        """
        import pandas as pd

        graph = cls(name=name, logger=logger)
        
        # Load nodes
        for _, row in nodes_df.iterrows():
            node_data = row.to_dict()
            node_id = node_data.pop('id')
            node = create_node_from_dict(node_data)
            node.id = node_id
            graph.add_node(node)

        # Load edges
        for _, row in edges_df.iterrows():
            edge_data = row.to_dict()
            source_id = edge_data.pop('source_id')
            target_id = edge_data.pop('target_id')
            edge_type = edge_data.pop('edge_type', 'generic')
            
            # Here you could add logic to create a proper cost_vector from columns
            
            graph.add_edge(
                source_id=source_id,
                target_id=target_id,
                edge_type=edge_type,
                metadata=edge_data # Store remaining columns as metadata
            )
            
        graph.logger.info("GRAPH", f"Loaded graph from DataFrames with {graph.num_nodes} nodes and {graph.num_edges} edges.")
        return graph

    @classmethod
    def load_json(cls, filepath: Union[str, Path], logger: Optional[ResearchLogger] = None) -> 'AttackGraph':
        """Load graph from JSON file"""
        filepath = Path(filepath)
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        graph = cls(name=data.get("name", "LoadedGraph"), logger=logger)
        graph.metadata = data.get("metadata", {})
        
        # Load nodes
        for node_id, node_data in data.get("nodes", {}).items():
            node = create_node_from_dict(node_data)
            node.id = node_id
            graph.add_node(node)
        
        # Load edges
        for edge_id, edge_data in data.get("edges", {}).items():
            graph.add_edge(
                source_id=edge_data["source_id"],
                target_id=edge_data["target_id"],
                edge_type=edge_data["edge_type"],
                conditions=edge_data.get("conditions", []),
                metadata=edge_data.get("metadata", {})
            )
        
        # Set entry points and goals
        graph.entry_points = set(data.get("entry_points", []))
        graph.goal_nodes = set(data.get("goal_nodes", []))
        
        return graph
    
    @classmethod
    def load_pickle(cls, filepath: Union[str, Path]) -> 'AttackGraph':
        """Load graph from pickle file"""
        filepath = Path(filepath)
        with open(filepath, 'rb') as f:
            return pickle.load(f)
    
    # =========================================================================
    # Representation
    # =========================================================================
    
    def __repr__(self) -> str:
        return (
            f"AttackGraph(name='{self.name}', "
            f"nodes={self.num_nodes}, edges={self.num_edges}, "
            f"entry_points={len(self.entry_points)}, goals={len(self.goal_nodes)})"
        )
    
    def summary(self) -> str:
        """Generate a text summary of the graph"""
        stats = self.get_statistics()
        
        lines = [
            f"Attack Graph: {self.name}",
            "=" * 50,
            f"Nodes: {stats['num_nodes']}",
            f"Edges: {stats['num_edges']}",
            f"Entry Points: {stats['num_entry_points']}",
            f"Goal Nodes: {stats['num_goals']}",
            "",
            "Nodes by Type:",
        ]
        
        for nt_name, count in stats['nodes_by_type'].items():
            if count > 0:
                lines.append(f"  - {nt_name}: {count}")
        
        lines.extend([
            "",
            f"Is DAG: {stats.get('is_dag', 'N/A')}",
            f"Density: {stats.get('density', 0):.4f}",
        ])
        
        return "\n".join(lines)


# Factory functions for building attack graphs
def create_sample_enterprise_graph(logger: Optional[ResearchLogger] = None) -> AttackGraph:
    """
    Create a sample enterprise attack graph for testing and demonstration.
    
    This creates a realistic enterprise network scenario with:
    - Multiple network zones (DMZ, internal, critical)
    - Common vulnerabilities
    - Various attack paths
    """
    graph = AttackGraph(name="SampleEnterpriseNetwork", logger=logger)
    
    # =========================================================================
    # Create Entry Points
    # =========================================================================
    internet_entry = EntryPointNode(
        name="Internet Entry",
        entry_type="internet",
        access_level=PrivilegeLevel.NONE,
        detection_probability=0.1
    )
    graph.add_node(internet_entry)
    
    insider_entry = EntryPointNode(
        name="Insider Entry",
        entry_type="insider",
        access_level=PrivilegeLevel.USER,
        detection_probability=0.05
    )
    graph.add_node(insider_entry)
    
    # =========================================================================
    # Create Assets - DMZ
    # =========================================================================
    web_server = AssetNode(
        name="WebServer01",
        asset_type=AssetType.WEB_APPLICATION,
        ip_addresses=["10.0.1.10"],
        hostname="web01.company.com",
        criticality=6.0,
        network_zone="dmz",
        services=[
            {"name": "Apache", "version": "2.4.51", "port": 443},
            {"name": "PHP", "version": "7.4.3", "port": 443}
        ],
        open_ports=[80, 443]
    )
    graph.add_node(web_server)
    
    email_server = AssetNode(
        name="EmailServer",
        asset_type=AssetType.EMAIL_SERVER,
        ip_addresses=["10.0.1.20"],
        hostname="mail.company.com",
        criticality=7.0,
        network_zone="dmz",
        services=[{"name": "Exchange", "version": "2019", "port": 443}],
        open_ports=[25, 443, 587]
    )
    graph.add_node(email_server)
    
    # =========================================================================
    # Create Assets - Internal Network
    # =========================================================================
    app_server = AssetNode(
        name="AppServer01",
        asset_type=AssetType.SERVER,
        ip_addresses=["10.0.2.10"],
        hostname="app01.internal",
        criticality=7.0,
        network_zone="internal",
        services=[
            {"name": "Tomcat", "version": "9.0.50", "port": 8080},
            {"name": "Java", "version": "11.0.11", "port": 8080}
        ]
    )
    graph.add_node(app_server)
    
    file_server = AssetNode(
        name="FileServer",
        asset_type=AssetType.FILE_SERVER,
        ip_addresses=["10.0.2.20"],
        hostname="files.internal",
        criticality=8.0,
        network_zone="internal",
        services=[{"name": "SMB", "version": "3.0", "port": 445}]
    )
    graph.add_node(file_server)
    
    workstation = AssetNode(
        name="Workstation01",
        asset_type=AssetType.WORKSTATION,
        ip_addresses=["10.0.3.100"],
        hostname="ws01.internal",
        criticality=4.0,
        network_zone="internal"
    )
    graph.add_node(workstation)
    
    # =========================================================================
    # Create Assets - Critical Zone
    # =========================================================================
    db_server = AssetNode(
        name="DatabaseServer",
        asset_type=AssetType.DATABASE,
        ip_addresses=["10.0.10.10"],
        hostname="db01.critical",
        criticality=10.0,
        network_zone="critical",
        services=[{"name": "PostgreSQL", "version": "13.4", "port": 5432}]
    )
    graph.add_node(db_server)
    
    dc_server = AssetNode(
        name="DomainController",
        asset_type=AssetType.DOMAIN_CONTROLLER,
        ip_addresses=["10.0.10.1"],
        hostname="dc01.company.com",
        criticality=10.0,
        network_zone="critical",
        services=[{"name": "AD", "version": "2019", "port": 389}]
    )
    graph.add_node(dc_server)
    
    # =========================================================================
    # Create Vulnerabilities
    # =========================================================================
    log4shell = VulnerabilityNode(
        name="Log4Shell",
        cve_id="CVE-2021-44228",
        cvss_score=10.0,
        severity=CVSSSeverity.CRITICAL,
        exploit_available=True,
        patch_available=True,
        attack_vector="network",
        attack_complexity="low",
        privileges_required="none"
    )
    graph.add_node(log4shell)
    
    proxyshell = VulnerabilityNode(
        name="ProxyShell",
        cve_id="CVE-2021-34473",
        cvss_score=9.8,
        exploit_available=True,
        attack_vector="network",
        attack_complexity="low"
    )
    graph.add_node(proxyshell)
    
    smb_vuln = VulnerabilityNode(
        name="SMB Vulnerability",
        cve_id="CVE-2020-0796",
        cvss_score=10.0,
        exploit_available=True,
        attack_vector="network"
    )
    graph.add_node(smb_vuln)
    
    sql_injection = VulnerabilityNode(
        name="SQL Injection",
        cve_id="CWE-89",
        cvss_score=8.5,
        exploit_available=True,
        attack_vector="network"
    )
    graph.add_node(sql_injection)
    
    # =========================================================================
    # Create Exploits
    # =========================================================================
    log4shell_exploit = ExploitNode(
        name="Log4Shell RCE",
        mitre_technique_id="T1190",
        mitre_tactic="initial-access",
        complexity=3.0,
        reliability=0.95,
        required_privileges=PrivilegeLevel.NONE,
        gained_privileges=PrivilegeLevel.ROOT
    )
    graph.add_node(log4shell_exploit)
    
    proxyshell_exploit = ExploitNode(
        name="ProxyShell Exploit Chain",
        mitre_technique_id="T1190",
        complexity=4.0,
        reliability=0.85,
        required_privileges=PrivilegeLevel.NONE,
        gained_privileges=PrivilegeLevel.SYSTEM
    )
    graph.add_node(proxyshell_exploit)
    
    lateral_movement = ExploitNode(
        name="Pass-the-Hash",
        mitre_technique_id="T1550.002",
        mitre_tactic="lateral-movement",
        complexity=5.0,
        reliability=0.7,
        required_privileges=PrivilegeLevel.LOCAL_ADMIN,
        gained_privileges=PrivilegeLevel.LOCAL_ADMIN
    )
    graph.add_node(lateral_movement)
    
    priv_escalation = ExploitNode(
        name="Token Impersonation",
        mitre_technique_id="T1134",
        mitre_tactic="privilege-escalation",
        complexity=6.0,
        reliability=0.6,
        required_privileges=PrivilegeLevel.USER,
        gained_privileges=PrivilegeLevel.SYSTEM
    )
    graph.add_node(priv_escalation)
    
    # =========================================================================
    # Create Impact Nodes
    # =========================================================================
    data_breach = ImpactNode(
        name="Customer Data Breach",
        category=ImpactCategory.CONFIDENTIALITY,
        severity=9.5,
        financial_impact=5000000,
        affected_users=100000,
        business_service="Customer Database"
    )
    graph.add_node(data_breach)
    
    ransomware = ImpactNode(
        name="Ransomware Deployment",
        severity=10.0,
        financial_impact=10000000,
        recovery_time_hours=168,
        business_service="All Services"
    )
    graph.add_node(ransomware)
    
    # =========================================================================
    # Create Goal Nodes
    # =========================================================================
    data_exfil_goal = GoalNode(
        name="Data Exfiltration",
        goal_type="data_exfiltration",
        target_assets=[db_server.id],
        required_privileges=PrivilegeLevel.ROOT,
        value_to_attacker=9.0
    )
    graph.add_node(data_exfil_goal)
    
    domain_control_goal = GoalNode(
        name="Domain Compromise",
        goal_type="domain_compromise",
        target_assets=[dc_server.id],
        required_privileges=PrivilegeLevel.DOMAIN_ADMIN,
        value_to_attacker=10.0
    )
    graph.add_node(domain_control_goal)
    
    # =========================================================================
    # Create Edges with Cost Vectors
    # =========================================================================
    
    # Entry point to DMZ
    cost_entry_web = EdgeCostVector.create_default()
    cost_entry_web.components[CostType.TIME_TO_EXPLOIT] = create_time_cost(0.5, 0.2)
    cost_entry_web.components[CostType.SUCCESS_PROBABILITY] = create_probability_cost(0.9)
    graph.add_edge(internet_entry.id, web_server.id, EdgeType.ENTRY_TO_ASSET, cost_entry_web)
    
    cost_entry_email = EdgeCostVector.create_default()
    cost_entry_email.components[CostType.TIME_TO_EXPLOIT] = create_time_cost(0.5, 0.2)
    cost_entry_email.components[CostType.SUCCESS_PROBABILITY] = create_probability_cost(0.85)
    graph.add_edge(internet_entry.id, email_server.id, EdgeType.ENTRY_TO_ASSET, cost_entry_email)
    
    # Insider to workstation
    graph.add_edge(insider_entry.id, workstation.id, EdgeType.ENTRY_TO_ASSET)
    
    # Asset vulnerabilities
    graph.add_edge(app_server.id, log4shell.id, EdgeType.ASSET_HAS_VULN)
    graph.add_edge(email_server.id, proxyshell.id, EdgeType.ASSET_HAS_VULN)
    graph.add_edge(file_server.id, smb_vuln.id, EdgeType.ASSET_HAS_VULN)
    graph.add_edge(web_server.id, sql_injection.id, EdgeType.ASSET_HAS_VULN)
    
    # Vulnerability enables exploit
    cost_log4shell = EdgeCostVector.create_default()
    cost_log4shell.components[CostType.TIME_TO_EXPLOIT] = create_time_cost(1.0, 0.3)
    cost_log4shell.components[CostType.SUCCESS_PROBABILITY] = create_probability_cost(0.95)
    cost_log4shell.components[CostType.BUSINESS_IMPACT] = create_impact_cost(6, 8, 10)
    graph.add_edge(log4shell.id, log4shell_exploit.id, EdgeType.VULN_ENABLES_EXPLOIT, cost_log4shell)
    
    graph.add_edge(proxyshell.id, proxyshell_exploit.id, EdgeType.VULN_ENABLES_EXPLOIT)
    
    # Network reachability (DMZ to internal)
    graph.add_edge(web_server.id, app_server.id, EdgeType.ASSET_REACHES_ASSET)
    graph.add_edge(email_server.id, file_server.id, EdgeType.ASSET_REACHES_ASSET)
    graph.add_edge(app_server.id, file_server.id, EdgeType.ASSET_REACHES_ASSET)
    graph.add_edge(app_server.id, db_server.id, EdgeType.ASSET_REACHES_ASSET)
    graph.add_edge(workstation.id, file_server.id, EdgeType.ASSET_REACHES_ASSET)
    graph.add_edge(file_server.id, dc_server.id, EdgeType.ASSET_REACHES_ASSET)
    
    # Exploits gain privileges
    graph.add_edge(log4shell_exploit.id, app_server.id, EdgeType.EXPLOIT_GAINS_PRIV)
    graph.add_edge(proxyshell_exploit.id, email_server.id, EdgeType.EXPLOIT_GAINS_PRIV)
    
    # Lateral movement paths
    graph.add_edge(app_server.id, lateral_movement.id, EdgeType.ASSET_REACHES_ASSET)
    graph.add_edge(lateral_movement.id, file_server.id, EdgeType.EXPLOIT_GAINS_PRIV)
    graph.add_edge(lateral_movement.id, db_server.id, EdgeType.EXPLOIT_GAINS_PRIV)
    
    # Privilege escalation
    graph.add_edge(workstation.id, priv_escalation.id, EdgeType.ASSET_REACHES_ASSET)
    graph.add_edge(priv_escalation.id, dc_server.id, EdgeType.EXPLOIT_GAINS_PRIV)
    
    # Impact connections
    graph.add_edge(db_server.id, data_breach.id, EdgeType.COMPROMISE_CAUSES_IMPACT)
    graph.add_edge(dc_server.id, ransomware.id, EdgeType.COMPROMISE_CAUSES_IMPACT)
    
    # Goals
    graph.add_edge(db_server.id, data_exfil_goal.id, EdgeType.ASSET_TO_GOAL)
    graph.add_edge(dc_server.id, domain_control_goal.id, EdgeType.ASSET_TO_GOAL)
    
    logger = logger or get_default_logger()
    logger.info(
        "GRAPH",
        "Created sample enterprise attack graph",
        graph.get_statistics()
    )
    
    return graph


if __name__ == "__main__":
    from rich import print as rprint
    
    # Create sample graph
    graph = create_sample_enterprise_graph()
    
    rprint("[bold green]Attack Graph Summary[/bold green]")
    rprint(graph.summary())
    
    rprint("\n[bold green]Graph Statistics[/bold green]")
    rprint(graph.get_statistics())
    
    # Find attack paths
    rprint("\n[bold green]Finding Attack Paths[/bold green]")
    paths = graph.get_attack_paths_from_entry_points(max_length=8)
    for (entry, goal), path_list in paths.items():
        entry_node = graph.get_node(entry)
        goal_node = graph.get_node(goal)
        rprint(f"\n{entry_node.name} -> {goal_node.name}: {len(path_list)} paths")
        for i, path in enumerate(path_list[:3]):  # Show first 3
            path_names = [graph.get_node(nid).name for nid in path]
            rprint(f"  Path {i+1}: {' -> '.join(path_names)}")
