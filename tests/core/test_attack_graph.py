"""
Unit Tests for AttackGraph
"""

import pytest
import pandas as pd
import sys
from pathlib import Path

# Add project root to path to allow absolute imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.attack_graph import AttackGraph
from core.node_types import AssetNode, VulnerabilityNode, NodeType, CVSSSeverity, AssetType

@pytest.fixture
def simple_graph() -> AttackGraph:
    """Provides a simple, empty AttackGraph for testing."""
    return AttackGraph(name="TestGraph")

@pytest.fixture
def populated_graph() -> AttackGraph:
    """Provides a graph with a few nodes and edges for path testing."""
    graph = AttackGraph(name="PopulatedTestGraph")
    a1 = AssetNode(name="A1")
    a2 = AssetNode(name="A2")
    v1 = VulnerabilityNode(name="V1", cve_id="CVE-001", cvss_score=7.0, severity=CVSSSeverity.HIGH)
    a3 = AssetNode(name="A3")

    graph.add_node(a1)
    graph.add_node(a2)
    graph.add_node(v1)
    graph.add_node(a3)

    graph.add_edge(a1.id, v1.id, "has_vuln")
    graph.add_edge(v1.id, a2.id, "enables_exploit")
    graph.add_edge(a1.id, a2.id, "reaches") # Direct path
    graph.add_edge(a2.id, a3.id, "reaches")
    
    return graph

def test_add_node(simple_graph: AttackGraph):
    """Test adding a node to the graph."""
    assert simple_graph.num_nodes == 0
    node = AssetNode(name="TestAsset", asset_type=AssetType.SERVER)
    simple_graph.add_node(node)
    
    assert simple_graph.num_nodes == 1
    assert simple_graph.get_node(node.id) is not None
    assert node.id in simple_graph.nodes_by_type[NodeType.ASSET]

def test_remove_node(populated_graph: AttackGraph):
    """Test removing a node and its connected edges."""
    node_to_remove_id = populated_graph.get_nodes_by_type(NodeType.VULNERABILITY)[0].id
    
    assert populated_graph.num_nodes == 4
    assert populated_graph.num_edges == 4
    
    populated_graph.remove_node(node_to_remove_id)
    
    assert populated_graph.num_nodes == 3
    assert populated_graph.get_node(node_to_remove_id) is None
    # Edges connected to the vulnerability node should be removed
    assert populated_graph.num_edges == 2 

def test_add_edge(simple_graph: AttackGraph):
    """Test adding an edge between two nodes."""
    a1 = AssetNode(name="A1")
    a2 = AssetNode(name="A2")
    simple_graph.add_node(a1)
    simple_graph.add_node(a2)

    assert simple_graph.num_edges == 0
    edge_id = simple_graph.add_edge(a1.id, a2.id, "reaches")
    
    assert simple_graph.num_edges == 1
    edge = simple_graph.get_edge(a1.id, a2.id)
    assert edge is not None
    assert edge.id == edge_id
    assert a2.id in simple_graph.get_successors(a1.id)
    assert a1.id in simple_graph.get_predecessors(a2.id)

def test_get_all_paths(populated_graph: AttackGraph):
    """Test finding all simple paths between two nodes."""
    nodes = {node.name: node.id for node in populated_graph.nodes.values()}
    paths = populated_graph.get_all_paths(nodes["A1"], nodes["A3"])
    
    assert len(paths) == 2
    
    # Sort paths to have a consistent order for checking
    sorted_paths = sorted([p for p in paths], key=len)
    
    # Expected path 1: A1 -> A2 -> A3
    path1 = [nodes["A1"], nodes["A2"], nodes["A3"]]
    # Expected path 2: A1 -> V1 -> A2 -> A3
    path2 = [nodes["A1"], nodes["V1"], nodes["A2"], nodes["A3"]]
    
    assert sorted_paths[0] == path1
    assert sorted_paths[1] == path2

def test_load_from_dataframes(simple_graph: AttackGraph):
    """Test loading graph content from pandas DataFrames."""
    nodes_data = {
        'id': ['node-1', 'node-2', 'node-3'],
        'name': ['Asset1', 'Vuln1', 'Asset2'],
        'node_type': [NodeType.ASSET, NodeType.VULNERABILITY, NodeType.ASSET],
        'cvss_score': [None, 9.0, None]
    }
    edges_data = {
        'source_id': ['node-1', 'node-2'],
        'target_id': ['node-2', 'node-3'],
        'edge_type': ['has_vuln', 'exploits']
    }
    nodes_df = pd.DataFrame(nodes_data)
    edges_df = pd.DataFrame(edges_data)

    graph = AttackGraph.load_from_dataframes(nodes_df, edges_df)

    assert graph.num_nodes == 3
    assert graph.num_edges == 2
    assert graph.get_node('node-2').name == 'Vuln1'
    assert graph.get_edge('node-1', 'node-2').edge_type == 'has_vuln'

def test_json_serialization(populated_graph: AttackGraph, tmp_path: Path):
    """Test saving to and loading from a JSON file."""
    filepath = tmp_path / "test_graph.json"
    
    # Save the graph
    populated_graph.save_json(filepath)
    assert filepath.exists()
    
    # Load the graph
    loaded_graph = AttackGraph.load_json(filepath)
    
    assert loaded_graph.name == populated_graph.name
    assert loaded_graph.num_nodes == populated_graph.num_nodes
    assert loaded_graph.num_edges == populated_graph.num_edges
    
    # Check if a specific node and its properties are preserved
    original_vuln = populated_graph.get_nodes_by_type(NodeType.VULNERABILITY)[0]
    loaded_vuln = loaded_graph.get_node(original_vuln.id)
    
    assert loaded_vuln is not None
    assert loaded_vuln.name == original_vuln.name
    assert loaded_vuln.cvss_score == original_vuln.cvss_score
