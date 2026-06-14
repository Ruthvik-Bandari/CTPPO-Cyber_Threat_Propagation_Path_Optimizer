"""
Core Module for Cyber Threat Propagation Path Optimizer
=======================================================

This module provides the core data structures and graph representation
for attack graph analysis.

Author: Ruthvik
Date: November 2025
"""

from .node_types import (
    NodeType, AssetType, PrivilegeLevel, ImpactCategory, CVSSSeverity,
    BaseNode, AssetNode, VulnerabilityNode, ExploitNode,
    PrivilegeNode, ImpactNode, EntryPointNode, GoalNode,
    AnyNode, create_node_from_dict
)

from .edge_costs import (
    CostType, AggregationType, DistributionType,
    Distribution, ConstantDistribution, NormalDistribution,
    LogNormalDistribution, ExponentialDistribution, UniformDistribution,
    TriangularDistribution, BetaDistribution, GammaDistribution, PERTDistribution,
    CostComponent, EdgeCostVector, PathCostVector,
    create_time_cost, create_probability_cost, create_impact_cost
)

from .attack_graph import (
    EdgeType, Edge, AttackGraph,
    create_sample_enterprise_graph
)

from .logging_system import (
    LogLevel, LogEntry, ResearchLogger, TimerContext, AlgorithmTracker,
    log_function, get_default_logger, set_default_logger, progress_bar
)

__all__ = [
    # Node Types
    'NodeType', 'AssetType', 'PrivilegeLevel', 'ImpactCategory', 'CVSSSeverity',
    'BaseNode', 'AssetNode', 'VulnerabilityNode', 'ExploitNode',
    'PrivilegeNode', 'ImpactNode', 'EntryPointNode', 'GoalNode',
    'AnyNode', 'create_node_from_dict',
    
    # Edge Costs
    'CostType', 'AggregationType', 'DistributionType',
    'Distribution', 'ConstantDistribution', 'NormalDistribution',
    'LogNormalDistribution', 'ExponentialDistribution', 'UniformDistribution',
    'TriangularDistribution', 'BetaDistribution', 'GammaDistribution', 'PERTDistribution',
    'CostComponent', 'EdgeCostVector', 'PathCostVector',
    'create_time_cost', 'create_probability_cost', 'create_impact_cost',
    
    # Attack Graph
    'EdgeType', 'Edge', 'AttackGraph', 'create_sample_enterprise_graph',
    
    # Logging
    'LogLevel', 'LogEntry', 'ResearchLogger', 'TimerContext', 'AlgorithmTracker',
    'log_function', 'get_default_logger', 'set_default_logger', 'progress_bar'
]
