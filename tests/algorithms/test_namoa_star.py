"""
Unit Tests for NAMOA* Algorithm
"""

import pytest
import numpy as np
import sys
from pathlib import Path

# Add project root to path to allow absolute imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.attack_graph import AttackGraph
from core.node_types import EntryPointNode, AssetNode, GoalNode
from core.edge_costs import EdgeCostVector, CostType, create_time_cost, create_probability_cost, create_impact_cost
from algorithms.namoa_star import NAMOAStar, run_namoa_star
from algorithms.pareto_utils import CostVector, ObjectiveSense, LabeledSolution, ParetoSet # Added imports for test_pareto_set_dominance

@pytest.fixture
def pareto_graph() -> AttackGraph:
    """
    Creates a graph designed to test Pareto optimality.
    
    Path 1 (A -> B -> D):
    - Time: 1 + 3 = 4
    - Prob: 0.9 * 0.9 = 0.99 (compounded)
    - Impact: max(5, 2) = 5
    
    Path 2 (A -> C -> D):
    - Time: 2 + 1 = 3
    - Prob: 0.8 * 0.8 = 0.96 (compounded)
    - Impact: max(3, 8) = 8

    Path 3 (A -> E -> D) - DOMINATED by Path 2
    - Time: 4 + 2 = 6
    - Prob: 0.7 * 0.7 = 0.91 (compounded)
    - Impact: max(4, 9) = 9

    Path 1 is better on Prob and Impact. Path 2 is better on Time.
    Both are Pareto-optimal. Path 3 should be pruned.
    """
    graph = AttackGraph("ParetoTest")
    
    # Nodes
    start_node = EntryPointNode(name="A")
    node_b = AssetNode(name="B")
    node_c = AssetNode(name="C")
    node_e = AssetNode(name="E") # For dominated path
    goal_node = GoalNode(name="D")
    
    graph.add_node(start_node)
    graph.add_node(node_b)
    graph.add_node(node_c)
    graph.add_node(node_e)
    graph.add_node(goal_node)

    # --- Path 1 Costs (A->B->D) ---
    cost_ab = EdgeCostVector()
    cost_ab.components[CostType.TIME_TO_EXPLOIT] = create_time_cost(1)
    cost_ab.components[CostType.SUCCESS_PROBABILITY] = create_probability_cost(0.9) # P_fail = 0.1
    cost_ab.components[CostType.BUSINESS_IMPACT] = create_impact_cost(5, 5, 5)
    
    cost_bd = EdgeCostVector()
    cost_bd.components[CostType.TIME_TO_EXPLOIT] = create_time_cost(3)
    cost_bd.components[CostType.SUCCESS_PROBABILITY] = create_probability_cost(0.9) # P_fail = 0.1
    cost_bd.components[CostType.BUSINESS_IMPACT] = create_impact_cost(2, 2, 2)

    # --- Path 2 Costs (A->C->D) ---
    cost_ac = EdgeCostVector()
    cost_ac.components[CostType.TIME_TO_EXPLOIT] = create_time_cost(2)
    cost_ac.components[CostType.SUCCESS_PROBABILITY] = create_probability_cost(0.8) # P_fail = 0.2
    cost_ac.components[CostType.BUSINESS_IMPACT] = create_impact_cost(3, 3, 3)

    cost_cd = EdgeCostVector()
    cost_cd.components[CostType.TIME_TO_EXPLOIT] = create_time_cost(1)
    cost_cd.components[CostType.SUCCESS_PROBABILITY] = create_probability_cost(0.8) # P_fail = 0.2
    cost_cd.components[CostType.BUSINESS_IMPACT] = create_impact_cost(8, 8, 8)
    
    # --- Path 3 Costs (A->E->D) - Dominated ---
    cost_ae = EdgeCostVector()
    cost_ae.components[CostType.TIME_TO_EXPLOIT] = create_time_cost(4)
    cost_ae.components[CostType.SUCCESS_PROBABILITY] = create_probability_cost(0.7) # P_fail = 0.3
    cost_ae.components[CostType.BUSINESS_IMPACT] = create_impact_cost(4, 4, 4)

    cost_ed = EdgeCostVector()
    cost_ed.components[CostType.TIME_TO_EXPLOIT] = create_time_cost(2)
    cost_ed.components[CostType.SUCCESS_PROBABILITY] = create_probability_cost(0.7) # P_fail = 0.3
    cost_ed.components[CostType.BUSINESS_IMPACT] = create_impact_cost(9, 9, 9)

    # Add Edges
    graph.add_edge(start_node.id, node_b.id, "reaches", cost_vector=cost_ab)
    graph.add_edge(node_b.id, goal_node.id, "reaches", cost_vector=cost_bd)
    graph.add_edge(start_node.id, node_c.id, "reaches", cost_vector=cost_ac)
    graph.add_edge(node_c.id, goal_node.id, "reaches", cost_vector=cost_cd)
    graph.add_edge(start_node.id, node_e.id, "reaches", cost_vector=cost_ae) 
    graph.add_edge(node_e.id, goal_node.id, "reaches", cost_vector=cost_ed) 
    
    return graph

def test_finds_pareto_optimal_paths(pareto_graph: AttackGraph):
    """
    Tests that NAMOA* finds the two non-dominated paths and their correct costs.
    """
    # Objectives: Minimize Time, Maximize Prob, Minimize Impact
    objectives = [CostType.TIME_TO_EXPLOIT, CostType.SUCCESS_PROBABILITY, CostType.BUSINESS_IMPACT]
    senses = [ObjectiveSense.MINIMIZE, ObjectiveSense.MAXIMIZE, ObjectiveSense.MINIMIZE]
    
    namoa = NAMOAStar(pareto_graph, objective_types=objectives, objective_senses=senses)
    result = namoa.search(
        source_ids=pareto_graph.entry_points,
        goal_ids=pareto_graph.goal_nodes
    )

    # Should find 2 non-dominated paths
    assert len(result.pareto_paths) == 2

    # Extract costs for easier comparison
    found_costs = sorted([p[1].values.tolist() for p in result.pareto_paths])

    # Expected Path 1: Time=4, Prob=0.99, Impact=5
    expected_cost1 = [4.0, 0.99, 5.0]
    
    # Expected Path 2: Time=3, Prob=0.96, Impact=8
    expected_cost2 = [3.0, 0.96, 8.0]
    
    expected_costs = sorted([expected_cost2, expected_cost1])

    print(f"Found costs: {found_costs}")
    print(f"Expected costs: {expected_costs}")
    assert np.allclose(found_costs, expected_costs)

def test_run_namoa_star_convenience_function(pareto_graph: AttackGraph):
    """
    Tests the convenience wrapper function `run_namoa_star`.
    """
    result = run_namoa_star(pareto_graph)
    assert len(result.pareto_paths) == 2

def test_empty_graph():
    """
    Test that the algorithm handles an empty graph gracefully.
    """
    graph = AttackGraph("Empty")
    with pytest.raises(ValueError, match="No source nodes specified"):
        run_namoa_star(graph)

def test_no_path_to_goal(pareto_graph: AttackGraph):
    """
    Test that the algorithm returns an empty result if no path exists.
    """
    # Add a new goal that is unreachable
    new_goal = GoalNode(name="Unreachable")
    pareto_graph.add_node(new_goal)
    
    result = run_namoa_star(pareto_graph, goal_ids={new_goal.id})
    assert len(result.pareto_paths) == 0

# Test for ParetoSet dominance logic
def test_pareto_set_dominance():
    """
    Test the fundamental dominance logic of the ParetoSet.
    """
    objectives = [CostType.TIME_TO_EXPLOIT, CostType.SUCCESS_PROBABILITY]
    senses = [ObjectiveSense.MINIMIZE, ObjectiveSense.MINIMIZE] # Time (min), 1-Prob (min)

    # All CostVectors are in the internal (minimize, minimize) representation
    # where Prob is actually 1-Prob (failure probability)
    s1_cost = CostVector(np.array([5.0, 0.2]), senses, labels=['TIME', '1-PROB']) # (Time=5, Prob=0.8)
    s2_cost = CostVector(np.array([4.0, 0.3]), senses, labels=['TIME', '1-PROB']) # (Time=4, Prob=0.7) - non-dominated vs s1
    s3_cost = CostVector(np.array([6.0, 0.1]), senses, labels=['TIME', '1-PROB']) # (Time=6, Prob=0.9) - non-dominated vs s1, s2
    s4_cost = CostVector(np.array([5.0, 0.2]), senses, labels=['TIME', '1-PROB']) # Duplicate of s1
    s5_cost = CostVector(np.array([5.0, 0.3]), senses, labels=['TIME', '1-PROB']) # Dominated by s1
    s6_cost = CostVector(np.array([3.0, 0.05]), senses, labels=['TIME', '1-PROB']) # Dominates s1, s2, s3

    pareto_set = ParetoSet(senses)

    # 1. Add s1
    assert pareto_set.add(LabeledSolution("S1", s1_cost)) is True
    assert len(pareto_set) == 1
    assert not pareto_set.is_dominated(s1_cost)

    # 2. Add s2 (non-dominated, better Time, worse 1-Prob)
    assert pareto_set.add(LabeledSolution("S2", s2_cost)) is True
    assert len(pareto_set) == 2
    assert not pareto_set.is_dominated(s2_cost)
    assert pareto_set.solutions[0].cost.values.tolist() == s1_cost.values.tolist() or \
           pareto_set.solutions[1].cost.values.tolist() == s1_cost.values.tolist()
    assert pareto_set.solutions[0].cost.values.tolist() == s2_cost.values.tolist() or \
           pareto_set.solutions[1].cost.values.tolist() == s2_cost.values.tolist()

    # 3. Add s3 (non-dominated, worse Time, better 1-Prob)
    assert pareto_set.add(LabeledSolution("S3", s3_cost)) is True
    assert len(pareto_set) == 3
    assert not pareto_set.is_dominated(s3_cost)

    # 4. Add s4 (duplicate of s1)
    assert pareto_set.add(LabeledSolution("S4", s4_cost)) is False # Should not be added as it's a duplicate
    assert len(pareto_set) == 3

    # 5. Add s5 (dominated by s1)
    assert pareto_set.add(LabeledSolution("S5", s5_cost)) is False
    assert len(pareto_set) == 3
    assert pareto_set.is_dominated(s5_cost)

    # 6. Add s6 (dominates s1, s2, s3)
    assert pareto_set.add(LabeledSolution("S6", s6_cost)) is True
    assert len(pareto_set) == 1 # Only the dominator should remain
    assert pareto_set.solutions[0].cost.values.tolist() == s6_cost.values.tolist()
    assert not pareto_set.is_dominated(s6_cost)