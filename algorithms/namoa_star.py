"""
NAMOA* Algorithm Implementation
===============================

New Approach to Multi-Objective A* (NAMOA*) for finding all Pareto-optimal
paths in attack graphs.

Key Features:
- Label-setting algorithm for multi-objective shortest paths
- Admissible heuristics for pruning
- Returns complete Pareto-optimal set of paths
- Adapted for cybersecurity cost vectors

Reference:
- Mandow & Pérez de la Cruz (2005): "A New Approach to Multiobjective A* Search"

Author: Ruthvik
Date: November 2025
"""

import heapq
import numpy as np
from typing import Any, Dict, List, Optional, Set, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum
import time

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.attack_graph import AttackGraph, Edge
from core.edge_costs import CostType, EdgeCostVector, PathCostVector
from core.logging_system import ResearchLogger, get_default_logger, AlgorithmTracker
from algorithms.pareto_utils import (
    CostVector, ObjectiveSense, LabeledSolution, ParetoSet,
    compute_hypervolume, fast_nondominated_sort
)

# Floor for success probability before taking -log, so a p of 0 maps to a large but
# finite surprisal instead of +inf (which would poison path-cost accumulation).
_P_FLOOR = 1e-6


@dataclass
class PathLabel:
    """
    A label representing a partial path in NAMOA*.
    
    Each label contains:
    - The current node
    - The cost vector to reach this node
    - The path taken (list of node IDs)
    - Heuristic estimate to goal (for A* pruning)
    """
    node_id: str
    g_cost: CostVector  # Actual cost from start
    h_cost: CostVector  # Heuristic estimate to goal
    path: List[str]
    
    @property
    def f_cost(self) -> CostVector:
        """f = g + h (for A* style search)"""
        return CostVector(
            values=self.g_cost.values + self.h_cost.values,
            objective_senses=self.g_cost.objective_senses,
            labels=self.g_cost.labels
        )
    
    def __lt__(self, other):
        """Comparison for heap - uses first objective of f-cost"""
        if isinstance(other, PathLabel):
            return self.f_cost.values[0] < other.f_cost.values[0]
        return NotImplemented
    
    def __hash__(self):
        return hash((self.node_id, tuple(self.g_cost.values.tolist())))
    
    def __eq__(self, other):
        if isinstance(other, PathLabel):
            return (self.node_id == other.node_id and 
                    np.allclose(self.g_cost.values, other.g_cost.values))
        return False


@dataclass
class NAMOAStarResult:
    """Results from NAMOA* algorithm execution"""
    pareto_paths: List[Tuple[List[str], CostVector]]  # (path, cost) pairs
    num_labels_created: int
    num_labels_expanded: int
    num_labels_pruned: int
    execution_time_ms: float
    iterations: int
    hypervolume: Optional[float] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "num_pareto_paths": len(self.pareto_paths),
            "num_labels_created": self.num_labels_created,
            "num_labels_expanded": self.num_labels_expanded,
            "num_labels_pruned": self.num_labels_pruned,
            "execution_time_ms": self.execution_time_ms,
            "iterations": self.iterations,
            "hypervolume": self.hypervolume
        }


class CyberHeuristic:
    """
    Admissible heuristics for cyber attack graph search.
    
    An admissible heuristic never overestimates the cost to reach the goal.
    For multi-objective search, we need component-wise admissibility.
    """
    
    def __init__(
        self,
        graph: AttackGraph,
        goal_ids: Set[str],
        objective_types: List[CostType]
    ):
        self.graph = graph
        self.goal_ids = goal_ids
        self.objective_types = objective_types
        self.n_objectives = len(objective_types)
        
        # Precompute minimum edge costs for each objective
        self._min_edge_costs = self._compute_min_edge_costs()
        
        # Precompute shortest path distances (for time objective)
        self._shortest_distances = self._compute_shortest_distances()
    
    def _compute_min_edge_costs(self) -> Dict[CostType, float]:
        """Find minimum edge cost for each objective type"""
        min_costs = {ct: float('inf') for ct in self.objective_types}
        
        for edge in self.graph.edges.values():
            expected = edge.cost_vector.expected_values()
            for ct in self.objective_types:
                if ct in expected:
                    min_costs[ct] = min(min_costs[ct], expected[ct])
        
        # Ensure no infinite values
        for ct in min_costs:
            if min_costs[ct] == float('inf'):
                min_costs[ct] = 0.0
        
        return min_costs
    
    def _compute_shortest_distances(self) -> Dict[str, int]:
        """
        Compute shortest hop distance from each node to the nearest goal.
        Uses a single multi-source BFS starting from all goal nodes in reverse.
        This is more efficient than running a separate BFS for each goal.
        """
        import networkx as nx
        from collections import deque

        G = self.graph.get_nx_graph().reverse(copy=False) # Work on the reversed graph
        distances = {nid: float('inf') for nid in self.graph.nodes}
        queue = deque()

        # Initialize queue with all valid goal nodes
        for goal_id in self.goal_ids:
            if goal_id in G:
                distances[goal_id] = 0
                queue.append((goal_id, 0))
        
        while queue:
            node, dist = queue.popleft()
            
            # Since we start from goals, successors in the reversed graph are predecessors in the original
            for neighbor in G.successors(node):
                if distances[neighbor] == float('inf'): # If not visited
                    distances[neighbor] = dist + 1
                    queue.append((neighbor, dist + 1))
        
        return distances
    
    def estimate(self, node_id: str) -> CostVector:
        """
        Compute admissible heuristic estimate from node to goal.
        
        For each objective:
        - Time: min_edge_time * hop_distance
        - Probability: 1.0 (optimistic - assume perfect success)
        - Impact: 0.0 (optimistic - assume no additional impact)
        """
        # hop_dist can be infinity if a node cannot reach any goal.
        hop_dist = self._shortest_distances.get(node_id, float('inf'))
        if hop_dist == float('inf'):
            # If a node cannot reach the goal, its heuristic cost should be infinite.
            return CostVector(
                values=np.full(self.n_objectives, float('inf')),
                labels=[ct.name for ct in self.objective_types]
            )

        estimates = []
        for ct in self.objective_types:
            if ct == CostType.TIME_TO_EXPLOIT:
                # Minimum time = min_edge_time * hops
                estimates.append(self._min_edge_costs[ct] * hop_dist)
            elif ct == CostType.SUCCESS_PROBABILITY:
                # Optimistic: assume remaining edges all succeed (p=1 => surprisal 0).
                # 0 is admissible — it never overestimates the remaining surprisal.
                estimates.append(0.0)
            elif ct == CostType.BUSINESS_IMPACT:
                # Optimistic: no additional impact
                estimates.append(0.0)
            elif ct == CostType.DETECTION_PROBABILITY:
                # Optimistic: no detection
                estimates.append(0.0)
            else:
                estimates.append(0.0)
        
        return CostVector(
            values=np.array(estimates),
            labels=[ct.name for ct in self.objective_types]
        )


class NAMOAStar:
    """
    NAMOA* (New Approach to Multi-Objective A*) Algorithm.
    
    Finds all Pareto-optimal paths from source(s) to goal(s) in an attack graph.
    
    Key concepts:
    - Maintains sets of non-dominated labels at each node
    - Uses admissible heuristics for pruning
    - Expands labels in order of f-cost (g + h)
    - Guarantees finding all Pareto-optimal solutions
    
    Attributes:
        graph: The attack graph to search
        objective_types: List of objectives to optimize
        objective_senses: Whether to minimize/maximize each objective
        logger: Research logger for documentation
    """
    
    def __init__(
        self,
        graph: AttackGraph,
        objective_types: Optional[List[CostType]] = None,
        objective_senses: Optional[List[ObjectiveSense]] = None,
        logger: Optional[ResearchLogger] = None,
        combine_impact: str = "max",
        epsilon: float = 0.0,
    ):
        self.graph = graph
        self.logger = logger or get_default_logger()
        # ε-Pareto / bounded-approximation fallback (roadmap D1): 0.0 = exact NAMOA*
        # (default, complete Pareto set); epsilon > 0 keeps a smaller (1+ε)-approximate
        # front by ε-dominance pruning. Sound here because every objective accumulates
        # monotonically (time = sum, success surprisal = sum, impact = max, all ≥ 0), so
        # ε-dominance on partial paths is preserved under extension to full paths.
        if epsilon < 0.0:
            raise ValueError(f"epsilon must be >= 0, got {epsilon}")
        self.epsilon = epsilon
        # How BUSINESS_IMPACT accumulates along a path: "max" (worst single host on
        # the path, the shipped default) or "sum" (cumulative damage across hosts).
        # Exposed for the B7 cost-combination sensitivity study. (See _combine_costs.)
        if combine_impact not in ("max", "sum"):
            raise ValueError(f"combine_impact must be 'max' or 'sum', got {combine_impact!r}")
        self.combine_impact = combine_impact
        
        # Default objectives for cyber attack paths
        self.objective_types = objective_types or [
            CostType.TIME_TO_EXPLOIT,
            CostType.SUCCESS_PROBABILITY,
            CostType.BUSINESS_IMPACT
        ]
        
        # Default senses (all minimization; success is tracked as surprisal -log(p),
        # so minimizing it maximizes the cumulative success probability)
        self.objective_senses = objective_senses or [
            ObjectiveSense.MINIMIZE,  # Time - minimize
            ObjectiveSense.MINIMIZE,  # Success surprisal -log(p) - minimize
            ObjectiveSense.MINIMIZE   # Impact - minimize (for stealth)
        ]
        
        self.n_objectives = len(self.objective_types)
    
    def _edge_to_cost_vector(self, edge: Edge) -> CostVector:
        """Convert edge cost to CostVector for the configured objectives"""
        expected = edge.cost_vector.expected_values()
        
        values = []
        for ct in self.objective_types:
            if ct in expected:
                val = expected[ct]
                # Success probability is multiplicative along a path and we want to
                # MAXIMISE it, but accumulation/dominance here are all-minimisation.
                # Track surprisal -log(p): it is >= 0, ADDS along the path
                # (-log of the product = sum of the -logs), and is minimised exactly
                # when cumulative success is maximised. Recovered via exp(-.) on output.
                if ct == CostType.SUCCESS_PROBABILITY:
                    val = -float(np.log(max(val, _P_FLOOR)))
                values.append(val)
            else:
                values.append(0.0)
        
        return CostVector(
            values=np.array(values),
            objective_senses=self.objective_senses,
            labels=[ct.name for ct in self.objective_types]
        )
    
    def _combine_costs(self, g_cost: CostVector, edge_cost: CostVector) -> CostVector:
        """Combine path cost with edge cost based on aggregation rules"""
        new_values = []
        
        for i, ct in enumerate(self.objective_types):
            g_val = g_cost.values[i]
            e_val = edge_cost.values[i]
            
            if ct == CostType.TIME_TO_EXPLOIT:
                # Time adds up
                new_values.append(g_val + e_val)
            elif ct == CostType.SUCCESS_PROBABILITY:
                # Surprisal is additive: -log(∏ pᵢ) = Σ -log(pᵢ).
                new_values.append(g_val + e_val)
            elif ct == CostType.BUSINESS_IMPACT:
                # Impact: worst single host on the path (default), or cumulative damage
                # across hosts ("sum") — the B7 alternative.
                new_values.append(g_val + e_val if self.combine_impact == "sum"
                                  else max(g_val, e_val))
            elif ct == CostType.DETECTION_PROBABILITY:
                # Detection probability compounds
                p_g = g_val
                p_e = e_val
                # P(detected) = 1 - P(not detected on any step)
                new_values.append(1.0 - (1.0 - p_g) * (1.0 - p_e))
            else:
                # Default: sum
                new_values.append(g_val + e_val)
        
        return CostVector(
            values=np.array(new_values),
            objective_senses=self.objective_senses,
            labels=[ct.name for ct in self.objective_types]
        )
    
    def search(
        self,
        source_ids: Set[str],
        goal_ids: Set[str],
        max_iterations: int = 100000,
        use_heuristic: bool = True,
        early_termination: Optional[int] = None
    ) -> NAMOAStarResult:
        """
        Execute NAMOA* search to find all Pareto-optimal paths.
        
        Args:
            source_ids: Set of source node IDs (entry points)
            goal_ids: Set of goal node IDs
            max_iterations: Maximum iterations before stopping
            use_heuristic: Whether to use A* heuristic (faster but same results)
            early_termination: Stop after finding this many Pareto-optimal paths
            
        Returns:
            NAMOAStarResult containing all Pareto-optimal paths and statistics
        """
        start_time = time.perf_counter()
        
        self.logger.algorithm(
            "NAMOA_START",
            "Starting NAMOA* search",
            {
                "sources": list(source_ids),
                "goals": list(goal_ids),
                "objectives": [ct.name for ct in self.objective_types],
                "use_heuristic": use_heuristic
            }
        )
        
        # Initialize heuristic
        heuristic = CyberHeuristic(self.graph, goal_ids, self.objective_types) if use_heuristic else None
        
        # Statistics
        labels_created = 0
        labels_expanded = 0
        labels_pruned = 0
        
        # Open list (priority queue) - labels to expand
        open_list: List[PathLabel] = []
        
        # Closed labels at each node - G_op(n) in NAMOA* terminology
        # Maps node_id -> set of non-dominated g-costs that have been expanded
        closed_labels: Dict[str, ParetoSet] = {nid: ParetoSet(epsilon=self.epsilon) for nid in self.graph.nodes}

        # Open labels at each node - G_cl(n)
        # Maps node_id -> set of non-dominated g-costs in open list
        open_labels: Dict[str, ParetoSet] = {nid: ParetoSet(epsilon=self.epsilon) for nid in self.graph.nodes}

        # Goal labels - non-dominated paths that reached goals
        goal_labels: ParetoSet = ParetoSet(self.objective_senses, epsilon=self.epsilon)
        
        # Initialize with source labels. All objectives start at 0; for the success
        # surprisal -log(p) that means cumulative success = exp(-0) = 1.0 before any
        # edge is traversed (each edge then adds its own -log(p)).
        initial_values = np.zeros(self.n_objectives)

        zero_cost = CostVector(
            values=initial_values,
            objective_senses=self.objective_senses,
            labels=[ct.name for ct in self.objective_types]
        )
        
        for source_id in source_ids:
            if source_id not in self.graph.nodes:
                continue
            
            h_cost = heuristic.estimate(source_id) if heuristic else zero_cost
            
            initial_label = PathLabel(
                node_id=source_id,
                g_cost=zero_cost,
                h_cost=h_cost,
                path=[source_id]
            )
            
            heapq.heappush(open_list, initial_label)
            open_labels[source_id].add(LabeledSolution(initial_label, initial_label.g_cost))
            labels_created += 1
        
        # Main search loop
        iteration = 0
        
        with self.logger.track_algorithm("NAMOA*", {
            "sources": len(source_ids),
            "goals": len(goal_ids),
            "n_objectives": self.n_objectives
        }) as tracker:
            
            while open_list and iteration < max_iterations:
                iteration += 1
                
                # Get label with best f-cost
                current_label = heapq.heappop(open_list)
                current_node = current_label.node_id
                
                # PRUNING 1: Check if the label was already dominated by a path in the
                # closed set of its node. This can happen if a better path to this
                # node was found after this label was added to the open list.
                if closed_labels[current_node].is_dominated(current_label.g_cost):
                    labels_pruned += 1
                    continue
                
                labels_expanded += 1
                
                # Move to closed set, indicating we have now fully processed this path.
                closed_labels[current_node].add(
                    LabeledSolution(current_label, current_label.g_cost)
                )
                
                # --- GOAL CHECK ---
                if current_node in goal_ids:
                    # A goal has been reached. Add the path to the set of goal solutions.
                    # The ParetoSet will automatically handle dominance, keeping only the best paths.
                    output_cost = self._convert_cost_for_output(current_label.g_cost)
                    goal_labels.add(LabeledSolution(
                        (current_label.path.copy(), output_cost),
                        current_label.g_cost  # Use internal representation for dominance
                    ))
                    
                    self.logger.debug(
                        "GOAL_REACHED",
                        f"Found path to goal {current_node}",
                        {"path_length": len(current_label.path), "cost": output_cost.values.tolist()}
                    )
                    
                    if early_termination and len(goal_labels) >= early_termination:
                        break
                    
                    continue # Don't expand beyond a goal node
                
                # --- EXPANSION TO SUCCESSORS ---
                for edge in self.graph.get_outgoing_edges(current_node):
                    successor_id = edge.target_id
                    edge_cost = self._edge_to_cost_vector(edge)
                    
                    new_g_cost = self._combine_costs(current_label.g_cost, edge_cost)
                    
                    # PRUNING 2: Check if the new path to the successor is dominated by any
                    # path ALREADY EXPANDED to that successor. If so, this new path is not useful.
                    if closed_labels[successor_id].is_dominated(new_g_cost):
                        labels_pruned += 1
                        continue
                    
                    # PRUNING 3 (Optimistic): Check if the new path is dominated by any path
                    # IN THE OPEN LIST for that successor. This prunes paths that are clearly
                    # worse than ones we are already considering but haven't expanded yet.
                    if open_labels[successor_id].is_dominated(new_g_cost):
                        labels_pruned += 1
                        continue
                    
                    # A* HEURISTIC PRUNING: Check if the estimated total cost (f = g + h)
                    # is already dominated by a complete solution we've found. If the *best case*
                    # for this path is already worse than a known solution, prune it.
                    h_cost = heuristic.estimate(successor_id) if heuristic else zero_cost
                    if np.any(np.isinf(h_cost.values)): # Path cannot reach goal
                        labels_pruned += 1
                        continue

                    f_cost = CostVector(
                        values=new_g_cost.values + h_cost.values,
                        objective_senses=self.objective_senses
                    )
                    if goal_labels.is_dominated(f_cost):
                        labels_pruned += 1
                        continue
                    
                    # This is a promising path. Create a new label for the open list.
                    new_label = PathLabel(
                        node_id=successor_id,
                        g_cost=new_g_cost,
                        h_cost=h_cost,
                        path=current_label.path + [successor_id]
                    )
                    
                    # Add to open list and remove any now-dominated labels from the open set.
                    open_labels[successor_id].add(LabeledSolution(new_label, new_g_cost))
                    heapq.heappush(open_list, new_label)
                    labels_created += 1
                
                # Log progress periodically
                if iteration % 1000 == 0:
                    tracker.log_iteration(iteration, {
                        "open_list_size": len(open_list),
                        "labels_expanded": labels_expanded,
                        "goal_paths_found": len(goal_labels)
                    })
        
        # Collect results
        execution_time = (time.perf_counter() - start_time) * 1000
        
        pareto_paths = [
            (sol.solution[0], sol.solution[1])
            for sol in goal_labels.solutions
        ]
        
        # Compute hypervolume if we have solutions
        hypervolume = None
        if pareto_paths:
            # Use internal costs for hypervolume (all minimization)
            internal_costs = [sol.cost for sol in goal_labels.solutions]
            # Reference point: worst case for each objective
            ref_point = np.array([100.0] * self.n_objectives)  # Adjust based on domain
            hypervolume = compute_hypervolume(internal_costs, ref_point)
        
        result = NAMOAStarResult(
            pareto_paths=pareto_paths,
            num_labels_created=labels_created,
            num_labels_expanded=labels_expanded,
            num_labels_pruned=labels_pruned,
            execution_time_ms=execution_time,
            iterations=iteration,
            hypervolume=hypervolume
        )
        
        self.logger.algorithm(
            "NAMOA_COMPLETE",
            f"NAMOA* search completed with {len(pareto_paths)} Pareto-optimal paths",
            result.to_dict()
        )
        
        return result
    
    def _convert_cost_for_output(self, cost: CostVector) -> CostVector:
        """Convert internal cost representation back to user-friendly format"""
        values = cost.values.copy()

        # Recover cumulative success probability from the surprisal: ∏ pᵢ = exp(-Σ -log pᵢ)
        for i, ct in enumerate(self.objective_types):
            if ct == CostType.SUCCESS_PROBABILITY:
                values[i] = float(np.exp(-values[i]))
        
        return CostVector(
            values=values,
            objective_senses=self.objective_senses,
            labels=cost.labels
        )


def run_namoa_star(
    graph: AttackGraph,
    source_ids: Optional[Set[str]] = None,
    goal_ids: Optional[Set[str]] = None,
    logger: Optional[ResearchLogger] = None,
    combine_impact: str = "max",
    use_heuristic: bool = True,
    epsilon: float = 0.0,
) -> NAMOAStarResult:
    """
    Convenience function to run NAMOA* on an attack graph.

    Uses graph's entry points and goal nodes if not specified. ``combine_impact``
    selects how BUSINESS_IMPACT accumulates ("max" default, or "sum"); ``use_heuristic``
    toggles A* pruning (set False to keep the exact Pareto set when using a non-default
    combination rule whose admissible heuristic is not specialised). ``epsilon`` > 0 runs
    the ε-Pareto bounded-approximation fallback (roadmap D1; 0.0 = exact, the default).
    """
    logger = logger or get_default_logger()

    if source_ids is None:
        source_ids = graph.entry_points
    if goal_ids is None:
        goal_ids = graph.goal_nodes

    if not source_ids:
        raise ValueError("No source nodes specified and graph has no entry points")
    if not goal_ids:
        raise ValueError("No goal nodes specified and graph has no goal nodes")

    namoa = NAMOAStar(graph, logger=logger, combine_impact=combine_impact, epsilon=epsilon)
    return namoa.search(source_ids, goal_ids, use_heuristic=use_heuristic)


if __name__ == "__main__":
    from rich import print as rprint
    from rich.table import Table
    
    # Import graph creation
    from core.attack_graph import create_sample_enterprise_graph
    
    rprint("[bold green]Testing NAMOA* Algorithm[/bold green]")
    
    # Create sample graph
    graph = create_sample_enterprise_graph()
    rprint(f"\nGraph: {graph}")
    
    # Run NAMOA*
    rprint("\n[bold cyan]Running NAMOA* Search...[/bold cyan]")
    result = run_namoa_star(graph)
    
    # Display results
    rprint(f"\n[bold green]Results:[/bold green]")
    rprint(f"Pareto-optimal paths found: {len(result.pareto_paths)}")
    rprint(f"Labels created: {result.num_labels_created}")
    rprint(f"Labels expanded: {result.num_labels_expanded}")
    rprint(f"Labels pruned: {result.num_labels_pruned}")
    rprint(f"Execution time: {result.execution_time_ms:.2f} ms")
    rprint(f"Hypervolume: {result.hypervolume:.4f}" if result.hypervolume else "Hypervolume: N/A")
    
    # Display Pareto-optimal paths
    if result.pareto_paths:
        rprint("\n[bold cyan]Pareto-Optimal Attack Paths:[/bold cyan]")
        
        table = Table(title="Attack Paths")
        table.add_column("Path", style="cyan")
        table.add_column("Time (hrs)", justify="right")
        table.add_column("Success Prob", justify="right")
        table.add_column("Impact", justify="right")
        
        for path, cost in result.pareto_paths[:10]:  # Show first 10
            path_str = " → ".join([graph.get_node(nid).name[:15] for nid in path])
            table.add_row(
                path_str[:60] + "..." if len(path_str) > 60 else path_str,
                f"{cost.values[0]:.2f}",
                f"{cost.values[1]:.2%}",
                f"{cost.values[2]:.2f}"
            )
        
        rprint(table)
