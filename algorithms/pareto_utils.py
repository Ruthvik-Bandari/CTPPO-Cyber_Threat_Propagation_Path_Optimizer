"""
Pareto Dominance and Set Operations
===================================

This module provides utilities for multi-objective optimization:
- Pareto dominance checking
- Non-dominated set maintenance
- Pareto frontier operations
- Dominance-based pruning

These are critical for the multi-objective shortest path algorithms.

Author: Ruthvik
Date: November 2025
"""

import numpy as np
from typing import Any, Dict, List, Optional, Set, Tuple, TypeVar, Generic, Callable, Union
from dataclasses import dataclass, field
from enum import Enum, auto
import heapq
from abc import ABC, abstractmethod

import sys

from core.logging_system import ResearchLogger, get_default_logger


class ObjectiveSense(Enum):
    """Whether to minimize or maximize an objective"""
    MINIMIZE = auto()
    MAXIMIZE = auto()


@dataclass
class CostVector:
    """
    Multi-dimensional cost vector for Pareto comparison.
    
    Attributes:
        values: Array of cost values
        objective_senses: Whether to minimize or maximize each objective
        labels: Optional labels for each objective
    """
    values: np.ndarray
    objective_senses: List[ObjectiveSense] = field(default_factory=list)
    labels: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        self.values = np.asarray(self.values, dtype=np.float64)
        
        # Default to minimization
        if not self.objective_senses:
            self.objective_senses = [ObjectiveSense.MINIMIZE] * len(self.values)
        
        if not self.labels:
            self.labels = [f"obj_{i}" for i in range(len(self.values))]
    
    @property
    def dimension(self) -> int:
        return len(self.values)
    
    def normalized_values(self) -> np.ndarray:
        """
        Return values normalized for dominance comparison.
        
        Maximization objectives are negated so all become minimization.
        """
        normalized = self.values.copy()
        for i, sense in enumerate(self.objective_senses):
            if sense == ObjectiveSense.MAXIMIZE:
                normalized[i] = -normalized[i]
        return normalized
    
    def dominates(self, other: 'CostVector') -> bool:
        """
        Check if this vector dominates another.
        
        Dominance: self ≺ other iff:
        - ∀i: self[i] ≤ other[i] (for minimization)
        - ∃i: self[i] < other[i]
        """
        if self.dimension != other.dimension:
            raise ValueError("Vectors must have same dimension")
        
        self_norm = self.normalized_values()
        other_norm = other.normalized_values()
        
        # Check if all objectives are at least as good
        all_leq = np.all(self_norm <= other_norm)
        
        # Check if at least one is strictly better
        any_lt = np.any(self_norm < other_norm)
        
        return all_leq and any_lt
    
    def weakly_dominates(self, other: 'CostVector') -> bool:
        """
        Check weak dominance (≤ in all objectives).
        """
        self_norm = self.normalized_values()
        other_norm = other.normalized_values()
        return np.all(self_norm <= other_norm)
    
    def strictly_dominates(self, other: 'CostVector') -> bool:
        """
        Check strict dominance (< in all objectives).
        """
        self_norm = self.normalized_values()
        other_norm = other.normalized_values()
        return np.all(self_norm < other_norm)
    
    def __eq__(self, other):
        if isinstance(other, CostVector):
            return np.allclose(self.values, other.values)
        return False
    
    def __hash__(self):
        return hash(tuple(self.values.tolist()))
    
    def __repr__(self):
        return f"CostVector({self.values})"
    
    def __lt__(self, other):
        """For heap operations - uses first objective"""
        if isinstance(other, CostVector):
            return self.normalized_values()[0] < other.normalized_values()[0]
        return NotImplemented
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "values": self.values.tolist(),
            "labels": self.labels,
            "metadata": self.metadata
        }


T = TypeVar('T')


@dataclass
class LabeledSolution(Generic[T]):
    """
    A solution with its associated cost vector.
    
    Used in label-setting algorithms where each node maintains
    a set of non-dominated labels (cost vectors).
    """
    solution: T
    cost: CostVector
    predecessor: Optional['LabeledSolution[T]'] = None
    
    def dominates(self, other: 'LabeledSolution[T]') -> bool:
        return self.cost.dominates(other.cost)
    
    def __lt__(self, other):
        if isinstance(other, LabeledSolution):
            return self.cost < other.cost
        return NotImplemented
    
    def __hash__(self):
        return hash((id(self.solution), hash(self.cost)))


class ParetoSet(Generic[T]):
    """
    Maintains a set of Pareto-optimal (non-dominated) solutions.
    
    When a new solution is added:
    1. Check if it's dominated by any existing solution
    2. If not, add it and remove any solutions it dominates
    
    Attributes:
        solutions: List of non-dominated solutions
        dominated_count: Number of solutions filtered as dominated
    """
    
    def __init__(
        self,
        objective_senses: Optional[List[ObjectiveSense]] = None,
        logger: Optional[ResearchLogger] = None,
        epsilon: float = 0.0
    ):
        self.solutions: List[LabeledSolution[T]] = []
        self.objective_senses = objective_senses
        self.logger = logger or get_default_logger()
        self.dominated_count = 0
        self.total_insertions = 0
        # When epsilon > 0 the set keeps an ε-Pareto (bounded approximation) front: a new
        # solution is pruned if an existing one ε-dominates it (within a (1+ε) factor on every
        # objective). Default 0.0 → exact dominance (unchanged). Roadmap D1.
        self.epsilon = epsilon

    def _dominates(self, a: CostVector, b: CostVector) -> bool:
        """Dominance test honoring ``epsilon``: exact when epsilon == 0, else ε-dominance."""
        if self.epsilon > 0.0:
            return epsilon_dominance(a, b, self.epsilon)
        return a.dominates(b)
    
    def add(self, solution: LabeledSolution[T]) -> bool:
        """
        Add a solution to the Pareto set.
        
        Args:
            solution: Solution to add
            
        Returns:
            True if solution was added (not dominated), False otherwise
        """
        self.total_insertions += 1
        
        # Check if dominated by existing solutions
        for existing in self.solutions:
            if self._dominates(existing.cost, solution.cost):
                self.dominated_count += 1
                return False
            if existing.cost.weakly_dominates(solution.cost) and not solution.cost.dominates(existing.cost):
                # Equal in all objectives - could be duplicate
                if np.allclose(existing.cost.values, solution.cost.values):
                    return False

        # Remove any solutions dominated by the new one
        self.solutions = [
            s for s in self.solutions
            if not self._dominates(solution.cost, s.cost)
        ]

        self.solutions.append(solution)
        return True

    def is_dominated(self, cost: CostVector) -> bool:
        """Check if a cost vector is dominated by any solution in the set"""
        for solution in self.solutions:
            if self._dominates(solution.cost, cost):
                return True
        return False
    
    def filter_dominated(self, candidates: List[LabeledSolution[T]]) -> List[LabeledSolution[T]]:
        """Filter out candidates that are dominated by existing solutions"""
        return [c for c in candidates if not self.is_dominated(c.cost)]
    
    def get_pareto_front(self) -> List[CostVector]:
        """Return the Pareto front (just the cost vectors)"""
        return [s.cost for s in self.solutions]
    
    def get_extreme_points(self) -> Dict[str, LabeledSolution[T]]:
        """
        Get the extreme points of the Pareto front.
        
        For each objective, return the solution that optimizes it.
        """
        if not self.solutions:
            return {}
        
        extremes = {}
        n_obj = self.solutions[0].cost.dimension
        labels = self.solutions[0].cost.labels
        
        for i in range(n_obj):
            sense = self.objective_senses[i] if self.objective_senses else ObjectiveSense.MINIMIZE
            
            if sense == ObjectiveSense.MINIMIZE:
                best = min(self.solutions, key=lambda s: s.cost.values[i])
            else:
                best = max(self.solutions, key=lambda s: s.cost.values[i])
            
            extremes[labels[i]] = best
        
        return extremes
    
    def __len__(self):
        return len(self.solutions)
    
    def __iter__(self):
        return iter(self.solutions)
    
    def statistics(self) -> Dict[str, Any]:
        """Return statistics about the Pareto set"""
        return {
            "size": len(self.solutions),
            "total_insertions": self.total_insertions,
            "dominated_count": self.dominated_count,
            "dominance_rate": self.dominated_count / max(1, self.total_insertions)
        }


class NDTree:
    """
    N-dimensional tree for efficient Pareto dominance queries.
    
    Uses a balanced tree structure for O(log n) dominance checks
    instead of O(n) linear scanning.
    
    Based on: "The Non-dominated Tree" - Jaszkiewicz (2016)
    """
    
    def __init__(self, dimension: int):
        self.dimension = dimension
        self.solutions: List[CostVector] = []
        self._tree_dirty = True
        self._tree = None
    
    def add(self, cost: CostVector) -> bool:
        """Add a cost vector if non-dominated"""
        if self.is_dominated(cost):
            return False
        
        # Remove dominated solutions
        self.solutions = [s for s in self.solutions if not cost.dominates(s)]
        self.solutions.append(cost)
        self._tree_dirty = True
        return True
    
    def is_dominated(self, cost: CostVector) -> bool:
        """Check if cost is dominated using tree structure"""
        # For simplicity, using linear scan. 
        # Full implementation would use spatial data structure.
        for s in self.solutions:
            if s.dominates(cost):
                return True
        return False
    
    def __len__(self):
        return len(self.solutions)


def compute_hypervolume(
    pareto_front: List[CostVector],
    reference_point: np.ndarray
) -> float:
    """
    Compute the hypervolume indicator for a Pareto front.
    
    Hypervolume is the volume of the space dominated by the Pareto front
    and bounded by a reference point.
    
    Args:
        pareto_front: List of non-dominated cost vectors
        reference_point: Upper bound reference point
        
    Returns:
        Hypervolume value
    """
    if not pareto_front:
        return 0.0
    
    # Normalize all solutions (for minimization)
    points = np.array([c.normalized_values() for c in pareto_front])
    ref = np.array(reference_point)
    
    # Simple 2D hypervolume computation
    if points.shape[1] == 2:
        # Sort by first objective
        sorted_idx = np.argsort(points[:, 0])
        points = points[sorted_idx]
        
        hv = 0.0
        prev_x = points[0, 0]
        prev_y = ref[1]
        
        for i in range(len(points)):
            hv += (points[i, 0] - prev_x) * (prev_y - points[i, 1])
            prev_x = points[i, 0]
            prev_y = points[i, 1]
        
        # Add final rectangle
        hv += (ref[0] - prev_x) * (ref[1] - points[-1, 1])
        
        return hv
    
    # For higher dimensions, use Monte Carlo estimation
    n_samples = 10000
    samples = np.random.uniform(
        low=points.min(axis=0),
        high=ref,
        size=(n_samples, points.shape[1])
    )
    
    # Count samples dominated by at least one point
    dominated = np.zeros(n_samples, dtype=bool)
    for point in points:
        dominated |= np.all(samples >= point, axis=1)
    
    # Hypervolume = fraction of dominated samples * total volume
    volume = np.prod(ref - points.min(axis=0))
    return volume * np.mean(dominated)


def compute_crowding_distance(pareto_front: List[CostVector]) -> Dict[int, float]:
    """
    Compute crowding distance for each solution in the Pareto front.
    
    Crowding distance measures how crowded the region around a solution is.
    Used for diversity preservation in evolutionary algorithms.
    
    Args:
        pareto_front: List of non-dominated cost vectors
        
    Returns:
        Dictionary mapping solution index to crowding distance
    """
    n = len(pareto_front)
    if n <= 2:
        return {i: float('inf') for i in range(n)}
    
    points = np.array([c.normalized_values() for c in pareto_front])
    n_obj = points.shape[1]
    
    distances = np.zeros(n)
    
    for obj in range(n_obj):
        # Sort by this objective
        sorted_idx = np.argsort(points[:, obj])
        
        # Boundary points get infinite distance
        distances[sorted_idx[0]] = float('inf')
        distances[sorted_idx[-1]] = float('inf')
        
        # Normalize by range
        obj_range = points[sorted_idx[-1], obj] - points[sorted_idx[0], obj]
        if obj_range > 0:
            for i in range(1, n - 1):
                distances[sorted_idx[i]] += (
                    (points[sorted_idx[i + 1], obj] - points[sorted_idx[i - 1], obj])
                    / obj_range
                )
    
    return {i: distances[i] for i in range(n)}


def epsilon_dominance(
    cost1: CostVector,
    cost2: CostVector,
    epsilon: Union[float, np.ndarray]
) -> bool:
    """
    Check ε-dominance for approximate Pareto optimality.
    
    cost1 ε-dominates cost2 iff:
    - For all i: cost1[i] ≤ (1 + ε) * cost2[i]
    - For some i: cost1[i] < cost2[i]
    
    Args:
        cost1: First cost vector
        cost2: Second cost vector
        epsilon: Tolerance (scalar or per-objective array)
        
    Returns:
        True if cost1 ε-dominates cost2
    """
    if isinstance(epsilon, (int, float)):
        epsilon = np.full(cost1.dimension, epsilon)
    
    v1 = cost1.normalized_values()
    v2 = cost2.normalized_values()
    
    # Check ε-dominance condition
    eps_leq = np.all(v1 <= (1 + epsilon) * v2)
    strict_lt = np.any(v1 < v2)
    
    return eps_leq and strict_lt


class WeightedScalarization:
    """
    Scalarization methods for converting multi-objective to single-objective.
    
    Useful for comparison with classic algorithms and for generating
    extreme points of the Pareto front.
    """
    
    @staticmethod
    def weighted_sum(cost: CostVector, weights: np.ndarray) -> float:
        """
        Weighted sum scalarization.
        
        f(x) = Σ wᵢ * fᵢ(x)
        
        Note: Can only find solutions on convex parts of Pareto front.
        """
        normalized = cost.normalized_values()
        return np.dot(weights, normalized)
    
    @staticmethod
    def tchebycheff(
        cost: CostVector,
        weights: np.ndarray,
        ideal: np.ndarray
    ) -> float:
        """
        Tchebycheff (Chebyshev) scalarization.
        
        f(x) = max_i { wᵢ * |fᵢ(x) - idealᵢ| }
        
        Can find solutions on non-convex parts of Pareto front.
        """
        normalized = cost.normalized_values()
        return np.max(weights * np.abs(normalized - ideal))
    
    @staticmethod
    def augmented_tchebycheff(
        cost: CostVector,
        weights: np.ndarray,
        ideal: np.ndarray,
        rho: float = 0.01
    ) -> float:
        """
        Augmented Tchebycheff scalarization.
        
        Adds a small weighted sum term to break ties and ensure
        finding weakly Pareto optimal solutions.
        """
        normalized = cost.normalized_values()
        tcheby = np.max(weights * np.abs(normalized - ideal))
        aug = rho * np.sum(np.abs(normalized - ideal))
        return tcheby + aug


def fast_nondominated_sort(solutions: List[LabeledSolution]) -> List[List[int]]:
    """
    Fast non-dominated sorting (NSGA-II style).
    
    Partitions solutions into fronts:
    - Front 0: Non-dominated solutions
    - Front 1: Solutions dominated only by Front 0
    - etc.
    
    Time complexity: O(MN²) where M = #objectives, N = #solutions
    
    Args:
        solutions: List of labeled solutions
        
    Returns:
        List of fronts, each front is a list of solution indices
    """
    n = len(solutions)
    if n == 0:
        return []
    
    # Domination info
    domination_count = [0] * n  # Number of solutions that dominate solution i
    dominated_set = [[] for _ in range(n)]  # Solutions dominated by solution i
    
    # Compare all pairs
    for i in range(n):
        for j in range(i + 1, n):
            if solutions[i].dominates(solutions[j]):
                dominated_set[i].append(j)
                domination_count[j] += 1
            elif solutions[j].dominates(solutions[i]):
                dominated_set[j].append(i)
                domination_count[i] += 1
    
    # Build fronts
    fronts = []
    current_front = [i for i in range(n) if domination_count[i] == 0]
    
    while current_front:
        fronts.append(current_front)
        next_front = []
        
        for i in current_front:
            for j in dominated_set[i]:
                domination_count[j] -= 1
                if domination_count[j] == 0:
                    next_front.append(j)
        
        current_front = next_front
    
    return fronts


if __name__ == "__main__":
    from rich import print as rprint
    from rich.table import Table
    
    rprint("[bold green]Testing Pareto Utilities[/bold green]")
    
    # Test dominance
    c1 = CostVector(np.array([1.0, 2.0]), labels=["time", "cost"])
    c2 = CostVector(np.array([2.0, 3.0]), labels=["time", "cost"])
    c3 = CostVector(np.array([1.5, 1.5]), labels=["time", "cost"])
    
    rprint(f"\nc1 = {c1}, c2 = {c2}, c3 = {c3}")
    rprint(f"c1 dominates c2: {c1.dominates(c2)}")  # True
    rprint(f"c1 dominates c3: {c1.dominates(c3)}")  # False
    rprint(f"c3 dominates c2: {c3.dominates(c2)}")  # True
    
    # Test Pareto set
    rprint("\n[bold green]Testing Pareto Set[/bold green]")
    
    pareto = ParetoSet()
    solutions = [
        LabeledSolution("A", CostVector(np.array([1.0, 4.0]))),
        LabeledSolution("B", CostVector(np.array([2.0, 3.0]))),
        LabeledSolution("C", CostVector(np.array([3.0, 2.0]))),
        LabeledSolution("D", CostVector(np.array([4.0, 1.0]))),
        LabeledSolution("E", CostVector(np.array([2.5, 2.5]))),  # Dominated
    ]
    
    for sol in solutions:
        added = pareto.add(sol)
        rprint(f"Added {sol.solution}: {added}")
    
    rprint(f"\nPareto set size: {len(pareto)}")
    rprint(f"Statistics: {pareto.statistics()}")
    
    # Compute hypervolume
    front = pareto.get_pareto_front()
    ref_point = np.array([5.0, 5.0])
    hv = compute_hypervolume(front, ref_point)
    rprint(f"\nHypervolume (ref=[5,5]): {hv:.4f}")
    
    # Test crowding distance
    crowding = compute_crowding_distance(front)
    rprint(f"\nCrowding distances: {crowding}")
    
    # Test non-dominated sorting
    rprint("\n[bold green]Testing Non-Dominated Sorting[/bold green]")
    
    more_solutions = [
        LabeledSolution("F1", CostVector(np.array([1.0, 1.0]))),
        LabeledSolution("F2", CostVector(np.array([2.0, 2.0]))),
        LabeledSolution("F3", CostVector(np.array([3.0, 3.0]))),
        LabeledSolution("F4", CostVector(np.array([1.5, 2.5]))),
        LabeledSolution("F5", CostVector(np.array([2.5, 1.5]))),
    ]
    
    fronts = fast_nondominated_sort(more_solutions)
    for i, front in enumerate(fronts):
        front_sols = [more_solutions[j].solution for j in front]
        rprint(f"Front {i}: {front_sols}")
