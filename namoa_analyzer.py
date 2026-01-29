#!/usr/bin/env python3
"""
NAMOA* Attack Path Analyzer
============================

New Approach to Multi-Objective A* (NAMOA*) implementation for finding
ALL Pareto-optimal attack paths through a vulnerability network.

Features:
- Multi-objective optimization (exploitability, impact, path length)
- Complete enumeration of all optimal paths
- Integration with CTPPO severity classifier

Author: Ruthvik Bandari
Date: January 2026
"""

import heapq
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple, Optional, Any
from collections import defaultdict
import json


@dataclass
class Vulnerability:
    """Represents a vulnerability (edge) in the attack graph."""
    cve_id: str
    source: str  # Source node (system)
    target: str  # Target node (system)
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    cvss_score: float
    exploitability_score: float
    impact_score: float
    has_exploit: bool = False
    description: str = ""
    
    def get_cost_vector(self) -> Tuple[float, float, float]:
        """
        Returns multi-objective cost vector.
        Lower is better for all objectives.
        
        Returns:
            (exploitability_cost, impact_cost, hop_cost)
        """
        # Invert scores so lower = easier to exploit / higher impact
        # Exploitability: higher score = easier, so cost = 4 - score
        exploit_cost = 4.0 - self.exploitability_score
        
        # Impact: higher score = more damage, we want to find high impact paths
        # So cost = 6 - score (lower cost = higher impact = worse for defender)
        impact_cost = 6.0 - self.impact_score
        
        # Hop cost is always 1
        hop_cost = 1.0
        
        return (exploit_cost, impact_cost, hop_cost)


@dataclass
class AttackGraph:
    """
    Represents the network as an attack graph.
    Nodes are systems, edges are vulnerabilities.
    """
    nodes: Set[str] = field(default_factory=set)
    edges: Dict[str, List[Vulnerability]] = field(default_factory=lambda: defaultdict(list))
    entry_points: Set[str] = field(default_factory=set)
    critical_assets: Set[str] = field(default_factory=set)
    
    def add_node(self, node_id: str, is_entry: bool = False, is_critical: bool = False):
        """Add a node (system) to the graph."""
        self.nodes.add(node_id)
        if is_entry:
            self.entry_points.add(node_id)
        if is_critical:
            self.critical_assets.add(node_id)
    
    def add_edge(self, vuln: Vulnerability):
        """Add an edge (vulnerability) to the graph."""
        self.nodes.add(vuln.source)
        self.nodes.add(vuln.target)
        self.edges[vuln.source].append(vuln)
    
    def get_neighbors(self, node: str) -> List[Tuple[str, Vulnerability]]:
        """Get all neighbors reachable from a node via vulnerabilities."""
        return [(vuln.target, vuln) for vuln in self.edges.get(node, [])]
    
    def to_dict(self) -> Dict:
        """Convert graph to dictionary for JSON serialization."""
        return {
            'nodes': list(self.nodes),
            'entry_points': list(self.entry_points),
            'critical_assets': list(self.critical_assets),
            'edges': {
                src: [
                    {
                        'cve_id': v.cve_id,
                        'target': v.target,
                        'severity': v.severity,
                        'cvss_score': v.cvss_score,
                        'exploitability_score': v.exploitability_score,
                        'impact_score': v.impact_score,
                        'has_exploit': v.has_exploit
                    }
                    for v in vulns
                ]
                for src, vulns in self.edges.items()
            }
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'AttackGraph':
        """Create graph from dictionary."""
        graph = cls()
        for node in data.get('nodes', []):
            is_entry = node in data.get('entry_points', [])
            is_critical = node in data.get('critical_assets', [])
            graph.add_node(node, is_entry, is_critical)
        
        for src, vulns in data.get('edges', {}).items():
            for v in vulns:
                vuln = Vulnerability(
                    cve_id=v['cve_id'],
                    source=src,
                    target=v['target'],
                    severity=v['severity'],
                    cvss_score=v['cvss_score'],
                    exploitability_score=v['exploitability_score'],
                    impact_score=v['impact_score'],
                    has_exploit=v.get('has_exploit', False)
                )
                graph.add_edge(vuln)
        
        return graph


@dataclass(order=True)
class NAMOALabel:
    """
    A label in NAMOA* representing a partial path.
    Labels are compared by their cost vector for Pareto dominance.
    """
    cost_vector: Tuple[float, ...] = field(compare=True)
    node: str = field(compare=False)
    path: List[Vulnerability] = field(compare=False, default_factory=list)
    
    def dominates(self, other: 'NAMOALabel') -> bool:
        """Check if this label Pareto-dominates another."""
        dominated = False
        for c1, c2 in zip(self.cost_vector, other.cost_vector):
            if c1 > c2:
                return False
            if c1 < c2:
                dominated = True
        return dominated
    
    def __hash__(self):
        return hash((self.cost_vector, self.node, tuple(v.cve_id for v in self.path)))


@dataclass
class AttackPath:
    """Represents a complete attack path."""
    vulnerabilities: List[Vulnerability]
    total_cost: Tuple[float, float, float]
    source: str
    target: str
    
    @property
    def path_length(self) -> int:
        return len(self.vulnerabilities)
    
    @property
    def total_cvss(self) -> float:
        return sum(v.cvss_score for v in self.vulnerabilities)
    
    @property
    def max_severity(self) -> str:
        severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        max_sev = max(self.vulnerabilities, key=lambda v: severity_order.get(v.severity, 0))
        return max_sev.severity
    
    @property
    def risk_score(self) -> float:
        """Calculate overall risk score for the path."""
        # Combine exploitability and impact
        total_exploit = sum(v.exploitability_score for v in self.vulnerabilities)
        total_impact = sum(v.impact_score for v in self.vulnerabilities)
        # Normalize by path length and weight
        return (total_exploit * 0.4 + total_impact * 0.6) / self.path_length
    
    def to_dict(self) -> Dict:
        return {
            'source': self.source,
            'target': self.target,
            'path_length': self.path_length,
            'total_cvss': self.total_cvss,
            'max_severity': self.max_severity,
            'risk_score': round(self.risk_score, 2),
            'total_cost': {
                'exploitability': round(self.total_cost[0], 2),
                'impact': round(self.total_cost[1], 2),
                'hops': int(self.total_cost[2])
            },
            'vulnerabilities': [
                {
                    'cve_id': v.cve_id,
                    'source': v.source,
                    'target': v.target,
                    'severity': v.severity,
                    'cvss_score': v.cvss_score,
                    'exploitability_score': v.exploitability_score,
                    'impact_score': v.impact_score,
                    'has_exploit': v.has_exploit
                }
                for v in self.vulnerabilities
            ]
        }


class NAMOAPathAnalyzer:
    """
    NAMOA* (New Approach to Multi-Objective A*) implementation.
    
    Finds ALL Pareto-optimal attack paths from entry points to critical assets.
    Uses multi-objective optimization with:
    - Exploitability (ease of attack)
    - Impact (damage potential)
    - Path length (number of hops)
    """
    
    def __init__(self, graph: AttackGraph):
        self.graph = graph
        self.num_objectives = 3  # exploitability, impact, hops
    
    def _add_cost_vectors(self, v1: Tuple[float, ...], v2: Tuple[float, ...]) -> Tuple[float, ...]:
        """Add two cost vectors element-wise."""
        return tuple(a + b for a, b in zip(v1, v2))
    
    def _is_dominated(self, label: NAMOALabel, label_set: Set[NAMOALabel]) -> bool:
        """Check if a label is dominated by any label in the set."""
        for existing in label_set:
            if existing.dominates(label):
                return True
        return False
    
    def _filter_dominated(self, label_set: Set[NAMOALabel]) -> Set[NAMOALabel]:
        """Remove dominated labels from a set."""
        result = set()
        for label in label_set:
            if not any(other.dominates(label) for other in label_set if other != label):
                result.add(label)
        return result
    
    def find_paths(
        self,
        source: str,
        target: str,
        max_depth: int = 10
    ) -> List[AttackPath]:
        """
        Find all Pareto-optimal paths from source to target.
        
        Args:
            source: Starting node (entry point)
            target: Goal node (critical asset)
            max_depth: Maximum path length
            
        Returns:
            List of Pareto-optimal attack paths
        """
        # G_op: Labels at each node that are not dominated
        g_op: Dict[str, Set[NAMOALabel]] = defaultdict(set)
        
        # G_cl: Closed labels (expanded)
        g_cl: Dict[str, Set[NAMOALabel]] = defaultdict(set)
        
        # OPEN: Priority queue of labels to expand
        open_set = []
        
        # Initialize with source
        initial_cost = (0.0, 0.0, 0.0)
        initial_label = NAMOALabel(cost_vector=initial_cost, node=source, path=[])
        heapq.heappush(open_set, (sum(initial_cost), initial_label))
        g_op[source].add(initial_label)
        
        # Solution paths
        solutions: List[AttackPath] = []
        solution_costs: Set[Tuple[float, ...]] = set()
        
        while open_set:
            _, current = heapq.heappop(open_set)
            
            # Skip if dominated
            if self._is_dominated(current, g_cl[current.node]):
                continue
            
            # Move to closed
            g_cl[current.node].add(current)
            
            # Check if reached target
            if current.node == target:
                # Check if this solution is not dominated by existing solutions
                is_new_solution = True
                for sol_cost in list(solution_costs):
                    # Check dominance
                    dominated_by_existing = all(
                        s <= c for s, c in zip(sol_cost, current.cost_vector)
                    ) and any(s < c for s, c in zip(sol_cost, current.cost_vector))
                    
                    dominates_existing = all(
                        c <= s for c, s in zip(current.cost_vector, sol_cost)
                    ) and any(c < s for c, s in zip(current.cost_vector, sol_cost))
                    
                    if dominated_by_existing:
                        is_new_solution = False
                        break
                    
                    if dominates_existing:
                        solution_costs.discard(sol_cost)
                
                if is_new_solution:
                    solution_costs.add(current.cost_vector)
                    solutions.append(AttackPath(
                        vulnerabilities=current.path.copy(),
                        total_cost=current.cost_vector,
                        source=source,
                        target=target
                    ))
                continue
            
            # Check depth limit
            if len(current.path) >= max_depth:
                continue
            
            # Expand neighbors
            for next_node, vuln in self.graph.get_neighbors(current.node):
                # Calculate new cost
                edge_cost = vuln.get_cost_vector()
                new_cost = self._add_cost_vectors(current.cost_vector, edge_cost)
                
                # Create new label
                new_path = current.path + [vuln]
                new_label = NAMOALabel(
                    cost_vector=new_cost,
                    node=next_node,
                    path=new_path
                )
                
                # Check if dominated by closed labels
                if self._is_dominated(new_label, g_cl[next_node]):
                    continue
                
                # Check if dominated by open labels
                if self._is_dominated(new_label, g_op[next_node]):
                    continue
                
                # Remove dominated labels from open
                g_op[next_node] = {
                    l for l in g_op[next_node] 
                    if not new_label.dominates(l)
                }
                
                # Add new label
                g_op[next_node].add(new_label)
                heapq.heappush(open_set, (sum(new_cost), new_label))
        
        # Filter dominated solutions
        final_solutions = []
        for sol in solutions:
            is_dominated = False
            for other in solutions:
                if other is sol:
                    continue
                if all(o <= s for o, s in zip(other.total_cost, sol.total_cost)) and \
                   any(o < s for o, s in zip(other.total_cost, sol.total_cost)):
                    is_dominated = True
                    break
            if not is_dominated:
                final_solutions.append(sol)
        
        return sorted(final_solutions, key=lambda p: p.risk_score, reverse=True)
    
    def find_all_critical_paths(self, max_depth: int = 10) -> Dict[str, List[AttackPath]]:
        """
        Find all Pareto-optimal paths from all entry points to all critical assets.
        
        Returns:
            Dictionary mapping (source, target) to list of paths
        """
        all_paths = {}
        
        for entry in self.graph.entry_points:
            for asset in self.graph.critical_assets:
                key = f"{entry} → {asset}"
                paths = self.find_paths(entry, asset, max_depth)
                if paths:
                    all_paths[key] = paths
        
        return all_paths
    
    def get_risk_summary(self) -> Dict:
        """Generate a risk summary for the entire network."""
        all_paths = self.find_all_critical_paths()
        
        total_paths = sum(len(paths) for paths in all_paths.values())
        
        if total_paths == 0:
            return {
                'total_paths': 0,
                'highest_risk_path': None,
                'critical_vulnerabilities': [],
                'risk_level': 'LOW'
            }
        
        # Find highest risk path
        all_path_list = [p for paths in all_paths.values() for p in paths]
        highest_risk = max(all_path_list, key=lambda p: p.risk_score)
        
        # Find most critical vulnerabilities (appear in most paths)
        vuln_counts = defaultdict(int)
        for path in all_path_list:
            for vuln in path.vulnerabilities:
                vuln_counts[vuln.cve_id] += 1
        
        critical_vulns = sorted(vuln_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        
        # Determine overall risk level
        max_risk = highest_risk.risk_score
        if max_risk >= 4.0:
            risk_level = 'CRITICAL'
        elif max_risk >= 3.0:
            risk_level = 'HIGH'
        elif max_risk >= 2.0:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        return {
            'total_paths': total_paths,
            'path_breakdown': {k: len(v) for k, v in all_paths.items()},
            'highest_risk_path': highest_risk.to_dict(),
            'critical_vulnerabilities': [
                {'cve_id': cve, 'path_count': count}
                for cve, count in critical_vulns
            ],
            'risk_level': risk_level,
            'recommendation': self._get_recommendation(risk_level, critical_vulns)
        }
    
    def _get_recommendation(self, risk_level: str, critical_vulns: List) -> str:
        """Generate remediation recommendation."""
        if risk_level == 'CRITICAL':
            return f"IMMEDIATE ACTION REQUIRED: Patch {critical_vulns[0][0] if critical_vulns else 'critical vulnerabilities'} immediately. This vulnerability appears in multiple attack paths to critical assets."
        elif risk_level == 'HIGH':
            return f"HIGH PRIORITY: Schedule patching for top vulnerabilities within 24-48 hours. Focus on {critical_vulns[0][0] if critical_vulns else 'high-severity vulnerabilities'}."
        elif risk_level == 'MEDIUM':
            return "MODERATE RISK: Review and prioritize patching within the next sprint cycle."
        else:
            return "LOW RISK: Continue regular patching schedule. No immediate action required."


def create_sample_network() -> AttackGraph:
    """Create a sample network for demonstration."""
    graph = AttackGraph()
    
    # Add nodes
    graph.add_node("internet", is_entry=True)
    graph.add_node("dmz_web")
    graph.add_node("dmz_mail")
    graph.add_node("internal_app")
    graph.add_node("internal_db")
    graph.add_node("admin_server")
    graph.add_node("database_server", is_critical=True)
    graph.add_node("domain_controller", is_critical=True)
    
    # Add vulnerabilities (edges)
    vulnerabilities = [
        # Internet to DMZ
        Vulnerability("CVE-2024-1001", "internet", "dmz_web", "CRITICAL", 9.8, 3.9, 5.9, True, "Remote code execution in web server"),
        Vulnerability("CVE-2024-1002", "internet", "dmz_mail", "HIGH", 7.5, 3.1, 4.2, False, "Email server authentication bypass"),
        
        # DMZ to Internal
        Vulnerability("CVE-2024-2001", "dmz_web", "internal_app", "HIGH", 8.1, 2.8, 5.2, True, "Web app SQL injection"),
        Vulnerability("CVE-2024-2002", "dmz_mail", "internal_app", "MEDIUM", 6.5, 2.1, 4.4, False, "Credential theft via phishing"),
        Vulnerability("CVE-2024-2003", "dmz_web", "internal_db", "CRITICAL", 9.1, 3.5, 5.6, True, "Direct database access via SQLi"),
        
        # Internal lateral movement
        Vulnerability("CVE-2024-3001", "internal_app", "admin_server", "HIGH", 7.8, 2.5, 5.3, False, "Privilege escalation"),
        Vulnerability("CVE-2024-3002", "internal_db", "admin_server", "MEDIUM", 5.5, 1.8, 3.7, False, "Stored credentials"),
        Vulnerability("CVE-2024-3003", "internal_app", "database_server", "HIGH", 8.5, 3.2, 5.3, True, "Application server compromise"),
        
        # To critical assets
        Vulnerability("CVE-2024-4001", "admin_server", "database_server", "CRITICAL", 9.5, 3.8, 5.7, True, "Admin access to DB"),
        Vulnerability("CVE-2024-4002", "admin_server", "domain_controller", "CRITICAL", 9.9, 3.9, 6.0, True, "Domain admin compromise"),
        Vulnerability("CVE-2024-4003", "internal_db", "database_server", "HIGH", 7.2, 2.9, 4.3, False, "Database replication exploit"),
    ]
    
    for vuln in vulnerabilities:
        graph.add_edge(vuln)
    
    return graph


# CLI for testing
if __name__ == "__main__":
    print("="*70)
    print("NAMOA* Attack Path Analyzer - Demo")
    print("="*70)
    
    # Create sample network
    graph = create_sample_network()
    analyzer = NAMOAPathAnalyzer(graph)
    
    print(f"\nNetwork topology:")
    print(f"  Nodes: {len(graph.nodes)}")
    print(f"  Entry points: {graph.entry_points}")
    print(f"  Critical assets: {graph.critical_assets}")
    print(f"  Vulnerabilities: {sum(len(v) for v in graph.edges.values())}")
    
    # Find all paths
    print("\n" + "="*70)
    print("Finding all Pareto-optimal attack paths...")
    print("="*70)
    
    all_paths = analyzer.find_all_critical_paths()
    
    for route, paths in all_paths.items():
        print(f"\n{route}: {len(paths)} optimal path(s)")
        for i, path in enumerate(paths[:3]):  # Show top 3
            print(f"\n  Path {i+1} (Risk: {path.risk_score:.2f}):")
            for vuln in path.vulnerabilities:
                print(f"    → {vuln.source} --[{vuln.cve_id} ({vuln.severity})]-- {vuln.target}")
    
    # Risk summary
    print("\n" + "="*70)
    print("Risk Summary")
    print("="*70)
    
    summary = analyzer.get_risk_summary()
    print(f"\n  Total attack paths: {summary['total_paths']}")
    print(f"  Risk level: {summary['risk_level']}")
    print(f"\n  Most critical vulnerabilities:")
    for v in summary['critical_vulnerabilities']:
        print(f"    - {v['cve_id']}: appears in {v['path_count']} paths")
    print(f"\n  Recommendation: {summary['recommendation']}")
