#!/usr/bin/env python3
"""
Quick Test Script for CTPPO
===========================

Run this script to verify your installation is working correctly.
This will test all core components and provide a summary.

Usage:
    python run_quick_test.py

Author: Ruthvik
Date: November 2025
"""

import sys
import time
from pathlib import Path

# Add project to path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

def print_header(text):
    print(f"\n{'='*60}")
    print(f"  {text}")
    print(f"{'='*60}")

def print_test(name, passed, details=""):
    status = "✓ PASS" if passed else "✗ FAIL"
    color_start = "\033[92m" if passed else "\033[91m"
    color_end = "\033[0m"
    print(f"{color_start}{status}{color_end} | {name}")
    if details and not passed:
        print(f"       Details: {details}")

def test_imports():
    """Test that all modules can be imported"""
    tests_passed = 0
    tests_total = 0
    
    print_header("Testing Module Imports")
    
    # Core imports
    try:
        from core.node_types import AssetNode, VulnerabilityNode, ExploitNode
        print_test("core.node_types", True)
        tests_passed += 1
    except Exception as e:
        print_test("core.node_types", False, str(e))
    tests_total += 1
    
    try:
        from core.edge_costs import EdgeCostVector, CostType, Distribution
        print_test("core.edge_costs", True)
        tests_passed += 1
    except Exception as e:
        print_test("core.edge_costs", False, str(e))
    tests_total += 1
    
    try:
        from core.attack_graph import AttackGraph, create_sample_enterprise_graph
        print_test("core.attack_graph", True)
        tests_passed += 1
    except Exception as e:
        print_test("core.attack_graph", False, str(e))
    tests_total += 1
    
    try:
        from core.logging_system import ResearchLogger
        print_test("core.logging_system", True)
        tests_passed += 1
    except Exception as e:
        print_test("core.logging_system", False, str(e))
    tests_total += 1
    
    try:
        from algorithms.pareto_utils import CostVector, ParetoSet, fast_nondominated_sort
        print_test("algorithms.pareto_utils", True)
        tests_passed += 1
    except Exception as e:
        print_test("algorithms.pareto_utils", False, str(e))
    tests_total += 1
    
    return tests_passed, tests_total

def test_graph_creation():
    """Test graph creation and basic operations"""
    tests_passed = 0
    tests_total = 0
    
    print_header("Testing Graph Operations")
    
    try:
        from core.attack_graph import AttackGraph, create_sample_enterprise_graph
        from core.node_types import AssetNode, AssetType
        
        # Test empty graph
        graph = AttackGraph(name="TestGraph")
        assert graph.num_nodes == 0
        assert graph.num_edges == 0
        print_test("Create empty graph", True)
        tests_passed += 1
    except Exception as e:
        print_test("Create empty graph", False, str(e))
    tests_total += 1
    
    try:
        # Test adding nodes
        asset = AssetNode(
            name="TestServer",
            asset_type=AssetType.SERVER,
            ip_addresses=["192.168.1.1"],
            criticality=8.0
        )
        graph.add_node(asset)
        assert graph.num_nodes == 1
        print_test("Add node to graph", True)
        tests_passed += 1
    except Exception as e:
        print_test("Add node to graph", False, str(e))
    tests_total += 1
    
    try:
        # Test sample graph creation
        sample_graph = create_sample_enterprise_graph()
        assert sample_graph.num_nodes > 0
        assert sample_graph.num_edges > 0
        print_test(f"Create sample graph ({sample_graph.num_nodes} nodes, {sample_graph.num_edges} edges)", True)
        tests_passed += 1
    except Exception as e:
        print_test("Create sample graph", False, str(e))
    tests_total += 1
    
    try:
        # Test path finding
        paths = sample_graph.get_attack_paths_from_entry_points(max_length=8)
        total_paths = sum(len(p) for p in paths.values())
        print_test(f"Find attack paths ({total_paths} paths found)", True)
        tests_passed += 1
    except Exception as e:
        print_test("Find attack paths", False, str(e))
    tests_total += 1
    
    return tests_passed, tests_total

def test_distributions():
    """Test probability distributions"""
    tests_passed = 0
    tests_total = 0
    
    print_header("Testing Probability Distributions")
    
    try:
        from core.edge_costs import (
            NormalDistribution, LogNormalDistribution, 
            BetaDistribution, PERTDistribution
        )
        import numpy as np
        
        # Test Normal distribution
        normal = NormalDistribution(mu=5.0, sigma=1.0)
        samples = normal.sample(1000)
        assert abs(np.mean(samples) - 5.0) < 0.2
        print_test("Normal distribution sampling", True)
        tests_passed += 1
    except Exception as e:
        print_test("Normal distribution sampling", False, str(e))
    tests_total += 1
    
    try:
        # Test Beta distribution
        beta = BetaDistribution(alpha=2, beta=5)
        samples = beta.sample(1000)
        assert 0 <= np.mean(samples) <= 1
        print_test("Beta distribution sampling", True)
        tests_passed += 1
    except Exception as e:
        print_test("Beta distribution sampling", False, str(e))
    tests_total += 1
    
    try:
        # Test PERT distribution
        pert = PERTDistribution(minimum=1, most_likely=5, maximum=10)
        samples = pert.sample(1000)
        assert np.min(samples) >= 1
        assert np.max(samples) <= 10
        print_test("PERT distribution sampling", True)
        tests_passed += 1
    except Exception as e:
        print_test("PERT distribution sampling", False, str(e))
    tests_total += 1
    
    return tests_passed, tests_total

def test_pareto_operations():
    """Test Pareto dominance and set operations"""
    tests_passed = 0
    tests_total = 0
    
    print_header("Testing Pareto Operations")
    
    try:
        from algorithms.pareto_utils import CostVector, ParetoSet, LabeledSolution
        import numpy as np
        
        # Test dominance
        c1 = CostVector(np.array([1.0, 2.0]))
        c2 = CostVector(np.array([2.0, 3.0]))
        assert c1.dominates(c2)
        assert not c2.dominates(c1)
        print_test("Pareto dominance checking", True)
        tests_passed += 1
    except Exception as e:
        print_test("Pareto dominance checking", False, str(e))
    tests_total += 1
    
    try:
        # Test Pareto set
        pareto = ParetoSet()
        pareto.add(LabeledSolution("A", CostVector(np.array([1.0, 4.0]))))
        pareto.add(LabeledSolution("B", CostVector(np.array([2.0, 3.0]))))
        pareto.add(LabeledSolution("C", CostVector(np.array([4.0, 1.0]))))
        pareto.add(LabeledSolution("D", CostVector(np.array([2.5, 2.5]))))  # Dominated
        assert len(pareto) == 3  # D should be filtered
        print_test("Pareto set maintenance", True)
        tests_passed += 1
    except Exception as e:
        print_test("Pareto set maintenance", False, str(e))
    tests_total += 1
    
    try:
        # Test hypervolume
        from algorithms.pareto_utils import compute_hypervolume
        front = pareto.get_pareto_front()
        hv = compute_hypervolume(front, np.array([5.0, 5.0]))
        assert hv > 0
        print_test(f"Hypervolume computation (HV={hv:.2f})", True)
        tests_passed += 1
    except Exception as e:
        print_test("Hypervolume computation", False, str(e))
    tests_total += 1
    
    return tests_passed, tests_total

def test_logging():
    """Test research logging system"""
    tests_passed = 0
    tests_total = 0
    
    print_header("Testing Logging System")
    
    try:
        from core.logging_system import ResearchLogger
        import tempfile
        from pathlib import Path
        
        # Create logger with temp directory
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = ResearchLogger(
                name="TestLogger",
                log_dir=Path(tmpdir),
                console_output=False
            )
            
            logger.info("TEST", "Test message", {"key": "value"})
            logger.algorithm("ALGO", "Algorithm decision", {"param": 123})
            logger.metric("METRIC", "Performance metric", {"accuracy": 0.95})
            
            assert len(logger.entries) == 3
            print_test("Log entry creation", True)
            tests_passed += 1
    except Exception as e:
        print_test("Log entry creation", False, str(e))
    tests_total += 1
    
    try:
        # Test timer context
        with logger.timer("TEST", "Timed operation"):
            time.sleep(0.01)
        
        assert len(logger.entries) >= 4
        print_test("Timer context manager", True)
        tests_passed += 1
    except Exception as e:
        print_test("Timer context manager", False, str(e))
    tests_total += 1
    
    return tests_passed, tests_total

def main():
    """Run all tests"""
    print("\n" + "="*60)
    print("  CTPPO - Quick Test Suite")
    print("  Verifying installation and core functionality")
    print("="*60)
    
    start_time = time.time()
    
    total_passed = 0
    total_tests = 0
    
    # Run test suites
    passed, total = test_imports()
    total_passed += passed
    total_tests += total
    
    passed, total = test_graph_creation()
    total_passed += passed
    total_tests += total
    
    passed, total = test_distributions()
    total_passed += passed
    total_tests += total
    
    passed, total = test_pareto_operations()
    total_passed += passed
    total_tests += total
    
    passed, total = test_logging()
    total_passed += passed
    total_tests += total
    
    # Summary
    elapsed = time.time() - start_time
    
    print_header("Test Summary")
    
    if total_passed == total_tests:
        print(f"\033[92m")
        print(f"  All tests passed! ({total_passed}/{total_tests})")
        print(f"  Time elapsed: {elapsed:.2f}s")
        print(f"\033[0m")
        print("\n✓ Your installation is working correctly!")
        print("\nNext step: Run 'python run_demo.py' to see the full demo")
        return 0
    else:
        print(f"\033[91m")
        print(f"  {total_passed}/{total_tests} tests passed")
        print(f"  {total_tests - total_passed} tests failed")
        print(f"\033[0m")
        print("\n✗ Some tests failed. Please check the errors above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
