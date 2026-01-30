#!/usr/bin/env python3
"""
Quick Installation Test
=======================

Run this to verify all components are working correctly.

Usage:
    python test_installation.py
"""

import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

def test_imports():
    """Test all imports"""
    print("Testing imports...")
    
    tests = [
        ("Core - Attack Graph", "from core.attack_graph import AttackGraph"),
        ("Core - Node Types", "from core.node_types import AssetNode, VulnerabilityNode"),
        ("Core - Edge Costs", "from core.edge_costs import EdgeCostVector"),
        ("Core - Logging", "from core.logging_system import ResearchLogger"),
        ("Algorithms - NAMOA*", "from algorithms.namoa_star import run_namoa_star"),
        ("Algorithms - Pareto", "from algorithms.pareto_utils import ParetoSet"),
        ("Scanners - Models", "from scanners.models import VulnerabilityFinding, ScanResult"),
        ("Scanners - Unified", "from scanners.unified_scanner import UnifiedScanner"),
        ("Scanners - Analyzer", "from scanners.website_analyzer import WebsiteSecurityAnalyzer"),
        ("ML - GNN Predictor", "from ml.gnn_predictor import AttackPathPredictor"),
        ("ML - Severity Classifier", "from ml.severity_classifier import SeverityClassifier"),
        ("ML - RL Defender", "from ml.rl_defender import DefenseOptimizer"),
    ]
    
    passed = 0
    failed = 0
    
    for name, import_stmt in tests:
        try:
            exec(import_stmt)
            print(f"  ✓ {name}")
            passed += 1
        except Exception as e:
            print(f"  ✗ {name}: {e}")
            failed += 1
    
    return passed, failed


def test_sample_graph():
    """Test creating a sample attack graph"""
    print("\nTesting sample graph creation...")
    
    try:
        from core.attack_graph import create_sample_enterprise_graph
        from core.logging_system import get_default_logger
        
        logger = get_default_logger()
        graph = create_sample_enterprise_graph(logger)
        
        print(f"  ✓ Created graph with {graph.num_nodes} nodes and {graph.num_edges} edges")
        return True
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        return False


def test_namoa_star():
    """Test NAMOA* algorithm"""
    print("\nTesting NAMOA* algorithm...")
    
    try:
        from core.attack_graph import create_sample_enterprise_graph
        from core.logging_system import get_default_logger
        from algorithms.namoa_star import run_namoa_star
        
        logger = get_default_logger()
        graph = create_sample_enterprise_graph(logger)
        result = run_namoa_star(graph, logger=logger)
        
        print(f"  ✓ Found {len(result.pareto_paths)} Pareto-optimal paths")
        print(f"  ✓ Execution time: {result.execution_time_ms:.2f}ms")
        return True
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_ml_components():
    """Test ML components"""
    print("\nTesting ML components...")
    
    try:
        from ml.gnn_predictor import AttackPathPredictor
        from ml.severity_classifier import SeverityClassifier
        from ml.rl_defender import DefenseOptimizer
        
        # Test GNN predictor
        predictor = AttackPathPredictor()
        print("  ✓ GNN Attack Path Predictor initialized")
        
        # Test severity classifier
        classifier = SeverityClassifier()
        print("  ✓ Severity Classifier initialized")
        
        # Test RL defender
        defender = DefenseOptimizer()
        print("  ✓ RL Defense Optimizer initialized")
        
        return True
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_scanner_simulation():
    """Test simulated scanner"""
    print("\nTesting simulated scanner...")
    
    try:
        from scanners.unified_scanner import UnifiedScanner
        from scanners.models import ScanTarget
        
        scanner = UnifiedScanner()
        target = ScanTarget(url="https://example.com")
        result = scanner.quick_scan("https://example.com")
        
        print(f"  ✓ Scan completed with {len(result.vulnerabilities)} findings")
        print(f"  ✓ Risk score: {result.risk_score:.1f}")
        return True
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_dashboard_imports():
    """Test dashboard imports"""
    print("\nTesting dashboard components...")
    
    try:
        import dash
        import dash_bootstrap_components
        import dash_cytoscape
        import plotly
        
        print("  ✓ Dash framework available")
        print("  ✓ Dash Bootstrap Components available")
        print("  ✓ Dash Cytoscape available")
        print("  ✓ Plotly available")
        return True
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        return False


def main():
    """Run all tests"""
    print("="*60)
    print("  CTPPO Installation Test")
    print("="*60)
    
    # Run tests
    import_passed, import_failed = test_imports()
    graph_ok = test_sample_graph()
    namoa_ok = test_namoa_star()
    ml_ok = test_ml_components()
    scanner_ok = test_scanner_simulation()
    dashboard_ok = test_dashboard_imports()
    
    # Summary
    print("\n" + "="*60)
    print("  Test Summary")
    print("="*60)
    print(f"  Imports: {import_passed} passed, {import_failed} failed")
    print(f"  Sample Graph: {'✓ PASS' if graph_ok else '✗ FAIL'}")
    print(f"  NAMOA* Algorithm: {'✓ PASS' if namoa_ok else '✗ FAIL'}")
    print(f"  ML Components: {'✓ PASS' if ml_ok else '✗ FAIL'}")
    print(f"  Scanner Simulation: {'✓ PASS' if scanner_ok else '✗ FAIL'}")
    print(f"  Dashboard Components: {'✓ PASS' if dashboard_ok else '✗ FAIL'}")
    
    all_passed = (
        import_failed == 0 and graph_ok and namoa_ok and 
        ml_ok and scanner_ok and dashboard_ok
    )
    
    if all_passed:
        print("\n✓ All tests passed! You can now run:")
        print("  python run_dashboard.py")
    else:
        print("\n✗ Some tests failed. Please check the errors above.")
    
    print("="*60)
    
    return 0 if all_passed else 1


if __name__ == '__main__':
    sys.exit(main())
