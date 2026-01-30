#!/usr/bin/env python3
"""
Cyber Threat Propagation Path Optimizer - Main Entry Point
==========================================================

This script demonstrates the complete CTPPO system:
1. Creates a sample enterprise attack graph
2. Runs NAMOA* multi-objective shortest path algorithm
3. Visualizes the results
4. Exports logs for research documentation

Run this script to see the system in action!

Usage:
    python main.py

Author: Ruthvik
Date: November 2025
"""

import sys
import os
from pathlib import Path
from datetime import datetime

# Add project root to path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

# Rich for beautiful console output
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import print as rprint

console = Console()


def print_header():
    """Print the application header"""
    header = """
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║     ██████╗████████╗██████╗ ██████╗  ██████╗                                  ║
║    ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██╔═══██╗                                 ║
║    ██║        ██║   ██████╔╝██████╔╝██║   ██║                                 ║
║    ██║        ██║   ██╔═══╝ ██╔═══╝ ██║   ██║                                 ║
║    ╚██████╗   ██║   ██║     ██║     ╚██████╔╝                                 ║
║     ╚═════╝   ╚═╝   ╚═╝     ╚═╝      ╚═════╝                                  ║
║                                                                               ║
║     Cyber Threat Propagation Path Optimizer                                   ║
║     Multi-Objective | Probabilistic | Dynamic                                 ║
║                                                                               ║
║     Author: Ruthvik                                                           ║
║     Institution: Northeastern University                                      ║
║     Course: AAI6610 - Applied Machine Learning                                ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
    """
    console.print(header, style="bold cyan")


def main():
    """Main execution function"""
    print_header()
    
    console.print("\n[bold green]═══ Starting CTPPO Demonstration ═══[/bold green]\n")
    
    # Step 1: Initialize logging
    console.print("[bold cyan]Step 1:[/bold cyan] Initializing Research Logging System...")
    
    from core.logging_system import ResearchLogger
    logger = ResearchLogger("CTPPO_Demo")
    
    console.print(f"   ✓ Log directory: [green]{logger.experiment_dir}[/green]")
    console.print(f"   ✓ Experiment ID: [green]{logger.experiment_id}[/green]\n")
    
    # Step 2: Create attack graph
    console.print("[bold cyan]Step 2:[/bold cyan] Creating Sample Enterprise Attack Graph...")
    
    from core.attack_graph import create_sample_enterprise_graph, AttackGraph
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True
    ) as progress:
        task = progress.add_task("Building attack graph...", total=None)
        graph = create_sample_enterprise_graph(logger=logger)
    
    # Display graph statistics
    stats = graph.get_statistics()
    
    stats_table = Table(title="Attack Graph Statistics", show_header=True)
    stats_table.add_column("Metric", style="cyan")
    stats_table.add_column("Value", style="green", justify="right")
    
    stats_table.add_row("Total Nodes", str(stats['num_nodes']))
    stats_table.add_row("Total Edges", str(stats['num_edges']))
    stats_table.add_row("Entry Points", str(stats['num_entry_points']))
    stats_table.add_row("Goal Nodes", str(stats['num_goals']))
    stats_table.add_row("Is DAG", str(stats.get('is_dag', 'N/A')))
    stats_table.add_row("Graph Density", f"{stats.get('density', 0):.4f}")
    
    console.print(stats_table)
    
    # Node breakdown
    console.print("\n   [bold]Nodes by Type:[/bold]")
    for node_type, count in stats['nodes_by_type'].items():
        if count > 0:
            console.print(f"      • {node_type}: {count}")
    console.print()
    
    # Step 3: Run NAMOA* Algorithm
    console.print("[bold cyan]Step 3:[/bold cyan] Running NAMOA* Multi-Objective Search...")
    console.print("   Objectives: [yellow]Time-to-Exploit[/yellow], [yellow]Success Probability[/yellow], [yellow]Business Impact[/yellow]\n")
    
    from algorithms.namoa_star import NAMOAStar, run_namoa_star
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True
    ) as progress:
        task = progress.add_task("Finding Pareto-optimal attack paths...", total=None)
        result = run_namoa_star(graph, logger=logger)
    
    # Display algorithm results
    results_table = Table(title="NAMOA* Algorithm Results", show_header=True)
    results_table.add_column("Metric", style="cyan")
    results_table.add_column("Value", style="green", justify="right")
    
    results_table.add_row("Pareto-Optimal Paths Found", str(len(result.pareto_paths)))
    results_table.add_row("Labels Created", str(result.num_labels_created))
    results_table.add_row("Labels Expanded", str(result.num_labels_expanded))
    results_table.add_row("Labels Pruned", str(result.num_labels_pruned))
    results_table.add_row("Iterations", str(result.iterations))
    results_table.add_row("Execution Time", f"{result.execution_time_ms:.2f} ms")
    if result.hypervolume:
        results_table.add_row("Hypervolume Indicator", f"{result.hypervolume:.4f}")
    
    console.print(results_table)
    
    # Step 4: Display Pareto-optimal paths
    if result.pareto_paths:
        console.print("\n[bold cyan]Step 4:[/bold cyan] Pareto-Optimal Attack Paths Discovered:\n")
        
        paths_table = Table(title="Critical Attack Paths (Pareto Front)")
        paths_table.add_column("#", style="dim", width=3)
        paths_table.add_column("Attack Path", style="cyan", max_width=50)
        paths_table.add_column("Time (hrs)", justify="right", style="yellow")
        paths_table.add_column("Success %", justify="right", style="green")
        paths_table.add_column("Impact", justify="right", style="red")
        
        for i, (path, cost) in enumerate(result.pareto_paths[:10], 1):
            # Format path with node names
            path_names = []
            for nid in path:
                node = graph.get_node(nid)
                if node:
                    name = node.name[:12] + "..." if len(node.name) > 12 else node.name
                    path_names.append(name)
            
            path_str = " → ".join(path_names)
            if len(path_str) > 50:
                path_str = path_str[:47] + "..."
            
            paths_table.add_row(
                str(i),
                path_str,
                f"{cost.values[0]:.2f}",
                f"{cost.values[1]*100:.1f}%",
                f"{cost.values[2]:.2f}"
            )
        
        console.print(paths_table)
        
        if len(result.pareto_paths) > 10:
            console.print(f"\n   [dim](Showing 10 of {len(result.pareto_paths)} paths)[/dim]")
    
    # Step 5: Analysis and Insights
    console.print("\n[bold cyan]Step 5:[/bold cyan] Security Analysis Insights:\n")
    
    if result.pareto_paths:
        # Find extreme points
        fastest_path = min(result.pareto_paths, key=lambda x: x[1].values[0])
        highest_success = max(result.pareto_paths, key=lambda x: x[1].values[1])
        lowest_impact = min(result.pareto_paths, key=lambda x: x[1].values[2])
        
        console.print("   [bold]Extreme Attack Paths:[/bold]")
        console.print(f"   • [yellow]Fastest Attack:[/yellow] {fastest_path[1].values[0]:.2f} hours")
        console.print(f"   • [green]Highest Success Rate:[/green] {highest_success[1].values[1]*100:.1f}%")
        console.print(f"   • [red]Lowest Detection Risk:[/red] Impact score {lowest_impact[1].values[2]:.2f}")
        
        # Efficiency metrics
        pruning_rate = result.num_labels_pruned / max(1, result.num_labels_created) * 100
        console.print(f"\n   [bold]Algorithm Efficiency:[/bold]")
        console.print(f"   • Pruning Rate: {pruning_rate:.1f}% (labels filtered by dominance)")
        console.print(f"   • Expansion Efficiency: {result.num_labels_expanded / max(1, result.num_labels_created) * 100:.1f}%")
    
    # Step 6: Export for Research Paper
    console.print("\n[bold cyan]Step 6:[/bold cyan] Exporting Logs for Research Documentation...")
    
    export_paths = logger.export_for_paper()
    
    console.print(f"   ✓ Metrics CSV: [green]{export_paths.get('metrics_csv', 'N/A')}[/green]")
    console.print(f"   ✓ Algorithm Decisions: [green]{export_paths.get('algorithm_md', 'N/A')}[/green]")
    console.print(f"   ✓ Experiment Summary: [green]{export_paths.get('summary_json', 'N/A')}[/green]")
    
    # Final summary
    console.print("\n" + "═" * 80)
    console.print(Panel(
        f"""
[bold green]✓ CTPPO Demonstration Complete![/bold green]

[bold]Summary:[/bold]
• Analyzed enterprise network with {stats['num_nodes']} nodes and {stats['num_edges']} edges
• Found {len(result.pareto_paths)} Pareto-optimal attack paths
• Algorithm completed in {result.execution_time_ms:.2f} ms
• All logs exported for research paper documentation

[bold]Next Steps:[/bold]
1. Review the attack paths in the Pareto front
2. Use the defense optimization layer to plan mitigations
3. Run experiments comparing with baseline algorithms
4. Generate visualizations for your research paper

[dim]Experiment ID: {logger.experiment_id}[/dim]
[dim]Log Directory: {logger.experiment_dir}[/dim]
        """,
        title="Execution Complete",
        border_style="green"
    ))
    
    return graph, result, logger


def run_quick_demo():
    """Run a minimal demo for testing"""
    console.print("[bold]Quick Demo Mode[/bold]\n")
    
    from core.logging_system import ResearchLogger
    from core.attack_graph import create_sample_enterprise_graph
    from algorithms.namoa_star import run_namoa_star
    
    logger = ResearchLogger("QuickDemo", console_output=False)
    graph = create_sample_enterprise_graph(logger=logger)
    result = run_namoa_star(graph, logger=logger)
    
    console.print(f"✓ Graph: {graph.num_nodes} nodes, {graph.num_edges} edges")
    console.print(f"✓ Found {len(result.pareto_paths)} Pareto-optimal paths")
    console.print(f"✓ Execution time: {result.execution_time_ms:.2f} ms")
    
    return graph, result


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Cyber Threat Propagation Path Optimizer")
    parser.add_argument("--quick", action="store_true", help="Run quick demo without visualization")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    try:
        if args.quick:
            run_quick_demo()
        else:
            main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
