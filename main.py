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


def main(use_gnn: bool = False):
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

    # Optional: refine edge success-probabilities with the GNN (rule-vs-GNN ablation)
    if use_gnn:
        from ml.gnn.refine import refine_graph_costs, DEFAULT_CHECKPOINT
        from core.threat_data import ThreatDataProvider
        n = refine_graph_costs(graph, provider=ThreatDataProvider(offline=True))
        src = "A3-trained checkpoint" if DEFAULT_CHECKPOINT.exists() else "untrained model"
        console.print(
            f"   [magenta]GNN-refined {n} edge success-probabilities[/magenta] "
            f"[dim]({src})[/dim]\n"
        )

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


def run_quick_demo(use_gnn: bool = False):
    """Run a minimal demo for testing"""
    console.print("[bold]Quick Demo Mode[/bold]\n")

    from core.logging_system import ResearchLogger
    from core.attack_graph import create_sample_enterprise_graph
    from algorithms.namoa_star import run_namoa_star

    logger = ResearchLogger("QuickDemo", console_output=False)
    graph = create_sample_enterprise_graph(logger=logger)
    if use_gnn:
        from ml.gnn.refine import refine_graph_costs, DEFAULT_CHECKPOINT
        from core.threat_data import ThreatDataProvider
        n = refine_graph_costs(graph, provider=ThreatDataProvider(offline=True))
        src = "A3-trained checkpoint" if DEFAULT_CHECKPOINT.exists() else "untrained model"
        console.print(f"✓ GNN-refined {n} edge success-probabilities ({src})")
    result = run_namoa_star(graph, logger=logger)
    
    console.print(f"✓ Graph: {graph.num_nodes} nodes, {graph.num_edges} edges")
    console.print(f"✓ Found {len(result.pareto_paths)} Pareto-optimal paths")
    console.print(f"✓ Execution time: {result.execution_time_ms:.2f} ms")
    
    return graph, result


# =============================================================================
# CLI command handlers (each imports lazily so missing optional deps don't break
# the whole CLI)
# =============================================================================

def cmd_demo(args):
    """Run the sample enterprise attack-graph demonstration."""
    run_quick_demo(use_gnn=args.gnn) if args.quick else main(use_gnn=args.gnn)


def cmd_scan_web(args):
    """Scan a website and find data-grounded Pareto-optimal attack paths."""
    from scanners.website_analyzer import analyze_website
    console.print(f"[bold cyan]Scanning[/bold cyan] {args.url} (mode={args.mode})...\n")
    result = analyze_website(args.url, mode=args.mode)
    d = result.to_dict()
    console.print(Panel(
        f"Vulnerabilities: [yellow]{d['scan_summary']['total_vulnerabilities']}[/yellow]   "
        f"Risk score: [red]{d['scan_summary']['risk_score']:.1f}[/red]   "
        f"Attack paths: [magenta]{d['attack_paths']}[/magenta]   "
        f"({d['analysis_time_seconds']:.1f}s)",
        title=f"Scan: {d['scan_summary']['target']}", border_style="cyan"))
    for rec in d.get("top_recommendations", [])[:5]:
        console.print(f"  [{rec.get('severity','?')}] {rec.get('title','')}")


def cmd_review_code(args):
    """Run the Claude-based code security reviewer over files/dirs."""
    from scanners.llm_code_review import LLMCodeReviewer
    reviewer = LLMCodeReviewer(model=args.model)
    if not reviewer.available:
        console.print(f"[yellow]LLM reviewer unavailable:[/yellow] {reviewer._unavailable_reason}")
        console.print("[dim]Install `anthropic` and set ANTHROPIC_API_KEY to enable.[/dim]")
        return
    paths = []
    for p in args.paths:
        pp = Path(p)
        paths.extend(str(f) for f in pp.rglob("*.py")) if pp.is_dir() else paths.append(str(pp))
    console.print(f"[bold cyan]Reviewing[/bold cyan] {len(paths)} file(s) with {args.model}...\n")
    findings = reviewer.review_paths(paths)
    console.print(f"[bold]{len(findings)} finding(s)[/bold]\n")
    for f in sorted(findings, key=lambda x: -x.severity.value):
        console.print(f"  [{f.severity.name}] {f.title}  {f.cve_ids or f.cwe_ids}")
        if f.solution:
            console.print(f"      [dim]{f.solution[:100]}[/dim]")


def cmd_threat_data(args):
    """Refresh/inspect the EPSS + CISA KEV (+ optional NVD) feeds with provenance + staleness."""
    from core.threat_data import ThreatDataProvider
    provider = ThreatDataProvider()

    if args.refresh:
        from core.threat_feeds import refresh_feeds
        sources = "EPSS + CISA KEV" + (" + NVD recent window" if args.nvd else "")
        console.print(f"[bold cyan]Refreshing[/bold cyan] {sources}...")
        refresh_feeds(provider=provider, include_nvd=args.nvd, nvd_days=args.nvd_days)

    stats = provider.stats()
    if stats["epss_cves"] == 0 and stats["kev_cves"] == 0:
        console.print("[yellow]No data cached.[/yellow] Run with --refresh while online "
                      "to download (needs network + certifi CA bundle).")
        return

    # Provenance + staleness table (the 3a deliverable: every source carries its as-of date).
    staleness = provider.staleness()
    table = Table(title="Threat-feed provenance & staleness", show_header=True)
    for col in ("Source", "Records", "Source as-of", "Version", "Fetched (age)", "Status"):
        table.add_column(col)
    color = {"fresh": "green", "stale": "yellow", "unknown": "dim"}
    for src in ("epss", "kev", "nvd"):
        s = staleness.get(src)
        if not s:
            continue
        age = f"{s['age_hours']:.1f}h" if s.get("age_hours") is not None else "?"
        status = s.get("status", "unknown")
        table.add_row(
            src.upper(),
            f"{s.get('record_count') or 0:,}",
            (s.get("source_as_of") or "—")[:19],
            str(s.get("source_version") or "—"),
            age,
            f"[{color.get(status, 'dim')}]{status}[/{color.get(status, 'dim')}]")
    console.print(table)
    console.print(f"[dim]Cache: {stats['cache_dir']}[/dim]")

    for cve in args.cve:
        epss = provider.epss(cve)
        console.print(f"  {cve}: epss={epss if epss is not None else 'n/a'}  "
                      f"kev={provider.is_kev(cve)}")


def cmd_analyze_network(args):
    """Build a multi-host network, find Pareto-optimal lateral-movement attack paths."""
    from core.logging_system import ResearchLogger
    from core.network_builder import create_sample_multihost_network
    from core.threat_data import ThreatDataProvider
    from core.node_types import NodeType
    from algorithms.namoa_star import run_namoa_star

    logger = ResearchLogger("AnalyzeNetwork", console_output=False)
    graph = create_sample_multihost_network(provider=ThreatDataProvider(), logger=logger)

    if args.gnn:
        from ml.gnn.refine import refine_graph_costs, DEFAULT_CHECKPOINT
        n = refine_graph_costs(graph, provider=ThreatDataProvider(offline=True))
        src = "A3-trained checkpoint" if DEFAULT_CHECKPOINT.exists() else "untrained model"
        console.print(f"[magenta]GNN-refined {n} edge success-probabilities[/magenta] [dim]({src})[/dim]")

    result = run_namoa_star(graph, logger=logger)
    console.print(Panel(
        f"Nodes: [cyan]{graph.num_nodes}[/cyan]   Edges: [cyan]{graph.num_edges}[/cyan]   "
        f"Pareto attack paths: [magenta]{len(result.pareto_paths)}[/magenta]",
        title="Multi-host network analysis", border_style="cyan"))

    def host_hops(path):
        return [graph.get_node(nid).hostname for nid in path
                if graph.get_node(nid) and graph.get_node(nid).node_type == NodeType.ASSET]

    # cost.values = [time (sum), success probability (∏ pᵢ), business impact (max)]
    for i, (path, cost) in enumerate(result.pareto_paths[:10], 1):
        console.print(f"  {i}. [green]{' → '.join(host_hops(path))}[/green]  "
                      f"[dim]time={cost.values[0]:.2f} success={cost.values[1]:.3f} "
                      f"impact={cost.values[2]:.2f}[/dim]")


def cmd_import_scan(args):
    """Import a Nessus/Qualys/OpenVAS/nmap scan file → multi-host attack graph → Pareto paths."""
    from core.logging_system import ResearchLogger
    from core.threat_data import ThreatDataProvider
    from core.node_types import NodeType
    from scanners.scan_import import import_scan_file
    from algorithms.namoa_star import run_namoa_star

    logger = ResearchLogger("ImportScan", console_output=False)
    provider = None if args.no_threat_data else ThreatDataProvider()
    graph, spec, findings, fmt = import_scan_file(
        args.file, fmt=args.format, provider=provider, logger_=logger,
        reachability=args.reachability)

    vulns = [v for h in spec.hosts for v in h.vulnerabilities]
    grounded = sum(1 for v in vulns if provider and provider.epss(v.cve_id) is not None)
    result = run_namoa_star(graph, logger=logger)

    console.print(Panel(
        f"Format: [cyan]{fmt}[/cyan]   Hosts: [cyan]{len(spec.hosts)}[/cyan]   "
        f"Vulns: [cyan]{len(vulns)}[/cyan]   "
        f"EPSS-grounded: [green]{grounded}/{len(vulns)}[/green]\n"
        f"Graph: [cyan]{graph.num_nodes}[/cyan] nodes / [cyan]{graph.num_edges}[/cyan] edges   "
        f"Pareto attack paths: [magenta]{len(result.pareto_paths)}[/magenta]",
        title=f"Imported scan: {args.file}", border_style="cyan"))

    def host_hops(path):
        return [graph.get_node(nid).name for nid in path
                if graph.get_node(nid) and graph.get_node(nid).node_type == NodeType.ASSET]

    for i, (path, cost) in enumerate(result.pareto_paths[:10], 1):
        console.print(f"  {i}. [green]{' → '.join(host_hops(path))}[/green]  "
                      f"[dim]time={cost.values[0]:.2f} success={cost.values[1]:.3f} "
                      f"impact={cost.values[2]:.2f}[/dim]")
    console.print("[yellow]Note:[/yellow] [dim]host vulnerabilities are from the scan (data-grounded); "
                  "reachability/zones/entry/goal are INFERRED heuristics (not in any scan file) — "
                  "override with ground truth for production use.[/dim]")


def cmd_compare_baselines(args):
    """Demonstrate CVSS-ranking vs NAMOA* Pareto divergence (offline)."""
    import logging
    logging.disable(logging.CRITICAL)
    from evaluation.baseline_comparison import illustrative_scenario, compare
    out = compare(*illustrative_scenario())
    console.print(Panel(
        f"CVSS-only would fix:  [yellow]{out['cvss_top']}[/yellow]\n"
        f"Pareto-path-critical: [green]{out['path_critical']}[/green]  "
        f"({out['num_pareto_paths']} path(s); critical={out['pareto_critical_counts']})\n"
        f"Diverge: [bold]{out['diverge']}[/bold]",
        title="Baseline comparison (illustrative)", border_style="magenta"))


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        prog="ctppo", description="Cyber Threat Propagation Path Optimizer")
    parser.add_argument("--verbose", "-v", action="store_true", help="verbose tracebacks")
    sub = parser.add_subparsers(dest="command")

    p_demo = sub.add_parser("demo", help="sample enterprise attack-graph demo")
    p_demo.add_argument("--quick", action="store_true", help="minimal output")
    p_demo.add_argument("--gnn", action="store_true",
                        help="run NAMOA* on GNN-refined costs (rule-vs-GNN ablation)")
    p_demo.set_defaults(func=cmd_demo)

    p_web = sub.add_parser("scan-web", help="scan a website for attack paths")
    p_web.add_argument("url")
    p_web.add_argument("--mode", choices=["quick", "full"], default="quick")
    p_web.set_defaults(func=cmd_scan_web)

    p_code = sub.add_parser("review-code", help="LLM security review of source files")
    p_code.add_argument("paths", nargs="+")
    p_code.add_argument("--model", default="claude-opus-4-8")
    p_code.set_defaults(func=cmd_review_code)

    p_net = sub.add_parser("analyze-network", help="multi-host lateral-movement attack paths")
    p_net.add_argument("--gnn", action="store_true",
                       help="run NAMOA* on GNN-refined costs (rule-vs-GNN ablation)")
    p_net.set_defaults(func=cmd_analyze_network)

    p_imp = sub.add_parser("import-scan",
                           help="import a Nessus/Qualys/OpenVAS/nmap scan file → attack paths")
    p_imp.add_argument("file", help="path to the scanner output file (.nessus/.xml)")
    p_imp.add_argument("--format", default="auto",
                       choices=["auto", "nessus", "qualys", "openvas", "nmap"],
                       help="scan format (default: auto-detect)")
    p_imp.add_argument("--reachability", default="subnet", choices=["subnet", "full_mesh"],
                       help="INFERRED host-to-host reachability policy (default: subnet)")
    p_imp.add_argument("--no-threat-data", action="store_true",
                       help="skip EPSS/KEV lookup (CVSS-only costs)")
    p_imp.set_defaults(func=cmd_import_scan)

    p_cmp = sub.add_parser("compare-baselines", help="CVSS-ranking vs NAMOA* Pareto (offline)")
    p_cmp.set_defaults(func=cmd_compare_baselines)

    p_td = sub.add_parser("threat-data",
                          help="refresh/inspect EPSS + CISA KEV (+ NVD) with provenance & staleness")
    p_td.add_argument("--refresh", action="store_true", help="force re-download (ignores TTL)")
    p_td.add_argument("--nvd", action="store_true",
                      help="also refresh the NVD recent-changes window (per-CVE CVSS)")
    p_td.add_argument("--nvd-days", type=int, default=1,
                      help="NVD recent-changes window in days (default 1)")
    p_td.add_argument("--cve", nargs="*", default=["CVE-2021-44228", "CVE-2017-0144"],
                      help="CVEs to look up after loading")
    p_td.set_defaults(func=cmd_threat_data)

    args = parser.parse_args()
    if not getattr(args, "command", None):
        args.quick = False
        args.gnn = False
        args.func = cmd_demo  # default to the demo

    try:
        args.func(args)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
