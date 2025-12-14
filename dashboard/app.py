"""
Web Dashboard for Cyber Threat Analysis Platform
================================================

Interactive web interface for:
- Website security scanning
- Attack graph visualization
- Pareto frontier visualization
- Defense recommendations

Built with Dash and Plotly.

Author: Ruthvik
Date: November 2025
"""

import sys
import os
import json
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional
import threading

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import dash
from dash import dcc, html, Input, Output, State, callback, ctx
import dash_bootstrap_components as dbc
import dash_cytoscape as cyto
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import numpy as np

# Import project modules
from core.logging_system import ResearchLogger
from core.attack_graph import AttackGraph, create_sample_enterprise_graph
from core.node_types import NodeType
from scanners.models import ScanResult, VulnerabilityFinding, Severity, ScanTarget, ScanMode
from scanners.website_analyzer import WebsiteSecurityAnalyzer, SecurityAnalysisResult

# Initialize logger
logger = ResearchLogger("Dashboard")

# Load cytoscape layouts
cyto.load_extra_layouts()

# Initialize Dash app
app = dash.Dash(
    __name__,
    external_stylesheets=[
        dbc.themes.CYBORG,  # Dark theme
        "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css"
    ],
    suppress_callback_exceptions=True,
    title="CTPPO - Cyber Threat Analyzer"
)

# Global storage for scan results
scan_results: Dict[str, SecurityAnalysisResult] = {}


# =============================================================================
# Layout Components
# =============================================================================

def create_header():
    """Create dashboard header"""
    return dbc.Navbar(
        dbc.Container([
            dbc.Row([
                dbc.Col([
                    html.I(className="fas fa-shield-alt fa-2x me-3", style={"color": "#00ff88"}),
                    dbc.NavbarBrand("CTPPO", className="ms-2 fs-3 fw-bold"),
                    html.Span("Cyber Threat Propagation Path Optimizer", 
                             className="ms-3 text-muted d-none d-md-inline")
                ], className="d-flex align-items-center"),
            ]),
            dbc.Row([
                dbc.Col([
                    html.Span("By Ruthvik | Northeastern University", 
                             className="text-muted small")
                ])
            ])
        ], fluid=True),
        color="dark",
        dark=True,
        className="mb-4"
    )


def create_scan_input():
    """Create URL input section"""
    return dbc.Card([
        dbc.CardHeader([
            html.I(className="fas fa-search me-2"),
            "Security Scan"
        ], className="bg-primary"),
        dbc.CardBody([
            dbc.Row([
                dbc.Col([
                    dbc.Label("Target URL", className="fw-bold"),
                    dbc.Input(
                        id="url-input",
                        type="url",
                        placeholder="https://example.com",
                        className="mb-3"
                    ),
                ], md=6),
                dbc.Col([
                    dbc.Label("Scan Mode", className="fw-bold"),
                    dbc.Select(
                        id="scan-mode",
                        options=[
                            {"label": "Quick Scan (Faster)", "value": "quick"},
                            {"label": "Full Scan (Comprehensive)", "value": "full"},
                        ],
                        value="quick",
                        className="mb-3"
                    ),
                ], md=3),
                dbc.Col([
                    dbc.Label("​", className="fw-bold"),  # Spacer
                    dbc.Button(
                        [html.I(className="fas fa-play me-2"), "Start Scan"],
                        id="scan-button",
                        color="success",
                        className="w-100"
                    ),
                ], md=3),
            ]),
            dbc.Row([
                dbc.Col([
                    dbc.Progress(
                        id="scan-progress",
                        value=0,
                        striped=True,
                        animated=True,
                        className="mb-2",
                        style={"display": "none"}
                    ),
                    html.Div(id="scan-status", className="text-center text-muted")
                ])
            ])
        ])
    ], className="mb-4")


def create_summary_cards(result: Optional[SecurityAnalysisResult] = None):
    """Create summary metric cards"""
    try:
        if result is None:
            total_vulns = 0
            critical = high = medium = low = 0
            risk_score = 0
            attack_paths = 0
        else:
            # Handle different result formats
            if hasattr(result, 'scan_result'):
                sr = result.scan_result
                vulns = sr.vulnerabilities if hasattr(sr, 'vulnerabilities') else []
                severity_counts = sr.severity_counts if hasattr(sr, 'severity_counts') else {}
            elif hasattr(result, 'vulnerabilities'):
                vulns = result.vulnerabilities
                severity_counts = {}
                for v in vulns:
                    sev = v.severity.name
                    severity_counts[sev] = severity_counts.get(sev, 0) + 1
            else:
                vulns = []
                severity_counts = {}
            
            total_vulns = len(vulns)
            critical = severity_counts.get('CRITICAL', 0)
            high = severity_counts.get('HIGH', 0)
            medium = severity_counts.get('MEDIUM', 0)
            low = severity_counts.get('LOW', 0)
            risk_score = result.risk_score if hasattr(result, 'risk_score') else 0
            attack_paths = len(result.pareto_paths) if hasattr(result, 'pareto_paths') else 0
    except Exception:
        total_vulns = 0
        critical = high = medium = low = 0
        risk_score = 0
        attack_paths = 0
    
    cards = [
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H2(total_vulns, className="text-center mb-0"),
                    html.P("Total Vulnerabilities", className="text-center text-muted mb-0")
                ])
            ], color="primary", outline=True)
        ], md=2),
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H2(critical, className="text-center mb-0 text-danger"),
                    html.P("Critical", className="text-center text-muted mb-0")
                ])
            ], color="danger", outline=True)
        ], md=2),
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H2(high, className="text-center mb-0 text-warning"),
                    html.P("High", className="text-center text-muted mb-0")
                ])
            ], color="warning", outline=True)
        ], md=2),
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H2(medium, className="text-center mb-0 text-info"),
                    html.P("Medium", className="text-center text-muted mb-0")
                ])
            ], color="info", outline=True)
        ], md=2),
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H2(f"{risk_score:.0f}", className="text-center mb-0"),
                    html.P("Risk Score", className="text-center text-muted mb-0")
                ])
            ], color="secondary", outline=True)
        ], md=2),
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H2(attack_paths, className="text-center mb-0 text-success"),
                    html.P("Attack Paths", className="text-center text-muted mb-0")
                ])
            ], color="success", outline=True)
        ], md=2),
    ]
    
    return dbc.Row(cards, className="mb-4", id="summary-cards")


def create_attack_graph_viz():
    """Create attack graph visualization section"""
    return dbc.Card([
        dbc.CardHeader([
            html.I(className="fas fa-project-diagram me-2"),
            "Attack Graph Topology"
        ], className="bg-info"),
        dbc.CardBody([
            dbc.Row([
                dbc.Col([
                    dbc.Label("Layout"),
                    dbc.Select(
                        id="graph-layout",
                        options=[
                            {"label": "Hierarchical (Dagre)", "value": "dagre"},
                            {"label": "Circular", "value": "circle"},
                            {"label": "Concentric", "value": "concentric"},
                            {"label": "Force-Directed", "value": "cose"},
                            {"label": "Breadthfirst", "value": "breadthfirst"},
                        ],
                        value="dagre"
                    )
                ], md=3),
                dbc.Col([
                    dbc.Label("Node Filter"),
                    dbc.Checklist(
                        id="node-filter",
                        options=[
                            {"label": "Vulnerabilities", "value": "VULNERABILITY"},
                            {"label": "Assets", "value": "ASSET"},
                            {"label": "Exploits", "value": "EXPLOIT"},
                            {"label": "Impacts", "value": "IMPACT"},
                        ],
                        value=["VULNERABILITY", "ASSET", "EXPLOIT", "IMPACT"],
                        inline=True
                    )
                ], md=9),
            ], className="mb-3"),
            cyto.Cytoscape(
                id='attack-graph',
                layout={'name': 'dagre', 'rankDir': 'LR'},
                style={'width': '100%', 'height': '500px', 'backgroundColor': '#1a1a2e'},
                elements=[],
                stylesheet=[
                    # Node styles
                    {
                        'selector': 'node',
                        'style': {
                            'label': 'data(label)',
                            'text-valign': 'bottom',
                            'text-halign': 'center',
                            'font-size': '10px',
                            'color': '#ffffff',
                            'text-outline-width': 1,
                            'text-outline-color': '#000000'
                        }
                    },
                    {
                        'selector': '[type = "ENTRY_POINT"]',
                        'style': {
                            'background-color': '#00ff88',
                            'shape': 'triangle',
                            'width': 40,
                            'height': 40
                        }
                    },
                    {
                        'selector': '[type = "ASSET"]',
                        'style': {
                            'background-color': '#4dabf7',
                            'shape': 'rectangle',
                            'width': 50,
                            'height': 30
                        }
                    },
                    {
                        'selector': '[type = "VULNERABILITY"]',
                        'style': {
                            'background-color': '#ff6b6b',
                            'shape': 'diamond',
                            'width': 35,
                            'height': 35
                        }
                    },
                    {
                        'selector': '[type = "EXPLOIT"]',
                        'style': {
                            'background-color': '#ffd43b',
                            'shape': 'star',
                            'width': 40,
                            'height': 40
                        }
                    },
                    {
                        'selector': '[type = "IMPACT"]',
                        'style': {
                            'background-color': '#e64980',
                            'shape': 'octagon',
                            'width': 40,
                            'height': 40
                        }
                    },
                    {
                        'selector': '[type = "GOAL"]',
                        'style': {
                            'background-color': '#ff0000',
                            'shape': 'ellipse',
                            'width': 45,
                            'height': 45,
                            'border-width': 3,
                            'border-color': '#ffffff'
                        }
                    },
                    # Edge styles
                    {
                        'selector': 'edge',
                        'style': {
                            'curve-style': 'bezier',
                            'target-arrow-shape': 'triangle',
                            'target-arrow-color': '#888888',
                            'line-color': '#888888',
                            'width': 2,
                            'opacity': 0.7
                        }
                    },
                    # Highlighted path
                    {
                        'selector': '.highlighted',
                        'style': {
                            'line-color': '#00ff88',
                            'target-arrow-color': '#00ff88',
                            'width': 4,
                            'opacity': 1
                        }
                    }
                ]
            ),
            html.Div(id="node-info", className="mt-3 p-3 bg-dark rounded")
        ])
    ], className="mb-4")


def create_pareto_viz():
    """Create Pareto frontier visualization section"""
    return dbc.Card([
        dbc.CardHeader([
            html.I(className="fas fa-chart-scatter me-2"),
            "Pareto Frontier - Attack Path Trade-offs"
        ], className="bg-warning text-dark"),
        dbc.CardBody([
            dcc.Graph(
                id='pareto-chart',
                config={'displayModeBar': True},
                style={'height': '400px'}
            )
        ])
    ], className="mb-4")


def create_vulnerabilities_table():
    """Create vulnerabilities table section"""
    return dbc.Card([
        dbc.CardHeader([
            html.I(className="fas fa-bug me-2"),
            "Discovered Vulnerabilities"
        ], className="bg-danger"),
        dbc.CardBody([
            html.Div(id="vulns-table")
        ])
    ], className="mb-4")


def create_recommendations_panel():
    """Create recommendations panel"""
    return dbc.Card([
        dbc.CardHeader([
            html.I(className="fas fa-shield-alt me-2"),
            "Security Recommendations"
        ], className="bg-success"),
        dbc.CardBody([
            html.Div(id="recommendations-panel")
        ])
    ], className="mb-4")


def create_tech_fingerprint_panel():
    """Create technology fingerprint and FP filtering display"""
    return dbc.Card([
        dbc.CardHeader([
            html.I(className="fas fa-fingerprint me-2"),
            "Technology Detection & False Positive Filtering"
        ], className="bg-secondary"),
        dbc.CardBody([
            html.Div(id="tech-fingerprint-panel")
        ])
    ], className="mb-4")


def create_demo_button():
    """Create demo mode button"""
    return dbc.Row([
        dbc.Col([
            dbc.Button(
                [html.I(className="fas fa-play-circle me-2"), "Run Demo (Sample Data)"],
                id="demo-button",
                color="secondary",
                className="me-2"
            ),
            dbc.Button(
                [html.I(className="fas fa-file-pdf me-2"), "Export PDF Report"],
                id="export-pdf-button",
                color="info",
                className="me-2",
                disabled=True
            ),
            dcc.Download(id="download-pdf"),
        ], className="d-flex")
    ], className="mb-4")


# =============================================================================
# Main Layout
# =============================================================================

app.layout = dbc.Container([
    create_header(),
    
    dbc.Row([
        dbc.Col([
            create_scan_input(),
            create_demo_button(),
        ], md=12)
    ]),
    
    # Summary cards (updated after scan)
    html.Div(id="summary-section", children=create_summary_cards()),
    
    dbc.Row([
        dbc.Col([
            create_attack_graph_viz()
        ], md=8),
        dbc.Col([
            create_pareto_viz()
        ], md=4)
    ]),
    
    dbc.Row([
        dbc.Col([
            create_vulnerabilities_table()
        ], md=6),
        dbc.Col([
            create_recommendations_panel()
        ], md=6)
    ]),
    
    dbc.Row([
        dbc.Col([
            create_tech_fingerprint_panel()
        ], md=12)
    ]),
    
    # Store for scan data
    dcc.Store(id='scan-data-store'),
    
    # Interval for progress updates
    dcc.Interval(id='progress-interval', interval=1000, disabled=True),
    
], fluid=True, className="px-4")


# =============================================================================
# Callbacks
# =============================================================================

@callback(
    [Output('scan-data-store', 'data'),
     Output('scan-status', 'children'),
     Output('scan-progress', 'style'),
     Output('scan-button', 'disabled')],
    [Input('scan-button', 'n_clicks'),
     Input('demo-button', 'n_clicks')],
    [State('url-input', 'value'),
     State('scan-mode', 'value')],
    prevent_initial_call=True
)
def run_scan(scan_clicks, demo_clicks, url, mode):
    """Handle scan button click"""
    triggered = ctx.triggered_id
    
    if triggered == 'demo-button':
        # Run demo with sample data
        logger.info("DASHBOARD", "Running demo mode")
        
        # Create sample analysis result
        graph = create_sample_enterprise_graph(logger)
        
        # Create sample scan result
        from scanners.models import VulnerabilityFinding, Severity, ScannerType
        
        sample_vulns = [
            VulnerabilityFinding(
                title="SQL Injection Vulnerability",
                description="A SQL injection vulnerability was found in the login form.",
                severity=Severity.CRITICAL,
                scanner=ScannerType.ZAP,
                target_url="https://example.com/login",
                cve_ids=["CVE-2024-1234"],
                solution="Use parameterized queries."
            ),
            VulnerabilityFinding(
                title="Cross-Site Scripting (XSS)",
                description="Reflected XSS in search parameter.",
                severity=Severity.HIGH,
                scanner=ScannerType.ZAP,
                target_url="https://example.com/search",
                cwe_ids=["CWE-79"],
                solution="Encode user input before rendering."
            ),
            VulnerabilityFinding(
                title="Missing Security Headers",
                description="X-Frame-Options header not set.",
                severity=Severity.MEDIUM,
                scanner=ScannerType.ZAP,
                target_url="https://example.com",
                solution="Add X-Frame-Options: DENY header."
            ),
            VulnerabilityFinding(
                title="Server Version Disclosure",
                description="Server banner reveals version information.",
                severity=Severity.LOW,
                scanner=ScannerType.NMAP,
                target_host="example.com",
                solution="Configure server to hide version."
            ),
        ]
        
        scan_result = ScanResult(
            target=ScanTarget(url="https://example.com"),
            vulnerabilities=sample_vulns,
            status="completed"
        )
        
        # Get attack paths
        from algorithms.namoa_star import run_namoa_star
        paths_result = run_namoa_star(graph, logger=logger)
        
        result = SecurityAnalysisResult(
            scan_result=scan_result,
            attack_graph=graph,
            pareto_paths=paths_result.pareto_paths,
            risk_score=scan_result.risk_score,
            recommendations=[
                {"priority": 1, "severity": "CRITICAL", "title": "Fix SQL Injection", 
                 "solution": "Use parameterized queries", "risk_reduction": 40},
                {"priority": 2, "severity": "HIGH", "title": "Fix XSS Vulnerability",
                 "solution": "Encode all user input", "risk_reduction": 25},
                {"priority": 3, "severity": "MEDIUM", "title": "Add Security Headers",
                 "solution": "Configure CSP and X-Frame-Options", "risk_reduction": 15}
            ],
            analysis_time_seconds=2.5
        )
        
        # Store result
        scan_results['demo'] = result
        
        return (
            {'id': 'demo', 'status': 'completed'},
            html.Span([html.I(className="fas fa-check-circle me-2 text-success"), 
                      "Demo scan completed!"], className="text-success"),
            {'display': 'none'},
            False
        )
    
    elif triggered == 'scan-button':
        if not url:
            return (
                None,
                html.Span([html.I(className="fas fa-exclamation-circle me-2 text-warning"),
                          "Please enter a URL"], className="text-warning"),
                {'display': 'none'},
                False
            )
        
        # Start actual scan
        logger.info("DASHBOARD", f"Starting scan of {url}")
        
        try:
            analyzer = WebsiteSecurityAnalyzer(research_logger=logger)
            result = analyzer.analyze(url, scan_mode=mode)
            
            # Store result
            scan_id = f"scan_{int(time.time())}"
            scan_results[scan_id] = result
            
            return (
                {'id': scan_id, 'status': 'completed'},
                html.Span([html.I(className="fas fa-check-circle me-2 text-success"),
                          f"Scan completed! Found {len(result.scan_result.vulnerabilities)} vulnerabilities"],
                         className="text-success"),
                {'display': 'none'},
                False
            )
        except Exception as e:
            logger.error("DASHBOARD", f"Scan failed: {e}")
            return (
                None,
                html.Span([html.I(className="fas fa-times-circle me-2 text-danger"),
                          f"Scan failed: {str(e)}"], className="text-danger"),
                {'display': 'none'},
                False
            )
    
    return (None, "", {'display': 'none'}, False)


@callback(
    Output('summary-section', 'children'),
    Input('scan-data-store', 'data')
)
def update_summary(scan_data):
    """Update summary cards after scan"""
    try:
        if not scan_data:
            return create_summary_cards()
        
        result = scan_results.get(scan_data.get('id'))
        return create_summary_cards(result)
    except Exception:
        return create_summary_cards()


@callback(
    Output('attack-graph', 'elements'),
    [Input('scan-data-store', 'data'),
     Input('graph-layout', 'value'),
     Input('node-filter', 'value')]
)
def update_attack_graph(scan_data, layout, node_filter):
    """Update attack graph visualization"""
    try:
        if not scan_data:
            return []
        
        result = scan_results.get(scan_data.get('id'))
        if not result:
            return []
        
        # Get attack graph from result
        if not hasattr(result, 'attack_graph') or result.attack_graph is None:
            return []
        
        graph = result.attack_graph
        elements = []
        
        # Ensure node_filter is a list
        if node_filter is None:
            node_filter = ['VULNERABILITY', 'ASSET', 'EXPLOIT', 'IMPACT']
        
        # Add nodes
        for node_id, node in graph.nodes.items():
            node_type = node.node_type.name
            
            # Apply filter
            if node_type not in node_filter and node_type not in ['ENTRY_POINT', 'GOAL']:
                continue
            
            elements.append({
                'data': {
                    'id': node_id,
                    'label': str(node.name)[:20] if node.name else 'Unknown',
                    'type': node_type
                }
            })
        
        # Add edges
        for edge in graph.edges.values():
            # Only add edge if both nodes are visible
            src_node = graph.get_node(edge.source_id)
            tgt_node = graph.get_node(edge.target_id)
            
            if src_node and tgt_node:
                src_type = src_node.node_type.name
                tgt_type = tgt_node.node_type.name
                
                if (src_type in node_filter or src_type in ['ENTRY_POINT', 'GOAL']) and \
                   (tgt_type in node_filter or tgt_type in ['ENTRY_POINT', 'GOAL']):
                    elements.append({
                        'data': {
                            'source': edge.source_id,
                            'target': edge.target_id
                        }
                    })
        
        return elements
    
    except Exception as e:
        print(f"Error updating attack graph: {e}")
        return []


@callback(
    Output('attack-graph', 'layout'),
    Input('graph-layout', 'value')
)
def update_graph_layout(layout):
    """Update graph layout"""
    layouts = {
        'dagre': {'name': 'dagre', 'rankDir': 'LR', 'spacingFactor': 1.5},
        'circle': {'name': 'circle'},
        'concentric': {'name': 'concentric'},
        'cose': {'name': 'cose', 'animate': False},
        'breadthfirst': {'name': 'breadthfirst', 'directed': True}
    }
    return layouts.get(layout, layouts['dagre'])


@callback(
    Output('node-info', 'children'),
    Input('attack-graph', 'tapNodeData')
)
def display_node_info(data):
    """Display info when node is clicked"""
    if not data:
        return html.P("Click a node to see details", className="text-muted")
    
    return html.Div([
        html.H5(data.get('label', 'Unknown'), className="text-info"),
        html.P([
            html.Strong("Type: "),
            data.get('type', 'Unknown')
        ]),
        html.P([
            html.Strong("ID: "),
            html.Code(data.get('id', '')[:30] + "...")
        ])
    ])


@callback(
    Output('pareto-chart', 'figure'),
    Input('scan-data-store', 'data')
)
def update_pareto_chart(scan_data):
    """Update Pareto frontier chart"""
    if not scan_data:
        # Empty chart
        fig = go.Figure()
        fig.update_layout(
            template='plotly_dark',
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            title="Pareto Frontier (No Data)",
            xaxis_title="Time to Exploit (hours)",
            yaxis_title="Success Probability"
        )
        return fig
    
    result = scan_results.get(scan_data['id'])
    if not result or not result.pareto_paths:
        fig = go.Figure()
        fig.update_layout(template='plotly_dark', title="No Attack Paths Found")
        return fig
    
    # Extract data from Pareto paths
    times = []
    probs = []
    impacts = []
    path_names = []
    
    for i, (path, cost) in enumerate(result.pareto_paths[:20]):  # Limit to 20
        if hasattr(cost, 'values') and len(cost.values) >= 3:
            times.append(cost.values[0])
            probs.append(cost.values[1] * 100)  # Convert to percentage
            impacts.append(cost.values[2])
            path_names.append(f"Path {i+1}")
    
    if not times:
        fig = go.Figure()
        fig.update_layout(template='plotly_dark', title="No Valid Path Data")
        return fig
    
    # Create 3D scatter plot
    fig = go.Figure(data=[go.Scatter3d(
        x=times,
        y=probs,
        z=impacts,
        mode='markers',
        marker=dict(
            size=8,
            color=impacts,
            colorscale='RdYlGn_r',
            showscale=True,
            colorbar=dict(title="Impact")
        ),
        text=path_names,
        hovertemplate="<b>%{text}</b><br>" +
                      "Time: %{x:.1f} hrs<br>" +
                      "Success: %{y:.1f}%<br>" +
                      "Impact: %{z:.1f}<extra></extra>"
    )])
    
    fig.update_layout(
        template='plotly_dark',
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        title="Attack Path Trade-offs (3D Pareto Frontier)",
        scene=dict(
            xaxis_title="Time (hours)",
            yaxis_title="Success %",
            zaxis_title="Impact"
        ),
        margin=dict(l=0, r=0, b=0, t=40)
    )
    
    return fig


@callback(
    Output('vulns-table', 'children'),
    Input('scan-data-store', 'data')
)
def update_vulns_table(scan_data):
    """Update vulnerabilities table"""
    try:
        if not scan_data:
            return html.P("No scan data available", className="text-muted")
        
        result = scan_results.get(scan_data.get('id'))
        if not result:
            return html.P("No results found", className="text-muted")
        
        # Handle both SecurityAnalysisResult and direct ScanResult
        if hasattr(result, 'scan_result'):
            vulns = result.scan_result.vulnerabilities
        elif hasattr(result, 'vulnerabilities'):
            vulns = result.vulnerabilities
        else:
            return html.P("Invalid result format", className="text-warning")
        
        if not vulns:
            return html.P("No vulnerabilities found", className="text-success")
        
        # Create table rows
        rows = []
        for vuln in vulns[:10]:  # Limit to 10
            try:
                # Get severity safely
                sev = getattr(vuln, 'severity', None)
                if sev:
                    sev_name = sev.name if hasattr(sev, 'name') else str(sev)
                    severity_color = {
                        'CRITICAL': "danger",
                        'HIGH': "warning", 
                        'MEDIUM': "info",
                        'LOW': "secondary",
                        'INFO': "light"
                    }.get(sev_name, "secondary")
                else:
                    sev_name = "UNKNOWN"
                    severity_color = "secondary"
                
                # Safe string handling
                title = str(getattr(vuln, 'title', 'Unknown') or 'Unknown')
                title_display = title[:40] + "..." if len(title) > 40 else title
                
                # Get target URL safely
                target = getattr(vuln, 'target_url', None) or getattr(vuln, 'target_host', None) or "-"
                target_display = str(target)[:30] + "..." if len(str(target)) > 30 else str(target)
                
                # Get CVE IDs safely
                cve_ids = getattr(vuln, 'cve_ids', None) or []
                cve_display = ", ".join(cve_ids) if cve_ids else "-"
                
                rows.append(html.Tr([
                    html.Td(dbc.Badge(sev_name, color=severity_color)),
                    html.Td(title_display),
                    html.Td(target_display),
                    html.Td(cve_display)
                ]))
            except Exception as row_error:
                # Skip problematic rows but continue
                print(f"Row error: {row_error}")
                continue
        
        if not rows:
            return html.P("Could not display vulnerabilities", className="text-warning")
        
        # Use simple HTML table instead of dbc.Table to avoid version issues
        table = html.Table([
            html.Thead(html.Tr([
                html.Th("Severity", style={"padding": "8px"}),
                html.Th("Title", style={"padding": "8px"}),
                html.Th("Target", style={"padding": "8px"}),
                html.Th("CVE", style={"padding": "8px"})
            ]), style={"backgroundColor": "#333"}),
            html.Tbody(rows)
        ], style={
            "width": "100%",
            "borderCollapse": "collapse",
            "color": "#fff"
        }, className="table table-dark table-striped table-hover")
        
        return table
    
    except Exception as e:
        return html.P(f"Error loading vulnerabilities: {str(e)[:100]}", className="text-danger")


@callback(
    Output('recommendations-panel', 'children'),
    Input('scan-data-store', 'data')
)
def update_recommendations(scan_data):
    """Update recommendations panel"""
    try:
        if not scan_data:
            return html.P("Run a scan to see recommendations", className="text-muted")
        
        result = scan_results.get(scan_data.get('id'))
        if not result:
            return html.P("No recommendations available", className="text-muted")
        
        # Get recommendations - handle different result formats
        recommendations = []
        if hasattr(result, 'recommendations') and result.recommendations:
            recommendations = result.recommendations
        elif isinstance(result, dict) and 'recommendations' in result:
            recommendations = result['recommendations']
        
        if not recommendations:
            # Generate basic recommendations from vulnerabilities
            vulns = []
            if hasattr(result, 'scan_result') and hasattr(result.scan_result, 'vulnerabilities'):
                vulns = result.scan_result.vulnerabilities
            elif hasattr(result, 'vulnerabilities'):
                vulns = result.vulnerabilities
            
            if vulns:
                for i, vuln in enumerate(vulns[:3]):
                    recommendations.append({
                        'priority': i + 1,
                        'severity': vuln.severity.name,
                        'title': f"Fix: {vuln.title[:30]}",
                        'solution': vuln.solution or "Review and remediate this vulnerability",
                        'risk_reduction': 20
                    })
        
        if not recommendations:
            return html.P("No recommendations available", className="text-muted")
        
        items = []
        for rec in recommendations[:5]:
            severity = rec.get('severity', 'MEDIUM')
            color = {
                'CRITICAL': 'danger',
                'HIGH': 'warning',
                'MEDIUM': 'info',
                'LOW': 'secondary'
            }.get(severity, 'secondary')
            
            items.append(
                dbc.ListGroupItem([
                    html.Div([
                        dbc.Badge(f"#{rec.get('priority', '?')}", color=color, className="me-2"),
                        html.Strong(rec.get('title', 'Unknown')),
                    ]),
                    html.P(str(rec.get('solution', ''))[:100], className="mb-1 small text-muted"),
                    html.Small([
                        html.I(className="fas fa-chart-line me-1"),
                        f"Risk Reduction: {rec.get('risk_reduction', 0)}%"
                    ], className="text-success")
                ])
            )
        
        return dbc.ListGroup(items)
    
    except Exception as e:
        return html.P(f"Error loading recommendations: {str(e)[:50]}", className="text-danger")


@callback(
    Output('export-pdf-button', 'disabled'),
    Input('scan-data-store', 'data')
)
def enable_pdf_button(scan_data):
    """Enable PDF export button after scan completes"""
    return scan_data is None


@callback(
    Output('tech-fingerprint-panel', 'children'),
    Input('scan-data-store', 'data')
)
def update_tech_fingerprint(scan_data):
    """Update technology fingerprint and FP filtering display"""
    try:
        if not scan_data:
            return html.P("Run a scan to see technology detection results", className="text-muted")
        
        result = scan_results.get(scan_data.get('id'))
        if not result:
            return html.P("No technology data available", className="text-muted")
        
        # Try to get FP filter metadata from scan
        # We'll show what we can detect from the result
        elements = []
        
        # Technology badges
        tech_detected = []
        if hasattr(result, 'scan_result') and result.scan_result:
            target_url = result.scan_result.target.url if result.scan_result.target else "Unknown"
            
            # Try to detect from vulnerabilities
            for vuln in result.scan_result.vulnerabilities[:20]:
                title_lower = vuln.title.lower()
                if 'react' in title_lower or 'javascript' in title_lower:
                    tech_detected.append(('React/JS', 'info'))
                if 'php' in title_lower:
                    tech_detected.append(('PHP', 'warning'))
                if 'apache' in title_lower:
                    tech_detected.append(('Apache', 'danger'))
                if 'nginx' in title_lower:
                    tech_detected.append(('Nginx', 'success'))
                if 'cloudflare' in title_lower:
                    tech_detected.append(('Cloudflare', 'primary'))
        
        # Remove duplicates
        tech_detected = list(set(tech_detected))
        
        if tech_detected:
            tech_badges = [
                dbc.Badge(tech, color=color, className="me-1")
                for tech, color in tech_detected[:10]
            ]
            elements.append(html.Div([
                html.Strong("Detected Technologies: "),
                *tech_badges
            ], className="mb-3"))
        
        # FP Filtering info
        elements.append(html.Div([
            html.I(className="fas fa-filter me-2 text-info"),
            html.Strong("False Positive Filtering: "),
            html.Span("Active", className="text-success ms-1"),
            html.Br(),
            html.Small(
                "The scanner automatically detects technology stack and filters out "
                "CVEs that don't apply (e.g., Drupal CVEs on non-Drupal sites, "
                "SQLite injection on enterprise databases).",
                className="text-muted"
            )
        ], className="mb-3"))
        
        # Confidence scoring info
        elements.append(html.Div([
            html.I(className="fas fa-star-half-alt me-2 text-warning"),
            html.Strong("Confidence Scoring: "),
            html.Span("Enabled", className="text-success ms-1"),
            html.Br(),
            html.Small(
                "Each vulnerability is scored based on evidence quality, CVE validation, "
                "scanner reliability, and technology applicability. Low confidence findings "
                "are filtered out automatically.",
                className="text-muted"
            )
        ]))
        
        return html.Div(elements)
    
    except Exception as e:
        return html.P(f"Error loading technology data: {str(e)[:50]}", className="text-danger")


@callback(
    Output('download-pdf', 'data'),
    Input('export-pdf-button', 'n_clicks'),
    State('scan-data-store', 'data'),
    prevent_initial_call=True
)
def export_pdf_report(n_clicks, scan_data):
    """Generate and download PDF report"""
    if not n_clicks or not scan_data:
        return None
    
    try:
        result = scan_results.get(scan_data.get('id'))
        if not result:
            return None
        
        # Try to import reportlab
        try:
            from reports.pdf_generator import generate_pdf_report
        except ImportError:
            # Return error message if reportlab not installed
            return dcc.send_string(
                "Error: reportlab library required. Install with: pip install reportlab",
                filename="error.txt"
            )
        
        # Generate the PDF
        import tempfile
        import os
        
        output_dir = tempfile.mkdtemp()
        
        # Get recommendations
        recommendations = result.recommendations if hasattr(result, 'recommendations') else []
        if not recommendations:
            # Generate basic recommendations from vulnerabilities
            recommendations = []
            if hasattr(result, 'scan_result'):
                for i, vuln in enumerate(result.scan_result.vulnerabilities[:5]):
                    recommendations.append({
                        'priority': i + 1,
                        'severity': vuln.severity.name,
                        'title': f"Fix: {vuln.title[:40]}",
                        'solution': vuln.solution or "Review and remediate",
                        'risk_reduction': 20
                    })
        
        pdf_path = generate_pdf_report(
            scan_result=result.scan_result,
            attack_paths=result.pareto_paths if hasattr(result, 'pareto_paths') else [],
            recommendations=recommendations,
            output_dir=output_dir
        )
        
        return dcc.send_file(pdf_path)
    
    except Exception as e:
        print(f"PDF generation error: {e}")
        import traceback
        traceback.print_exc()
        return None


# =============================================================================
# Server
# =============================================================================

server = app.server

if __name__ == '__main__':
    print("\n" + "="*60)
    print("  CTPPO - Cyber Threat Propagation Path Optimizer")
    print("  Web Dashboard Starting...")
    print("="*60)
    print("\n  Open your browser to: http://127.0.0.1:8050")
    print("\n  Press Ctrl+C to stop the server\n")
    
    app.run(debug=True, host='127.0.0.1', port=8050)
