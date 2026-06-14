"""
Website Security Analyzer
=========================

Analyzes website security by:
1. Running vulnerability scans
2. Converting findings to attack graph
3. Running NAMOA* to find attack paths
4. Recommending mitigations

Author: Ruthvik
Date: November 2025
"""

import sys
import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from .models import (
    ScanTarget, ScanResult, VulnerabilityFinding,
    Severity, ScannerType, ScanMode
)
from .unified_scanner import UnifiedScanner, UnifiedScanConfig

from core.attack_graph import AttackGraph, EdgeType
from core.node_types import (
    AssetNode, VulnerabilityNode, ExploitNode, ImpactNode,
    EntryPointNode, GoalNode, AssetType, PrivilegeLevel,
    CVSSSeverity
)
from core.edge_costs import (
    EdgeCostVector, CostType,
    create_time_cost, create_probability_cost, create_impact_cost
)
from core.cost_model import build_edge_cost, EdgeCostInputs
from core.threat_data import ThreatDataProvider
from core.logging_system import ResearchLogger, get_default_logger

logger = logging.getLogger(__name__)


@dataclass
class SecurityAnalysisResult:
    """Complete security analysis result"""
    scan_result: ScanResult
    attack_graph: AttackGraph
    pareto_paths: List[Tuple[List[str], Any]]  # (path, cost_vector)
    risk_score: float
    recommendations: List[Dict[str, Any]]
    analysis_time_seconds: float
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_summary": {
                "target": self.scan_result.target.url,
                "total_vulnerabilities": len(self.scan_result.vulnerabilities),
                "severity_counts": self.scan_result.severity_counts,
                "risk_score": self.risk_score
            },
            "attack_graph": {
                "nodes": self.attack_graph.num_nodes,
                "edges": self.attack_graph.num_edges,
                "entry_points": len(self.attack_graph.entry_points),
                "goals": len(self.attack_graph.goal_nodes)
            },
            "attack_paths": len(self.pareto_paths),
            "top_recommendations": self.recommendations[:5],
            "analysis_time_seconds": self.analysis_time_seconds
        }


class WebsiteSecurityAnalyzer:
    """
    Complete website security analyzer.
    
    Workflow:
    1. Scan website for vulnerabilities
    2. Build attack graph from findings
    3. Find Pareto-optimal attack paths
    4. Generate security recommendations
    """
    
    def __init__(
        self,
        zap_api_key: str = None,
        zap_proxy_url: str = None,
        research_logger: ResearchLogger = None,
        threat_provider: ThreatDataProvider = None
    ):
        """
        Initialize analyzer.

        Args:
            zap_api_key: OWASP ZAP API key
            zap_proxy_url: ZAP proxy URL
            research_logger: Logger for research documentation
            threat_provider: EPSS/KEV data source for the cost model (defaults to a
                live + cached ThreatDataProvider)
        """
        self.scanner = UnifiedScanner(
            zap_api_key=zap_api_key,
            zap_proxy_url=zap_proxy_url
        )
        self.logger = research_logger or get_default_logger()
        self.threat_provider = threat_provider or ThreatDataProvider()
    
    def analyze(
        self,
        url: str,
        scan_mode: str = "quick",
        credentials: dict = None
    ) -> SecurityAnalysisResult:
        """
        Perform complete security analysis on a website.
        
        Args:
            url: Target URL
            scan_mode: 'quick' or 'full'
            credentials: Optional credentials for authenticated scanning
            
        Returns:
            SecurityAnalysisResult with all findings and recommendations
        """
        start_time = datetime.now()
        
        self.logger.info("ANALYSIS", f"Starting security analysis of {url}")
        
        # Step 1: Scan the website
        self.logger.info("SCAN", "Running vulnerability scans...")
        
        target = ScanTarget(
            url=url,
            scan_mode=ScanMode.GRAY_BOX if credentials else ScanMode.BLACK_BOX,
            auth_username=credentials.get('username', '') if credentials else '',
            auth_password=credentials.get('password', '') if credentials else ''
        )
        
        if scan_mode == "full":
            scan_result = self.scanner.full_scan(url, credentials)
        else:
            scan_result = self.scanner.quick_scan(url)
        
        # Apply false positive filtering
        scan_result = self._apply_fp_filter(scan_result, url)
        
        self.logger.info(
            "SCAN",
            f"Scan completed. Found {len(scan_result.vulnerabilities)} vulnerabilities",
            {"severity_counts": scan_result.severity_counts}
        )
        
        # Step 2: Build attack graph
        self.logger.info("GRAPH", "Building attack graph from scan results...")
        attack_graph = self._build_attack_graph(url, scan_result)
        
        self.logger.info(
            "GRAPH",
            f"Attack graph built",
            {"nodes": attack_graph.num_nodes, "edges": attack_graph.num_edges}
        )
        
        # Step 3: Find Pareto-optimal attack paths
        self.logger.info("PATHS", "Finding Pareto-optimal attack paths...")
        pareto_paths = self._find_attack_paths(attack_graph)
        
        self.logger.info(
            "PATHS",
            f"Found {len(pareto_paths)} Pareto-optimal attack paths"
        )
        
        # Step 4: Generate recommendations
        self.logger.info("RECOMMENDATIONS", "Generating security recommendations...")
        recommendations = self._generate_recommendations(
            scan_result, attack_graph, pareto_paths
        )
        
        # Calculate analysis time
        analysis_time = (datetime.now() - start_time).total_seconds()
        
        result = SecurityAnalysisResult(
            scan_result=scan_result,
            attack_graph=attack_graph,
            pareto_paths=pareto_paths,
            risk_score=scan_result.risk_score,
            recommendations=recommendations,
            analysis_time_seconds=analysis_time
        )
        
        self.logger.info(
            "ANALYSIS",
            f"Analysis complete in {analysis_time:.2f}s",
            result.to_dict()
        )
        
        return result
    
    def _apply_fp_filter(self, scan_result: ScanResult, url: str) -> ScanResult:
        """Apply false positive filtering to scan results"""
        try:
            from scanners.false_positive_filter import FalsePositiveFilter, enhance_scan_result
            import requests
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            
            original_count = len(scan_result.vulnerabilities)
            
            # Fetch target for technology fingerprinting
            headers = {}
            html_content = ""
            
            try:
                response = requests.get(
                    url, 
                    timeout=10, 
                    verify=False,
                    headers={'User-Agent': 'CTPPO Security Scanner/1.0'}
                )
                headers = dict(response.headers)
                html_content = response.text[:100000]  # First 100KB
            except Exception as e:
                self.logger.info("FP_FILTER", f"Could not fetch target for fingerprinting: {e}")
            
            # Apply filter
            filtered_result, metadata = enhance_scan_result(
                scan_result=scan_result,
                headers=headers,
                html_content=html_content,
                min_confidence=30.0
            )
            
            filtered_count = len(filtered_result.vulnerabilities)
            removed_count = original_count - filtered_count
            
            # Log detected technology FIRST
            tech = metadata.get('technology_fingerprint', {})
            detected = [f"{k}:{v}" for k, v in tech.items() if v]
            if detected:
                self.logger.info("TECH_DETECTED", ", ".join(detected[:5]))
            
            # Log what was removed
            if removed_count > 0:
                self.logger.info(
                    "FP_FILTER", 
                    f"Filtered {original_count} -> {filtered_count} ({removed_count} false positives removed)"
                )
                
                # Show which vulns were removed
                filtered_titles = {v.title for v in filtered_result.vulnerabilities}
                for vuln in scan_result.vulnerabilities:
                    if vuln.title not in filtered_titles:
                        self.logger.info("FP_REMOVED", f"{vuln.title} (CVEs: {vuln.cve_ids})")
            else:
                self.logger.info("FP_FILTER", f"No false positives detected in {original_count} vulnerabilities")
            
            return filtered_result
            
        except ImportError as e:
            self.logger.info("FP_FILTER", f"Filter module not available: {e}")
            return scan_result
        except Exception as e:
            self.logger.info("FP_FILTER", f"Filter error (continuing with unfiltered): {e}")
            return scan_result
    
    def _build_attack_graph(self, url: str, scan_result: ScanResult) -> AttackGraph:
        """Build attack graph from scan results"""
        parsed = urlparse(url)
        hostname = parsed.hostname or "target"
        
        graph = AttackGraph(name=f"SecurityAnalysis_{hostname}", logger=self.logger)
        
        # Create entry point (internet attacker)
        entry_point = EntryPointNode(
            name="Internet Attacker",
            entry_type="internet",
            access_level=PrivilegeLevel.NONE,
            detection_probability=0.1
        )
        graph.add_node(entry_point)
        
        # Create main asset (the website)
        web_asset = AssetNode(
            name=f"WebServer ({hostname})",
            asset_type=AssetType.WEB_APPLICATION,
            hostname=hostname,
            criticality=7.0,
            network_zone="dmz"
        )
        graph.add_node(web_asset)
        
        # Connect entry point to web asset
        graph.add_edge(
            entry_point.id,
            web_asset.id,
            EdgeType.ENTRY_TO_ASSET,
            self._create_entry_cost()
        )
        
        # DEDUPLICATE vulnerabilities by title (group same vuln types together)
        unique_vulns = {}
        for vuln in scan_result.vulnerabilities:
            if vuln.severity.value >= Severity.LOW.value:  # Skip INFO
                # Use title as key for deduplication
                key = vuln.title
                if key not in unique_vulns:
                    unique_vulns[key] = vuln
                else:
                    # Keep the higher severity version
                    if vuln.severity.value > unique_vulns[key].severity.value:
                        unique_vulns[key] = vuln
        
        # Limit to top 20 most severe vulnerabilities to prevent graph explosion
        sorted_vulns = sorted(unique_vulns.values(), key=lambda v: v.severity.value, reverse=True)[:20]
        
        # Create nodes for each unique vulnerability
        vuln_nodes = {}
        for vuln in sorted_vulns:
            vuln_node = self._create_vulnerability_node(vuln)
            graph.add_node(vuln_node)
            vuln_nodes[vuln.id] = vuln_node
            
            # Connect asset to vulnerability
            graph.add_edge(
                web_asset.id,
                vuln_node.id,
                EdgeType.ASSET_HAS_VULN,
                self._create_discovery_cost(vuln)
            )
        
        # Create exploit nodes and connect to vulnerabilities
        exploit_nodes = {}
        for vuln_id, vuln_node in vuln_nodes.items():
            vuln = next((v for v in sorted_vulns if v.id == vuln_id), None)
            if vuln:
                exploit = self._create_exploit_node(vuln)
                graph.add_node(exploit)
                exploit_nodes[vuln_id] = exploit
                
                # Connect vulnerability to exploit
                graph.add_edge(
                    vuln_node.id,
                    exploit.id,
                    EdgeType.VULN_ENABLES_EXPLOIT,
                    self._create_exploit_cost(vuln)
                )
        
        # Create impact nodes based on vulnerability severity
        impact_nodes = self._create_impact_nodes(sorted_vulns)
        for impact in impact_nodes:
            graph.add_node(impact)
        
        # Connect exploits to impacts
        for vuln_id, exploit in exploit_nodes.items():
            vuln = next((v for v in sorted_vulns if v.id == vuln_id), None)
            if vuln and impact_nodes:
                # Connect to appropriate impact based on severity
                for impact in impact_nodes:
                    if self._should_connect_to_impact(vuln, impact):
                        graph.add_edge(
                            exploit.id,
                            impact.id,
                            EdgeType.COMPROMISE_CAUSES_IMPACT,
                            self._create_impact_cost(vuln)
                        )
        
        # Create goal nodes
        data_breach_goal = GoalNode(
            name="Data Breach",
            goal_type="data_exfiltration",
            required_privileges=PrivilegeLevel.USER,
            value_to_attacker=8.0
        )
        graph.add_node(data_breach_goal)
        
        full_compromise_goal = GoalNode(
            name="Full System Compromise",
            goal_type="system_compromise",
            required_privileges=PrivilegeLevel.ROOT,
            value_to_attacker=10.0
        )
        graph.add_node(full_compromise_goal)
        
        # Connect impacts to goals
        for impact in impact_nodes:
            if "data" in impact.name.lower() or "confidentiality" in impact.name.lower():
                graph.add_edge(impact.id, data_breach_goal.id, EdgeType.ASSET_TO_GOAL)
            if impact.severity >= 8.0:
                graph.add_edge(impact.id, full_compromise_goal.id, EdgeType.ASSET_TO_GOAL)
        
        return graph
    
    def _create_vulnerability_node(self, vuln: VulnerabilityFinding) -> VulnerabilityNode:
        """Create vulnerability node from finding"""
        return VulnerabilityNode(
            name=vuln.title[:50],
            description=vuln.description[:200],
            cve_id=vuln.cve_ids[0] if vuln.cve_ids else None,
            cvss_score=vuln.cvss_score or (vuln.severity.value * 2),
            exploit_available=vuln.severity.value >= Severity.HIGH.value,
            attack_vector="network",
            attack_complexity="low" if vuln.severity.value >= Severity.HIGH.value else "high"
        )
    
    def _create_exploit_node(self, vuln: VulnerabilityFinding) -> ExploitNode:
        """Create exploit node from vulnerability"""
        # Map vulnerability to MITRE technique
        mitre_id = vuln.mitre_attack_ids[0] if vuln.mitre_attack_ids else "T1190"
        
        # Determine gained privileges based on severity
        if vuln.severity == Severity.CRITICAL:
            gained_priv = PrivilegeLevel.ROOT
        elif vuln.severity == Severity.HIGH:
            gained_priv = PrivilegeLevel.LOCAL_ADMIN
        else:
            gained_priv = PrivilegeLevel.USER
        
        return ExploitNode(
            name=f"Exploit: {vuln.title[:30]}",
            mitre_technique_id=mitre_id,
            complexity=10 - vuln.severity.value * 2,  # Lower severity = higher complexity
            reliability=0.5 + (vuln.severity.value * 0.1),  # Higher severity = more reliable
            required_privileges=PrivilegeLevel.NONE,
            gained_privileges=gained_priv
        )
    
    def _create_impact_nodes(self, vulnerabilities: List[VulnerabilityFinding]) -> List[ImpactNode]:
        """Create impact nodes based on vulnerabilities"""
        impacts = []
        
        # Check for different impact types
        has_injection = any("injection" in v.title.lower() for v in vulnerabilities)
        has_auth_issues = any("auth" in v.title.lower() or "session" in v.title.lower() for v in vulnerabilities)
        has_crypto_issues = any("ssl" in v.title.lower() or "tls" in v.title.lower() or "crypto" in v.title.lower() for v in vulnerabilities)
        has_high_severity = any(v.severity.value >= Severity.HIGH.value for v in vulnerabilities)
        
        if has_injection or has_high_severity:
            impacts.append(ImpactNode(
                name="Data Breach Impact",
                severity=9.0,
                financial_impact=100000,
                affected_users=1000,
                business_service="Customer Data"
            ))
        
        if has_auth_issues:
            impacts.append(ImpactNode(
                name="Account Compromise Impact",
                severity=7.0,
                financial_impact=50000,
                affected_users=500,
                business_service="User Accounts"
            ))
        
        if has_crypto_issues:
            impacts.append(ImpactNode(
                name="Confidentiality Breach Impact",
                severity=6.0,
                financial_impact=25000,
                business_service="Data In Transit"
            ))
        
        # Always add a generic impact
        if not impacts:
            impacts.append(ImpactNode(
                name="Security Compromise Impact",
                severity=5.0,
                financial_impact=10000,
                business_service="Web Application"
            ))
        
        return impacts
    
    def _should_connect_to_impact(self, vuln: VulnerabilityFinding, impact: ImpactNode) -> bool:
        """Determine if vulnerability should connect to impact"""
        # Connect based on vulnerability type and impact category
        vuln_lower = vuln.title.lower()
        impact_lower = impact.name.lower()
        
        if "injection" in vuln_lower and "data" in impact_lower:
            return True
        if ("auth" in vuln_lower or "session" in vuln_lower) and "account" in impact_lower:
            return True
        if ("ssl" in vuln_lower or "tls" in vuln_lower) and "confidentiality" in impact_lower:
            return True
        if vuln.severity.value >= Severity.HIGH.value:
            return True
        
        return False
    
    def _create_entry_cost(self) -> EdgeCostVector:
        """Create cost vector for entry point"""
        cost = EdgeCostVector.create_default()
        cost.components[CostType.TIME_TO_EXPLOIT] = create_time_cost(0.5, 0.1)
        cost.components[CostType.SUCCESS_PROBABILITY] = create_probability_cost(0.95)
        cost.components[CostType.BUSINESS_IMPACT] = create_impact_cost(0, 1, 2)
        return cost
    
    def _create_discovery_cost(self, vuln: VulnerabilityFinding) -> EdgeCostVector:
        """Create cost vector for vulnerability discovery"""
        cost = EdgeCostVector.create_default()
        # Easier to discover higher severity vulnerabilities
        time_hours = 1.0 + (5 - vuln.severity.value) * 0.5
        cost.components[CostType.TIME_TO_EXPLOIT] = create_time_cost(time_hours, time_hours * 0.2)
        cost.components[CostType.SUCCESS_PROBABILITY] = create_probability_cost(0.9)
        cost.components[CostType.BUSINESS_IMPACT] = create_impact_cost(0, 0, 1)
        return cost
    
    def _create_exploit_cost(self, vuln: VulnerabilityFinding) -> EdgeCostVector:
        """Create the exploitation-edge cost vector, grounded in real exploit data.

        Uses the data-grounded cost model (EPSS / CISA KEV / CVSS sub-metrics) instead
        of severity heuristics. See core/cost_model.py and
        docs/RESEARCH/02_COST_MODEL_SPEC.md. Falls back to CVSS-only when EPSS/KEV/vector
        data is unavailable (the back-off is recorded in the cost vector's metadata).
        """
        inputs = EdgeCostInputs(
            cve_id=vuln.cve_ids[0] if vuln.cve_ids else None,
            cvss_vector=vuln.cvss_vector or "",
            cvss_score=vuln.cvss_score if vuln.cvss_score is not None else vuln.severity.value * 2,
            asset_criticality=7.0,  # matches the web-asset node criticality
        )
        return build_edge_cost(inputs, provider=self.threat_provider)
    
    def _create_impact_cost(self, vuln: VulnerabilityFinding) -> EdgeCostVector:
        """Create cost vector for impact realization"""
        cost = EdgeCostVector.create_default()
        cost.components[CostType.TIME_TO_EXPLOIT] = create_time_cost(1.0, 0.5)
        cost.components[CostType.SUCCESS_PROBABILITY] = create_probability_cost(0.8)
        cost.components[CostType.BUSINESS_IMPACT] = create_impact_cost(
            vuln.severity.value * 1.5,
            vuln.severity.value * 2,
            10.0
        )
        return cost
    
    def _find_attack_paths(self, graph: AttackGraph) -> List[Tuple[List[str], Any]]:
        """Find Pareto-optimal attack paths using NAMOA*"""
        try:
            from algorithms.namoa_star import run_namoa_star
            
            if not graph.entry_points or not graph.goal_nodes:
                return []
            
            result = run_namoa_star(graph, logger=self.logger)
            return result.pareto_paths
        except Exception as e:
            self.logger.error("PATHS", f"Error finding attack paths: {e}")
            return []
    
    def _generate_recommendations(
        self,
        scan_result: ScanResult,
        graph: AttackGraph,
        pareto_paths: List[Tuple[List[str], Any]]
    ) -> List[Dict[str, Any]]:
        """Generate security recommendations based on analysis"""
        recommendations = []
        
        # Group vulnerabilities by severity
        critical_vulns = scan_result.get_vulnerabilities_by_severity(Severity.CRITICAL)
        high_vulns = scan_result.get_vulnerabilities_by_severity(Severity.HIGH)
        medium_vulns = scan_result.get_vulnerabilities_by_severity(Severity.MEDIUM)
        
        priority = 1
        
        # Critical vulnerabilities - immediate action required
        for vuln in critical_vulns:
            recommendations.append({
                "priority": priority,
                "severity": "CRITICAL",
                "title": f"Fix: {vuln.title}",
                "description": vuln.description[:200],
                "solution": vuln.solution or "Apply vendor patch or implement compensating controls immediately.",
                "affected": vuln.target_url or vuln.target_host,
                "cves": vuln.cve_ids,
                "estimated_effort": "High",
                "risk_reduction": 40
            })
            priority += 1
        
        # High severity vulnerabilities
        for vuln in high_vulns[:5]:  # Limit to top 5
            recommendations.append({
                "priority": priority,
                "severity": "HIGH",
                "title": f"Fix: {vuln.title}",
                "description": vuln.description[:200],
                "solution": vuln.solution or "Review and remediate within 7 days.",
                "affected": vuln.target_url or vuln.target_host,
                "cves": vuln.cve_ids,
                "estimated_effort": "Medium",
                "risk_reduction": 25
            })
            priority += 1
        
        # Add general recommendations based on findings
        if any("header" in v.title.lower() for v in scan_result.vulnerabilities):
            recommendations.append({
                "priority": priority,
                "severity": "MEDIUM",
                "title": "Implement Security Headers",
                "description": "Multiple security headers are missing or misconfigured.",
                "solution": "Add Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, "
                           "Strict-Transport-Security, and Referrer-Policy headers.",
                "affected": scan_result.target.url,
                "estimated_effort": "Low",
                "risk_reduction": 15
            })
            priority += 1
        
        if any("cookie" in v.title.lower() for v in scan_result.vulnerabilities):
            recommendations.append({
                "priority": priority,
                "severity": "MEDIUM",
                "title": "Secure Cookie Configuration",
                "description": "Cookies are not properly secured.",
                "solution": "Set Secure, HttpOnly, and SameSite flags on all cookies.",
                "affected": scan_result.target.url,
                "estimated_effort": "Low",
                "risk_reduction": 10
            })
            priority += 1
        
        # Add recommendation based on attack paths
        if pareto_paths:
            fastest_path = min(pareto_paths, key=lambda x: x[1].values[0] if hasattr(x[1], 'values') else 0)
            recommendations.append({
                "priority": priority,
                "severity": "HIGH",
                "title": "Block Critical Attack Path",
                "description": f"Found {len(pareto_paths)} potential attack paths. "
                              f"Lowest-time path has relative time-cost {fastest_path[1].values[0]:.2f} (unitless; see cost model)." if hasattr(fastest_path[1], 'values') else "Attack paths detected.",
                "solution": "Focus remediation on vulnerabilities in the fastest attack paths first.",
                "estimated_effort": "Medium",
                "risk_reduction": 30
            })
        
        return recommendations


def analyze_website(url: str, mode: str = "quick") -> SecurityAnalysisResult:
    """
    Convenience function to analyze a website.
    
    Args:
        url: Target URL (e.g., "https://example.com")
        mode: 'quick' for fast scan, 'full' for comprehensive
        
    Returns:
        SecurityAnalysisResult with findings, attack graph, and recommendations
    """
    analyzer = WebsiteSecurityAnalyzer()
    return analyzer.analyze(url, scan_mode=mode)
