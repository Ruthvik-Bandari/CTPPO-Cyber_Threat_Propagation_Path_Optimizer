#!/usr/bin/env python3
"""
CTPPO Security Scanner - Real Network & Web Application Scanning
=================================================================

Integrates:
- Nmap: Network discovery, port scanning, service detection
- OWASP ZAP: Web application vulnerability scanning
- NVD API: Real CVE data correlation
- Shodan: Internet intelligence (optional)

Author: Ruthvik Bandari
Date: January 2026
"""

import os
import re
import json
import time
import asyncio
import subprocess
import socket
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta
from urllib.parse import urlparse
import httpx

# Optional imports - will gracefully degrade if not installed
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    print("⚠️ python-nmap not installed. Run: pip install python-nmap")

try:
    from zapv2 import ZAPv2
    ZAP_AVAILABLE = True
except ImportError:
    ZAP_AVAILABLE = False
    print("⚠️ python-owasp-zap-v2.4 not installed. Run: pip install python-owasp-zap-v2.4")


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class DiscoveredService:
    """A discovered network service."""
    host: str
    port: int
    protocol: str
    service: str
    version: str = ""
    product: str = ""
    cpe: List[str] = field(default_factory=list)
    state: str = "open"
    banner: str = ""


@dataclass
class DiscoveredVulnerability:
    """A discovered vulnerability."""
    id: str  # CVE ID or ZAP alert ID
    name: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    cvss_score: float = 0.0
    affected_component: str = ""
    host: str = ""
    port: int = 0
    url: str = ""
    evidence: str = ""
    solution: str = ""
    references: List[str] = field(default_factory=list)
    cwe_id: str = ""
    exploit_available: bool = False


@dataclass
class AttackVector:
    """An attack vector between two points."""
    source: str
    target: str
    vulnerability: DiscoveredVulnerability
    exploitability: float = 0.0
    impact: float = 0.0


@dataclass
class AttackPath:
    """A complete attack path from entry to target."""
    entry_point: str
    target: str
    vectors: List[AttackVector]
    total_risk: float = 0.0
    likelihood: float = 0.0
    impact: float = 0.0
    
    def calculate_risk(self):
        """Calculate total risk score."""
        if not self.vectors:
            return 0.0
        
        # Cumulative exploitability (product of probabilities)
        self.likelihood = 1.0
        for v in self.vectors:
            self.likelihood *= (v.exploitability / 10.0)
        
        # Impact is the maximum impact in the path
        self.impact = max(v.impact for v in self.vectors) if self.vectors else 0.0
        
        # Risk = Likelihood * Impact
        self.total_risk = round(self.likelihood * self.impact * 10, 2)
        return self.total_risk


@dataclass
class ScanResult:
    """Complete scan result."""
    target: str
    scan_type: str
    started_at: str
    completed_at: str = ""
    duration_seconds: float = 0.0
    hosts_discovered: List[str] = field(default_factory=list)
    services: List[DiscoveredService] = field(default_factory=list)
    vulnerabilities: List[DiscoveredVulnerability] = field(default_factory=list)
    attack_paths: List[AttackPath] = field(default_factory=list)
    risk_summary: Dict[str, Any] = field(default_factory=dict)
    raw_output: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self):
        return {
            "target": self.target,
            "scan_type": self.scan_type,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_seconds": self.duration_seconds,
            "hosts_discovered": self.hosts_discovered,
            "services": [asdict(s) for s in self.services],
            "vulnerabilities": [asdict(v) for v in self.vulnerabilities],
            "attack_paths": [
                {
                    "entry_point": p.entry_point,
                    "target": p.target,
                    "vectors": [asdict(v) for v in p.vectors],
                    "total_risk": p.total_risk,
                    "likelihood": p.likelihood,
                    "impact": p.impact
                }
                for p in self.attack_paths
            ],
            "risk_summary": self.risk_summary,
            "errors": self.errors
        }


# ============================================================================
# NVD CVE DATABASE
# ============================================================================

class NVDClient:
    """Client for NIST National Vulnerability Database."""
    
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("NVD_API_KEY")
        self.cache: Dict[str, Dict] = {}
        self.rate_limit_delay = 0.6 if not self.api_key else 0.1
    
    async def search_cves_by_cpe(self, cpe: str, limit: int = 10) -> List[Dict]:
        """Search CVEs by CPE (Common Platform Enumeration)."""
        cache_key = f"cpe:{cpe}"
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        params = {
            "cpeName": cpe,
            "resultsPerPage": limit
        }
        
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(self.BASE_URL, params=params, headers=headers)
                await asyncio.sleep(self.rate_limit_delay)
                
                if response.status_code == 200:
                    data = response.json()
                    cves = self._parse_cve_response(data)
                    self.cache[cache_key] = cves
                    return cves
        except Exception as e:
            print(f"NVD API error: {e}")
        
        return []
    
    async def search_cves_by_keyword(self, keyword: str, limit: int = 10) -> List[Dict]:
        """Search CVEs by keyword."""
        cache_key = f"kw:{keyword}"
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": limit
        }
        
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(self.BASE_URL, params=params, headers=headers)
                await asyncio.sleep(self.rate_limit_delay)
                
                if response.status_code == 200:
                    data = response.json()
                    cves = self._parse_cve_response(data)
                    self.cache[cache_key] = cves
                    return cves
        except Exception as e:
            print(f"NVD API error: {e}")
        
        return []
    
    def _parse_cve_response(self, data: Dict) -> List[Dict]:
        """Parse NVD API response."""
        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            
            # Extract CVSS score
            cvss_score = 0.0
            severity = "UNKNOWN"
            
            metrics = cve.get("metrics", {})
            if "cvssMetricV31" in metrics:
                cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                cvss_score = cvss_data.get("baseScore", 0.0)
                severity = cvss_data.get("baseSeverity", "UNKNOWN")
            elif "cvssMetricV30" in metrics:
                cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
                cvss_score = cvss_data.get("baseScore", 0.0)
                severity = cvss_data.get("baseSeverity", "UNKNOWN")
            elif "cvssMetricV2" in metrics:
                cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
                cvss_score = cvss_data.get("baseScore", 0.0)
                severity = "HIGH" if cvss_score >= 7.0 else "MEDIUM" if cvss_score >= 4.0 else "LOW"
            
            # Extract description
            descriptions = cve.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            
            # Extract CWE
            cwe_id = ""
            weaknesses = cve.get("weaknesses", [])
            for weakness in weaknesses:
                for desc in weakness.get("description", []):
                    if desc.get("lang") == "en":
                        cwe_id = desc.get("value", "")
                        break
            
            cves.append({
                "id": cve.get("id", ""),
                "description": description,
                "cvss_score": cvss_score,
                "severity": severity,
                "cwe_id": cwe_id,
                "published": cve.get("published", ""),
                "references": [ref.get("url") for ref in cve.get("references", [])]
            })
        
        return cves


# ============================================================================
# NMAP SCANNER
# ============================================================================

class NmapScanner:
    """Nmap network scanner wrapper."""
    
    def __init__(self):
        if not NMAP_AVAILABLE:
            raise RuntimeError("python-nmap not installed")
        self.nm = nmap.PortScanner()
        self.nvd = NVDClient()
    
    def check_nmap_installed(self) -> bool:
        """Check if nmap is installed on the system."""
        try:
            result = subprocess.run(["nmap", "--version"], capture_output=True, text=True)
            return result.returncode == 0
        except FileNotFoundError:
            return False
    
    async def scan_target(
        self,
        target: str,
        ports: str = "1-1000",
        arguments: str = "-sV -sC --script vuln",
        sudo: bool = False
    ) -> ScanResult:
        """
        Scan a target with nmap.
        
        Args:
            target: IP address, hostname, or CIDR range
            ports: Port range to scan (e.g., "22,80,443" or "1-1000")
            arguments: Nmap arguments
            sudo: Run with sudo for SYN scans
        """
        result = ScanResult(
            target=target,
            scan_type="nmap",
            started_at=datetime.utcnow().isoformat()
        )
        
        if not self.check_nmap_installed():
            result.errors.append("Nmap is not installed. Please install: brew install nmap (Mac) or apt install nmap (Linux)")
            return result
        
        try:
            print(f"🔍 Starting Nmap scan on {target}...")
            start_time = time.time()
            
            # Run nmap scan
            self.nm.scan(
                hosts=target,
                ports=ports,
                arguments=arguments,
                sudo=sudo
            )
            
            # Parse results
            for host in self.nm.all_hosts():
                result.hosts_discovered.append(host)
                
                for proto in self.nm[host].all_protocols():
                    ports_info = self.nm[host][proto]
                    
                    for port, port_data in ports_info.items():
                        if port_data.get("state") == "open":
                            service = DiscoveredService(
                                host=host,
                                port=port,
                                protocol=proto,
                                service=port_data.get("name", "unknown"),
                                version=port_data.get("version", ""),
                                product=port_data.get("product", ""),
                                cpe=port_data.get("cpe", "").split() if port_data.get("cpe") else [],
                                state=port_data.get("state", ""),
                                banner=port_data.get("extrainfo", "")
                            )
                            result.services.append(service)
                
                # Check for script results (vulnerability scripts)
                if "hostscript" in self.nm[host]:
                    for script in self.nm[host]["hostscript"]:
                        vuln = self._parse_script_output(script, host)
                        if vuln:
                            result.vulnerabilities.append(vuln)
            
            # Correlate services with CVEs from NVD
            await self._correlate_cves(result)
            
            result.completed_at = datetime.utcnow().isoformat()
            result.duration_seconds = round(time.time() - start_time, 2)
            result.raw_output = dict(self.nm._scan_result) if hasattr(self.nm, '_scan_result') else {}
            
            # Calculate risk summary
            self._calculate_risk_summary(result)
            
            print(f"✅ Nmap scan completed in {result.duration_seconds}s")
            print(f"   Found {len(result.hosts_discovered)} hosts, {len(result.services)} services, {len(result.vulnerabilities)} vulnerabilities")
            
        except Exception as e:
            result.errors.append(f"Nmap scan error: {str(e)}")
            print(f"❌ Nmap error: {e}")
        
        return result
    
    def _parse_script_output(self, script: Dict, host: str) -> Optional[DiscoveredVulnerability]:
        """Parse Nmap script output for vulnerabilities."""
        script_id = script.get("id", "")
        output = script.get("output", "")
        
        # Check for CVE references in output
        cve_pattern = r"CVE-\d{4}-\d{4,7}"
        cves = re.findall(cve_pattern, output)
        
        if cves or "VULNERABLE" in output.upper():
            severity = "HIGH" if "VULNERABLE" in output.upper() else "MEDIUM"
            
            return DiscoveredVulnerability(
                id=cves[0] if cves else f"NMAP-{script_id}",
                name=script_id,
                description=output[:500],
                severity=severity,
                host=host,
                evidence=output,
                references=cves
            )
        
        return None
    
    async def _correlate_cves(self, result: ScanResult):
        """Correlate discovered services with known CVEs."""
        for service in result.services:
            # Search by CPE if available
            for cpe in service.cpe:
                cves = await self.nvd.search_cves_by_cpe(cpe, limit=5)
                for cve in cves:
                    vuln = DiscoveredVulnerability(
                        id=cve["id"],
                        name=cve["id"],
                        description=cve["description"][:500],
                        severity=cve["severity"],
                        cvss_score=cve["cvss_score"],
                        affected_component=f"{service.product} {service.version}",
                        host=service.host,
                        port=service.port,
                        cwe_id=cve["cwe_id"],
                        references=cve["references"][:5]
                    )
                    
                    # Avoid duplicates
                    if not any(v.id == vuln.id for v in result.vulnerabilities):
                        result.vulnerabilities.append(vuln)
            
            # Search by product name
            if service.product:
                keyword = f"{service.product} {service.version}".strip()
                cves = await self.nvd.search_cves_by_keyword(keyword, limit=3)
                for cve in cves:
                    vuln = DiscoveredVulnerability(
                        id=cve["id"],
                        name=cve["id"],
                        description=cve["description"][:500],
                        severity=cve["severity"],
                        cvss_score=cve["cvss_score"],
                        affected_component=keyword,
                        host=service.host,
                        port=service.port,
                        cwe_id=cve["cwe_id"],
                        references=cve["references"][:5]
                    )
                    
                    if not any(v.id == vuln.id for v in result.vulnerabilities):
                        result.vulnerabilities.append(vuln)
    
    def _calculate_risk_summary(self, result: ScanResult):
        """Calculate risk summary from vulnerabilities."""
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        
        for vuln in result.vulnerabilities:
            severity = vuln.severity.upper()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Determine overall risk level
        if severity_counts["CRITICAL"] > 0:
            risk_level = "CRITICAL"
        elif severity_counts["HIGH"] > 0:
            risk_level = "HIGH"
        elif severity_counts["MEDIUM"] > 0:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        result.risk_summary = {
            "risk_level": risk_level,
            "total_vulnerabilities": len(result.vulnerabilities),
            "severity_breakdown": severity_counts,
            "total_services": len(result.services),
            "total_hosts": len(result.hosts_discovered),
            "most_critical": [
                {"id": v.id, "severity": v.severity, "cvss": v.cvss_score}
                for v in sorted(result.vulnerabilities, key=lambda x: x.cvss_score, reverse=True)[:5]
            ]
        }


# ============================================================================
# OWASP ZAP SCANNER
# ============================================================================

class ZAPScanner:
    """OWASP ZAP web application scanner."""
    
    def __init__(self, zap_url: str = "http://localhost:8080", api_key: str = ""):
        if not ZAP_AVAILABLE:
            raise RuntimeError("python-owasp-zap-v2.4 not installed")
        
        self.zap_url = zap_url
        self.api_key = api_key or os.environ.get("ZAP_API_KEY", "")
        self.zap = ZAPv2(apikey=self.api_key, proxies={"http": zap_url, "https": zap_url})
    
    def check_zap_running(self) -> bool:
        """Check if ZAP is running."""
        try:
            self.zap.core.version
            return True
        except:
            return False
    
    async def scan_url(
        self,
        target_url: str,
        scan_type: str = "active",  # "spider", "passive", "active", "full"
        max_duration: int = 300  # 5 minutes max
    ) -> ScanResult:
        """
        Scan a web application with OWASP ZAP.
        
        Args:
            target_url: URL to scan
            scan_type: Type of scan (spider, passive, active, full)
            max_duration: Maximum scan duration in seconds
        """
        result = ScanResult(
            target=target_url,
            scan_type=f"zap-{scan_type}",
            started_at=datetime.utcnow().isoformat()
        )
        
        if not self.check_zap_running():
            result.errors.append(
                "OWASP ZAP is not running. Please start ZAP:\n"
                "  1. Download from https://www.zaproxy.org/\n"
                "  2. Start ZAP with API enabled: zap.sh -daemon -port 8080 -config api.key=YOUR_API_KEY"
            )
            return result
        
        try:
            print(f"🔍 Starting ZAP {scan_type} scan on {target_url}...")
            start_time = time.time()
            
            # Access the target
            print("   Accessing target...")
            self.zap.urlopen(target_url)
            await asyncio.sleep(2)
            
            # Spider scan
            if scan_type in ["spider", "full"]:
                print("   Running spider scan...")
                spider_id = self.zap.spider.scan(target_url)
                
                while int(self.zap.spider.status(spider_id)) < 100:
                    if time.time() - start_time > max_duration / 2:
                        break
                    await asyncio.sleep(2)
                
                print(f"   Spider found {len(self.zap.spider.results(spider_id))} URLs")
            
            # Passive scan (runs automatically)
            if scan_type in ["passive", "full"]:
                print("   Running passive scan...")
                while int(self.zap.pscan.records_to_scan) > 0:
                    if time.time() - start_time > max_duration / 2:
                        break
                    await asyncio.sleep(1)
            
            # Active scan
            if scan_type in ["active", "full"]:
                print("   Running active scan (this may take a while)...")
                active_id = self.zap.ascan.scan(target_url)
                
                while int(self.zap.ascan.status(active_id)) < 100:
                    if time.time() - start_time > max_duration:
                        print("   Max duration reached, stopping active scan...")
                        self.zap.ascan.stop(active_id)
                        break
                    progress = self.zap.ascan.status(active_id)
                    print(f"   Active scan progress: {progress}%")
                    await asyncio.sleep(5)
            
            # Get alerts (vulnerabilities)
            alerts = self.zap.core.alerts(baseurl=target_url)
            
            for alert in alerts:
                vuln = DiscoveredVulnerability(
                    id=f"ZAP-{alert.get('pluginId', 'unknown')}",
                    name=alert.get("name", "Unknown"),
                    description=alert.get("description", ""),
                    severity=self._map_zap_risk(alert.get("risk", "Low")),
                    url=alert.get("url", ""),
                    evidence=alert.get("evidence", ""),
                    solution=alert.get("solution", ""),
                    cwe_id=f"CWE-{alert.get('cweid', '')}" if alert.get('cweid') else "",
                    references=[alert.get("reference", "")]
                )
                result.vulnerabilities.append(vuln)
            
            # Get hosts
            result.hosts_discovered = [urlparse(target_url).netloc]
            
            result.completed_at = datetime.utcnow().isoformat()
            result.duration_seconds = round(time.time() - start_time, 2)
            
            # Calculate risk summary
            self._calculate_risk_summary(result)
            
            print(f"✅ ZAP scan completed in {result.duration_seconds}s")
            print(f"   Found {len(result.vulnerabilities)} vulnerabilities")
            
        except Exception as e:
            result.errors.append(f"ZAP scan error: {str(e)}")
            print(f"❌ ZAP error: {e}")
        
        return result
    
    def _map_zap_risk(self, risk: str) -> str:
        """Map ZAP risk levels to our severity levels."""
        mapping = {
            "High": "HIGH",
            "Medium": "MEDIUM",
            "Low": "LOW",
            "Informational": "INFO"
        }
        return mapping.get(risk, "UNKNOWN")
    
    def _calculate_risk_summary(self, result: ScanResult):
        """Calculate risk summary."""
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        
        for vuln in result.vulnerabilities:
            severity = vuln.severity.upper()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        if severity_counts["CRITICAL"] > 0:
            risk_level = "CRITICAL"
        elif severity_counts["HIGH"] > 0:
            risk_level = "HIGH"
        elif severity_counts["MEDIUM"] > 0:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        result.risk_summary = {
            "risk_level": risk_level,
            "total_vulnerabilities": len(result.vulnerabilities),
            "severity_breakdown": severity_counts
        }


# ============================================================================
# ATTACK PATH GENERATOR
# ============================================================================

class AttackPathGenerator:
    """Generate attack paths from discovered vulnerabilities."""
    
    def __init__(self):
        self.service_attack_surfaces = {
            "ssh": ["brute_force", "key_theft", "privilege_escalation"],
            "http": ["web_exploit", "sql_injection", "xss", "rce"],
            "https": ["web_exploit", "ssl_strip", "mitm"],
            "smb": ["eternal_blue", "relay_attack", "credential_theft"],
            "rdp": ["brute_force", "bluekeep", "credential_theft"],
            "mysql": ["sql_injection", "credential_theft", "privilege_escalation"],
            "postgresql": ["sql_injection", "credential_theft"],
            "ftp": ["brute_force", "anonymous_access", "bounce_attack"],
            "telnet": ["brute_force", "credential_sniffing"],
            "dns": ["zone_transfer", "cache_poisoning"],
            "smtp": ["relay_abuse", "user_enumeration"],
            "ldap": ["injection", "anonymous_bind"],
        }
    
    def generate_attack_paths(
        self,
        scan_result: ScanResult,
        entry_point: str = "attacker",
        critical_assets: List[str] = None
    ) -> List[AttackPath]:
        """
        Generate attack paths from scan results.
        
        Args:
            scan_result: Results from network/web scan
            entry_point: Starting point for attacks
            critical_assets: List of critical asset IPs/hostnames
        """
        paths = []
        
        if not scan_result.vulnerabilities:
            return paths
        
        # If no critical assets specified, use all discovered hosts
        if not critical_assets:
            critical_assets = scan_result.hosts_discovered or [scan_result.target]
        
        # Group vulnerabilities by host
        vulns_by_host: Dict[str, List[DiscoveredVulnerability]] = {}
        for vuln in scan_result.vulnerabilities:
            host = vuln.host or urlparse(vuln.url).netloc or scan_result.target
            if host not in vulns_by_host:
                vulns_by_host[host] = []
            vulns_by_host[host].append(vuln)
        
        # Generate paths to each critical asset
        for target in critical_assets:
            target_vulns = vulns_by_host.get(target, [])
            
            if not target_vulns:
                continue
            
            # Sort by severity/CVSS
            target_vulns.sort(key=lambda v: v.cvss_score, reverse=True)
            
            # Create attack path
            vectors = []
            for vuln in target_vulns[:5]:  # Top 5 vulnerabilities
                vector = AttackVector(
                    source=entry_point if not vectors else vectors[-1].target,
                    target=target,
                    vulnerability=vuln,
                    exploitability=self._calculate_exploitability(vuln),
                    impact=vuln.cvss_score
                )
                vectors.append(vector)
            
            if vectors:
                path = AttackPath(
                    entry_point=entry_point,
                    target=target,
                    vectors=vectors
                )
                path.calculate_risk()
                paths.append(path)
        
        # Sort paths by risk
        paths.sort(key=lambda p: p.total_risk, reverse=True)
        
        return paths
    
    def _calculate_exploitability(self, vuln: DiscoveredVulnerability) -> float:
        """Calculate exploitability score."""
        base = 5.0
        
        # Higher CVSS = more exploitable
        if vuln.cvss_score >= 9.0:
            base += 3.0
        elif vuln.cvss_score >= 7.0:
            base += 2.0
        elif vuln.cvss_score >= 4.0:
            base += 1.0
        
        # Known exploit available
        if vuln.exploit_available:
            base += 2.0
        
        # Public CVE
        if vuln.id.startswith("CVE-"):
            base += 0.5
        
        return min(base, 10.0)


# ============================================================================
# UNIFIED SECURITY SCANNER
# ============================================================================

class SecurityScanner:
    """
    Unified security scanner combining multiple tools.
    
    Usage:
        scanner = SecurityScanner()
        result = await scanner.scan("https://example.com", scan_type="full")
    """
    
    def __init__(self, nvd_api_key: str = None, zap_url: str = "http://localhost:8080", zap_api_key: str = ""):
        self.nvd = NVDClient(nvd_api_key)
        self.nmap = NmapScanner() if NMAP_AVAILABLE else None
        self.zap = ZAPScanner(zap_url, zap_api_key) if ZAP_AVAILABLE else None
        self.path_generator = AttackPathGenerator()
    
    async def scan(
        self,
        target: str,
        scan_type: str = "full",  # "quick", "network", "web", "full"
        ports: str = "21,22,23,25,53,80,110,143,443,445,993,995,3306,3389,5432,8080,8443",
        max_duration: int = 600
    ) -> ScanResult:
        """
        Perform a security scan on the target.
        
        Args:
            target: URL, IP address, or hostname
            scan_type: Type of scan to perform
            ports: Ports to scan (for network scans)
            max_duration: Maximum scan duration in seconds
        
        Returns:
            ScanResult with all findings
        """
        # Parse target
        parsed = urlparse(target if "://" in target else f"http://{target}")
        hostname = parsed.netloc or parsed.path
        is_url = parsed.scheme in ["http", "https"]
        
        print(f"\n{'='*60}")
        print(f"🛡️  CTPPO Security Scanner")
        print(f"{'='*60}")
        print(f"Target: {target}")
        print(f"Scan Type: {scan_type}")
        print(f"{'='*60}\n")
        
        # Initialize combined result
        result = ScanResult(
            target=target,
            scan_type=scan_type,
            started_at=datetime.utcnow().isoformat()
        )
        
        start_time = time.time()
        
        # Network scan
        if scan_type in ["network", "full", "quick"] and self.nmap:
            try:
                # Resolve hostname to IP
                ip = socket.gethostbyname(hostname)
                
                nmap_args = "-sV"  # Version detection
                if scan_type == "quick":
                    nmap_args = "-sV -T4"  # Fast scan
                elif scan_type == "full":
                    nmap_args = "-sV -sC --script vuln"  # With vulnerability scripts
                
                nmap_result = await self.nmap.scan_target(
                    ip,
                    ports=ports,
                    arguments=nmap_args
                )
                
                result.hosts_discovered.extend(nmap_result.hosts_discovered)
                result.services.extend(nmap_result.services)
                result.vulnerabilities.extend(nmap_result.vulnerabilities)
                result.errors.extend(nmap_result.errors)
                
            except socket.gaierror as e:
                result.errors.append(f"Could not resolve hostname: {e}")
            except Exception as e:
                result.errors.append(f"Network scan error: {e}")
        
        # Web scan
        if scan_type in ["web", "full"] and is_url and self.zap:
            try:
                zap_type = "active" if scan_type == "full" else "passive"
                zap_result = await self.zap.scan_url(
                    target,
                    scan_type=zap_type,
                    max_duration=max_duration // 2
                )
                
                result.vulnerabilities.extend(zap_result.vulnerabilities)
                result.errors.extend(zap_result.errors)
                
            except Exception as e:
                result.errors.append(f"Web scan error: {e}")
        
        # Generate attack paths
        if result.vulnerabilities:
            result.attack_paths = self.path_generator.generate_attack_paths(
                result,
                entry_point="internet",
                critical_assets=[hostname]
            )
        
        # Calculate final risk summary
        self._calculate_final_risk_summary(result)
        
        result.completed_at = datetime.utcnow().isoformat()
        result.duration_seconds = round(time.time() - start_time, 2)
        
        print(f"\n{'='*60}")
        print(f"✅ Scan Complete!")
        print(f"{'='*60}")
        print(f"Duration: {result.duration_seconds}s")
        print(f"Hosts: {len(result.hosts_discovered)}")
        print(f"Services: {len(result.services)}")
        print(f"Vulnerabilities: {len(result.vulnerabilities)}")
        print(f"Attack Paths: {len(result.attack_paths)}")
        print(f"Risk Level: {result.risk_summary.get('risk_level', 'UNKNOWN')}")
        print(f"{'='*60}\n")
        
        return result
    
    def _calculate_final_risk_summary(self, result: ScanResult):
        """Calculate comprehensive risk summary."""
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        
        for vuln in result.vulnerabilities:
            severity = vuln.severity.upper()
            if severity in severity_counts:
                severity_counts[severity] += 1
            elif vuln.cvss_score >= 9.0:
                severity_counts["CRITICAL"] += 1
            elif vuln.cvss_score >= 7.0:
                severity_counts["HIGH"] += 1
            elif vuln.cvss_score >= 4.0:
                severity_counts["MEDIUM"] += 1
            else:
                severity_counts["LOW"] += 1
        
        # Determine risk level
        if severity_counts["CRITICAL"] > 0:
            risk_level = "CRITICAL"
        elif severity_counts["HIGH"] > 0:
            risk_level = "HIGH"
        elif severity_counts["MEDIUM"] > 0:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        # Top recommendations
        recommendations = []
        critical_vulns = [v for v in result.vulnerabilities if v.severity == "CRITICAL" or v.cvss_score >= 9.0]
        for vuln in critical_vulns[:3]:
            recommendations.append(f"IMMEDIATE: Patch {vuln.id} ({vuln.name})")
        
        result.risk_summary = {
            "risk_level": risk_level,
            "total_vulnerabilities": len(result.vulnerabilities),
            "severity_breakdown": severity_counts,
            "total_services": len(result.services),
            "total_hosts": len(result.hosts_discovered),
            "total_attack_paths": len(result.attack_paths),
            "highest_risk_score": max([p.total_risk for p in result.attack_paths], default=0),
            "recommendations": recommendations,
            "most_critical_vulns": [
                {"id": v.id, "name": v.name, "severity": v.severity, "cvss": v.cvss_score}
                for v in sorted(result.vulnerabilities, key=lambda x: x.cvss_score, reverse=True)[:5]
            ]
        }


# ============================================================================
# CLI INTERFACE
# ============================================================================

async def main():
    """CLI interface for the scanner."""
    import argparse
    
    parser = argparse.ArgumentParser(description="CTPPO Security Scanner")
    parser.add_argument("target", help="Target URL, IP, or hostname")
    parser.add_argument("-t", "--type", choices=["quick", "network", "web", "full"], default="quick", help="Scan type")
    parser.add_argument("-p", "--ports", default="21,22,80,443,3306,5432,8080", help="Ports to scan")
    parser.add_argument("-o", "--output", help="Output JSON file")
    parser.add_argument("--nvd-key", help="NVD API key")
    parser.add_argument("--zap-url", default="http://localhost:8080", help="ZAP proxy URL")
    parser.add_argument("--zap-key", help="ZAP API key")
    
    args = parser.parse_args()
    
    scanner = SecurityScanner(
        nvd_api_key=args.nvd_key,
        zap_url=args.zap_url,
        zap_api_key=args.zap_key or ""
    )
    
    result = await scanner.scan(
        args.target,
        scan_type=args.type,
        ports=args.ports
    )
    
    if args.output:
        with open(args.output, "w") as f:
            json.dump(result.to_dict(), f, indent=2)
        print(f"Results saved to {args.output}")
    else:
        print(json.dumps(result.to_dict(), indent=2))


if __name__ == "__main__":
    asyncio.run(main())
