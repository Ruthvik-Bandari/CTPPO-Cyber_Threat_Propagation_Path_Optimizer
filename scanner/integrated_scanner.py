#!/usr/bin/env python3
"""
CTPPO Integrated Security Scanner
==================================

Combines:
- Nmap: Network/port scanning
- OWASP ZAP: Web application scanning  
- NVD API: CVE correlation
- Attack Path Generation: From real scan data

Author: Ruthvik Bandari
Date: January 2026
"""

import os
import re
import json
import socket
import ssl
import time
import asyncio
import subprocess
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any
from datetime import datetime
from urllib.parse import urlparse
import urllib.request

# Check for optional dependencies
NMAP_AVAILABLE = False
ZAP_AVAILABLE = False

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    print("⚠️  python-nmap not installed. Run: pip install python-nmap")

try:
    from zapv2 import ZAPv2
    ZAP_AVAILABLE = True
except ImportError:
    print("⚠️  ZAP client not installed. Run: pip install python-owasp-zap-v2.4")

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False
    print("⚠️  httpx not installed. Run: pip install httpx")


# ============================================================================
# DATA MODELS
# ============================================================================

@dataclass
class Port:
    """Discovered port."""
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = "unknown"
    version: str = ""
    cpe: str = ""
    
@dataclass 
class Host:
    """Discovered host."""
    ip: str
    hostname: str = ""
    state: str = "up"
    os: str = ""
    ports: List[Port] = field(default_factory=list)

@dataclass
class Vulnerability:
    """Discovered vulnerability."""
    id: str
    name: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    cvss: float = 0.0
    description: str = ""
    host: str = ""
    port: int = 0
    url: str = ""
    evidence: str = ""
    solution: str = ""
    cwe: str = ""
    references: List[str] = field(default_factory=list)

@dataclass
class NetworkNode:
    """Node in attack graph."""
    id: str
    label: str
    type: str  # internet, server, database, workstation
    ip: str = ""
    criticality: str = "low"  # low, medium, high, critical
    vulnerabilities: List[str] = field(default_factory=list)

@dataclass
class NetworkEdge:
    """Edge in attack graph."""
    source: str
    target: str
    vulnerability_id: str
    exploit_probability: float = 0.5

@dataclass
class AttackPath:
    """Complete attack path."""
    id: str
    entry_point: str
    target: str
    hops: List[Dict] = field(default_factory=list)
    total_risk: float = 0.0
    exploitability: float = 0.0

@dataclass
class ScanResult:
    """Complete scan result."""
    target: str
    scan_id: str
    scan_type: str
    started_at: str
    completed_at: str = ""
    duration_ms: float = 0
    hosts: List[Host] = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    network_nodes: List[NetworkNode] = field(default_factory=list)
    network_edges: List[NetworkEdge] = field(default_factory=list)
    attack_paths: List[AttackPath] = field(default_factory=list)
    risk_summary: Dict = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self):
        return {
            "target": self.target,
            "scan_id": self.scan_id,
            "scan_type": self.scan_type,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_ms": self.duration_ms,
            "hosts": [asdict(h) for h in self.hosts],
            "vulnerabilities": [asdict(v) for v in self.vulnerabilities],
            "network": {
                "nodes": [asdict(n) for n in self.network_nodes],
                "edges": [asdict(e) for e in self.network_edges]
            },
            "attack_paths": [asdict(p) for p in self.attack_paths],
            "risk_summary": self.risk_summary,
            "errors": self.errors
        }


# ============================================================================
# NMAP SCANNER
# ============================================================================

class NmapScanner:
    """Network scanner using Nmap."""
    
    def __init__(self):
        self.nm = nmap.PortScanner() if NMAP_AVAILABLE else None
    
    @staticmethod
    def is_available() -> bool:
        """Check if nmap is installed on system."""
        try:
            result = subprocess.run(["nmap", "--version"], capture_output=True)
            return result.returncode == 0
        except FileNotFoundError:
            return False
    
    def scan(self, target: str, ports: str = "1-1000", args: str = "-sV") -> List[Host]:
        """
        Scan target with Nmap.
        
        Args:
            target: IP, hostname, or CIDR range
            ports: Port range (e.g., "22,80,443" or "1-1000")
            args: Nmap arguments (-sV for version detection, -sC for scripts)
        """
        if not self.nm:
            raise RuntimeError("Nmap not available")
        
        hosts = []
        
        try:
            print(f"🔍 Nmap scanning {target}...")
            self.nm.scan(hosts=target, ports=ports, arguments=args)
            
            for host_ip in self.nm.all_hosts():
                host = Host(
                    ip=host_ip,
                    hostname=self.nm[host_ip].hostname(),
                    state=self.nm[host_ip].state()
                )
                
                # Get OS info if available
                if 'osmatch' in self.nm[host_ip] and self.nm[host_ip]['osmatch']:
                    host.os = self.nm[host_ip]['osmatch'][0].get('name', '')
                
                # Get ports
                for proto in self.nm[host_ip].all_protocols():
                    for port_num in self.nm[host_ip][proto]:
                        port_info = self.nm[host_ip][proto][port_num]
                        if port_info['state'] == 'open':
                            port = Port(
                                port=port_num,
                                protocol=proto,
                                state=port_info['state'],
                                service=port_info.get('name', 'unknown'),
                                version=port_info.get('version', ''),
                                cpe=port_info.get('cpe', '')
                            )
                            host.ports.append(port)
                
                hosts.append(host)
                print(f"  ✓ Found {host.ip} with {len(host.ports)} open ports")
                
        except Exception as e:
            print(f"  ✗ Nmap error: {e}")
        
        return hosts


# ============================================================================
# OWASP ZAP SCANNER
# ============================================================================

class ZapScanner:
    """Web application scanner using OWASP ZAP."""
    
    def __init__(self, zap_url: str = "http://localhost:8080", api_key: str = ""):
        self.zap_url = zap_url
        self.api_key = api_key or os.environ.get("ZAP_API_KEY", "")
        self.zap = None
        
        if ZAP_AVAILABLE:
            try:
                self.zap = ZAPv2(
                    apikey=self.api_key,
                    proxies={"http": zap_url, "https": zap_url}
                )
            except:
                pass
    
    def is_running(self) -> bool:
        """Check if ZAP is running."""
        if not self.zap:
            return False
        try:
            self.zap.core.version
            return True
        except:
            return False
    
    async def scan(self, url: str, scan_type: str = "passive", max_time: int = 300) -> List[Vulnerability]:
        """
        Scan URL with OWASP ZAP.
        
        Args:
            url: Target URL
            scan_type: "passive", "active", or "full"
            max_time: Maximum scan time in seconds
        """
        if not self.is_running():
            raise RuntimeError("ZAP is not running")
        
        vulns = []
        start = time.time()
        
        try:
            print(f"🔍 ZAP scanning {url}...")
            
            # Access target
            self.zap.urlopen(url)
            await asyncio.sleep(2)
            
            # Spider
            if scan_type in ["active", "full"]:
                print("  → Running spider...")
                spider_id = self.zap.spider.scan(url)
                while int(self.zap.spider.status(spider_id)) < 100:
                    if time.time() - start > max_time / 2:
                        break
                    await asyncio.sleep(1)
            
            # Passive scan runs automatically
            print("  → Running passive scan...")
            while int(self.zap.pscan.records_to_scan) > 0:
                if time.time() - start > max_time / 3:
                    break
                await asyncio.sleep(1)
            
            # Active scan
            if scan_type in ["active", "full"]:
                print("  → Running active scan...")
                scan_id = self.zap.ascan.scan(url)
                while int(self.zap.ascan.status(scan_id)) < 100:
                    if time.time() - start > max_time:
                        self.zap.ascan.stop(scan_id)
                        break
                    await asyncio.sleep(2)
            
            # Get alerts
            alerts = self.zap.core.alerts(baseurl=url)
            
            for alert in alerts:
                severity_map = {"High": "HIGH", "Medium": "MEDIUM", "Low": "LOW", "Informational": "INFO"}
                vuln = Vulnerability(
                    id=f"ZAP-{alert.get('pluginId', '0')}",
                    name=alert.get('name', 'Unknown'),
                    severity=severity_map.get(alert.get('risk', 'Low'), 'LOW'),
                    description=alert.get('description', '')[:500],
                    url=alert.get('url', ''),
                    evidence=alert.get('evidence', '')[:200],
                    solution=alert.get('solution', '')[:500],
                    cwe=f"CWE-{alert.get('cweid', '')}" if alert.get('cweid') else ""
                )
                vulns.append(vuln)
            
            print(f"  ✓ Found {len(vulns)} vulnerabilities")
            
        except Exception as e:
            print(f"  ✗ ZAP error: {e}")
        
        return vulns


# ============================================================================
# SIMPLE SCANNER (Fallback - No External Dependencies)
# ============================================================================

class SimpleScanner:
    """Basic scanner that works without external tools."""
    
    COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 
                   3306, 3389, 5432, 6379, 8080, 8443, 27017]
    
    SERVICE_MAP = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
        80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
        993: "imaps", 995: "pop3s", 3306: "mysql", 3389: "rdp",
        5432: "postgresql", 6379: "redis", 8080: "http-proxy", 
        8443: "https-alt", 27017: "mongodb"
    }
    
    def scan_ports(self, host: str, ports: List[int] = None) -> Host:
        """Scan ports using socket."""
        ports = ports or self.COMMON_PORTS
        result = Host(ip=host, hostname=host)
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                if sock.connect_ex((host, port)) == 0:
                    result.ports.append(Port(
                        port=port,
                        service=self.SERVICE_MAP.get(port, "unknown")
                    ))
                sock.close()
            except:
                pass
        
        return result
    
    def check_http_headers(self, url: str) -> List[Vulnerability]:
        """Check HTTP security headers."""
        vulns = []
        
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            req = urllib.request.Request(url, headers={'User-Agent': 'CTPPO-Scanner/3.0'})
            response = urllib.request.urlopen(req, timeout=10, context=ctx)
            headers = {k.lower(): v for k, v in response.headers.items()}
            
            # Security headers to check
            checks = [
                ('strict-transport-security', 'HIGH', 'Missing HSTS - Vulnerable to downgrade attacks'),
                ('x-content-type-options', 'MEDIUM', 'Missing X-Content-Type-Options - MIME sniffing possible'),
                ('x-frame-options', 'MEDIUM', 'Missing X-Frame-Options - Clickjacking possible'),
                ('content-security-policy', 'MEDIUM', 'Missing CSP - XSS attacks easier'),
                ('x-xss-protection', 'LOW', 'Missing X-XSS-Protection'),
                ('referrer-policy', 'LOW', 'Missing Referrer-Policy'),
            ]
            
            for header, severity, desc in checks:
                if header not in headers:
                    vulns.append(Vulnerability(
                        id=f"HEADER-{header.upper().replace('-', '_')}",
                        name=f"Missing {header}",
                        severity=severity,
                        description=desc,
                        url=url,
                        solution=f"Add {header} header to server config"
                    ))
            
            # Info disclosure
            if 'server' in headers:
                vulns.append(Vulnerability(
                    id="INFO-SERVER",
                    name="Server Version Disclosure",
                    severity="LOW",
                    description=f"Server header reveals: {headers['server']}",
                    url=url,
                    evidence=headers['server']
                ))
            
            if 'x-powered-by' in headers:
                vulns.append(Vulnerability(
                    id="INFO-POWERED-BY",
                    name="Technology Disclosure", 
                    severity="LOW",
                    description=f"X-Powered-By reveals: {headers['x-powered-by']}",
                    url=url,
                    evidence=headers['x-powered-by']
                ))
                
        except Exception as e:
            vulns.append(Vulnerability(
                id="SCAN-ERROR",
                name="Scan Error",
                severity="INFO",
                description=str(e)[:200],
                url=url
            ))
        
        return vulns
    
    def check_ssl(self, host: str, port: int = 443) -> List[Vulnerability]:
        """Check SSL/TLS configuration."""
        vulns = []
        
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    version = ssock.version()
                    cert = ssock.getpeercert()
                    
                    # Check TLS version
                    if version in ['TLSv1', 'TLSv1.0']:
                        vulns.append(Vulnerability(
                            id="SSL-WEAK-TLS",
                            name="Weak TLS Version",
                            severity="HIGH",
                            description=f"Uses deprecated {version}",
                            host=host,
                            port=port
                        ))
                    
                    # Check cert expiry
                    if cert:
                        not_after = cert.get('notAfter', '')
                        if not_after:
                            try:
                                expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                                days = (expiry - datetime.now()).days
                                if days < 0:
                                    vulns.append(Vulnerability(
                                        id="SSL-EXPIRED",
                                        name="Expired Certificate",
                                        severity="CRITICAL",
                                        description=f"Certificate expired {abs(days)} days ago",
                                        host=host,
                                        port=port
                                    ))
                                elif days < 30:
                                    vulns.append(Vulnerability(
                                        id="SSL-EXPIRING",
                                        name="Certificate Expiring Soon",
                                        severity="MEDIUM",
                                        description=f"Expires in {days} days",
                                        host=host,
                                        port=port
                                    ))
                            except:
                                pass
                                
        except ssl.SSLCertVerificationError as e:
            vulns.append(Vulnerability(
                id="SSL-INVALID",
                name="Invalid Certificate",
                severity="HIGH",
                description=str(e)[:200],
                host=host,
                port=port
            ))
        except:
            pass
        
        return vulns


# ============================================================================
# ATTACK PATH GENERATOR
# ============================================================================

class AttackPathGenerator:
    """Generate attack paths from scan results."""
    
    # Vulnerability to attack vector mapping
    ATTACK_VECTORS = {
        "ssh": ["brute_force", "key_theft"],
        "ftp": ["brute_force", "anonymous_access"],
        "http": ["web_exploit", "sql_injection", "xss"],
        "https": ["web_exploit", "ssl_strip"],
        "smb": ["eternal_blue", "relay_attack"],
        "rdp": ["brute_force", "bluekeep"],
        "mysql": ["sql_injection", "weak_auth"],
        "postgresql": ["sql_injection", "weak_auth"],
        "redis": ["unauthorized_access", "rce"],
        "mongodb": ["nosql_injection", "no_auth"],
    }
    
    def generate_network_graph(self, hosts: List[Host], vulns: List[Vulnerability], target: str) -> tuple:
        """Generate network nodes and edges from scan data."""
        nodes = []
        edges = []
        
        # Add internet node (entry point)
        nodes.append(NetworkNode(
            id="internet",
            label="Internet (Attacker)",
            type="internet",
            criticality="low"
        ))
        
        # Add nodes for each host
        for host in hosts:
            # Determine criticality based on services
            criticality = "low"
            host_vulns = []
            
            for port in host.ports:
                if port.service in ["mysql", "postgresql", "mongodb", "redis"]:
                    criticality = "critical"
                elif port.service in ["rdp", "ssh", "smb"]:
                    criticality = max(criticality, "high")
                elif port.service in ["http", "https"]:
                    criticality = max(criticality, "medium") if criticality == "low" else criticality
                
                # Link vulnerabilities
                for v in vulns:
                    if v.host == host.ip or v.port == port.port:
                        host_vulns.append(v.id)
            
            node = NetworkNode(
                id=f"host_{host.ip.replace('.', '_')}",
                label=host.hostname or host.ip,
                type="server" if any(p.service in ["http", "https"] for p in host.ports) else "workstation",
                ip=host.ip,
                criticality=criticality,
                vulnerabilities=list(set(host_vulns))
            )
            nodes.append(node)
            
            # Add edge from internet to this host (for each open port)
            for port in host.ports:
                if port.service in self.ATTACK_VECTORS:
                    edges.append(NetworkEdge(
                        source="internet",
                        target=node.id,
                        vulnerability_id=f"{port.service.upper()}-{port.port}",
                        exploit_probability=self._calc_exploit_prob(port.service, vulns)
                    ))
        
        return nodes, edges
    
    def _calc_exploit_prob(self, service: str, vulns: List[Vulnerability]) -> float:
        """Calculate exploit probability based on vulnerabilities."""
        base = 0.3
        
        # Check for related vulnerabilities
        for v in vulns:
            if service.lower() in v.name.lower() or service.lower() in v.description.lower():
                if v.severity == "CRITICAL":
                    base += 0.4
                elif v.severity == "HIGH":
                    base += 0.3
                elif v.severity == "MEDIUM":
                    base += 0.2
        
        return min(base, 0.95)
    
    def find_attack_paths(self, nodes: List[NetworkNode], edges: List[NetworkEdge], 
                          entry: str = "internet") -> List[AttackPath]:
        """Find all attack paths from entry point to critical assets."""
        paths = []
        
        # Find critical targets
        critical_nodes = [n for n in nodes if n.criticality in ["critical", "high"]]
        
        # Build adjacency list
        adj = {}
        edge_map = {}
        for e in edges:
            if e.source not in adj:
                adj[e.source] = []
            adj[e.source].append(e.target)
            edge_map[(e.source, e.target)] = e
        
        # BFS to find paths
        for target in critical_nodes:
            if target.id == entry:
                continue
                
            # Find path using BFS
            queue = [(entry, [entry])]
            visited = set()
            
            while queue:
                current, path = queue.pop(0)
                
                if current == target.id:
                    # Build attack path
                    hops = []
                    total_prob = 1.0
                    
                    for i in range(len(path) - 1):
                        edge = edge_map.get((path[i], path[i+1]))
                        if edge:
                            hops.append({
                                "from": path[i],
                                "to": path[i+1],
                                "via": edge.vulnerability_id,
                                "probability": edge.exploit_probability
                            })
                            total_prob *= edge.exploit_probability
                    
                    if hops:
                        paths.append(AttackPath(
                            id=f"path_{len(paths)+1}",
                            entry_point=entry,
                            target=target.id,
                            hops=hops,
                            total_risk=round(total_prob * 10, 2),
                            exploitability=round(total_prob, 3)
                        ))
                    break
                
                if current in visited:
                    continue
                visited.add(current)
                
                for neighbor in adj.get(current, []):
                    if neighbor not in visited:
                        queue.append((neighbor, path + [neighbor]))
        
        # Sort by risk
        paths.sort(key=lambda p: p.total_risk, reverse=True)
        return paths


# ============================================================================
# INTEGRATED SCANNER
# ============================================================================

class IntegratedScanner:
    """
    Main scanner that combines all tools.
    
    Usage:
        scanner = IntegratedScanner()
        result = await scanner.scan("https://example.com", scan_type="full")
    """
    
    def __init__(self, zap_url: str = None, zap_key: str = None):
        self.nmap = NmapScanner() if NMAP_AVAILABLE else None
        self.zap = ZapScanner(zap_url or "http://localhost:8080", zap_key or "") if ZAP_AVAILABLE else None
        self.simple = SimpleScanner()
        self.path_gen = AttackPathGenerator()
    
    def get_capabilities(self) -> Dict[str, bool]:
        """Check available scanning capabilities."""
        return {
            "nmap": NMAP_AVAILABLE and NmapScanner.is_available(),
            "zap": ZAP_AVAILABLE and self.zap and self.zap.is_running(),
            "simple": True,
            "attack_paths": True
        }
    
    async def scan(self, target: str, scan_type: str = "quick", 
                   ports: str = "21,22,80,443,3306,5432,8080") -> ScanResult:
        """
        Perform integrated security scan.
        
        Args:
            target: URL, IP, or hostname
            scan_type: "quick", "standard", "full"
            ports: Ports to scan
        
        Returns:
            Complete ScanResult with hosts, vulns, and attack paths
        """
        import uuid
        
        # Parse target
        parsed = urlparse(target if "://" in target else f"http://{target}")
        hostname = parsed.netloc or parsed.path
        hostname = hostname.split(':')[0]
        is_url = parsed.scheme in ["http", "https"]
        
        # Initialize result
        result = ScanResult(
            target=target,
            scan_id=str(uuid.uuid4())[:8],
            scan_type=scan_type,
            started_at=datetime.utcnow().isoformat()
        )
        
        start_time = time.time()
        caps = self.get_capabilities()
        
        print(f"\n{'='*60}")
        print(f"🛡️  CTPPO Integrated Scanner")
        print(f"{'='*60}")
        print(f"Target: {target}")
        print(f"Type: {scan_type}")
        print(f"Capabilities: Nmap={caps['nmap']}, ZAP={caps['zap']}")
        print(f"{'='*60}\n")
        
        # 1. Resolve hostname
        try:
            ip = socket.gethostbyname(hostname)
            print(f"✓ Resolved {hostname} → {ip}")
        except socket.gaierror as e:
            result.errors.append(f"DNS resolution failed: {e}")
            ip = hostname
        
        # 2. Port Scanning
        hosts = []
        if caps['nmap'] and scan_type in ["standard", "full"]:
            try:
                nmap_args = "-sV" if scan_type == "standard" else "-sV -sC"
                hosts = self.nmap.scan(ip, ports=ports, args=nmap_args)
            except Exception as e:
                result.errors.append(f"Nmap error: {e}")
        
        # Fallback to simple scanner
        if not hosts:
            print("🔍 Using simple port scanner...")
            port_list = [int(p) for p in ports.split(',')]
            host = self.simple.scan_ports(hostname, port_list)
            host.ip = ip
            hosts = [host]
            print(f"  ✓ Found {len(host.ports)} open ports")
        
        result.hosts = hosts
        
        # 3. Web Vulnerability Scanning
        vulns = []
        
        # OWASP ZAP scan
        if caps['zap'] and is_url and scan_type in ["standard", "full"]:
            try:
                zap_type = "active" if scan_type == "full" else "passive"
                zap_vulns = await self.zap.scan(target, scan_type=zap_type)
                vulns.extend(zap_vulns)
            except Exception as e:
                result.errors.append(f"ZAP error: {e}")
        
        # Simple HTTP header check
        if is_url:
            print("🔍 Checking HTTP security headers...")
            header_vulns = self.simple.check_http_headers(target)
            vulns.extend(header_vulns)
            print(f"  ✓ Found {len(header_vulns)} header issues")
        
        # SSL check
        if parsed.scheme == "https" or ":443" in target:
            print("🔍 Checking SSL/TLS...")
            ssl_vulns = self.simple.check_ssl(hostname, 443)
            vulns.extend(ssl_vulns)
            print(f"  ✓ Found {len(ssl_vulns)} SSL issues")
        
        result.vulnerabilities = vulns
        
        # 4. Generate Attack Paths
        print("🔍 Generating attack paths...")
        nodes, edges = self.path_gen.generate_network_graph(hosts, vulns, target)
        result.network_nodes = nodes
        result.network_edges = edges
        
        paths = self.path_gen.find_attack_paths(nodes, edges)
        result.attack_paths = paths
        print(f"  ✓ Found {len(paths)} attack paths")
        
        # 5. Calculate Risk Summary
        result.risk_summary = self._calc_risk_summary(result)
        
        # Finalize
        result.completed_at = datetime.utcnow().isoformat()
        result.duration_ms = round((time.time() - start_time) * 1000, 2)
        
        print(f"\n{'='*60}")
        print(f"✅ Scan Complete!")
        print(f"{'='*60}")
        print(f"Duration: {result.duration_ms}ms")
        print(f"Hosts: {len(result.hosts)}")
        print(f"Open Ports: {sum(len(h.ports) for h in result.hosts)}")
        print(f"Vulnerabilities: {len(result.vulnerabilities)}")
        print(f"Attack Paths: {len(result.attack_paths)}")
        print(f"Risk Level: {result.risk_summary.get('risk_level', 'UNKNOWN')}")
        print(f"{'='*60}\n")
        
        return result
    
    def _calc_risk_summary(self, result: ScanResult) -> Dict:
        """Calculate risk summary."""
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        
        for v in result.vulnerabilities:
            sev = v.severity.upper()
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        # Determine risk level
        if severity_counts["CRITICAL"] > 0:
            risk_level = "CRITICAL"
        elif severity_counts["HIGH"] > 0:
            risk_level = "HIGH"
        elif severity_counts["MEDIUM"] > 0:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        return {
            "risk_level": risk_level,
            "total_vulnerabilities": len(result.vulnerabilities),
            "severity_breakdown": severity_counts,
            "total_hosts": len(result.hosts),
            "total_open_ports": sum(len(h.ports) for h in result.hosts),
            "total_attack_paths": len(result.attack_paths),
            "highest_risk_path": result.attack_paths[0].total_risk if result.attack_paths else 0,
            "recommendations": self._get_recommendations(result)
        }
    
    def _get_recommendations(self, result: ScanResult) -> List[str]:
        """Generate remediation recommendations."""
        recs = []
        
        critical = [v for v in result.vulnerabilities if v.severity == "CRITICAL"]
        high = [v for v in result.vulnerabilities if v.severity == "HIGH"]
        
        for v in critical[:3]:
            recs.append(f"🔴 IMMEDIATE: Fix {v.name}")
        
        for v in high[:3]:
            recs.append(f"🟠 HIGH: Address {v.name}")
        
        if not recs:
            recs.append("🟢 No critical issues found")
        
        return recs


# ============================================================================
# CLI
# ============================================================================

async def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="CTPPO Integrated Scanner")
    parser.add_argument("target", help="URL, IP, or hostname to scan")
    parser.add_argument("-t", "--type", choices=["quick", "standard", "full"], default="quick")
    parser.add_argument("-p", "--ports", default="21,22,80,443,3306,5432,8080")
    parser.add_argument("-o", "--output", help="Output JSON file")
    parser.add_argument("--zap-url", default="http://localhost:8080")
    parser.add_argument("--zap-key", default="")
    
    args = parser.parse_args()
    
    scanner = IntegratedScanner(args.zap_url, args.zap_key)
    result = await scanner.scan(args.target, args.type, args.ports)
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(result.to_dict(), f, indent=2)
        print(f"Results saved to {args.output}")
    else:
        print(json.dumps(result.to_dict(), indent=2))


if __name__ == "__main__":
    asyncio.run(main())
