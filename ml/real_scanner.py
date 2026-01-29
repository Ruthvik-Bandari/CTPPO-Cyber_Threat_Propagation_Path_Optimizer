#!/usr/bin/env python3
"""
CTPPO Real Vulnerability Scanner
=================================

Real-world vulnerability scanning using:
- Nmap for network discovery and port scanning
- OWASP ZAP for web application security testing
- NVD/CVE database for vulnerability correlation

Author: Ruthvik Bandari
Date: January 2026
"""

import subprocess
import json
import re
import asyncio
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any, Tuple
from datetime import datetime
from pathlib import Path
import socket
import ssl
import urllib.parse
import http.client
import os

# Optional imports
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
class Port:
    """Represents an open port on a host."""
    number: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    version: str = ""
    product: str = ""
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class DiscoveredHost:
    """Represents a discovered host in the network."""
    ip: str
    hostname: str = ""
    mac: str = ""
    os_guess: str = ""
    ports: List[Port] = field(default_factory=list)
    status: str = "up"
    
    def to_dict(self) -> Dict:
        return {
            **asdict(self),
            "ports": [p.to_dict() for p in self.ports]
        }


@dataclass 
class WebVulnerability:
    """Represents a web application vulnerability found by ZAP."""
    alert: str
    risk: str  # High, Medium, Low, Informational
    confidence: str  # High, Medium, Low
    url: str
    description: str
    solution: str
    reference: str = ""
    cwe_id: Optional[int] = None
    wasc_id: Optional[int] = None
    evidence: str = ""
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class CVEMatch:
    """Represents a CVE that matches a discovered service."""
    cve_id: str
    severity: str
    cvss_score: float
    description: str
    affected_product: str
    affected_version: str
    references: List[str] = field(default_factory=list)
    has_exploit: bool = False
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class ScanResult:
    """Complete scan result for a target."""
    target: str
    scan_type: str
    started_at: str
    completed_at: str
    hosts: List[DiscoveredHost] = field(default_factory=list)
    web_vulns: List[WebVulnerability] = field(default_factory=list)
    cve_matches: List[CVEMatch] = field(default_factory=list)
    attack_paths: List[Dict] = field(default_factory=list)
    risk_summary: Dict = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "target": self.target,
            "scan_type": self.scan_type,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "hosts": [h.to_dict() for h in self.hosts],
            "web_vulns": [v.to_dict() for v in self.web_vulns],
            "cve_matches": [c.to_dict() for c in self.cve_matches],
            "attack_paths": self.attack_paths,
            "risk_summary": self.risk_summary,
            "errors": self.errors
        }


# ============================================================================
# NMAP SCANNER
# ============================================================================

class NmapScanner:
    """Network scanner using Nmap."""
    
    def __init__(self):
        self.scanner = nmap.PortScanner() if NMAP_AVAILABLE else None
    
    def is_available(self) -> bool:
        """Check if Nmap is available."""
        if not NMAP_AVAILABLE:
            return False
        try:
            subprocess.run(["nmap", "--version"], capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False
    
    def quick_scan(self, target: str) -> List[DiscoveredHost]:
        """Quick scan of common ports."""
        if not self.scanner:
            raise RuntimeError("Nmap not available")
        
        # Quick scan of top 100 ports
        self.scanner.scan(target, arguments='-F -sV --version-light -T4')
        return self._parse_results()
    
    def full_scan(self, target: str) -> List[DiscoveredHost]:
        """Full scan with service detection and OS fingerprinting."""
        if not self.scanner:
            raise RuntimeError("Nmap not available")
        
        # Full scan with service and OS detection
        self.scanner.scan(target, arguments='-sV -sC -O -T4 --top-ports 1000')
        return self._parse_results()
    
    def vulnerability_scan(self, target: str) -> Tuple[List[DiscoveredHost], List[Dict]]:
        """Scan with Nmap vulnerability scripts."""
        if not self.scanner:
            raise RuntimeError("Nmap not available")
        
        # Use Nmap's vuln scripts
        self.scanner.scan(target, arguments='-sV --script vuln -T4')
        hosts = self._parse_results()
        vulns = self._parse_vuln_scripts()
        return hosts, vulns
    
    def _parse_results(self) -> List[DiscoveredHost]:
        """Parse Nmap scan results."""
        hosts = []
        
        for host_ip in self.scanner.all_hosts():
            host_data = self.scanner[host_ip]
            
            # Get hostname
            hostname = ""
            if 'hostnames' in host_data and host_data['hostnames']:
                hostname = host_data['hostnames'][0].get('name', '')
            
            # Get OS guess
            os_guess = ""
            if 'osmatch' in host_data and host_data['osmatch']:
                os_guess = host_data['osmatch'][0].get('name', '')
            
            # Get MAC address
            mac = ""
            if 'addresses' in host_data and 'mac' in host_data['addresses']:
                mac = host_data['addresses']['mac']
            
            # Get ports
            ports = []
            for protocol in ['tcp', 'udp']:
                if protocol in host_data:
                    for port_num, port_data in host_data[protocol].items():
                        ports.append(Port(
                            number=port_num,
                            protocol=protocol,
                            state=port_data.get('state', 'unknown'),
                            service=port_data.get('name', ''),
                            version=port_data.get('version', ''),
                            product=port_data.get('product', '')
                        ))
            
            hosts.append(DiscoveredHost(
                ip=host_ip,
                hostname=hostname,
                mac=mac,
                os_guess=os_guess,
                ports=ports,
                status=host_data.get('status', {}).get('state', 'unknown')
            ))
        
        return hosts
    
    def _parse_vuln_scripts(self) -> List[Dict]:
        """Parse vulnerability script output."""
        vulns = []
        
        for host_ip in self.scanner.all_hosts():
            host_data = self.scanner[host_ip]
            
            for protocol in ['tcp', 'udp']:
                if protocol not in host_data:
                    continue
                    
                for port_num, port_data in host_data[protocol].items():
                    if 'script' not in port_data:
                        continue
                    
                    for script_name, script_output in port_data['script'].items():
                        if 'VULNERABLE' in script_output.upper():
                            # Extract CVE if present
                            cve_match = re.search(r'CVE-\d{4}-\d+', script_output)
                            cve_id = cve_match.group(0) if cve_match else None
                            
                            vulns.append({
                                'host': host_ip,
                                'port': port_num,
                                'protocol': protocol,
                                'script': script_name,
                                'output': script_output,
                                'cve_id': cve_id
                            })
        
        return vulns


# ============================================================================
# ZAP SCANNER
# ============================================================================

class ZAPScanner:
    """Web application scanner using OWASP ZAP."""
    
    def __init__(self, zap_url: str = "http://127.0.0.1:8080", api_key: str = ""):
        self.zap_url = zap_url
        self.api_key = api_key or os.environ.get("ZAP_API_KEY", "")
        self.zap = None
        
        if ZAP_AVAILABLE and self.api_key:
            try:
                self.zap = ZAPv2(apikey=self.api_key, proxies={'http': zap_url, 'https': zap_url})
            except Exception as e:
                print(f"⚠️ Could not connect to ZAP: {e}")
    
    def is_available(self) -> bool:
        """Check if ZAP is available and running."""
        if not ZAP_AVAILABLE or not self.zap:
            return False
        try:
            self.zap.core.version
            return True
        except:
            return False
    
    def spider_scan(self, target_url: str, max_depth: int = 5) -> List[str]:
        """Spider the target URL to discover pages."""
        if not self.zap:
            raise RuntimeError("ZAP not available")
        
        # Start spider
        scan_id = self.zap.spider.scan(target_url, maxchildren=max_depth)
        
        # Wait for spider to complete
        while int(self.zap.spider.status(scan_id)) < 100:
            asyncio.sleep(1)
        
        # Return discovered URLs
        return self.zap.spider.results(scan_id)
    
    def active_scan(self, target_url: str) -> List[WebVulnerability]:
        """Perform active vulnerability scan."""
        if not self.zap:
            raise RuntimeError("ZAP not available")
        
        # Start active scan
        scan_id = self.zap.ascan.scan(target_url)
        
        # Wait for scan to complete
        while int(self.zap.ascan.status(scan_id)) < 100:
            asyncio.sleep(2)
        
        # Get alerts
        return self._get_alerts(target_url)
    
    def passive_scan(self, target_url: str) -> List[WebVulnerability]:
        """Get results from passive scanning."""
        if not self.zap:
            raise RuntimeError("ZAP not available")
        
        # Access the URL to trigger passive scanning
        self.zap.urlopen(target_url)
        asyncio.sleep(2)  # Wait for passive scan
        
        return self._get_alerts(target_url)
    
    def _get_alerts(self, target_url: str = None) -> List[WebVulnerability]:
        """Get all alerts from ZAP."""
        if not self.zap:
            return []
        
        alerts = self.zap.core.alerts(baseurl=target_url) if target_url else self.zap.core.alerts()
        
        vulns = []
        for alert in alerts:
            vulns.append(WebVulnerability(
                alert=alert.get('alert', ''),
                risk=alert.get('risk', 'Informational'),
                confidence=alert.get('confidence', 'Low'),
                url=alert.get('url', ''),
                description=alert.get('description', ''),
                solution=alert.get('solution', ''),
                reference=alert.get('reference', ''),
                cwe_id=int(alert['cweid']) if alert.get('cweid') and alert['cweid'] != '-1' else None,
                wasc_id=int(alert['wascid']) if alert.get('wascid') and alert['wascid'] != '-1' else None,
                evidence=alert.get('evidence', '')
            ))
        
        return vulns


# ============================================================================
# SIMPLE SCANNER (No external dependencies)
# ============================================================================

class SimpleScanner:
    """Basic scanner using only Python stdlib - works without Nmap/ZAP."""
    
    def __init__(self):
        self.common_ports = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
            80: 'http', 110: 'pop3', 143: 'imap', 443: 'https', 445: 'smb',
            993: 'imaps', 995: 'pop3s', 1433: 'mssql', 1521: 'oracle',
            3306: 'mysql', 3389: 'rdp', 5432: 'postgresql', 5900: 'vnc',
            6379: 'redis', 8080: 'http-proxy', 8443: 'https-alt', 27017: 'mongodb'
        }
    
    def scan_host(self, target: str, ports: List[int] = None, timeout: float = 1.0) -> DiscoveredHost:
        """Scan a single host for open ports."""
        if ports is None:
            ports = list(self.common_ports.keys())
        
        # Resolve hostname to IP
        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror:
            ip = target
        
        # Try to get hostname
        hostname = ""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            hostname = target if target != ip else ""
        
        # Scan ports
        open_ports = []
        for port in ports:
            if self._check_port(ip, port, timeout):
                service = self.common_ports.get(port, "unknown")
                version = self._get_banner(ip, port, timeout)
                open_ports.append(Port(
                    number=port,
                    protocol="tcp",
                    state="open",
                    service=service,
                    version=version
                ))
        
        return DiscoveredHost(
            ip=ip,
            hostname=hostname,
            ports=open_ports,
            status="up" if open_ports else "down"
        )
    
    def _check_port(self, ip: str, port: int, timeout: float) -> bool:
        """Check if a port is open."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def _get_banner(self, ip: str, port: int, timeout: float) -> str:
        """Try to grab service banner."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            
            # For HTTP/HTTPS
            if port in [80, 8080]:
                sock.send(b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
            elif port == 443:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=ip)
                sock.send(b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
            else:
                sock.send(b"\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            # Extract server info
            if 'Server:' in banner:
                match = re.search(r'Server:\s*(.+)', banner)
                if match:
                    return match.group(1).strip()
            
            return banner[:100] if banner else ""
        except:
            return ""
    
    def check_ssl_vulnerabilities(self, target: str, port: int = 443) -> List[Dict]:
        """Check for common SSL/TLS vulnerabilities."""
        vulns = []
        
        try:
            ip = socket.gethostbyname(target)
            
            # Check supported TLS versions
            for version_name, version in [
                ('SSLv2', ssl.PROTOCOL_SSLv23),
                ('SSLv3', ssl.PROTOCOL_SSLv23),
                ('TLSv1.0', ssl.PROTOCOL_TLSv1 if hasattr(ssl, 'PROTOCOL_TLSv1') else None),
                ('TLSv1.1', ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, 'PROTOCOL_TLSv1_1') else None),
            ]:
                if version is None:
                    continue
                    
                try:
                    context = ssl.SSLContext(version)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3)
                    sock.connect((ip, port))
                    
                    ssl_sock = context.wrap_socket(sock, server_hostname=target)
                    ssl_sock.close()
                    
                    if version_name in ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']:
                        vulns.append({
                            'type': 'weak_tls',
                            'severity': 'MEDIUM' if 'TLS' in version_name else 'HIGH',
                            'description': f'{version_name} is enabled (deprecated and insecure)',
                            'recommendation': 'Disable {version_name} and use TLS 1.2 or higher'
                        })
                except:
                    pass
            
            # Check certificate
            try:
                context = ssl.create_default_context()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((ip, port))
                ssl_sock = context.wrap_socket(sock, server_hostname=target)
                cert = ssl_sock.getpeercert()
                ssl_sock.close()
                
                # Check expiration
                from datetime import datetime
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                if not_after < datetime.now():
                    vulns.append({
                        'type': 'expired_cert',
                        'severity': 'HIGH',
                        'description': f'SSL certificate expired on {not_after}',
                        'recommendation': 'Renew the SSL certificate'
                    })
                elif (not_after - datetime.now()).days < 30:
                    vulns.append({
                        'type': 'expiring_cert',
                        'severity': 'MEDIUM',
                        'description': f'SSL certificate expires in {(not_after - datetime.now()).days} days',
                        'recommendation': 'Renew the SSL certificate soon'
                    })
            except ssl.SSLCertVerificationError as e:
                vulns.append({
                    'type': 'invalid_cert',
                    'severity': 'HIGH',
                    'description': f'SSL certificate verification failed: {str(e)}',
                    'recommendation': 'Use a valid SSL certificate from a trusted CA'
                })
            except:
                pass
        
        except Exception as e:
            vulns.append({
                'type': 'ssl_error',
                'severity': 'INFO',
                'description': f'Could not check SSL: {str(e)}',
                'recommendation': ''
            })
        
        return vulns
    
    def check_http_security_headers(self, url: str) -> List[Dict]:
        """Check for missing HTTP security headers."""
        vulns = []
        
        required_headers = {
            'Strict-Transport-Security': {
                'severity': 'MEDIUM',
                'description': 'HSTS header is missing',
                'cwe': 'CWE-311'
            },
            'X-Content-Type-Options': {
                'severity': 'LOW',
                'description': 'X-Content-Type-Options header is missing',
                'cwe': 'CWE-16'
            },
            'X-Frame-Options': {
                'severity': 'MEDIUM',
                'description': 'X-Frame-Options header is missing (Clickjacking)',
                'cwe': 'CWE-1021'
            },
            'Content-Security-Policy': {
                'severity': 'MEDIUM',
                'description': 'Content-Security-Policy header is missing',
                'cwe': 'CWE-16'
            },
            'X-XSS-Protection': {
                'severity': 'LOW',
                'description': 'X-XSS-Protection header is missing',
                'cwe': 'CWE-79'
            }
        }
        
        try:
            parsed = urllib.parse.urlparse(url)
            
            if parsed.scheme == 'https':
                conn = http.client.HTTPSConnection(parsed.netloc, timeout=10)
            else:
                conn = http.client.HTTPConnection(parsed.netloc, timeout=10)
            
            conn.request("HEAD", parsed.path or "/")
            response = conn.getresponse()
            headers = {k.lower(): v for k, v in response.getheaders()}
            conn.close()
            
            for header, info in required_headers.items():
                if header.lower() not in headers:
                    vulns.append({
                        'type': 'missing_header',
                        'header': header,
                        'severity': info['severity'],
                        'description': info['description'],
                        'cwe': info['cwe']
                    })
            
            # Check for information disclosure
            if 'server' in headers:
                vulns.append({
                    'type': 'info_disclosure',
                    'severity': 'LOW',
                    'description': f'Server header reveals: {headers["server"]}',
                    'recommendation': 'Remove or obfuscate the Server header'
                })
            
            if 'x-powered-by' in headers:
                vulns.append({
                    'type': 'info_disclosure',
                    'severity': 'LOW',
                    'description': f'X-Powered-By header reveals: {headers["x-powered-by"]}',
                    'recommendation': 'Remove the X-Powered-By header'
                })
        
        except Exception as e:
            vulns.append({
                'type': 'http_error',
                'severity': 'INFO',
                'description': f'Could not check HTTP headers: {str(e)}'
            })
        
        return vulns


# ============================================================================
# CVE CORRELATOR
# ============================================================================

class CVECorrelator:
    """Correlates discovered services with known CVEs."""
    
    # Known vulnerable versions (simplified - in production, query NVD API)
    KNOWN_VULNS = {
        'apache': [
            ('2.4.49', 'CVE-2021-41773', 'CRITICAL', 9.8, 'Path Traversal'),
            ('2.4.50', 'CVE-2021-42013', 'CRITICAL', 9.8, 'Path Traversal RCE'),
        ],
        'nginx': [
            ('1.18.0', 'CVE-2021-23017', 'HIGH', 7.7, 'DNS Resolver Vulnerability'),
        ],
        'openssh': [
            ('8.2', 'CVE-2020-15778', 'HIGH', 7.8, 'Command Injection'),
            ('7.7', 'CVE-2018-15919', 'MEDIUM', 5.3, 'Username Enumeration'),
        ],
        'mysql': [
            ('5.7', 'CVE-2020-14812', 'MEDIUM', 4.9, 'DoS Vulnerability'),
        ],
        'redis': [
            ('6.0', 'CVE-2021-32761', 'HIGH', 7.5, 'Integer Overflow'),
        ],
        'log4j': [
            ('2.14', 'CVE-2021-44228', 'CRITICAL', 10.0, 'Log4Shell RCE'),
            ('2.15', 'CVE-2021-45046', 'CRITICAL', 9.0, 'Log4Shell Bypass'),
        ]
    }
    
    def correlate(self, hosts: List[DiscoveredHost]) -> List[CVEMatch]:
        """Find CVEs that match discovered services."""
        matches = []
        
        for host in hosts:
            for port in host.ports:
                product = port.product.lower() if port.product else port.service.lower()
                version = port.version
                
                for product_name, vulns in self.KNOWN_VULNS.items():
                    if product_name in product:
                        for vuln_version, cve_id, severity, cvss, desc in vulns:
                            if version and vuln_version in version:
                                matches.append(CVEMatch(
                                    cve_id=cve_id,
                                    severity=severity,
                                    cvss_score=cvss,
                                    description=desc,
                                    affected_product=product,
                                    affected_version=version,
                                    has_exploit=(severity == 'CRITICAL')
                                ))
        
        return matches


# ============================================================================
# MAIN SCANNER ORCHESTRATOR
# ============================================================================

class VulnerabilityScanner:
    """Main scanner that orchestrates all scanning tools."""
    
    def __init__(self, zap_url: str = None, zap_api_key: str = None):
        self.nmap = NmapScanner()
        self.zap = ZAPScanner(zap_url, zap_api_key) if zap_url else None
        self.simple = SimpleScanner()
        self.cve_correlator = CVECorrelator()
    
    def get_capabilities(self) -> Dict[str, bool]:
        """Check what scanning capabilities are available."""
        return {
            'nmap': self.nmap.is_available(),
            'zap': self.zap.is_available() if self.zap else False,
            'simple': True  # Always available
        }
    
    async def scan(
        self,
        target: str,
        scan_type: str = "quick",
        include_web_scan: bool = True
    ) -> ScanResult:
        """
        Perform a comprehensive vulnerability scan.
        
        Args:
            target: URL, IP, or hostname to scan
            scan_type: 'quick', 'full', or 'vuln'
            include_web_scan: Whether to include web application scanning
        
        Returns:
            ScanResult with all findings
        """
        started_at = datetime.now().isoformat()
        result = ScanResult(
            target=target,
            scan_type=scan_type,
            started_at=started_at,
            completed_at=""
        )
        
        # Parse target
        parsed = urllib.parse.urlparse(target if '://' in target else f'http://{target}')
        host = parsed.netloc or parsed.path
        host = host.split(':')[0]  # Remove port if present
        
        # Network scan
        try:
            if self.nmap.is_available():
                if scan_type == "quick":
                    result.hosts = self.nmap.quick_scan(host)
                elif scan_type == "full":
                    result.hosts = self.nmap.full_scan(host)
                elif scan_type == "vuln":
                    hosts, nmap_vulns = self.nmap.vulnerability_scan(host)
                    result.hosts = hosts
                    # Add Nmap vuln findings
                    for v in nmap_vulns:
                        if v.get('cve_id'):
                            result.cve_matches.append(CVEMatch(
                                cve_id=v['cve_id'],
                                severity="HIGH",
                                cvss_score=7.5,
                                description=v.get('output', '')[:200],
                                affected_product=f"{v['host']}:{v['port']}",
                                affected_version=""
                            ))
            else:
                # Fallback to simple scanner
                result.hosts = [self.simple.scan_host(host)]
        except Exception as e:
            result.errors.append(f"Network scan error: {str(e)}")
            # Try simple scanner as fallback
            try:
                result.hosts = [self.simple.scan_host(host)]
            except Exception as e2:
                result.errors.append(f"Simple scan error: {str(e2)}")
        
        # Web application scan
        if include_web_scan and (parsed.scheme in ['http', 'https'] or target.startswith('http')):
            url = target if '://' in target else f'http://{target}'
            
            # Try ZAP first
            if self.zap and self.zap.is_available():
                try:
                    # Spider and active scan
                    self.zap.spider_scan(url)
                    result.web_vulns = self.zap.active_scan(url)
                except Exception as e:
                    result.errors.append(f"ZAP scan error: {str(e)}")
            
            # Always do basic HTTP checks
            try:
                header_vulns = self.simple.check_http_security_headers(url)
                for hv in header_vulns:
                    result.web_vulns.append(WebVulnerability(
                        alert=hv.get('type', 'Unknown'),
                        risk=hv.get('severity', 'LOW'),
                        confidence='High',
                        url=url,
                        description=hv.get('description', ''),
                        solution=hv.get('recommendation', ''),
                        cwe_id=int(hv['cwe'].replace('CWE-', '')) if hv.get('cwe') else None
                    ))
            except Exception as e:
                result.errors.append(f"HTTP header check error: {str(e)}")
            
            # SSL checks for HTTPS
            if 'https' in url or ':443' in target:
                try:
                    ssl_vulns = self.simple.check_ssl_vulnerabilities(host, 443)
                    for sv in ssl_vulns:
                        result.web_vulns.append(WebVulnerability(
                            alert=sv.get('type', 'SSL Issue'),
                            risk=sv.get('severity', 'MEDIUM'),
                            confidence='High',
                            url=url,
                            description=sv.get('description', ''),
                            solution=sv.get('recommendation', '')
                        ))
                except Exception as e:
                    result.errors.append(f"SSL check error: {str(e)}")
        
        # Correlate CVEs
        try:
            cve_matches = self.cve_correlator.correlate(result.hosts)
            result.cve_matches.extend(cve_matches)
        except Exception as e:
            result.errors.append(f"CVE correlation error: {str(e)}")
        
        # Generate risk summary
        result.risk_summary = self._calculate_risk_summary(result)
        result.completed_at = datetime.now().isoformat()
        
        return result
    
    def _calculate_risk_summary(self, result: ScanResult) -> Dict:
        """Calculate overall risk summary."""
        critical = 0
        high = 0
        medium = 0
        low = 0
        
        # Count CVE severities
        for cve in result.cve_matches:
            if cve.severity == 'CRITICAL':
                critical += 1
            elif cve.severity == 'HIGH':
                high += 1
            elif cve.severity == 'MEDIUM':
                medium += 1
            else:
                low += 1
        
        # Count web vuln severities
        for vuln in result.web_vulns:
            if vuln.risk == 'High':
                high += 1
            elif vuln.risk == 'Medium':
                medium += 1
            elif vuln.risk == 'Low':
                low += 1
        
        # Determine overall risk level
        if critical > 0:
            risk_level = 'CRITICAL'
        elif high > 0:
            risk_level = 'HIGH'
        elif medium > 0:
            risk_level = 'MEDIUM'
        elif low > 0:
            risk_level = 'LOW'
        else:
            risk_level = 'INFO'
        
        # Count total open ports
        total_ports = sum(len(h.ports) for h in result.hosts)
        
        return {
            'risk_level': risk_level,
            'total_hosts': len(result.hosts),
            'total_open_ports': total_ports,
            'vulnerabilities': {
                'critical': critical,
                'high': high,
                'medium': medium,
                'low': low,
                'total': critical + high + medium + low
            },
            'web_vulnerabilities': len(result.web_vulns),
            'cve_matches': len(result.cve_matches),
            'recommendation': self._get_recommendation(risk_level, critical, high)
        }
    
    def _get_recommendation(self, risk_level: str, critical: int, high: int) -> str:
        """Generate recommendation based on findings."""
        if critical > 0:
            return f"URGENT: {critical} critical vulnerabilities found. Immediate patching required!"
        elif high > 0:
            return f"WARNING: {high} high-severity issues found. Schedule patching within 24-48 hours."
        elif risk_level == 'MEDIUM':
            return "Review medium-severity findings and plan remediation."
        else:
            return "No critical issues found. Continue regular security monitoring."


# ============================================================================
# CLI INTERFACE
# ============================================================================

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="CTPPO Vulnerability Scanner")
    parser.add_argument("target", help="Target URL, IP, or hostname")
    parser.add_argument("-t", "--type", choices=["quick", "full", "vuln"], default="quick",
                       help="Scan type (default: quick)")
    parser.add_argument("--no-web", action="store_true", help="Skip web application scanning")
    parser.add_argument("--zap-url", help="ZAP API URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--zap-key", help="ZAP API key")
    parser.add_argument("-o", "--output", help="Output file (JSON)")
    
    args = parser.parse_args()
    
    # Create scanner
    scanner = VulnerabilityScanner(args.zap_url, args.zap_key)
    
    # Show capabilities
    caps = scanner.get_capabilities()
    print(f"Scanner capabilities: Nmap={caps['nmap']}, ZAP={caps['zap']}, Simple={caps['simple']}")
    
    # Run scan
    print(f"Scanning {args.target} ({args.type} scan)...")
    result = asyncio.run(scanner.scan(args.target, args.type, not args.no_web))
    
    # Output
    output = result.to_dict()
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(output, f, indent=2)
        print(f"Results saved to {args.output}")
    else:
        print(json.dumps(output, indent=2))
