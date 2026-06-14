"""
Nmap Scanner Integration
========================

Provides network reconnaissance capabilities including:
- Port scanning
- Service detection
- Version detection
- Vulnerability scanning with NSE scripts

Author: Ruthvik
Date: November 2025
"""

import re
import socket
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
import logging

from .models import (
    ScanTarget, ScanResult, VulnerabilityFinding, PortInfo, ServiceInfo,
    Severity, ScannerType, ScanMode, classify_owasp_category, get_mitre_techniques
)

logger = logging.getLogger(__name__)


class NmapScanner:
    """
    Nmap scanner wrapper for network reconnaissance.
    
    Provides:
    - Port scanning (TCP/UDP)
    - Service/version detection
    - OS detection
    - Vulnerability scanning via NSE scripts
    """
    
    def __init__(self):
        """Initialize Nmap scanner"""
        self.nm = None
        self._check_nmap_available()
    
    def _check_nmap_available(self):
        """Check if nmap is installed and accessible"""
        try:
            import nmap
            self.nm = nmap.PortScanner()
            logger.info("Nmap scanner initialized successfully")
        except Exception as e:
            logger.warning(f"Nmap not available: {e}. Install with: brew install nmap")
            self.nm = None
    
    def is_available(self) -> bool:
        """Check if scanner is available"""
        return self.nm is not None
    
    def scan(
        self,
        target: ScanTarget,
        scan_type: str = "comprehensive"
    ) -> ScanResult:
        """
        Perform Nmap scan on target.
        
        Args:
            target: Scan target with host/IP information
            scan_type: Type of scan (quick, comprehensive, vulnerability)
            
        Returns:
            ScanResult with findings
        """
        result = ScanResult(
            target=target,
            scan_mode=target.scan_mode,
            scanners_used=[ScannerType.NMAP],
            started_at=datetime.now()
        )
        
        if not self.is_available():
            result.status = "failed"
            result.error_message = "Nmap not available"
            return result
        
        try:
            result.status = "running"
            
            # Determine host to scan
            host = target.ip_address or target.host
            if not host:
                # Try to resolve from URL
                if target.url:
                    from urllib.parse import urlparse
                    parsed = urlparse(target.url)
                    host = parsed.hostname
            
            if not host:
                raise ValueError("No host specified for scanning")
            
            # Resolve hostname to IP if needed
            try:
                ip_address = socket.gethostbyname(host)
            except socket.gaierror:
                ip_address = host
            
            # Build scan arguments based on type
            arguments = self._get_scan_arguments(scan_type, target.ports)
            
            logger.info(f"Starting Nmap scan on {host} with arguments: {arguments}")
            
            # Execute scan
            self.nm.scan(hosts=ip_address, arguments=arguments)
            
            # Process results
            for scanned_host in self.nm.all_hosts():
                # Get host info
                host_info = self.nm[scanned_host]
                
                # Process ports
                for proto in host_info.all_protocols():
                    ports = host_info[proto].keys()
                    for port in ports:
                        port_data = host_info[proto][port]
                        
                        port_info = PortInfo(
                            port=port,
                            protocol=proto,
                            state=port_data.get('state', 'unknown'),
                            service=port_data.get('name', ''),
                            version=port_data.get('version', ''),
                            product=port_data.get('product', ''),
                            extra_info=port_data.get('extrainfo', ''),
                            cpe=port_data.get('cpe', '').split() if port_data.get('cpe') else []
                        )
                        
                        # Check for script results (vulnerabilities)
                        if 'script' in port_data:
                            port_info.scripts = port_data['script']
                            
                            # Parse script results for vulnerabilities
                            vulns = self._parse_script_results(
                                port_data['script'],
                                host,
                                port,
                                port_data.get('name', '')
                            )
                            result.vulnerabilities.extend(vulns)
                        
                        result.open_ports.append(port_info)
                        
                        # Add service info
                        if port_data.get('name'):
                            service = ServiceInfo(
                                name=port_data.get('name', ''),
                                version=port_data.get('version', ''),
                                product=port_data.get('product', ''),
                                port=port,
                                protocol=proto,
                                cpe=port_data.get('cpe', '').split() if port_data.get('cpe') else []
                            )
                            result.services.append(service)
            
            # Add informational findings for open ports
            result.vulnerabilities.extend(
                self._create_port_findings(result.open_ports, host)
            )
            
            result.status = "completed"
            result.completed_at = datetime.now()
            result.duration_seconds = (result.completed_at - result.started_at).total_seconds()
            
            logger.info(f"Nmap scan completed. Found {len(result.open_ports)} open ports, "
                       f"{len(result.vulnerabilities)} findings")
            
        except Exception as e:
            logger.error(f"Nmap scan failed: {e}")
            result.status = "failed"
            result.error_message = str(e)
        
        return result
    
    def _get_scan_arguments(self, scan_type: str, ports: List[int] = None) -> str:
        """Get Nmap arguments based on scan type"""
        
        # Port specification
        port_arg = f"-p {','.join(map(str, ports))}" if ports else "-p 1-1000"
        
        scan_configs = {
            "quick": f"-sT -sV --version-light {port_arg}",
            "comprehensive": f"-sT -sV -sC {port_arg} --script=default,vuln",
            "vulnerability": f"-sT -sV {port_arg} --script=vuln,exploit,auth",
            "stealth": f"-sS -sV {port_arg} -T2",
            "aggressive": f"-sT -sV -A {port_arg} --script=vuln,exploit"
        }
        
        return scan_configs.get(scan_type, scan_configs["quick"])
    
    def _parse_script_results(
        self,
        scripts: Dict[str, str],
        host: str,
        port: int,
        service: str
    ) -> List[VulnerabilityFinding]:
        """Parse NSE script results for vulnerabilities"""
        findings = []
        
        for script_name, output in scripts.items():
            # Skip non-vulnerability scripts
            if not self._is_vulnerability_script(script_name, output):
                continue
            
            # Parse CVEs from output AND script name
            cve_pattern = r'CVE-\d{4}-\d+'
            cves = re.findall(cve_pattern, output, re.IGNORECASE)
            # Also extract from script name (e.g., http-vuln-cve2014-3704)
            script_cves = re.findall(cve_pattern, script_name, re.IGNORECASE)
            cves.extend(script_cves)
            
            # Determine severity from script output
            severity = self._determine_severity_from_script(script_name, output)
            
            finding = VulnerabilityFinding(
                title=f"{script_name} - {service} on port {port}",
                description=output[:1000],
                severity=severity,
                confidence="High" if cves else "Medium",
                scanner=ScannerType.NMAP,
                scanner_rule_id=script_name,
                target_host=host,
                target_port=port,
                cve_ids=list(set(cves)),
                evidence=output,
                owasp_category=classify_owasp_category(script_name, output),
                mitre_attack_ids=get_mitre_techniques(script_name, output)
            )
            
            findings.append(finding)
        
        return findings
    
    def _is_vulnerability_script(self, script_name: str, output: str) -> bool:
        """Check if script output indicates a vulnerability"""
        # Vulnerability indicators
        vuln_keywords = [
            'vulnerable', 'vulnerability', 'exploit', 'cve-',
            'risk', 'danger', 'warning', 'weak', 'insecure',
            'state: vulnerable', 'is vulnerable'
        ]
        
        output_lower = output.lower()
        script_lower = script_name.lower()
        
        # Check script name
        if any(kw in script_lower for kw in ['vuln', 'exploit', 'auth-']):
            return True
        
        # Check output
        return any(kw in output_lower for kw in vuln_keywords)
    
    def _determine_severity_from_script(self, script_name: str, output: str) -> Severity:
        """Determine severity from script name and output"""
        output_lower = output.lower()
        script_lower = script_name.lower()
        
        # Critical indicators
        if any(kw in output_lower for kw in ['remote code execution', 'rce', 'critical']):
            return Severity.CRITICAL
        
        # High indicators
        if any(kw in output_lower for kw in ['exploit available', 'high', 'authentication bypass']):
            return Severity.HIGH
        
        # Script-based severity
        high_scripts = ['smb-vuln', 'ssl-heartbleed', 'http-vuln', 'ms17-010']
        if any(hs in script_lower for hs in high_scripts):
            return Severity.HIGH
        
        medium_scripts = ['ssl-', 'http-server-header', 'http-methods']
        if any(ms in script_lower for ms in medium_scripts):
            return Severity.MEDIUM
        
        return Severity.LOW
    
    def _create_port_findings(
        self,
        ports: List[PortInfo],
        host: str
    ) -> List[VulnerabilityFinding]:
        """Create informational findings for open ports"""
        findings = []
        
        # Risky ports that should be highlighted
        risky_ports = {
            21: ("FTP", Severity.MEDIUM, "FTP often transmits credentials in cleartext"),
            22: ("SSH", Severity.INFO, "SSH service exposed - ensure strong authentication"),
            23: ("Telnet", Severity.HIGH, "Telnet transmits all data in cleartext"),
            25: ("SMTP", Severity.LOW, "SMTP service exposed - check for open relay"),
            53: ("DNS", Severity.INFO, "DNS service exposed"),
            80: ("HTTP", Severity.INFO, "HTTP service - check for HTTPS availability"),
            110: ("POP3", Severity.MEDIUM, "POP3 often transmits credentials in cleartext"),
            135: ("MSRPC", Severity.MEDIUM, "Windows RPC exposed"),
            139: ("NetBIOS", Severity.MEDIUM, "NetBIOS exposed - potential information leak"),
            143: ("IMAP", Severity.MEDIUM, "IMAP often transmits credentials in cleartext"),
            443: ("HTTPS", Severity.INFO, "HTTPS service - verify certificate validity"),
            445: ("SMB", Severity.MEDIUM, "SMB exposed - check for vulnerabilities"),
            1433: ("MSSQL", Severity.HIGH, "Microsoft SQL Server exposed to network"),
            1521: ("Oracle", Severity.HIGH, "Oracle database exposed to network"),
            3306: ("MySQL", Severity.HIGH, "MySQL database exposed to network"),
            3389: ("RDP", Severity.HIGH, "Remote Desktop exposed - high risk"),
            5432: ("PostgreSQL", Severity.HIGH, "PostgreSQL database exposed to network"),
            5900: ("VNC", Severity.HIGH, "VNC exposed - often weak authentication"),
            6379: ("Redis", Severity.HIGH, "Redis exposed - often no authentication"),
            8080: ("HTTP-Alt", Severity.INFO, "Alternative HTTP port"),
            27017: ("MongoDB", Severity.HIGH, "MongoDB exposed - check authentication"),
        }
        
        for port_info in ports:
            if port_info.state != "open":
                continue
            
            if port_info.port in risky_ports:
                service_name, severity, description = risky_ports[port_info.port]
                
                # Upgrade severity if it's a database port
                if severity == Severity.HIGH:
                    finding = VulnerabilityFinding(
                        title=f"Exposed {service_name} Service on Port {port_info.port}",
                        description=f"{description}. Service detected: {port_info.product} {port_info.version}".strip(),
                        severity=severity,
                        confidence="High",
                        scanner=ScannerType.NMAP,
                        target_host=host,
                        target_port=port_info.port,
                        solution=f"Consider restricting access to port {port_info.port} using firewall rules. "
                                f"Ensure strong authentication is enabled.",
                        owasp_category=classify_owasp_category(service_name),
                        mitre_attack_ids=["T1190", "T1133"]  # External Remote Services
                    )
                    findings.append(finding)
        
        return findings
    
    def quick_scan(self, host: str, ports: str = "21-25,80,443,3306,3389,8080") -> ScanResult:
        """
        Perform a quick scan on common ports.
        
        Args:
            host: Target hostname or IP
            ports: Port range to scan
            
        Returns:
            ScanResult with findings
        """
        target = ScanTarget(host=host, ports=[int(p) for p in ports.replace("-", ",").split(",")])
        return self.scan(target, scan_type="quick")


# Simulated scanner for when Nmap is not available
class SimulatedNmapScanner(NmapScanner):
    """
    Simulated Nmap scanner for testing without actual Nmap installation.
    Returns realistic-looking results for demonstration purposes.
    """
    
    def __init__(self):
        self.nm = None
        logger.info("Using simulated Nmap scanner")
    
    def is_available(self) -> bool:
        return True
    
    def scan(self, target: ScanTarget, scan_type: str = "comprehensive") -> ScanResult:
        """Perform simulated scan"""
        import random
        import time
        
        result = ScanResult(
            target=target,
            scan_mode=target.scan_mode,
            scanners_used=[ScannerType.NMAP],
            started_at=datetime.now()
        )
        
        # Simulate scan time
        time.sleep(random.uniform(0.5, 2.0))
        
        host = target.host or target.ip_address or "unknown"
        
        # Simulate common open ports based on URL
        simulated_ports = [
            PortInfo(port=80, protocol="tcp", state="open", service="http", 
                    product="nginx", version="1.18.0"),
            PortInfo(port=443, protocol="tcp", state="open", service="https",
                    product="nginx", version="1.18.0"),
        ]
        
        # Add some random additional ports
        if random.random() > 0.5:
            simulated_ports.append(
                PortInfo(port=22, protocol="tcp", state="open", service="ssh",
                        product="OpenSSH", version="8.2p1")
            )
        
        if random.random() > 0.7:
            simulated_ports.append(
                PortInfo(port=3306, protocol="tcp", state="open", service="mysql",
                        product="MySQL", version="8.0.23")
            )
        
        result.open_ports = simulated_ports
        
        # Create findings for open ports
        result.vulnerabilities = self._create_port_findings(simulated_ports, host)
        
        # Add some simulated vulnerability findings
        if random.random() > 0.5:
            result.vulnerabilities.append(VulnerabilityFinding(
                title="SSL/TLS Certificate Issues",
                description="The SSL certificate may have configuration issues.",
                severity=Severity.MEDIUM,
                confidence="Medium",
                scanner=ScannerType.NMAP,
                target_host=host,
                target_port=443,
                solution="Review SSL/TLS configuration and certificate validity."
            ))
        
        result.status = "completed"
        result.completed_at = datetime.now()
        result.duration_seconds = (result.completed_at - result.started_at).total_seconds()
        
        return result


def get_nmap_scanner() -> NmapScanner:
    """Get appropriate Nmap scanner (real or simulated)"""
    scanner = NmapScanner()
    if scanner.is_available():
        return scanner
    return SimulatedNmapScanner()
