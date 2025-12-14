"""
Unified Security Scanner
========================

Combines OWASP ZAP, Nmap, and Nikto into a unified scanning interface.
Automatically generates attack graphs from scan results.

Author: Ruthvik
Date: November 2025
"""

import logging
from typing import Dict, List, Optional, Set
from datetime import datetime
from urllib.parse import urlparse
from dataclasses import dataclass, field
import concurrent.futures

from .models import (
    ScanTarget, ScanResult, VulnerabilityFinding,
    Severity, ScannerType, ScanMode, PortInfo, ServiceInfo
)
from .zap_scanner import ZAPScanner, get_zap_scanner
from .nmap_scanner import NmapScanner, get_nmap_scanner

logger = logging.getLogger(__name__)


@dataclass
class UnifiedScanConfig:
    """Configuration for unified scanning"""
    enable_zap: bool = True
    enable_nmap: bool = True
    enable_nikto: bool = False  # Nikto not implemented yet
    
    # ZAP settings
    zap_spider: bool = True
    zap_active_scan: bool = True
    zap_ajax_spider: bool = False
    
    # Nmap settings
    nmap_scan_type: str = "comprehensive"
    nmap_ports: List[int] = field(default_factory=lambda: [80, 443, 8080, 8443])
    
    # General settings
    max_duration_minutes: int = 30
    parallel_scans: bool = True


class UnifiedScanner:
    """
    Unified scanner combining multiple security tools.
    
    Provides:
    - Combined vulnerability scanning
    - Automatic deduplication of findings
    - Attack graph generation from results
    - Risk scoring and prioritization
    """
    
    def __init__(
        self,
        zap_api_key: str = None,
        zap_proxy_url: str = None,
        config: UnifiedScanConfig = None
    ):
        """
        Initialize unified scanner.
        
        Args:
            zap_api_key: OWASP ZAP API key
            zap_proxy_url: ZAP proxy URL
            config: Scan configuration
        """
        self.config = config or UnifiedScanConfig()
        
        # Initialize scanners
        self.zap_scanner = get_zap_scanner(zap_api_key, zap_proxy_url) if self.config.enable_zap else None
        self.nmap_scanner = get_nmap_scanner() if self.config.enable_nmap else None
        
        logger.info("Unified scanner initialized")
        logger.info(f"  ZAP available: {self.zap_scanner.is_available() if self.zap_scanner else False}")
        logger.info(f"  Nmap available: {self.nmap_scanner.is_available() if self.nmap_scanner else False}")
    
    def scan(self, target: ScanTarget) -> ScanResult:
        """
        Perform comprehensive security scan.
        
        Args:
            target: Scan target
            
        Returns:
            Unified ScanResult with all findings
        """
        logger.info(f"Starting unified scan on {target.url or target.host}")
        
        result = ScanResult(
            target=target,
            scan_mode=target.scan_mode,
            started_at=datetime.now()
        )
        
        all_vulnerabilities: List[VulnerabilityFinding] = []
        all_ports: List[PortInfo] = []
        all_services: List[ServiceInfo] = []
        
        try:
            result.status = "running"
            
            # Run scans (parallel or sequential)
            if self.config.parallel_scans:
                scan_results = self._run_parallel_scans(target)
            else:
                scan_results = self._run_sequential_scans(target)
            
            # Merge results
            for scanner_result in scan_results:
                if scanner_result.status == "completed":
                    all_vulnerabilities.extend(scanner_result.vulnerabilities)
                    all_ports.extend(scanner_result.open_ports)
                    all_services.extend(scanner_result.services)
                    result.scanners_used.extend(scanner_result.scanners_used)
                    result.total_urls_scanned += scanner_result.total_urls_scanned
            
            # Deduplicate findings
            result.vulnerabilities = self._deduplicate_findings(all_vulnerabilities)
            result.open_ports = self._deduplicate_ports(all_ports)
            result.services = all_services
            
            # Sort by severity
            result.vulnerabilities.sort(key=lambda v: v.severity.value, reverse=True)
            
            result.status = "completed"
            result.completed_at = datetime.now()
            result.duration_seconds = (result.completed_at - result.started_at).total_seconds()
            
            logger.info(f"Unified scan completed:")
            logger.info(f"  Total vulnerabilities: {len(result.vulnerabilities)}")
            logger.info(f"  Critical: {result.critical_count}")
            logger.info(f"  High: {result.high_count}")
            logger.info(f"  Open ports: {len(result.open_ports)}")
            logger.info(f"  Risk score: {result.risk_score:.1f}")
            
        except Exception as e:
            logger.error(f"Unified scan failed: {e}")
            result.status = "failed"
            result.error_message = str(e)
        
        return result
    
    def _run_parallel_scans(self, target: ScanTarget) -> List[ScanResult]:
        """Run scans in parallel"""
        results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = []
            
            # Submit ZAP scan
            if self.zap_scanner and self.zap_scanner.is_available() and target.url:
                futures.append(executor.submit(
                    self.zap_scanner.scan,
                    target,
                    self.config.zap_spider,
                    self.config.zap_active_scan,
                    self.config.zap_ajax_spider,
                    self.config.max_duration_minutes
                ))
            
            # Submit Nmap scan
            if self.nmap_scanner and self.nmap_scanner.is_available():
                nmap_target = ScanTarget(
                    host=target.host or urlparse(target.url).hostname if target.url else "",
                    ip_address=target.ip_address,
                    ports=self.config.nmap_ports or target.ports,
                    scan_mode=target.scan_mode
                )
                futures.append(executor.submit(
                    self.nmap_scanner.scan,
                    nmap_target,
                    self.config.nmap_scan_type
                ))
            
            # Collect results
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    logger.error(f"Scan failed: {e}")
        
        return results
    
    def _run_sequential_scans(self, target: ScanTarget) -> List[ScanResult]:
        """Run scans sequentially"""
        results = []
        
        # ZAP scan
        if self.zap_scanner and self.zap_scanner.is_available() and target.url:
            logger.info("Running ZAP scan...")
            zap_result = self.zap_scanner.scan(
                target,
                self.config.zap_spider,
                self.config.zap_active_scan,
                self.config.zap_ajax_spider,
                self.config.max_duration_minutes
            )
            results.append(zap_result)
        
        # Nmap scan
        if self.nmap_scanner and self.nmap_scanner.is_available():
            logger.info("Running Nmap scan...")
            host = target.host or (urlparse(target.url).hostname if target.url else "")
            if host:
                nmap_target = ScanTarget(
                    host=host,
                    ip_address=target.ip_address,
                    ports=self.config.nmap_ports or target.ports,
                    scan_mode=target.scan_mode
                )
                nmap_result = self.nmap_scanner.scan(nmap_target, self.config.nmap_scan_type)
                results.append(nmap_result)
        
        return results
    
    def _deduplicate_findings(
        self,
        findings: List[VulnerabilityFinding]
    ) -> List[VulnerabilityFinding]:
        """Remove duplicate findings based on title and target"""
        seen = set()
        unique = []
        
        for finding in findings:
            # Create a key for deduplication
            key = (
                finding.title.lower(),
                finding.target_url or finding.target_host,
                finding.target_port,
                finding.affected_parameter
            )
            
            if key not in seen:
                seen.add(key)
                unique.append(finding)
            else:
                # Merge CVEs from duplicate findings
                for existing in unique:
                    existing_key = (
                        existing.title.lower(),
                        existing.target_url or existing.target_host,
                        existing.target_port,
                        existing.affected_parameter
                    )
                    if existing_key == key:
                        existing.cve_ids = list(set(existing.cve_ids + finding.cve_ids))
                        break
        
        return unique
    
    def _deduplicate_ports(self, ports: List[PortInfo]) -> List[PortInfo]:
        """Remove duplicate port entries"""
        seen = set()
        unique = []
        
        for port in ports:
            key = (port.port, port.protocol)
            if key not in seen:
                seen.add(key)
                unique.append(port)
        
        return unique
    
    def quick_scan(self, url: str) -> ScanResult:
        """
        Perform a quick scan (reduced depth, no active scanning).
        
        Args:
            url: Target URL
            
        Returns:
            ScanResult with findings
        """
        target = ScanTarget(url=url, max_duration_minutes=5)
        
        # Override config for quick scan
        original_active = self.config.zap_active_scan
        original_spider = self.config.zap_spider
        self.config.zap_active_scan = False
        self.config.zap_spider = True
        
        try:
            return self.scan(target)
        finally:
            self.config.zap_active_scan = original_active
            self.config.zap_spider = original_spider
    
    def full_scan(self, url: str, credentials: dict = None) -> ScanResult:
        """
        Perform a comprehensive scan with all features enabled.
        
        Args:
            url: Target URL
            credentials: Optional dict with 'username' and 'password' for authenticated scan
            
        Returns:
            ScanResult with findings
        """
        scan_mode = ScanMode.BLACK_BOX
        auth_user = ""
        auth_pass = ""
        
        if credentials:
            scan_mode = ScanMode.GRAY_BOX
            auth_user = credentials.get('username', '')
            auth_pass = credentials.get('password', '')
        
        target = ScanTarget(
            url=url,
            scan_mode=scan_mode,
            auth_username=auth_user,
            auth_password=auth_pass,
            max_duration_minutes=30
        )
        
        return self.scan(target)


def scan_website(url: str, mode: str = "quick") -> ScanResult:
    """
    Convenience function to scan a website.
    
    Args:
        url: Target URL
        mode: 'quick' for fast scan, 'full' for comprehensive scan
        
    Returns:
        ScanResult with findings
    """
    scanner = UnifiedScanner()
    
    if mode == "full":
        return scanner.full_scan(url)
    return scanner.quick_scan(url)
