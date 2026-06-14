"""
Scanner Integration Module
==========================

Integrates OWASP ZAP, Nmap, and Nikto for comprehensive vulnerability scanning.
Provides both black-box (external) and authenticated (gray-box) scanning modes.

Author: Ruthvik
Date: November 2025
"""

from .models import (
    ScanTarget, ScanMode, ScannerType, Severity,
    VulnerabilityFinding, ScanResult, PortInfo, ServiceInfo
)
from .unified_scanner import UnifiedScanner
from .zap_scanner import ZAPScanner
from .nmap_scanner import NmapScanner
from .website_analyzer import WebsiteSecurityAnalyzer

__all__ = [
    'ScanTarget', 'ScanMode', 'ScannerType', 'Severity',
    'VulnerabilityFinding', 'ScanResult', 'PortInfo', 'ServiceInfo',
    'UnifiedScanner', 'ZAPScanner', 'NmapScanner',
    'WebsiteSecurityAnalyzer'
]
