"""
Vulnerability Data Models
=========================

Unified data models for vulnerability findings from multiple scanners.
Follows SARIF-inspired structure for interoperability.

Author: Ruthvik
Date: November 2025
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from enum import Enum, auto
from datetime import datetime
import uuid
import json


class ScanMode(Enum):
    """Scanning mode"""
    BLACK_BOX = "black_box"      # External, no authentication
    GRAY_BOX = "gray_box"        # Authenticated scan
    WHITE_BOX = "white_box"      # Full access, code review


class ScannerType(Enum):
    """Type of scanner"""
    ZAP = "owasp_zap"
    NMAP = "nmap"
    NIKTO = "nikto"
    MANUAL = "manual"
    COMBINED = "combined"


class Severity(Enum):
    """Vulnerability severity levels (aligned with CVSS)"""
    CRITICAL = 5    # CVSS 9.0-10.0
    HIGH = 4        # CVSS 7.0-8.9
    MEDIUM = 3      # CVSS 4.0-6.9
    LOW = 2         # CVSS 0.1-3.9
    INFO = 1        # Informational
    
    @classmethod
    def from_cvss(cls, score: float) -> 'Severity':
        """Convert CVSS score to severity"""
        if score >= 9.0:
            return cls.CRITICAL
        elif score >= 7.0:
            return cls.HIGH
        elif score >= 4.0:
            return cls.MEDIUM
        elif score > 0:
            return cls.LOW
        return cls.INFO
    
    @classmethod
    def from_zap_risk(cls, risk: str) -> 'Severity':
        """Convert ZAP risk level to severity"""
        mapping = {
            'High': cls.HIGH,
            'Medium': cls.MEDIUM,
            'Low': cls.LOW,
            'Informational': cls.INFO
        }
        return mapping.get(risk, cls.INFO)


class VulnerabilityCategory(Enum):
    """OWASP Top 10 2021 Categories"""
    A01_BROKEN_ACCESS_CONTROL = "A01:2021-Broken Access Control"
    A02_CRYPTOGRAPHIC_FAILURES = "A02:2021-Cryptographic Failures"
    A03_INJECTION = "A03:2021-Injection"
    A04_INSECURE_DESIGN = "A04:2021-Insecure Design"
    A05_SECURITY_MISCONFIGURATION = "A05:2021-Security Misconfiguration"
    A06_VULNERABLE_COMPONENTS = "A06:2021-Vulnerable and Outdated Components"
    A07_AUTH_FAILURES = "A07:2021-Identification and Authentication Failures"
    A08_INTEGRITY_FAILURES = "A08:2021-Software and Data Integrity Failures"
    A09_LOGGING_FAILURES = "A09:2021-Security Logging and Monitoring Failures"
    A10_SSRF = "A10:2021-Server-Side Request Forgery"
    OTHER = "Other"


@dataclass
class PortInfo:
    """Information about an open port"""
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    version: str = ""
    product: str = ""
    extra_info: str = ""
    cpe: List[str] = field(default_factory=list)
    scripts: Dict[str, str] = field(default_factory=dict)


@dataclass
class ServiceInfo:
    """Information about a detected service"""
    name: str
    version: str = ""
    product: str = ""
    port: int = 0
    protocol: str = "tcp"
    os_type: str = ""
    hostname: str = ""
    cpe: List[str] = field(default_factory=list)


@dataclass
class VulnerabilityFinding:
    """
    A single vulnerability finding from any scanner.
    
    Unified format that normalizes output from ZAP, Nmap, and Nikto.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    
    # Basic info
    title: str = ""
    description: str = ""
    severity: Severity = Severity.INFO
    confidence: str = "Medium"  # High, Medium, Low
    
    # Source
    scanner: ScannerType = ScannerType.MANUAL
    scanner_rule_id: str = ""
    
    # Target
    target_url: str = ""
    target_host: str = ""
    target_port: int = 0
    affected_parameter: str = ""
    affected_endpoint: str = ""
    
    # Technical details
    evidence: str = ""
    request: str = ""
    response: str = ""
    
    # Classification
    cve_ids: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    cvss_vector: str = ""
    owasp_category: VulnerabilityCategory = VulnerabilityCategory.OTHER
    mitre_attack_ids: List[str] = field(default_factory=list)
    
    # Remediation
    solution: str = ""
    reference_urls: List[str] = field(default_factory=list)
    
    # Metadata
    discovered_at: datetime = field(default_factory=datetime.now)
    tags: Set[str] = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.name,
            "severity_score": self.severity.value,
            "confidence": self.confidence,
            "scanner": self.scanner.value,
            "target_url": self.target_url,
            "target_host": self.target_host,
            "target_port": self.target_port,
            "cve_ids": self.cve_ids,
            "cwe_ids": self.cwe_ids,
            "cvss_score": self.cvss_score,
            "owasp_category": self.owasp_category.value,
            "mitre_attack_ids": self.mitre_attack_ids,
            "solution": self.solution,
            "evidence": self.evidence[:500] if self.evidence else "",
            "discovered_at": self.discovered_at.isoformat()
        }
    
    def __hash__(self):
        return hash(self.id)


@dataclass
class ScanTarget:
    """Target for scanning"""
    url: str = ""
    host: str = ""
    ip_address: str = ""
    ports: List[int] = field(default_factory=list)
    
    # Authentication for gray-box scanning
    auth_username: str = ""
    auth_password: str = ""
    auth_token: str = ""
    auth_cookies: Dict[str, str] = field(default_factory=dict)
    
    # Scan configuration
    scan_mode: ScanMode = ScanMode.BLACK_BOX
    max_depth: int = 5
    max_duration_minutes: int = 30
    excluded_paths: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Extract host from URL if not provided"""
        if self.url and not self.host:
            from urllib.parse import urlparse
            parsed = urlparse(self.url)
            self.host = parsed.hostname or ""
            if parsed.port:
                self.ports = [parsed.port]


@dataclass
class ScanResult:
    """
    Complete scan result from one or more scanners.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target: ScanTarget = field(default_factory=ScanTarget)
    
    # Findings
    vulnerabilities: List[VulnerabilityFinding] = field(default_factory=list)
    
    # Network info
    open_ports: List[PortInfo] = field(default_factory=list)
    services: List[ServiceInfo] = field(default_factory=list)
    
    # Scan metadata
    scan_mode: ScanMode = ScanMode.BLACK_BOX
    scanners_used: List[ScannerType] = field(default_factory=list)
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    duration_seconds: float = 0.0
    
    # Status
    status: str = "pending"  # pending, running, completed, failed
    error_message: str = ""
    
    # Summary statistics
    total_urls_scanned: int = 0
    total_requests_made: int = 0
    
    @property
    def severity_counts(self) -> Dict[str, int]:
        """Count vulnerabilities by severity"""
        counts = {s.name: 0 for s in Severity}
        for vuln in self.vulnerabilities:
            counts[vuln.severity.name] += 1
        return counts
    
    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.CRITICAL)
    
    @property
    def high_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.HIGH)
    
    @property
    def risk_score(self) -> float:
        """Calculate overall risk score (0-100)"""
        if not self.vulnerabilities:
            return 0.0
        
        weights = {
            Severity.CRITICAL: 40,
            Severity.HIGH: 25,
            Severity.MEDIUM: 10,
            Severity.LOW: 3,
            Severity.INFO: 1
        }
        
        total_weight = sum(weights[v.severity] for v in self.vulnerabilities)
        max_possible = len(self.vulnerabilities) * weights[Severity.CRITICAL]
        
        return min(100.0, (total_weight / max(1, max_possible)) * 100)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "target_url": self.target.url,
            "target_host": self.target.host,
            "scan_mode": self.scan_mode.value,
            "status": self.status,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "total_vulnerabilities": len(self.vulnerabilities),
            "severity_counts": self.severity_counts,
            "risk_score": self.risk_score,
            "open_ports": [{"port": p.port, "service": p.service} for p in self.open_ports],
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "scanners_used": [s.value for s in self.scanners_used]
        }
    
    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict(), indent=indent, default=str)
    
    def get_vulnerabilities_by_severity(self, severity: Severity) -> List[VulnerabilityFinding]:
        """Get all vulnerabilities of a specific severity"""
        return [v for v in self.vulnerabilities if v.severity == severity]
    
    def get_unique_cves(self) -> Set[str]:
        """Get all unique CVE IDs found"""
        cves = set()
        for vuln in self.vulnerabilities:
            cves.update(vuln.cve_ids)
        return cves


# Mapping of common vulnerability titles to OWASP categories
VULN_TO_OWASP = {
    "sql injection": VulnerabilityCategory.A03_INJECTION,
    "xss": VulnerabilityCategory.A03_INJECTION,
    "cross-site scripting": VulnerabilityCategory.A03_INJECTION,
    "command injection": VulnerabilityCategory.A03_INJECTION,
    "ldap injection": VulnerabilityCategory.A03_INJECTION,
    "broken authentication": VulnerabilityCategory.A07_AUTH_FAILURES,
    "session": VulnerabilityCategory.A07_AUTH_FAILURES,
    "password": VulnerabilityCategory.A07_AUTH_FAILURES,
    "ssl": VulnerabilityCategory.A02_CRYPTOGRAPHIC_FAILURES,
    "tls": VulnerabilityCategory.A02_CRYPTOGRAPHIC_FAILURES,
    "certificate": VulnerabilityCategory.A02_CRYPTOGRAPHIC_FAILURES,
    "encryption": VulnerabilityCategory.A02_CRYPTOGRAPHIC_FAILURES,
    "csrf": VulnerabilityCategory.A01_BROKEN_ACCESS_CONTROL,
    "access control": VulnerabilityCategory.A01_BROKEN_ACCESS_CONTROL,
    "authorization": VulnerabilityCategory.A01_BROKEN_ACCESS_CONTROL,
    "misconfiguration": VulnerabilityCategory.A05_SECURITY_MISCONFIGURATION,
    "header": VulnerabilityCategory.A05_SECURITY_MISCONFIGURATION,
    "outdated": VulnerabilityCategory.A06_VULNERABLE_COMPONENTS,
    "vulnerable component": VulnerabilityCategory.A06_VULNERABLE_COMPONENTS,
    "ssrf": VulnerabilityCategory.A10_SSRF,
    "logging": VulnerabilityCategory.A09_LOGGING_FAILURES,
}


def classify_owasp_category(title: str, description: str = "") -> VulnerabilityCategory:
    """Classify a vulnerability into OWASP Top 10 category"""
    text = (title + " " + description).lower()
    
    for keyword, category in VULN_TO_OWASP.items():
        if keyword in text:
            return category
    
    return VulnerabilityCategory.OTHER


# Mapping of vulnerabilities to MITRE ATT&CK techniques
VULN_TO_MITRE = {
    "sql injection": ["T1190", "T1059"],
    "xss": ["T1189", "T1059.007"],
    "command injection": ["T1059", "T1190"],
    "file upload": ["T1105", "T1190"],
    "directory traversal": ["T1083", "T1190"],
    "ssrf": ["T1090", "T1190"],
    "authentication bypass": ["T1078", "T1190"],
    "brute force": ["T1110"],
    "default credentials": ["T1078.001"],
    "information disclosure": ["T1082", "T1083"],
}


def get_mitre_techniques(title: str, description: str = "") -> List[str]:
    """Get related MITRE ATT&CK technique IDs"""
    text = (title + " " + description).lower()
    techniques = set()
    
    for keyword, techs in VULN_TO_MITRE.items():
        if keyword in text:
            techniques.update(techs)
    
    return list(techniques)
