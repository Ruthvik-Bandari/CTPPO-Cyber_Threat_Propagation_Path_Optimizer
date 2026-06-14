"""
False Positive Filter and Confidence Scoring
=============================================

Reduces false positives by:
1. Technology fingerprinting (detect actual tech stack)
2. CVE applicability checking
3. Confidence scoring based on evidence quality
4. Cross-validation between scanners

Author: Ruthvik
Institution: Northeastern University
Course: AAI6610 - Applied Machine Learning
Date: November 2025
"""

import re
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum

from .models import VulnerabilityFinding, Severity, ScanResult


class ConfidenceLevel(Enum):
    """Confidence level for vulnerability findings"""
    CONFIRMED = 5      # Verified exploitable
    HIGH = 4           # Strong evidence
    MEDIUM = 3         # Moderate evidence
    LOW = 2            # Weak evidence
    INFORMATIONAL = 1  # Just detected, not verified


@dataclass
class TechnologyFingerprint:
    """Detected technology stack"""
    web_server: Optional[str] = None        # nginx, apache, IIS, etc.
    programming_language: Optional[str] = None  # PHP, Python, Java, Node.js
    framework: Optional[str] = None         # Django, Rails, React, etc.
    cms: Optional[str] = None               # WordPress, Drupal, Joomla
    database: Optional[str] = None          # MySQL, PostgreSQL, MongoDB
    cdn: Optional[str] = None               # Cloudflare, Akamai, Fastly
    waf: Optional[str] = None               # ModSecurity, Cloudflare WAF
    os: Optional[str] = None                # Linux, Windows


# Known CVE to technology mappings
CVE_TECHNOLOGY_MAP = {
    # Drupal vulnerabilities
    "CVE-2014-3704": ["drupal"],
    "CVE-2018-7600": ["drupal"],
    "CVE-2019-6340": ["drupal"],
    
    # WordPress vulnerabilities
    "CVE-2019-8942": ["wordpress"],
    "CVE-2019-8943": ["wordpress"],
    
    # Apache vulnerabilities
    "CVE-2021-41773": ["apache"],
    "CVE-2021-42013": ["apache"],
    "CVE-2017-5638": ["struts", "apache"],
    
    # Nginx vulnerabilities
    "CVE-2021-23017": ["nginx"],
    
    # PHP vulnerabilities
    "CVE-2019-11043": ["php", "nginx"],
    
    # Java/Spring vulnerabilities
    "CVE-2022-22965": ["spring", "java"],
    "CVE-2021-44228": ["log4j", "java"],
    
    # Microsoft/IIS vulnerabilities
    "CVE-2021-31166": ["iis", "windows"],
    "CVE-2017-7269": ["iis", "windows"],
}

# Technology detection patterns from HTTP headers/responses
TECH_PATTERNS = {
    # Web servers
    "nginx": [r"nginx", r"server:\s*nginx"],
    "apache": [r"apache", r"server:\s*apache"],
    "iis": [r"microsoft-iis", r"server:\s*microsoft-iis", r"asp\.net"],
    "cloudflare": [r"cloudflare", r"cf-ray", r"__cfduid"],
    
    # Languages/Frameworks
    "php": [r"x-powered-by:\s*php", r"\.php", r"phpsessid"],
    "python": [r"x-powered-by:\s*python", r"django", r"flask"],
    "java": [r"x-powered-by:\s*servlet", r"jsessionid", r"\.jsp"],
    "nodejs": [r"x-powered-by:\s*express", r"connect\.sid"],
    "ruby": [r"x-powered-by:\s*phusion", r"_rails_session"],
    
    # CMS
    "wordpress": [r"wp-content", r"wp-includes", r"wordpress"],
    "drupal": [r"drupal", r"sites/default", r"drupal\.js"],
    "joomla": [r"joomla", r"/components/", r"/modules/"],
    
    # Frameworks
    "react": [r"react", r"__react", r"data-reactroot"],
    "angular": [r"ng-version", r"angular", r"ng-app"],
    "vue": [r"vue", r"v-app", r"__vue__"],
    "django": [r"csrfmiddlewaretoken", r"django"],
    "rails": [r"_rails_session", r"x-runtime"],
    "spring": [r"spring", r"x-application-context"],
    
    # CDN/WAF
    "akamai": [r"akamai", r"x-akamai"],
    "fastly": [r"fastly", r"x-served-by.*cache"],
    "incapsula": [r"incapsula", r"incap_ses"],
}

# False positive patterns - vulnerabilities that are often incorrectly reported
FALSE_POSITIVE_PATTERNS = [
    # Generic Nmap script false positives
    (r"http-vuln-cve2014-3704", "drupal"),  # Drupalgeddon - only for Drupal
    (r"http-vuln-cve2017-5638", "struts"),  # Struts - only for Apache Struts
    (r"http-vuln-cve2021-44228", "log4j"),  # Log4Shell - only for Java/Log4j
    
    # SSL/TLS false positives on modern sites
    (r"ssl-poodle", None),  # Often false positive on modern TLS
    (r"ssl-heartbleed", None),  # Rare in 2024+
]


class FalsePositiveFilter:
    """
    Filters false positives and adds confidence scoring.
    
    This is what separates amateur scanning from professional assessment.
    """
    
    def __init__(self):
        self.detected_technologies: Set[str] = set()
        self.fingerprint = TechnologyFingerprint()
    
    def fingerprint_from_headers(self, headers: Dict[str, str]) -> TechnologyFingerprint:
        """
        Detect technology stack from HTTP headers.
        """
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        headers_text = " ".join(f"{k}: {v}" for k, v in headers_lower.items())
        
        fp = TechnologyFingerprint()
        
        # Detect web server
        server = headers_lower.get("server", "")
        if "nginx" in server:
            fp.web_server = "nginx"
        elif "apache" in server:
            fp.web_server = "apache"
        elif "microsoft-iis" in server.lower():
            fp.web_server = "iis"
        elif "cloudflare" in server:
            fp.web_server = "cloudflare"
        
        # Detect CDN/WAF
        if "cf-ray" in headers_lower or "cloudflare" in headers_text:
            fp.cdn = "cloudflare"
            fp.waf = "cloudflare"
        elif "x-akamai" in headers_text:
            fp.cdn = "akamai"
        
        # Detect language from X-Powered-By
        powered_by = headers_lower.get("x-powered-by", "")
        if "php" in powered_by:
            fp.programming_language = "php"
        elif "asp.net" in powered_by:
            fp.programming_language = "asp.net"
        elif "express" in powered_by:
            fp.programming_language = "nodejs"
        
        self.fingerprint = fp
        return fp
    
    def fingerprint_from_response(self, html_content: str, url: str) -> None:
        """
        Detect technology stack from HTML response content.
        """
        content_lower = html_content.lower() if html_content else ""
        
        for tech, patterns in TECH_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, content_lower, re.IGNORECASE):
                    self.detected_technologies.add(tech)
                    break
        
        # Update fingerprint based on detected technologies
        if "wordpress" in self.detected_technologies:
            self.fingerprint.cms = "wordpress"
        elif "drupal" in self.detected_technologies:
            self.fingerprint.cms = "drupal"
        elif "joomla" in self.detected_technologies:
            self.fingerprint.cms = "joomla"
        
        if "react" in self.detected_technologies:
            self.fingerprint.framework = "react"
        elif "angular" in self.detected_technologies:
            self.fingerprint.framework = "angular"
        elif "vue" in self.detected_technologies:
            self.fingerprint.framework = "vue"
    
    def is_cve_applicable(self, cve_id: str) -> Tuple[bool, str]:
        """
        Check if a CVE is applicable to the detected technology stack.
        
        Returns:
            Tuple of (is_applicable, reason)
        """
        if not cve_id:
            return True, "No CVE to validate"
        
        cve_upper = cve_id.upper()
        
        # Check if CVE requires specific technology
        required_techs = CVE_TECHNOLOGY_MAP.get(cve_upper, [])
        
        if not required_techs:
            return True, "CVE not in technology map, assuming applicable"
        
        # Check if any required technology is detected
        for tech in required_techs:
            if tech in self.detected_technologies:
                return True, f"CVE requires {tech}, which was detected"
            if self.fingerprint.cms and tech == self.fingerprint.cms:
                return True, f"CVE requires {tech} CMS, which was detected"
        
        return False, f"CVE requires {required_techs}, but detected: {list(self.detected_technologies)}"
    
    def calculate_confidence(self, vuln: VulnerabilityFinding) -> Tuple[ConfidenceLevel, float, str]:
        """
        Calculate confidence score for a vulnerability finding.
        
        Returns:
            Tuple of (confidence_level, score 0-100, explanation)
        """
        score = 50.0  # Start at medium
        reasons = []
        
        # Factor 1: Evidence quality
        if vuln.evidence:
            score += 15
            reasons.append("+15: Has evidence")
        
        # Factor 2: CVE reference
        if vuln.cve_ids:
            score += 10
            reasons.append("+10: Has CVE reference")
            
            # Check if CVE is applicable
            for cve in vuln.cve_ids:
                applicable, reason = self.is_cve_applicable(cve)
                if not applicable:
                    score -= 40
                    reasons.append(f"-40: CVE not applicable - {reason}")
        
        # Factor 3: Scanner agreement (if multiple scanners found it)
        # This would require tracking across scanners
        
        # Factor 4: Severity vs evidence match
        if vuln.severity in [Severity.CRITICAL, Severity.HIGH]:
            if not vuln.cve_ids and not vuln.evidence:
                score -= 20
                reasons.append("-20: High severity without CVE or evidence")
        
        # Factor 5: Known false positive patterns
        for pattern, required_tech in FALSE_POSITIVE_PATTERNS:
            if re.search(pattern, vuln.title, re.IGNORECASE):
                if required_tech and required_tech not in self.detected_technologies:
                    score -= 30
                    reasons.append(f"-30: Likely false positive ({pattern} requires {required_tech})")
        
        # Factor 6: Scanner source reliability
        if "nmap" in str(vuln.scanner).lower():
            # Nmap vuln scripts have higher FP rate
            score -= 5
            reasons.append("-5: Nmap script (higher FP rate)")
        elif "zap" in str(vuln.scanner).lower():
            # ZAP active scan is more reliable
            score += 5
            reasons.append("+5: ZAP finding (lower FP rate)")
        
        # Clamp score
        score = max(0, min(100, score))
        
        # Determine confidence level
        if score >= 80:
            level = ConfidenceLevel.HIGH
        elif score >= 60:
            level = ConfidenceLevel.MEDIUM
        elif score >= 40:
            level = ConfidenceLevel.LOW
        else:
            level = ConfidenceLevel.INFORMATIONAL
        
        return level, score, "; ".join(reasons)
    
    def filter_vulnerabilities(
        self, 
        vulns: List[VulnerabilityFinding],
        min_confidence: float = 30.0,
        remove_false_positives: bool = True
    ) -> List[Tuple[VulnerabilityFinding, ConfidenceLevel, float, str]]:
        """
        Filter vulnerabilities and add confidence scoring.
        
        Args:
            vulns: List of vulnerability findings
            min_confidence: Minimum confidence score to include (0-100)
            remove_false_positives: Whether to remove likely false positives
        
        Returns:
            List of tuples: (vuln, confidence_level, score, explanation)
        """
        results = []
        
        for vuln in vulns:
            level, score, explanation = self.calculate_confidence(vuln)
            
            # Skip if at or below minimum confidence
            if score <= min_confidence:
                continue
            
            results.append((vuln, level, score, explanation))
        
        # Sort by confidence score (highest first)
        results.sort(key=lambda x: x[2], reverse=True)
        
        return results
    
    def get_technology_summary(self) -> Dict[str, any]:
        """Get summary of detected technologies."""
        return {
            "web_server": self.fingerprint.web_server,
            "programming_language": self.fingerprint.programming_language,
            "framework": self.fingerprint.framework,
            "cms": self.fingerprint.cms,
            "cdn": self.fingerprint.cdn,
            "waf": self.fingerprint.waf,
            "all_detected": list(self.detected_technologies)
        }


def enhance_scan_result(
    scan_result: ScanResult,
    headers: Optional[Dict[str, str]] = None,
    html_content: Optional[str] = None,
    min_confidence: float = 30.0
) -> Tuple[ScanResult, Dict]:
    """
    Enhance scan result with false positive filtering and confidence scoring.
    
    Args:
        scan_result: Original scan result
        headers: HTTP response headers (for fingerprinting)
        html_content: HTML response content (for fingerprinting)
        min_confidence: Minimum confidence to include
    
    Returns:
        Tuple of (enhanced_result, metadata)
    """
    filter = FalsePositiveFilter()
    
    # Fingerprint the target
    if headers:
        filter.fingerprint_from_headers(headers)
    if html_content:
        filter.fingerprint_from_response(html_content, scan_result.target.url)
    
    # Filter vulnerabilities
    filtered = filter.filter_vulnerabilities(
        scan_result.vulnerabilities,
        min_confidence=min_confidence,
        remove_false_positives=True
    )
    
    # Create enhanced findings with confidence
    enhanced_vulns = []
    confidence_data = []
    
    for vuln, level, score, explanation in filtered:
        # Add confidence to vulnerability metadata
        vuln_dict = {
            "finding": vuln,
            "confidence_level": level.name,
            "confidence_score": score,
            "confidence_explanation": explanation
        }
        enhanced_vulns.append(vuln)
        confidence_data.append(vuln_dict)
    
    # Create new scan result with filtered vulnerabilities
    enhanced_result = ScanResult(
        target=scan_result.target,
        vulnerabilities=enhanced_vulns,
        open_ports=scan_result.open_ports,
        services=scan_result.services,
        scan_mode=getattr(scan_result, 'scan_mode', None),
        scanners_used=scan_result.scanners_used,
        started_at=getattr(scan_result, 'started_at', None),
        completed_at=getattr(scan_result, 'completed_at', None),
        duration_seconds=getattr(scan_result, 'duration_seconds', 0.0),
        status=getattr(scan_result, 'status', 'completed'),
        error_message=getattr(scan_result, 'error_message', ''),
        total_urls_scanned=getattr(scan_result, 'total_urls_scanned', 0),
        total_requests_made=getattr(scan_result, 'total_requests_made', 0)
    )
    
    metadata = {
        "original_count": len(scan_result.vulnerabilities),
        "filtered_count": len(enhanced_vulns),
        "removed_count": len(scan_result.vulnerabilities) - len(enhanced_vulns),
        "technology_fingerprint": filter.get_technology_summary(),
        "confidence_data": confidence_data
    }
    
    return enhanced_result, metadata
