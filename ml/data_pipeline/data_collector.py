# -*- coding: utf-8 -*-
"""
CTPPO v2.0 - Data Collector
============================

Fetches CVE data from NVD API with PROPER ground truth labels.
Ground truth comes from CVSS scores - NEVER from model predictions.

Key Principles:
1. CVSS score is the GROUND TRUTH for severity
2. Never use a model to generate labels during data collection
3. Handle missing data explicitly
4. Preserve all metadata for feature engineering

Author: Ruthvik (Fixed by Claude)
Date: January 2026
"""

import requests
import time
import logging
import json
import hashlib
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class Severity(Enum):
    """CVE Severity levels based on CVSS v3.0/v3.1 thresholds."""
    CRITICAL = "CRITICAL"  # 9.0 - 10.0
    HIGH = "HIGH"          # 7.0 - 8.9
    MEDIUM = "MEDIUM"      # 4.0 - 6.9
    LOW = "LOW"            # 0.1 - 3.9
    NONE = "NONE"          # 0.0
    UNKNOWN = "UNKNOWN"    # Missing CVSS


@dataclass
class CVSSVector:
    """CVSS v3.1 Vector Components - valuable for feature engineering."""
    attack_vector: Optional[str] = None        # NETWORK, ADJACENT_NETWORK, LOCAL, PHYSICAL
    attack_complexity: Optional[str] = None    # LOW, HIGH
    privileges_required: Optional[str] = None  # NONE, LOW, HIGH
    user_interaction: Optional[str] = None     # NONE, REQUIRED
    scope: Optional[str] = None                # UNCHANGED, CHANGED
    confidentiality_impact: Optional[str] = None  # NONE, LOW, HIGH
    integrity_impact: Optional[str] = None     # NONE, LOW, HIGH
    availability_impact: Optional[str] = None  # NONE, LOW, HIGH
    
    @classmethod
    def from_nvd(cls, cvss_data: Dict) -> 'CVSSVector':
        """Parse CVSS vector from NVD API response."""
        return cls(
            attack_vector=cvss_data.get('attackVector'),
            attack_complexity=cvss_data.get('attackComplexity'),
            privileges_required=cvss_data.get('privilegesRequired'),
            user_interaction=cvss_data.get('userInteraction'),
            scope=cvss_data.get('scope'),
            confidentiality_impact=cvss_data.get('confidentialityImpact'),
            integrity_impact=cvss_data.get('integrityImpact'),
            availability_impact=cvss_data.get('availabilityImpact')
        )


@dataclass 
class CVERecord:
    """
    Complete CVE record with all data needed for ML training.
    
    IMPORTANT: severity_label is derived from cvss_score (GROUND TRUTH),
    never from model predictions!
    """
    # Core identifiers
    cve_id: str
    
    # Description (raw and will be cleaned later)
    description: str
    
    # GROUND TRUTH - severity from CVSS score
    cvss_score: Optional[float] = None
    severity_label: Severity = Severity.UNKNOWN
    
    # CVSS vector components (for feature engineering)
    cvss_vector: Optional[CVSSVector] = None
    cvss_version: Optional[str] = None
    
    # Temporal information
    published_date: Optional[datetime] = None
    modified_date: Optional[datetime] = None
    
    # Related information
    cwe_ids: List[str] = field(default_factory=list)
    references: List[Dict[str, str]] = field(default_factory=list)
    affected_products: List[str] = field(default_factory=list)
    
    # Metadata
    source: str = "NVD"
    fetch_date: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        d = asdict(self)
        d['severity_label'] = self.severity_label.value
        d['published_date'] = self.published_date.isoformat() if self.published_date else None
        d['modified_date'] = self.modified_date.isoformat() if self.modified_date else None
        d['fetch_date'] = self.fetch_date.isoformat()
        return d
    
    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'CVERecord':
        """Reconstruct from dictionary."""
        d = d.copy()
        d['severity_label'] = Severity(d['severity_label'])
        if d['published_date']:
            d['published_date'] = datetime.fromisoformat(d['published_date'])
        if d['modified_date']:
            d['modified_date'] = datetime.fromisoformat(d['modified_date'])
        d['fetch_date'] = datetime.fromisoformat(d['fetch_date'])
        if d['cvss_vector']:
            d['cvss_vector'] = CVSSVector(**d['cvss_vector'])
        return cls(**d)


class CVEDataCollector:
    """
    Collects CVE data from NVD API with proper ground truth labeling.
    
    CRITICAL: This class NEVER uses ML models to generate labels.
    Labels come ONLY from CVSS scores (ground truth).
    """
    
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        cache_dir: Optional[Path] = None,
        rate_limit_delay: float = 0.6
    ):
        """
        Initialize the collector.
        
        Args:
            api_key: NVD API key (faster rate limits)
            cache_dir: Directory to cache fetched data
            rate_limit_delay: Delay between API calls (0.6s with key, 6s without)
        """
        self.api_key = api_key
        self.cache_dir = Path(cache_dir) if cache_dir else Path("./data/cache")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Rate limiting
        self.rate_limit_delay = rate_limit_delay if api_key else 6.0
        self.last_request_time = 0
        
        logger.info(f"CVEDataCollector initialized. API key: {'Yes' if api_key else 'No'}")
        logger.info(f"Rate limit delay: {self.rate_limit_delay}s")
    
    @staticmethod
    def cvss_to_severity(cvss_score: Optional[float]) -> Severity:
        """
        Convert CVSS score to severity label.
        
        This is the GROUND TRUTH derivation - official NVD thresholds.
        https://nvd.nist.gov/vuln-metrics/cvss
        
        Args:
            cvss_score: CVSS v3.x base score (0.0 - 10.0)
            
        Returns:
            Severity enum value
        """
        if cvss_score is None:
            return Severity.UNKNOWN
        if cvss_score == 0.0:
            return Severity.NONE
        if cvss_score < 4.0:
            return Severity.LOW
        if cvss_score < 7.0:
            return Severity.MEDIUM
        if cvss_score < 9.0:
            return Severity.HIGH
        return Severity.CRITICAL
    
    def _wait_for_rate_limit(self):
        """Respect API rate limits."""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - elapsed)
        self.last_request_time = time.time()
    
    def _get_cache_key(self, params: Dict) -> str:
        """Generate cache key from query parameters."""
        param_str = json.dumps(params, sort_keys=True)
        return hashlib.md5(param_str.encode()).hexdigest()
    
    def _parse_cve(self, cve_item: Dict) -> CVERecord:
        """
        Parse a single CVE from NVD API response.
        
        IMPORTANT: Severity is derived from CVSS score ONLY.
        """
        cve = cve_item.get("cve", {})
        
        # Get CVE ID
        cve_id = cve.get("id", "UNKNOWN")
        
        # Get description (prefer English)
        description = "No description available."
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", description)
                break
        
        # Get CVSS data - try v3.1, then v3.0, then v2.0
        cvss_score = None
        cvss_vector = None
        cvss_version = None
        
        metrics = cve.get("metrics", {})
        
        # Try CVSS v3.1 first
        if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
            cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_vector = CVSSVector.from_nvd(cvss_data)
            cvss_version = "3.1"
        # Try CVSS v3.0
        elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
            cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_vector = CVSSVector.from_nvd(cvss_data)
            cvss_version = "3.0"
        # Try CVSS v2.0 (convert to approximate v3 scale)
        elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
            cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
            v2_score = cvss_data.get("baseScore")
            if v2_score is not None:
                # Approximate conversion (v2 scores tend to be lower)
                cvss_score = min(10.0, v2_score * 1.1)
                cvss_version = "2.0 (converted)"
        
        # GROUND TRUTH: Derive severity from CVSS score
        severity_label = self.cvss_to_severity(cvss_score)
        
        # Get dates
        published_date = None
        modified_date = None
        if cve.get("published"):
            try:
                published_date = datetime.fromisoformat(
                    cve["published"].replace("Z", "+00:00")
                )
            except ValueError:
                pass
        if cve.get("lastModified"):
            try:
                modified_date = datetime.fromisoformat(
                    cve["lastModified"].replace("Z", "+00:00")
                )
            except ValueError:
                pass
        
        # Get CWE IDs
        cwe_ids = []
        for weakness in cve.get("weaknesses", []):
            for desc in weakness.get("description", []):
                if desc.get("value", "").startswith("CWE-"):
                    cwe_ids.append(desc["value"])
        
        # Get references
        references = []
        for ref in cve.get("references", []):
            references.append({
                "url": ref.get("url", ""),
                "source": ref.get("source", ""),
                "tags": ref.get("tags", [])
            })
        
        # Get affected products (CPE)
        affected_products = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if cpe_match.get("vulnerable", False):
                        affected_products.append(cpe_match.get("criteria", ""))
        
        return CVERecord(
            cve_id=cve_id,
            description=description,
            cvss_score=cvss_score,
            severity_label=severity_label,
            cvss_vector=cvss_vector,
            cvss_version=cvss_version,
            published_date=published_date,
            modified_date=modified_date,
            cwe_ids=cwe_ids,
            references=references,
            affected_products=affected_products
        )
    
    def fetch_cves(
        self,
        keyword: Optional[str] = None,
        cpe_name: Optional[str] = None,
        cwe_id: Optional[str] = None,
        cvss_severity: Optional[str] = None,
        pub_start_date: Optional[datetime] = None,
        pub_end_date: Optional[datetime] = None,
        limit: int = 1000,
        use_cache: bool = True
    ) -> List[CVERecord]:
        """
        Fetch CVEs from NVD API.
        
        Args:
            keyword: Search keyword
            cpe_name: CPE name to filter by
            cwe_id: CWE ID to filter by
            cvss_severity: CVSS v3 severity to filter by (LOW, MEDIUM, HIGH, CRITICAL)
            pub_start_date: Filter by publication start date
            pub_end_date: Filter by publication end date
            limit: Maximum number of CVEs to fetch
            use_cache: Whether to use cached results
            
        Returns:
            List of CVERecord objects with GROUND TRUTH labels
        """
        logger.info(f"Fetching up to {limit} CVEs...")
        
        # Build parameters
        params = {"resultsPerPage": min(2000, limit)}
        
        if keyword:
            params["keywordSearch"] = keyword
        if cpe_name:
            params["cpeName"] = cpe_name
        if cwe_id:
            params["cweId"] = cwe_id
        if cvss_severity:
            params["cvssV3Severity"] = cvss_severity
        if pub_start_date:
            params["pubStartDate"] = pub_start_date.isoformat()
        if pub_end_date:
            params["pubEndDate"] = pub_end_date.isoformat()
        
        # Check cache
        cache_key = self._get_cache_key(params)
        cache_file = self.cache_dir / f"{cache_key}.json"
        
        if use_cache and cache_file.exists():
            logger.info(f"Loading from cache: {cache_file}")
            with open(cache_file, 'r') as f:
                cached_data = json.load(f)
            return [CVERecord.from_dict(d) for d in cached_data[:limit]]
        
        # Fetch from API
        headers = {"apiKey": self.api_key} if self.api_key else {}
        all_records = []
        start_index = 0
        
        while len(all_records) < limit:
            params["startIndex"] = start_index
            
            self._wait_for_rate_limit()
            
            try:
                response = requests.get(
                    self.NVD_API_URL,
                    params=params,
                    headers=headers,
                    timeout=30
                )
                response.raise_for_status()
                data = response.json()
                
                vulnerabilities = data.get("vulnerabilities", [])
                if not vulnerabilities:
                    logger.info("No more results from API.")
                    break
                
                for item in vulnerabilities:
                    record = self._parse_cve(item)
                    all_records.append(record)
                    
                    if len(all_records) >= limit:
                        break
                
                total_results = data.get("totalResults", 0)
                logger.info(
                    f"Fetched {len(all_records)}/{min(limit, total_results)} CVEs"
                )
                
                start_index += len(vulnerabilities)
                
                if start_index >= total_results:
                    break
                    
            except requests.exceptions.RequestException as e:
                logger.error(f"API request failed: {e}")
                break
            except Exception as e:
                logger.error(f"Unexpected error: {e}")
                break
        
        # Cache results
        if all_records:
            with open(cache_file, 'w') as f:
                json.dump([r.to_dict() for r in all_records], f)
            logger.info(f"Cached {len(all_records)} records to {cache_file}")
        
        return all_records[:limit]
    
    def fetch_balanced_dataset(
        self,
        samples_per_class: int = 1000,
        use_cache: bool = True
    ) -> List[CVERecord]:
        """
        Fetch a balanced dataset with equal samples per severity class.
        
        This helps with class imbalance by explicitly fetching from each class.
        
        Args:
            samples_per_class: Number of samples per severity level
            use_cache: Whether to use cached results
            
        Returns:
            List of CVERecord objects with balanced class distribution
        """
        logger.info(f"Fetching balanced dataset: {samples_per_class} per class")
        
        all_records = []
        
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            logger.info(f"Fetching {severity} severity CVEs...")
            records = self.fetch_cves(
                cvss_severity=severity,
                limit=samples_per_class,
                use_cache=use_cache
            )
            all_records.extend(records)
            logger.info(f"Got {len(records)} {severity} CVEs")
        
        logger.info(f"Total balanced dataset: {len(all_records)} records")
        return all_records
    
    def get_statistics(self, records: List[CVERecord]) -> Dict[str, Any]:
        """
        Get statistics about the collected dataset.
        
        Args:
            records: List of CVERecord objects
            
        Returns:
            Dictionary with dataset statistics
        """
        if not records:
            return {"error": "No records provided"}
        
        # Severity distribution
        severity_counts = {}
        for record in records:
            label = record.severity_label.value
            severity_counts[label] = severity_counts.get(label, 0) + 1
        
        # CVSS score statistics
        cvss_scores = [r.cvss_score for r in records if r.cvss_score is not None]
        
        # Missing data
        missing_cvss = sum(1 for r in records if r.cvss_score is None)
        missing_cwe = sum(1 for r in records if not r.cwe_ids)
        
        # Date range
        dates = [r.published_date for r in records if r.published_date]
        
        return {
            "total_records": len(records),
            "severity_distribution": severity_counts,
            "cvss_statistics": {
                "mean": sum(cvss_scores) / len(cvss_scores) if cvss_scores else None,
                "min": min(cvss_scores) if cvss_scores else None,
                "max": max(cvss_scores) if cvss_scores else None,
                "missing_count": missing_cvss
            },
            "missing_cwe_count": missing_cwe,
            "date_range": {
                "earliest": min(dates).isoformat() if dates else None,
                "latest": max(dates).isoformat() if dates else None
            }
        }


# Example usage
if __name__ == "__main__":
    import os
    
    api_key = os.environ.get("NVD_API_KEY")
    collector = CVEDataCollector(api_key=api_key)
    
    # Fetch sample data
    records = collector.fetch_cves(keyword="apache", limit=100)
    
    # Print statistics
    stats = collector.get_statistics(records)
    print("\nDataset Statistics:")
    print(json.dumps(stats, indent=2))
    
    # Show sample records
    print("\nSample Records:")
    for record in records[:3]:
        print(f"\n{record.cve_id}:")
        print(f"  CVSS Score: {record.cvss_score}")
        print(f"  Severity (GROUND TRUTH): {record.severity_label.value}")
        print(f"  Description: {record.description[:100]}...")
