#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CTPPO v2.0 - Full NVD Database Fetcher
=======================================

Fetches the ENTIRE NVD CVE database (200,000+ vulnerabilities).
Supports checkpointing, resuming, and incremental saves.

Usage:
    # Fetch all CVEs (will take several hours without API key)
    python ml/fetch_all_cves.py
    
    # Fetch with API key (much faster - get key from https://nvd.nist.gov/developers/request-an-api-key)
    python ml/fetch_all_cves.py --api-key YOUR_API_KEY
    
    # Resume interrupted fetch
    python ml/fetch_all_cves.py --resume
    
    # Fetch only recent CVEs (last N days)
    python ml/fetch_all_cves.py --days 365

Time Estimates:
    - Without API key (6s delay): ~14 days for full database
    - With API key (0.6s delay): ~1.5 days for full database
    - Fetching last 365 days: ~2-4 hours with API key

Author: Ruthvik
Date: January 2026
"""

import os
import sys
import json
import time
import logging
import argparse
import requests
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, asdict

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class FetchProgress:
    """Tracks fetch progress for checkpointing."""
    total_fetched: int = 0
    total_available: int = 0
    last_start_index: int = 0
    last_fetch_time: str = ""
    completed: bool = False
    fetch_mode: str = "all"  # "all", "recent", "date_range"
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, d: Dict) -> 'FetchProgress':
        return cls(**d)


class FullNVDFetcher:
    """
    Fetches the complete NVD CVE database with:
    - Checkpointing (resume interrupted fetches)
    - Incremental saves (don't lose data on failure)
    - Progress tracking
    - Rate limit handling
    """
    
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    RESULTS_PER_PAGE = 2000  # Maximum allowed by NVD
    
    def __init__(
        self,
        output_dir: Path = Path("./data/nvd_full"),
        api_key: Optional[str] = None
    ):
        """
        Initialize the fetcher.
        
        Args:
            output_dir: Directory to save data
            api_key: NVD API key (highly recommended!)
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.api_key = api_key
        self.rate_limit_delay = 0.6 if api_key else 6.0
        self.last_request_time = 0
        
        # File paths
        self.progress_file = self.output_dir / "fetch_progress.json"
        self.data_file = self.output_dir / "all_cves.jsonl"  # JSON Lines format
        self.stats_file = self.output_dir / "fetch_stats.json"
        
        logger.info(f"Output directory: {self.output_dir}")
        logger.info(f"API key provided: {'Yes' if api_key else 'No'}")
        logger.info(f"Rate limit delay: {self.rate_limit_delay}s per request")
        
        if not api_key:
            logger.warning("="*60)
            logger.warning("NO API KEY PROVIDED!")
            logger.warning("Fetching will be 10x slower (6s vs 0.6s per request)")
            logger.warning("Get a FREE API key: https://nvd.nist.gov/developers/request-an-api-key")
            logger.warning("="*60)
    
    def _wait_for_rate_limit(self):
        """Respect NVD API rate limits."""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.rate_limit_delay:
            sleep_time = self.rate_limit_delay - elapsed
            time.sleep(sleep_time)
        self.last_request_time = time.time()
    
    def _save_progress(self, progress: FetchProgress):
        """Save fetch progress for resuming."""
        with open(self.progress_file, 'w') as f:
            json.dump(progress.to_dict(), f, indent=2)
    
    def _load_progress(self) -> Optional[FetchProgress]:
        """Load saved progress."""
        if self.progress_file.exists():
            with open(self.progress_file, 'r') as f:
                return FetchProgress.from_dict(json.load(f))
        return None
    
    def _append_records(self, records: List[Dict]):
        """Append records to data file (JSON Lines format)."""
        with open(self.data_file, 'a') as f:
            for record in records:
                f.write(json.dumps(record) + '\n')
    
    @staticmethod
    def cvss_to_severity(cvss_score: Optional[float]) -> str:
        """Convert CVSS score to severity label (GROUND TRUTH!)."""
        if cvss_score is None:
            return "UNKNOWN"
        if cvss_score == 0.0:
            return "NONE"
        if cvss_score < 4.0:
            return "LOW"
        if cvss_score < 7.0:
            return "MEDIUM"
        if cvss_score < 9.0:
            return "HIGH"
        return "CRITICAL"
    
    def _parse_cve(self, cve_item: Dict) -> Dict:
        """
        Parse a CVE from NVD API response.
        
        Returns a dictionary with all relevant fields.
        GROUND TRUTH: Severity derived from CVSS score only!
        """
        cve = cve_item.get("cve", {})
        
        # Basic info
        cve_id = cve.get("id", "UNKNOWN")
        
        # Description (English)
        description = "No description available."
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", description)
                break
        
        # CVSS metrics - try v3.1, v3.0, v2.0 in order
        cvss_score = None
        cvss_vector = {}
        cvss_version = None
        
        metrics = cve.get("metrics", {})
        
        if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
            cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_vector = {
                "attack_vector": cvss_data.get("attackVector"),
                "attack_complexity": cvss_data.get("attackComplexity"),
                "privileges_required": cvss_data.get("privilegesRequired"),
                "user_interaction": cvss_data.get("userInteraction"),
                "scope": cvss_data.get("scope"),
                "confidentiality_impact": cvss_data.get("confidentialityImpact"),
                "integrity_impact": cvss_data.get("integrityImpact"),
                "availability_impact": cvss_data.get("availabilityImpact"),
            }
            cvss_version = "3.1"
        elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
            cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_vector = {
                "attack_vector": cvss_data.get("attackVector"),
                "attack_complexity": cvss_data.get("attackComplexity"),
                "privileges_required": cvss_data.get("privilegesRequired"),
                "user_interaction": cvss_data.get("userInteraction"),
                "scope": cvss_data.get("scope"),
                "confidentiality_impact": cvss_data.get("confidentialityImpact"),
                "integrity_impact": cvss_data.get("integrityImpact"),
                "availability_impact": cvss_data.get("availabilityImpact"),
            }
            cvss_version = "3.0"
        elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
            cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
            v2_score = cvss_data.get("baseScore")
            if v2_score is not None:
                cvss_score = min(10.0, v2_score * 1.1)  # Approximate conversion
                cvss_version = "2.0"
        
        # GROUND TRUTH: Severity from CVSS
        severity = self.cvss_to_severity(cvss_score)
        
        # Dates
        published = cve.get("published")
        modified = cve.get("lastModified")
        
        # CWE IDs
        cwe_ids = []
        for weakness in cve.get("weaknesses", []):
            for desc in weakness.get("description", []):
                if desc.get("lang") == "en":
                    cwe_id = desc.get("value", "")
                    if cwe_id.startswith("CWE-"):
                        cwe_ids.append(cwe_id)
        
        # References
        references = []
        for ref in cve.get("references", []):
            references.append({
                "url": ref.get("url"),
                "source": ref.get("source"),
                "tags": ref.get("tags", [])
            })
        
        # Affected products (CPE)
        affected_products = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    criteria = match.get("criteria", "")
                    if criteria:
                        affected_products.append(criteria)
        
        return {
            "cve_id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "cvss_version": cvss_version,
            "severity": severity,  # GROUND TRUTH!
            "published_date": published,
            "modified_date": modified,
            "cwe_ids": cwe_ids,
            "references": references,
            "affected_products": affected_products[:10],  # Limit to first 10
            "fetch_timestamp": datetime.now().isoformat()
        }
    
    def _fetch_page(
        self,
        start_index: int,
        pub_start_date: Optional[str] = None,
        pub_end_date: Optional[str] = None
    ) -> Dict:
        """
        Fetch a single page from NVD API.
        
        Args:
            start_index: Starting index for pagination
            pub_start_date: Filter by publication date start
            pub_end_date: Filter by publication date end
            
        Returns:
            API response as dictionary
        """
        self._wait_for_rate_limit()
        
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        
        params = {
            "startIndex": start_index,
            "resultsPerPage": self.RESULTS_PER_PAGE
        }
        
        if pub_start_date:
            params["pubStartDate"] = pub_start_date
        if pub_end_date:
            params["pubEndDate"] = pub_end_date
        
        max_retries = 5
        for attempt in range(max_retries):
            try:
                # Debug: show what we're requesting
                if attempt == 0:
                    logger.debug(f"API URL: {self.NVD_API_URL}")
                    logger.debug(f"Params: {params}")
                    logger.debug(f"Headers: {list(headers.keys())}")
                
                response = requests.get(
                    self.NVD_API_URL,
                    headers=headers,
                    params=params,
                    timeout=60
                )
                
                if response.status_code == 200:
                    return response.json()
                elif response.status_code == 403:
                    logger.error("API key invalid or rate limit exceeded")
                    if not self.api_key:
                        logger.info("Waiting 30 seconds before retry...")
                        time.sleep(30)
                elif response.status_code == 404:
                    # Debug 404 errors
                    logger.warning(f"404 Error - URL: {response.url}")
                    logger.warning(f"Response: {response.text[:500]}")
                elif response.status_code == 503:
                    logger.warning("NVD API temporarily unavailable, waiting...")
                    time.sleep(60)
                else:
                    logger.warning(f"API returned {response.status_code}: {response.text[:200]}")
                    
            except requests.exceptions.Timeout:
                logger.warning(f"Request timeout (attempt {attempt + 1}/{max_retries})")
                time.sleep(10)
            except requests.exceptions.RequestException as e:
                logger.error(f"Request error: {e}")
                time.sleep(10)
        
        raise Exception(f"Failed to fetch after {max_retries} attempts")
    
    def fetch_all(
        self,
        resume: bool = False,
        days: Optional[int] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None
    ) -> int:
        """
        Fetch all CVEs from NVD.
        
        Args:
            resume: Resume from last checkpoint
            days: Only fetch CVEs from last N days
            start_date: Filter start date (ISO format)
            end_date: Filter end date (ISO format)
            
        Returns:
            Total number of CVEs fetched
        """
        # Handle date filters
        pub_start = None
        pub_end = None
        
        if days:
            # NVD API 2.0 expects ISO 8601 format WITHOUT timezone suffix
            from datetime import timezone
            now = datetime.now(timezone.utc)
            start = now - timedelta(days=days)
            pub_start = start.strftime("%Y-%m-%dT00:00:00.000")
            pub_end = now.strftime("%Y-%m-%dT23:59:59.999")
            logger.info(f"Fetching CVEs from last {days} days")
        elif start_date or end_date:
            pub_start = start_date
            pub_end = end_date
        
        # Check for resume
        progress = None
        if resume:
            progress = self._load_progress()
            if progress and not progress.completed:
                logger.info(f"Resuming from index {progress.last_start_index}")
                logger.info(f"Previously fetched: {progress.total_fetched}")
            else:
                progress = None
                logger.info("No incomplete progress found, starting fresh")
        
        # Initialize progress
        if not progress:
            # Clear existing data file if starting fresh
            if self.data_file.exists():
                backup = self.data_file.with_suffix('.jsonl.bak')
                self.data_file.rename(backup)
                logger.info(f"Backed up existing data to {backup}")
            
            progress = FetchProgress(
                start_date=pub_start,
                end_date=pub_end,
                fetch_mode="recent" if days else "all"
            )
        
        # Get total count first
        logger.info("Getting total CVE count...")
        initial_response = self._fetch_page(0, pub_start, pub_end)
        total_results = initial_response.get("totalResults", 0)
        progress.total_available = total_results
        
        logger.info(f"Total CVEs to fetch: {total_results:,}")
        
        # Calculate estimated time
        pages = (total_results + self.RESULTS_PER_PAGE - 1) // self.RESULTS_PER_PAGE
        estimated_time = pages * self.rate_limit_delay
        hours = estimated_time / 3600
        logger.info(f"Estimated time: {hours:.1f} hours ({pages} API calls)")
        
        # Start fetching
        start_index = progress.last_start_index
        
        # Process first page
        if start_index == 0:
            vulns = initial_response.get("vulnerabilities", [])
            records = [self._parse_cve(v) for v in vulns]
            self._append_records(records)
            progress.total_fetched += len(records)
            start_index = self.RESULTS_PER_PAGE
        
        # Fetch remaining pages
        while start_index < total_results:
            try:
                logger.info(f"Fetching {start_index:,} - {start_index + self.RESULTS_PER_PAGE:,} of {total_results:,} ({100*start_index/total_results:.1f}%)")
                
                response = self._fetch_page(start_index, pub_start, pub_end)
                vulns = response.get("vulnerabilities", [])
                
                if not vulns:
                    logger.warning("No vulnerabilities in response, may have reached end")
                    break
                
                records = [self._parse_cve(v) for v in vulns]
                self._append_records(records)
                
                progress.total_fetched += len(records)
                progress.last_start_index = start_index
                progress.last_fetch_time = datetime.now().isoformat()
                self._save_progress(progress)
                
                start_index += self.RESULTS_PER_PAGE
                
            except KeyboardInterrupt:
                logger.info("Interrupted by user. Progress saved.")
                logger.info(f"To resume, run: python fetch_all_cves.py --resume")
                self._save_progress(progress)
                return progress.total_fetched
            except Exception as e:
                logger.error(f"Error fetching: {e}")
                logger.info("Progress saved. Can resume with --resume flag.")
                self._save_progress(progress)
                raise
        
        # Mark as completed
        progress.completed = True
        self._save_progress(progress)
        
        # Save final stats
        self._save_stats(progress)
        
        logger.info("="*60)
        logger.info("FETCH COMPLETED!")
        logger.info(f"Total CVEs fetched: {progress.total_fetched:,}")
        logger.info(f"Data saved to: {self.data_file}")
        logger.info("="*60)
        
        return progress.total_fetched
    
    def _save_stats(self, progress: FetchProgress):
        """Save final statistics."""
        # Count severities
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        
        if self.data_file.exists():
            with open(self.data_file, 'r') as f:
                for line in f:
                    record = json.loads(line)
                    sev = record.get("severity", "UNKNOWN")
                    if sev in severity_counts:
                        severity_counts[sev] += 1
        
        stats = {
            "total_cves": progress.total_fetched,
            "fetch_completed": progress.completed,
            "fetch_time": progress.last_fetch_time,
            "severity_distribution": severity_counts,
            "data_file": str(self.data_file),
            "file_size_mb": self.data_file.stat().st_size / (1024 * 1024) if self.data_file.exists() else 0
        }
        
        with open(self.stats_file, 'w') as f:
            json.dump(stats, f, indent=2)
        
        logger.info(f"Statistics saved to: {self.stats_file}")
        logger.info(f"Severity distribution: {severity_counts}")


def main():
    parser = argparse.ArgumentParser(
        description="Fetch ALL CVEs from NVD database",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Fetch all CVEs (takes many hours)
  python fetch_all_cves.py --api-key YOUR_KEY
  
  # Fetch CVEs from last year
  python fetch_all_cves.py --api-key YOUR_KEY --days 365
  
  # Resume interrupted fetch
  python fetch_all_cves.py --api-key YOUR_KEY --resume
  
  # Fetch specific date range
  python fetch_all_cves.py --api-key YOUR_KEY --start-date 2023-01-01 --end-date 2023-12-31

Get your FREE API key at: https://nvd.nist.gov/developers/request-an-api-key
        """
    )
    
    parser.add_argument(
        "--api-key",
        type=str,
        default=os.environ.get("NVD_API_KEY"),
        help="NVD API key (or set NVD_API_KEY env var)"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="./data/nvd_full",
        help="Directory to save fetched data"
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume from last checkpoint"
    )
    parser.add_argument(
        "--days",
        type=int,
        help="Only fetch CVEs from last N days"
    )
    parser.add_argument(
        "--start-date",
        type=str,
        help="Start date filter (YYYY-MM-DD)"
    )
    parser.add_argument(
        "--end-date",
        type=str,
        help="End date filter (YYYY-MM-DD)"
    )
    
    args = parser.parse_args()
    
    # Create fetcher
    fetcher = FullNVDFetcher(
        output_dir=Path(args.output_dir),
        api_key=args.api_key
    )
    
    # Format dates for API (NVD API 2.0 - no timezone suffix)
    start_date = None
    end_date = None
    if args.start_date:
        start_date = f"{args.start_date}T00:00:00.000"
    if args.end_date:
        end_date = f"{args.end_date}T23:59:59.999"
    
    # Run fetch
    try:
        total = fetcher.fetch_all(
            resume=args.resume,
            days=args.days,
            start_date=start_date,
            end_date=end_date
        )
        print(f"\nSuccess! Fetched {total:,} CVEs")
        print(f"Data saved to: {args.output_dir}/all_cves.jsonl")
    except KeyboardInterrupt:
        print("\nInterrupted. Run with --resume to continue.")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        print("\nFetch failed. Run with --resume to retry from checkpoint.")
        sys.exit(1)


if __name__ == "__main__":
    main()
