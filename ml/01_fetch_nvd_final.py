#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CTPPO v3.0 - Complete NVD Data Fetcher (FINAL FIXED)
=====================================================

NVD API has 120-day max range limit - this script chunks by quarters.

Usage:
    python ml/01_fetch_nvd_final.py --output data/nvd_complete --start-year 2020 --end-year 2025 --api-key YOUR_KEY

Author: Ruthvik
Date: January 2026
"""

import json
import logging
import time
import requests
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import argparse

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class NVDFetcher:
    """Fetches complete CVE data from NVD API 2.0."""
    
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    MAX_DAYS = 120  # NVD API limit!
    
    def __init__(self, api_key: Optional[str] = None):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'CTPPO-Research/1.0'})
        
        if api_key:
            self.session.headers['apiKey'] = api_key
            self.rate_limit = 50
            logger.info("✓ API key set - rate limit: 50 requests/30s")
        else:
            self.rate_limit = 5
            logger.info("No API key - rate limit: 5 requests/30s")
        
        self.request_count = 0
        self.window_start = time.time()
    
    def _rate_limit_wait(self):
        """Enforce rate limiting."""
        self.request_count += 1
        if self.request_count >= self.rate_limit:
            elapsed = time.time() - self.window_start
            if elapsed < 30:
                sleep_time = 31 - elapsed
                logger.info(f"Rate limit: sleeping {sleep_time:.0f}s...")
                time.sleep(sleep_time)
            self.request_count = 0
            self.window_start = time.time()
    
    def _extract_cvss_v3(self, metrics: Dict) -> Dict[str, Any]:
        """Extract CVSS v3.x data."""
        result = {
            'version': None, 'vectorString': None, 'baseScore': None,
            'baseSeverity': None, 'attackVector': None, 'attackComplexity': None,
            'privilegesRequired': None, 'userInteraction': None, 'scope': None,
            'confidentialityImpact': None, 'integrityImpact': None,
            'availabilityImpact': None, 'exploitabilityScore': None, 'impactScore': None
        }
        
        cvss_data = None
        if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
            cvss_data = metrics['cvssMetricV31'][0]
            result['version'] = '3.1'
        elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
            cvss_data = metrics['cvssMetricV30'][0]
            result['version'] = '3.0'
        
        if cvss_data:
            cvss = cvss_data.get('cvssData', {})
            for key in ['vectorString', 'baseScore', 'baseSeverity', 'attackVector',
                       'attackComplexity', 'privilegesRequired', 'userInteraction',
                       'scope', 'confidentialityImpact', 'integrityImpact', 'availabilityImpact']:
                result[key] = cvss.get(key)
            result['exploitabilityScore'] = cvss_data.get('exploitabilityScore')
            result['impactScore'] = cvss_data.get('impactScore')
        
        return result
    
    def _extract_cvss_v2(self, metrics: Dict) -> Dict[str, Any]:
        """Extract CVSS v2.0 data."""
        result = {
            'version': '2.0', 'vectorString': None, 'baseScore': None,
            'baseSeverity': None, 'accessVector': None, 'accessComplexity': None,
            'authentication': None, 'confidentialityImpact': None,
            'integrityImpact': None, 'availabilityImpact': None,
            'exploitabilityScore': None, 'impactScore': None
        }
        
        if 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
            cvss_data = metrics['cvssMetricV2'][0]
            cvss = cvss_data.get('cvssData', {})
            
            for key in ['vectorString', 'baseScore', 'accessVector', 'accessComplexity',
                       'authentication', 'confidentialityImpact', 'integrityImpact', 'availabilityImpact']:
                result[key] = cvss.get(key)
            result['exploitabilityScore'] = cvss_data.get('exploitabilityScore')
            result['impactScore'] = cvss_data.get('impactScore')
            
            score = result['baseScore']
            if score is not None:
                result['baseSeverity'] = 'HIGH' if score >= 7.0 else 'MEDIUM' if score >= 4.0 else 'LOW'
        
        return result
    
    def _process_cve(self, cve: Dict) -> Dict[str, Any]:
        """Process a single CVE."""
        cve_data = cve.get('cve', {})
        cve_id = cve_data.get('id', '')
        
        # Description
        description = ''
        for desc in cve_data.get('descriptions', []):
            if desc.get('lang') == 'en':
                description = desc.get('value', '')
                break
        
        # CVSS
        metrics = cve_data.get('metrics', {})
        cvss_v3 = self._extract_cvss_v3(metrics)
        cvss_v2 = self._extract_cvss_v2(metrics)
        
        # Primary score
        if cvss_v3['baseScore'] is not None:
            primary_score = cvss_v3['baseScore']
            primary_severity = cvss_v3['baseSeverity']
            cvss_version = cvss_v3['version']
        elif cvss_v2['baseScore'] is not None:
            primary_score = cvss_v2['baseScore']
            primary_severity = cvss_v2['baseSeverity']
            cvss_version = '2.0'
        else:
            primary_score = None
            primary_severity = None
            cvss_version = None
        
        # Computed severity
        computed_severity = None
        if primary_score is not None:
            if primary_score >= 9.0: computed_severity = 'CRITICAL'
            elif primary_score >= 7.0: computed_severity = 'HIGH'
            elif primary_score >= 4.0: computed_severity = 'MEDIUM'
            elif primary_score > 0: computed_severity = 'LOW'
        
        # References
        refs = cve_data.get('references', [])
        references = [{'url': r.get('url', ''), 'tags': r.get('tags', [])} for r in refs]
        has_exploit = any('Exploit' in r.get('tags', []) for r in refs)
        has_patch = any('Patch' in r.get('tags', []) for r in refs)
        
        # CWE
        cwe_ids = []
        for w in cve_data.get('weaknesses', []):
            for d in w.get('description', []):
                v = d.get('value', '')
                if v.startswith('CWE-') or v.startswith('NVD-CWE'):
                    cwe_ids.append(v)
        cwe_ids = list(set(cwe_ids))
        
        # Products
        vendors, products = set(), set()
        for config in cve_data.get('configurations', []):
            for node in config.get('nodes', []):
                for match in node.get('cpeMatch', []):
                    parts = match.get('criteria', '').split(':')
                    if len(parts) > 4:
                        if parts[3] and parts[3] != '*': vendors.add(parts[3])
                        if parts[4] and parts[4] != '*': products.add(parts[4])
        
        return {
            'cve_id': cve_id,
            'description': description,
            'published_date': cve_data.get('published', ''),
            'last_modified_date': cve_data.get('lastModified', ''),
            'cvss_v3': cvss_v3,
            'cvss_v2': cvss_v2,
            'cvss_score': primary_score,
            'cvss_version': cvss_version,
            'nvd_severity': primary_severity,
            'computed_severity': computed_severity,
            'cwe_ids': cwe_ids,
            'references': references,
            'reference_count': len(references),
            'has_exploit': has_exploit,
            'has_patch': has_patch,
            'affected_vendors': list(vendors),
            'affected_products': list(products),
            'product_count': len(products),
            'vuln_status': cve_data.get('vulnStatus', '')
        }
    
    def _fetch_chunk(self, start_date: str, end_date: str) -> List[Dict]:
        """Fetch a single chunk (max 120 days)."""
        all_records = []
        start_index = 0
        
        while True:
            self._rate_limit_wait()
            
            params = {
                'pubStartDate': f'{start_date}T00:00:00.000',
                'pubEndDate': f'{end_date}T23:59:59.999',
                'startIndex': start_index,
                'resultsPerPage': 2000
            }
            
            try:
                response = self.session.get(self.BASE_URL, params=params, timeout=120)
                
                if response.status_code == 403:
                    logger.warning("Rate limited. Waiting 60s...")
                    time.sleep(60)
                    continue
                
                response.raise_for_status()
                data = response.json()
                
            except requests.exceptions.RequestException as e:
                logger.error(f"Request error: {e}")
                time.sleep(30)
                continue
            
            vulnerabilities = data.get('vulnerabilities', [])
            total_results = data.get('totalResults', 0)
            
            if not vulnerabilities:
                break
            
            for vuln in vulnerabilities:
                try:
                    record = self._process_cve(vuln)
                    all_records.append(record)
                except Exception as e:
                    pass
            
            start_index += len(vulnerabilities)
            if start_index >= total_results:
                break
        
        return all_records
    
    def fetch_year(self, year: int, output_file: str) -> int:
        """Fetch a full year by chunking into quarters (90 days each)."""
        logger.info(f"Fetching year {year} in quarterly chunks...")
        
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        
        # Define quarters
        quarters = [
            (f"{year}-01-01", f"{year}-03-31"),
            (f"{year}-04-01", f"{year}-06-30"),
            (f"{year}-07-01", f"{year}-09-30"),
            (f"{year}-10-01", f"{year}-12-31"),
        ]
        
        all_records = []
        
        for i, (start, end) in enumerate(quarters, 1):
            logger.info(f"  Q{i}: {start} to {end}")
            records = self._fetch_chunk(start, end)
            all_records.extend(records)
            logger.info(f"      → {len(records):,} CVEs (total: {len(all_records):,})")
        
        # Write to file
        with open(output_file, 'w') as f:
            for record in all_records:
                f.write(json.dumps(record) + '\n')
        
        logger.info(f"  ✓ Year {year}: {len(all_records):,} CVEs → {output_file}")
        return len(all_records)
    
    def fetch_years(self, start_year: int, end_year: int, output_dir: str) -> Dict[int, int]:
        """Fetch multiple years."""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        results = {}
        
        for year in range(start_year, end_year + 1):
            print(f"\n{'='*50}")
            print(f"  YEAR {year}")
            print('='*50)
            
            output_file = output_path / f"nvd_{year}.jsonl"
            count = self.fetch_year(year, str(output_file))
            results[year] = count
        
        # Combine all years
        combined = output_path / "nvd_complete.jsonl"
        print(f"\nCombining all years → {combined}")
        
        total = 0
        with open(combined, 'w') as out:
            for year in range(start_year, end_year + 1):
                yf = output_path / f"nvd_{year}.jsonl"
                if yf.exists():
                    with open(yf) as f:
                        for line in f:
                            out.write(line)
                            total += 1
        
        # Summary
        print("\n" + "="*50)
        print("  FETCH COMPLETE!")
        print("="*50)
        for y, c in sorted(results.items()):
            print(f"  {y}: {c:>7,} CVEs")
        print("  " + "-"*25)
        print(f"  TOTAL: {total:,} CVEs")
        print("="*50)
        
        return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="./data/nvd_complete")
    parser.add_argument("--start-year", type=int, default=2020)
    parser.add_argument("--end-year", type=int, default=2025)
    parser.add_argument("--api-key", default=None)
    args = parser.parse_args()
    
    print("""
╔═══════════════════════════════════════════════════════════════════════════════╗
║              CTPPO - NVD FETCHER (FINAL)                                      ║
║              Fetching ALL CVSS components in quarterly chunks!                ║
╚═══════════════════════════════════════════════════════════════════════════════╝
    """)
    
    fetcher = NVDFetcher(api_key=args.api_key)
    fetcher.fetch_years(args.start_year, args.end_year, args.output)
    
    print(f"\n✅ Done! Data saved to: {args.output}/")
    print("\nNext steps:")
    print("  1. python ml/02_eda_complete.py --input data/nvd_complete/nvd_complete.jsonl")
    print("  2. python ml/03_clean_and_label.py --input data/nvd_complete/nvd_complete.jsonl")


if __name__ == "__main__":
    main()
