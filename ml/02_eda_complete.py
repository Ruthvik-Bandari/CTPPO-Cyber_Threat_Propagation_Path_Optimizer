#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CTPPO v3.0 - Complete Data EDA
================================

Comprehensive exploratory data analysis of NVD data including:
- CVSS component distributions
- Label consistency analysis
- Feature quality assessment
- Data cleaning recommendations

Usage:
    python ml/02_eda_complete.py --input data/nvd_complete/nvd_complete.jsonl

Author: Ruthvik
Date: January 2026
"""

import json
import logging
from pathlib import Path
from collections import Counter, defaultdict
from typing import Dict, List, Any
import argparse

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class CompleteEDA:
    """Comprehensive EDA for NVD data."""
    
    def __init__(self, data_path: str):
        self.data_path = data_path
        self.records = []
        self.stats = {}
    
    def load_data(self):
        """Load all records."""
        logger.info(f"Loading data from {self.data_path}...")
        
        with open(self.data_path, 'r') as f:
            for line in f:
                self.records.append(json.loads(line))
        
        logger.info(f"Loaded {len(self.records):,} records")
    
    def analyze_basic_stats(self):
        """Basic statistics."""
        
        print("\n" + "="*80)
        print("1. BASIC STATISTICS")
        print("="*80)
        
        total = len(self.records)
        print(f"\n   Total CVEs: {total:,}")
        
        # Year distribution
        years = Counter()
        for r in self.records:
            date = r.get('published_date', '')
            if date:
                year = date[:4]
                years[year] += 1
        
        print(f"\n   Year Distribution:")
        for year in sorted(years.keys())[-10:]:  # Last 10 years
            pct = 100 * years[year] / total
            bar = '█' * int(pct)
            print(f"      {year}: {years[year]:>7,} ({pct:>5.1f}%) {bar}")
        
        self.stats['total'] = total
        self.stats['years'] = dict(years)
    
    def analyze_cvss_coverage(self):
        """Analyze CVSS data availability."""
        
        print("\n" + "="*80)
        print("2. CVSS COVERAGE")
        print("="*80)
        
        has_v3 = 0
        has_v2_only = 0
        no_cvss = 0
        
        v3_versions = Counter()
        
        for r in self.records:
            cvss_v3 = r.get('cvss_v3', {})
            cvss_v2 = r.get('cvss_v2', {})
            
            if cvss_v3.get('baseScore') is not None:
                has_v3 += 1
                v3_versions[cvss_v3.get('version', 'unknown')] += 1
            elif cvss_v2.get('baseScore') is not None:
                has_v2_only += 1
            else:
                no_cvss += 1
        
        total = len(self.records)
        print(f"\n   CVSS v3.x available: {has_v3:>7,} ({100*has_v3/total:.1f}%)")
        for v, count in v3_versions.items():
            print(f"      - v{v}: {count:,}")
        print(f"   CVSS v2 only:        {has_v2_only:>7,} ({100*has_v2_only/total:.1f}%)")
        print(f"   No CVSS:             {no_cvss:>7,} ({100*no_cvss/total:.1f}%)")
        
        self.stats['cvss'] = {
            'has_v3': has_v3,
            'has_v2_only': has_v2_only,
            'no_cvss': no_cvss
        }
    
    def analyze_cvss_components(self):
        """Analyze CVSS v3 component distributions."""
        
        print("\n" + "="*80)
        print("3. CVSS V3 COMPONENT DISTRIBUTIONS")
        print("="*80)
        
        components = {
            'attackVector': Counter(),
            'attackComplexity': Counter(),
            'privilegesRequired': Counter(),
            'userInteraction': Counter(),
            'scope': Counter(),
            'confidentialityImpact': Counter(),
            'integrityImpact': Counter(),
            'availabilityImpact': Counter()
        }
        
        for r in self.records:
            cvss_v3 = r.get('cvss_v3', {})
            if cvss_v3.get('baseScore') is not None:
                for comp in components:
                    value = cvss_v3.get(comp)
                    if value:
                        components[comp][value] += 1
        
        for comp, dist in components.items():
            total = sum(dist.values())
            print(f"\n   {comp}:")
            for value, count in sorted(dist.items(), key=lambda x: -x[1]):
                pct = 100 * count / total if total > 0 else 0
                bar = '█' * int(pct / 3)
                print(f"      {value:<20} {count:>7,} ({pct:>5.1f}%) {bar}")
        
        self.stats['cvss_components'] = {k: dict(v) for k, v in components.items()}
    
    def analyze_severity_labels(self):
        """Compare NVD severity vs computed severity from scores."""
        
        print("\n" + "="*80)
        print("4. SEVERITY LABEL ANALYSIS")
        print("="*80)
        
        nvd_severity = Counter()
        computed_severity = Counter()
        mismatches = 0
        mismatch_details = Counter()
        
        for r in self.records:
            nvd_sev = r.get('nvd_severity')
            comp_sev = r.get('computed_severity')
            
            if nvd_sev:
                nvd_severity[nvd_sev] += 1
            if comp_sev:
                computed_severity[comp_sev] += 1
            
            if nvd_sev and comp_sev and nvd_sev != comp_sev:
                mismatches += 1
                mismatch_details[f"{nvd_sev} → {comp_sev}"] += 1
        
        print(f"\n   NVD Severity Distribution:")
        total_nvd = sum(nvd_severity.values())
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE']:
            count = nvd_severity.get(sev, 0)
            pct = 100 * count / total_nvd if total_nvd > 0 else 0
            bar = '█' * int(pct)
            print(f"      {sev:<10} {count:>7,} ({pct:>5.1f}%) {bar}")
        
        print(f"\n   Computed Severity (from CVSS score):")
        total_comp = sum(computed_severity.values())
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE']:
            count = computed_severity.get(sev, 0)
            pct = 100 * count / total_comp if total_comp > 0 else 0
            bar = '█' * int(pct)
            print(f"      {sev:<10} {count:>7,} ({pct:>5.1f}%) {bar}")
        
        print(f"\n   Label Mismatches (NVD vs Computed):")
        print(f"      Total mismatches: {mismatches:,} ({100*mismatches/len(self.records):.1f}%)")
        
        if mismatch_details:
            print(f"\n      Top mismatch patterns:")
            for pattern, count in mismatch_details.most_common(10):
                print(f"         {pattern}: {count:,}")
        
        self.stats['severity'] = {
            'nvd': dict(nvd_severity),
            'computed': dict(computed_severity),
            'mismatches': mismatches
        }
    
    def analyze_references(self):
        """Analyze reference quality."""
        
        print("\n" + "="*80)
        print("5. REFERENCE ANALYSIS")
        print("="*80)
        
        ref_counts = []
        has_exploit = 0
        has_patch = 0
        has_vendor_advisory = 0
        
        tag_counts = Counter()
        
        for r in self.records:
            ref_counts.append(r.get('reference_count', 0))
            
            if r.get('has_exploit'):
                has_exploit += 1
            if r.get('has_patch'):
                has_patch += 1
            if r.get('has_vendor_advisory'):
                has_vendor_advisory += 1
            
            for ref in r.get('references', []):
                for tag in ref.get('tags', []):
                    tag_counts[tag] += 1
        
        total = len(self.records)
        avg_refs = sum(ref_counts) / total if total > 0 else 0
        
        print(f"\n   Reference Statistics:")
        print(f"      Average refs per CVE: {avg_refs:.1f}")
        print(f"      CVEs with 0 refs:     {ref_counts.count(0):,}")
        print(f"      CVEs with 5+ refs:    {sum(1 for c in ref_counts if c >= 5):,}")
        
        print(f"\n   Reference Tags:")
        print(f"      Has Exploit:          {has_exploit:>7,} ({100*has_exploit/total:.1f}%)")
        print(f"      Has Patch:            {has_patch:>7,} ({100*has_patch/total:.1f}%)")
        print(f"      Has Vendor Advisory:  {has_vendor_advisory:>7,} ({100*has_vendor_advisory/total:.1f}%)")
        
        print(f"\n   All Reference Tags:")
        for tag, count in tag_counts.most_common(15):
            pct = 100 * count / total
            print(f"      {tag:<30} {count:>7,} ({pct:>5.1f}%)")
        
        self.stats['references'] = {
            'avg_count': avg_refs,
            'has_exploit': has_exploit,
            'has_patch': has_patch,
            'tags': dict(tag_counts.most_common(20))
        }
    
    def analyze_cwe(self):
        """Analyze CWE distribution."""
        
        print("\n" + "="*80)
        print("6. CWE ANALYSIS")
        print("="*80)
        
        cwe_counts = Counter()
        has_cwe = 0
        no_cwe = 0
        multi_cwe = 0
        
        for r in self.records:
            cwes = r.get('cwe_ids', [])
            if cwes:
                has_cwe += 1
                if len(cwes) > 1:
                    multi_cwe += 1
                for cwe in cwes:
                    cwe_counts[cwe] += 1
            else:
                no_cwe += 1
        
        total = len(self.records)
        print(f"\n   CWE Coverage:")
        print(f"      Has CWE:      {has_cwe:>7,} ({100*has_cwe/total:.1f}%)")
        print(f"      No CWE:       {no_cwe:>7,} ({100*no_cwe/total:.1f}%)")
        print(f"      Multiple CWEs:{multi_cwe:>7,} ({100*multi_cwe/total:.1f}%)")
        print(f"      Unique CWEs:  {len(cwe_counts):>7,}")
        
        print(f"\n   Top 20 CWEs:")
        for cwe, count in cwe_counts.most_common(20):
            pct = 100 * count / total
            print(f"      {cwe:<20} {count:>7,} ({pct:>5.1f}%)")
        
        self.stats['cwe'] = {
            'has_cwe': has_cwe,
            'no_cwe': no_cwe,
            'unique': len(cwe_counts),
            'top_cwes': dict(cwe_counts.most_common(50))
        }
    
    def analyze_products(self):
        """Analyze affected products."""
        
        print("\n" + "="*80)
        print("7. AFFECTED PRODUCTS ANALYSIS")
        print("="*80)
        
        vendor_counts = Counter()
        product_counts = []
        has_products = 0
        
        for r in self.records:
            vendors = r.get('affected_vendors', [])
            products = r.get('affected_products', [])
            
            product_counts.append(len(products))
            
            if products:
                has_products += 1
            
            for v in vendors:
                vendor_counts[v] += 1
        
        total = len(self.records)
        avg_products = sum(product_counts) / total if total > 0 else 0
        
        print(f"\n   Product Statistics:")
        print(f"      Has affected products: {has_products:>7,} ({100*has_products/total:.1f}%)")
        print(f"      Average products/CVE:  {avg_products:.1f}")
        print(f"      Unique vendors:        {len(vendor_counts):>7,}")
        
        print(f"\n   Top 20 Vendors:")
        for vendor, count in vendor_counts.most_common(20):
            pct = 100 * count / total
            print(f"      {vendor:<30} {count:>7,} ({pct:>5.1f}%)")
        
        self.stats['products'] = {
            'has_products': has_products,
            'avg_count': avg_products,
            'unique_vendors': len(vendor_counts),
            'top_vendors': dict(vendor_counts.most_common(30))
        }
    
    def analyze_description_quality(self):
        """Analyze description quality."""
        
        print("\n" + "="*80)
        print("8. DESCRIPTION QUALITY")
        print("="*80)
        
        lengths = []
        word_counts = []
        empty = 0
        short = 0  # < 50 words
        
        for r in self.records:
            desc = r.get('description', '')
            lengths.append(len(desc))
            words = len(desc.split())
            word_counts.append(words)
            
            if not desc:
                empty += 1
            elif words < 50:
                short += 1
        
        total = len(self.records)
        avg_len = sum(lengths) / total
        avg_words = sum(word_counts) / total
        
        print(f"\n   Description Statistics:")
        print(f"      Empty descriptions:    {empty:>7,} ({100*empty/total:.1f}%)")
        print(f"      Short (<50 words):     {short:>7,} ({100*short/total:.1f}%)")
        print(f"      Average characters:    {avg_len:.1f}")
        print(f"      Average words:         {avg_words:.1f}")
        
        # Word count distribution
        bins = [(0, 25), (25, 50), (50, 100), (100, 200), (200, 500), (500, float('inf'))]
        print(f"\n   Word Count Distribution:")
        for low, high in bins:
            count = sum(1 for w in word_counts if low <= w < high)
            pct = 100 * count / total
            label = f"{low}-{high}" if high != float('inf') else f"{low}+"
            bar = '█' * int(pct / 2)
            print(f"      {label:<10} {count:>7,} ({pct:>5.1f}%) {bar}")
        
        self.stats['descriptions'] = {
            'empty': empty,
            'short': short,
            'avg_length': avg_len,
            'avg_words': avg_words
        }
    
    def generate_recommendations(self):
        """Generate data cleaning recommendations."""
        
        print("\n" + "="*80)
        print("9. DATA CLEANING RECOMMENDATIONS")
        print("="*80)
        
        total = len(self.records)
        recommendations = []
        
        # Check for records without CVSS
        no_cvss = self.stats['cvss']['no_cvss']
        if no_cvss > 0:
            recommendations.append(f"REMOVE {no_cvss:,} CVEs without CVSS scores (no reliable label)")
        
        # Check for empty descriptions
        empty_desc = self.stats['descriptions']['empty']
        if empty_desc > 0:
            recommendations.append(f"REMOVE {empty_desc:,} CVEs with empty descriptions")
        
        # Check for severity mismatches
        mismatches = self.stats['severity']['mismatches']
        if mismatches > 0:
            recommendations.append(f"USE computed severity from CVSS score (fixes {mismatches:,} inconsistent labels)")
        
        # CVSS v2 only
        v2_only = self.stats['cvss']['has_v2_only']
        if v2_only > 0:
            recommendations.append(f"CONVERT {v2_only:,} CVSS v2 records to v3-equivalent features")
        
        # No CWE
        no_cwe = self.stats['cwe']['no_cwe']
        if no_cwe > 0:
            recommendations.append(f"HANDLE {no_cwe:,} CVEs without CWE (use 'unknown' category)")
        
        print("\n   Recommendations:")
        for i, rec in enumerate(recommendations, 1):
            print(f"      {i}. {rec}")
        
        # Estimate final dataset size
        estimated_usable = total - no_cvss - empty_desc
        print(f"\n   Estimated Usable Records: {estimated_usable:,} ({100*estimated_usable/total:.1f}%)")
        
        return recommendations
    
    def run_full_analysis(self):
        """Run complete EDA."""
        
        print("""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                    COMPLETE NVD DATA - EXPLORATORY ANALYSIS                   ║
╚═══════════════════════════════════════════════════════════════════════════════╝
        """)
        
        self.load_data()
        self.analyze_basic_stats()
        self.analyze_cvss_coverage()
        self.analyze_cvss_components()
        self.analyze_severity_labels()
        self.analyze_references()
        self.analyze_cwe()
        self.analyze_products()
        self.analyze_description_quality()
        recommendations = self.generate_recommendations()
        
        print("\n" + "="*80)
        print("10. SUMMARY")
        print("="*80)
        
        print(f"""
   Total CVEs:           {len(self.records):,}
   CVSS v3 available:    {self.stats['cvss']['has_v3']:,}
   Has exploit info:     {self.stats['references']['has_exploit']:,}
   Has CWE:              {self.stats['cwe']['has_cwe']:,}
   
   Label Quality:
   - NVD severity available for most records
   - {self.stats['severity']['mismatches']:,} mismatches between NVD label and CVSS score
   - Recommendation: Use CVSS score for consistent labels
   
   Feature Richness:
   - 8 CVSS v3 components available (attackVector, complexity, etc.)
   - Reference tags indicate exploits, patches
   - CWE IDs for vulnerability categorization
   - Vendor and product information
        """)
        
        # Save stats
        stats_file = Path(self.data_path).parent / "eda_stats.json"
        with open(stats_file, 'w') as f:
            json.dump(self.stats, f, indent=2)
        
        print(f"\n   📁 Statistics saved to: {stats_file}")
        
        return self.stats


def main():
    parser = argparse.ArgumentParser(description="EDA for complete NVD data")
    parser.add_argument("--input", type=str, default="./data/nvd_complete/nvd_complete.jsonl",
                       help="Input JSONL file")
    
    args = parser.parse_args()
    
    eda = CompleteEDA(args.input)
    eda.run_full_analysis()


if __name__ == "__main__":
    main()
