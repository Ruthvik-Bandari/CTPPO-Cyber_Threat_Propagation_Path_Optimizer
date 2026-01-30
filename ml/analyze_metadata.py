#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CTPPO v2.0 - Metadata Quality Analysis
=======================================

Analyzes metadata fields before multi-modal training:
1. CWE coverage and distribution
2. Missing values
3. Duplicates
4. Data quality issues

Run this BEFORE multi-modal training to understand your data.

Usage:
    python ml/analyze_metadata.py
    python ml/analyze_metadata.py --input data/cleaned/cleaned_cves.jsonl

Author: Ruthvik
Date: January 2026
"""

import json
import logging
from pathlib import Path
from collections import Counter
from typing import Dict, List, Any
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def analyze_metadata(input_path: str) -> Dict[str, Any]:
    """Analyze metadata quality in CVE dataset."""
    
    logger.info(f"Loading data from {input_path}...")
    
    records = []
    with open(input_path, 'r') as f:
        for line in f:
            records.append(json.loads(line))
    
    total = len(records)
    logger.info(f"Loaded {total:,} records")
    
    # Initialize counters
    stats = {
        'total_records': total,
        'cwe': {
            'has_cwe': 0,
            'missing_cwe': 0,
            'single_cwe': 0,
            'multi_cwe': 0,
            'cwe_distribution': Counter(),
            'unique_cwes': set()
        },
        'references': {
            'has_refs': 0,
            'missing_refs': 0,
            'ref_count_distribution': Counter()
        },
        'dates': {
            'has_date': 0,
            'missing_date': 0,
            'year_distribution': Counter()
        },
        'duplicates': {
            'duplicate_cve_ids': [],
            'duplicate_descriptions': 0
        },
        'severity_by_cwe': {},
        'issues': []
    }
    
    cve_ids_seen = set()
    descriptions_seen = set()
    
    for record in records:
        cve_id = record.get('cve_id', '')
        
        # Check duplicates
        if cve_id in cve_ids_seen:
            stats['duplicates']['duplicate_cve_ids'].append(cve_id)
        cve_ids_seen.add(cve_id)
        
        desc = record.get('description', '')
        desc_hash = hash(desc[:100])  # First 100 chars
        if desc_hash in descriptions_seen:
            stats['duplicates']['duplicate_descriptions'] += 1
        descriptions_seen.add(desc_hash)
        
        # CWE Analysis
        cwe_ids = record.get('cwe_ids', [])
        if cwe_ids and len(cwe_ids) > 0:
            stats['cwe']['has_cwe'] += 1
            
            if len(cwe_ids) == 1:
                stats['cwe']['single_cwe'] += 1
            else:
                stats['cwe']['multi_cwe'] += 1
            
            for cwe in cwe_ids:
                cwe_str = cwe if isinstance(cwe, str) else f"CWE-{cwe}"
                stats['cwe']['cwe_distribution'][cwe_str] += 1
                stats['cwe']['unique_cwes'].add(cwe_str)
                
                # Track severity by CWE
                severity = record.get('severity', 'UNKNOWN')
                if cwe_str not in stats['severity_by_cwe']:
                    stats['severity_by_cwe'][cwe_str] = Counter()
                stats['severity_by_cwe'][cwe_str][severity] += 1
        else:
            stats['cwe']['missing_cwe'] += 1
        
        # References Analysis
        refs = record.get('references', [])
        if refs and len(refs) > 0:
            stats['references']['has_refs'] += 1
            ref_count = min(len(refs), 20)  # Cap at 20
            stats['references']['ref_count_distribution'][ref_count] += 1
        else:
            stats['references']['missing_refs'] += 1
        
        # Date Analysis
        pub_date = record.get('published_date', '')
        if pub_date:
            stats['dates']['has_date'] += 1
            try:
                year = int(pub_date[:4])
                stats['dates']['year_distribution'][year] += 1
            except:
                pass
        else:
            stats['dates']['missing_date'] += 1
    
    # Convert sets to counts
    stats['cwe']['unique_cwe_count'] = len(stats['cwe']['unique_cwes'])
    stats['cwe']['unique_cwes'] = None  # Remove set for JSON serialization
    
    # Identify issues
    if stats['cwe']['missing_cwe'] > total * 0.1:
        stats['issues'].append({
            'type': 'HIGH_MISSING_CWE',
            'message': f"{stats['cwe']['missing_cwe']:,} records ({100*stats['cwe']['missing_cwe']/total:.1f}%) missing CWE",
            'action': 'Will use "unknown" category for these'
        })
    
    if stats['references']['missing_refs'] > total * 0.1:
        stats['issues'].append({
            'type': 'HIGH_MISSING_REFS',
            'message': f"{stats['references']['missing_refs']:,} records missing references",
            'action': 'Will use 0 for reference count'
        })
    
    if len(stats['duplicates']['duplicate_cve_ids']) > 0:
        stats['issues'].append({
            'type': 'DUPLICATE_CVE_IDS',
            'message': f"{len(stats['duplicates']['duplicate_cve_ids'])} duplicate CVE IDs found",
            'action': 'Should remove duplicates before training'
        })
    
    return stats


def print_report(stats: Dict[str, Any]):
    """Print metadata analysis report."""
    
    total = stats['total_records']
    
    print("""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                    METADATA QUALITY ANALYSIS                                  ║
║               Check Before Multi-Modal Training                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
    """)
    
    # Overall
    print("="*80)
    print("1. OVERVIEW")
    print("="*80)
    print(f"\n   📊 Total Records: {total:,}")
    
    # CWE Analysis
    print("\n" + "="*80)
    print("2. CWE (WEAKNESS TYPE) ANALYSIS")
    print("="*80)
    
    cwe = stats['cwe']
    cwe_coverage = 100 * cwe['has_cwe'] / total
    
    print(f"""
   📊 Coverage:
      Has CWE:     {cwe['has_cwe']:>10,} ({cwe_coverage:.1f}%) ✓
      Missing CWE: {cwe['missing_cwe']:>10,} ({100-cwe_coverage:.1f}%) {'⚠️ HIGH' if cwe_coverage < 80 else ''}
   
   📊 CWE Count per Record:
      Single CWE:  {cwe['single_cwe']:>10,}
      Multi CWE:   {cwe['multi_cwe']:>10,}
   
   📊 Unique CWEs: {cwe['unique_cwe_count']:,}
    """)
    
    # Top CWEs
    print("   🏆 Top 15 CWEs:")
    top_cwes = sorted(cwe['cwe_distribution'].items(), key=lambda x: x[1], reverse=True)[:15]
    for cwe_id, count in top_cwes:
        pct = 100 * count / cwe['has_cwe']
        bar = "█" * int(pct)
        print(f"      {cwe_id:<10}: {count:>8,} ({pct:>5.1f}%) {bar}")
    
    # CWE to Severity correlation
    print("\n   📊 Top CWEs by Typical Severity:")
    print(f"   {'CWE':<12} {'CRITICAL':>10} {'HIGH':>10} {'MEDIUM':>10} {'LOW':>10} {'Dominant':<10}")
    print("   " + "-"*65)
    
    for cwe_id, _ in top_cwes[:10]:
        sev_dist = stats['severity_by_cwe'].get(cwe_id, {})
        crit = sev_dist.get('CRITICAL', 0)
        high = sev_dist.get('HIGH', 0)
        med = sev_dist.get('MEDIUM', 0)
        low = sev_dist.get('LOW', 0)
        total_cwe = crit + high + med + low
        
        if total_cwe > 0:
            dominant = max(sev_dist.items(), key=lambda x: x[1])[0] if sev_dist else 'N/A'
            print(f"   {cwe_id:<12} {crit:>10} {high:>10} {med:>10} {low:>10} {dominant:<10}")
    
    # References Analysis
    print("\n" + "="*80)
    print("3. REFERENCES ANALYSIS")
    print("="*80)
    
    refs = stats['references']
    refs_coverage = 100 * refs['has_refs'] / total
    
    print(f"""
   📊 Coverage:
      Has References:     {refs['has_refs']:>10,} ({refs_coverage:.1f}%) ✓
      Missing References: {refs['missing_refs']:>10,} ({100-refs_coverage:.1f}%)
    """)
    
    print("   📊 Reference Count Distribution:")
    ref_dist = sorted(refs['ref_count_distribution'].items())
    for ref_count, count in ref_dist[:10]:
        pct = 100 * count / refs['has_refs'] if refs['has_refs'] > 0 else 0
        bar = "█" * int(pct / 2)
        print(f"      {ref_count:>2} refs: {count:>8,} ({pct:>5.1f}%) {bar}")
    
    # Date Analysis
    print("\n" + "="*80)
    print("4. DATE ANALYSIS")
    print("="*80)
    
    dates = stats['dates']
    date_coverage = 100 * dates['has_date'] / total
    
    print(f"""
   📊 Coverage:
      Has Date:     {dates['has_date']:>10,} ({date_coverage:.1f}%) ✓
      Missing Date: {dates['missing_date']:>10,} ({100-date_coverage:.1f}%)
    """)
    
    print("   📊 Records by Year (last 10 years):")
    years = sorted(dates['year_distribution'].items())
    for year, count in years[-10:]:
        pct = 100 * count / total
        bar = "█" * int(pct)
        print(f"      {year}: {count:>8,} ({pct:>5.1f}%) {bar}")
    
    # Duplicates
    print("\n" + "="*80)
    print("5. DUPLICATES CHECK")
    print("="*80)
    
    dups = stats['duplicates']
    dup_ids = len(dups['duplicate_cve_ids'])
    dup_desc = dups['duplicate_descriptions']
    
    if dup_ids == 0 and dup_desc == 0:
        print("\n   ✅ No duplicates found!")
    else:
        print(f"""
   ⚠️ Duplicates Found:
      Duplicate CVE IDs:     {dup_ids}
      Duplicate Descriptions: {dup_desc}
        """)
        if dup_ids > 0:
            print(f"      Sample duplicates: {dups['duplicate_cve_ids'][:5]}")
    
    # Issues Summary
    print("\n" + "="*80)
    print("6. ISSUES & RECOMMENDATIONS")
    print("="*80)
    
    if stats['issues']:
        for issue in stats['issues']:
            print(f"""
   ⚠️ {issue['type']}
      {issue['message']}
      Action: {issue['action']}
            """)
    else:
        print("\n   ✅ No major issues found!")
    
    # Final Recommendation
    print("\n" + "="*80)
    print("7. RECOMMENDATION FOR MULTI-MODAL TRAINING")
    print("="*80)
    
    cwe_pct = cwe['has_cwe'] / total
    refs_pct = refs['has_refs'] / total
    
    if cwe_pct >= 0.7 and refs_pct >= 0.9:
        print("""
   ✅ GOOD TO GO!
   
   Metadata quality is sufficient for multi-modal training:
   - CWE coverage: {:.1f}% (≥70%)
   - Reference coverage: {:.1f}% (≥90%)
   
   The multi-modal model will handle missing values by:
   - Missing CWE → "unknown" category (embedded)
   - Missing refs → 0 reference count
   
   Run: python ml/04_train_multimodal.py
        """.format(100*cwe_pct, 100*refs_pct))
    else:
        print("""
   ⚠️ CONSIDER TEXT-ONLY FIRST
   
   Metadata coverage is lower than ideal:
   - CWE coverage: {:.1f}% (target: ≥70%)
   - Reference coverage: {:.1f}% (target: ≥90%)
   
   Options:
   1. Run improved text-only model first: python ml/04_train_improved.py
   2. Then try multi-modal to compare
        """.format(100*cwe_pct, 100*refs_pct))


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Analyze metadata quality")
    parser.add_argument(
        "--input", "-i",
        type=str,
        default="./data/cleaned/cleaned_cves.jsonl",
        help="Input data file"
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        help="Save stats to JSON file"
    )
    
    args = parser.parse_args()
    
    stats = analyze_metadata(args.input)
    print_report(stats)
    
    if args.output:
        # Convert Counter objects for JSON serialization
        stats_json = stats.copy()
        stats_json['cwe']['cwe_distribution'] = dict(stats['cwe']['cwe_distribution'])
        stats_json['references']['ref_count_distribution'] = dict(stats['references']['ref_count_distribution'])
        stats_json['dates']['year_distribution'] = dict(stats['dates']['year_distribution'])
        stats_json['severity_by_cwe'] = {k: dict(v) for k, v in stats['severity_by_cwe'].items()}
        
        with open(args.output, 'w') as f:
            json.dump(stats_json, f, indent=2)
        print(f"\n   📁 Stats saved to: {args.output}")


if __name__ == "__main__":
    main()
