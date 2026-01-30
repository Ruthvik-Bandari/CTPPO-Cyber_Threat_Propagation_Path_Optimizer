#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CTPPO v2.0 - Pre-Training Data Verification
=============================================

Run this AFTER fixing data, BEFORE training to verify:
1. Class distribution is correct
2. References are properly loaded
3. Features are distributed well
4. No data quality issues

Usage:
    python ml/verify_fixed_data.py --data-dir data/fixed_splits

Author: Ruthvik
Date: January 2026
"""

import json
import logging
from pathlib import Path
from collections import Counter
from typing import Dict, List
import numpy as np

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def load_split(path: str) -> List[Dict]:
    """Load a data split."""
    records = []
    with open(path, 'r') as f:
        for line in f:
            records.append(json.loads(line))
    return records


def analyze_split(records: List[Dict], name: str) -> Dict:
    """Analyze a single split."""
    
    stats = {
        'name': name,
        'total': len(records),
        'severity_dist': Counter(),
        'cwe_coverage': 0,
        'refs_coverage': 0,
        'products_coverage': 0,
        'ref_counts': [],
        'desc_lengths': [],
        'cwe_counts': [],
        'product_counts': [],
        'years': []
    }
    
    for record in records:
        # Severity
        severity = record.get('severity', 'UNKNOWN')
        stats['severity_dist'][severity] += 1
        
        # CWE
        cwe_ids = record.get('cwe_ids', [])
        if cwe_ids and len(cwe_ids) > 0:
            stats['cwe_coverage'] += 1
        stats['cwe_counts'].append(len(cwe_ids) if cwe_ids else 0)
        
        # References
        refs = record.get('references', [])
        if refs and len(refs) > 0:
            stats['refs_coverage'] += 1
        stats['ref_counts'].append(len(refs) if refs else 0)
        
        # Products
        products = record.get('affected_products', [])
        if products and len(products) > 0:
            stats['products_coverage'] += 1
        stats['product_counts'].append(len(products) if products else 0)
        
        # Description length
        desc = record.get('description', '')
        stats['desc_lengths'].append(len(desc.split()))
        
        # Year
        pub_date = record.get('published_date', '')
        if pub_date:
            try:
                year = int(pub_date[:4])
                stats['years'].append(year)
            except:
                pass
    
    return stats


def print_report(train_stats: Dict, val_stats: Dict, test_stats: Dict):
    """Print verification report."""
    
    print("""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                    PRE-TRAINING DATA VERIFICATION                             ║
║                  Verify Data Quality Before Training                          ║
╚═══════════════════════════════════════════════════════════════════════════════╝
    """)
    
    # 1. Dataset Sizes
    print("="*80)
    print("1. DATASET SIZES")
    print("="*80)
    
    total = train_stats['total'] + val_stats['total'] + test_stats['total']
    print(f"""
   📊 Total Records: {total:,}
   
   Split          Records      Percentage
   ----------------------------------------
   Train          {train_stats['total']:>8,}      {100*train_stats['total']/total:.1f}%
   Validation     {val_stats['total']:>8,}      {100*val_stats['total']/total:.1f}%
   Test           {test_stats['total']:>8,}      {100*test_stats['total']/total:.1f}%
    """)
    
    # 2. Class Distribution
    print("="*80)
    print("2. CLASS DISTRIBUTION (Verify Stratification)")
    print("="*80)
    
    print(f"\n   {'Severity':<12} {'Train':>10} {'Val':>10} {'Test':>10} {'Balanced?':<10}")
    print("   " + "-"*55)
    
    all_balanced = True
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE']:
        train_pct = 100 * train_stats['severity_dist'].get(sev, 0) / train_stats['total']
        val_pct = 100 * val_stats['severity_dist'].get(sev, 0) / val_stats['total']
        test_pct = 100 * test_stats['severity_dist'].get(sev, 0) / test_stats['total']
        
        if train_pct > 0 or val_pct > 0 or test_pct > 0:
            # Check if balanced (within 1% of each other)
            balanced = abs(train_pct - val_pct) < 1 and abs(train_pct - test_pct) < 1
            status = "✅" if balanced else "⚠️"
            if not balanced:
                all_balanced = False
            print(f"   {sev:<12} {train_pct:>9.1f}% {val_pct:>9.1f}% {test_pct:>9.1f}% {status}")
    
    if all_balanced:
        print("\n   ✅ Class distribution is properly stratified!")
    else:
        print("\n   ⚠️ Some classes are not evenly distributed across splits")
    
    # 3. Feature Coverage
    print("\n" + "="*80)
    print("3. FEATURE COVERAGE (For Multi-Modal Training)")
    print("="*80)
    
    print(f"\n   {'Feature':<20} {'Train':>12} {'Val':>12} {'Test':>12}")
    print("   " + "-"*55)
    
    for feature, key in [('CWE IDs', 'cwe_coverage'), 
                         ('References', 'refs_coverage'), 
                         ('Affected Products', 'products_coverage')]:
        train_cov = 100 * train_stats[key] / train_stats['total']
        val_cov = 100 * val_stats[key] / val_stats['total']
        test_cov = 100 * test_stats[key] / test_stats['total']
        
        status = "✅" if train_cov > 70 else "⚠️"
        print(f"   {feature:<20} {train_cov:>11.1f}% {val_cov:>11.1f}% {test_cov:>11.1f}% {status}")
    
    # 4. Feature Statistics
    print("\n" + "="*80)
    print("4. FEATURE STATISTICS (Training Set)")
    print("="*80)
    
    ref_counts = train_stats['ref_counts']
    desc_lens = train_stats['desc_lengths']
    cwe_counts = train_stats['cwe_counts']
    product_counts = train_stats['product_counts']
    
    print(f"""
   Reference Count:
      Mean: {np.mean(ref_counts):.1f}, Median: {np.median(ref_counts):.0f}
      Min: {np.min(ref_counts)}, Max: {np.max(ref_counts)}
      Zero refs: {sum(1 for x in ref_counts if x == 0):,} ({100*sum(1 for x in ref_counts if x == 0)/len(ref_counts):.1f}%)
   
   Description Length (words):
      Mean: {np.mean(desc_lens):.1f}, Median: {np.median(desc_lens):.0f}
      Min: {np.min(desc_lens)}, Max: {np.max(desc_lens)}
   
   CWE Count per Record:
      Mean: {np.mean(cwe_counts):.2f}, Median: {np.median(cwe_counts):.0f}
      Records with CWE: {sum(1 for x in cwe_counts if x > 0):,} ({100*sum(1 for x in cwe_counts if x > 0)/len(cwe_counts):.1f}%)
      Records with 2+ CWEs: {sum(1 for x in cwe_counts if x > 1):,} ({100*sum(1 for x in cwe_counts if x > 1)/len(cwe_counts):.1f}%)
   
   Affected Products Count:
      Mean: {np.mean(product_counts):.1f}, Median: {np.median(product_counts):.0f}
      Records with products: {sum(1 for x in product_counts if x > 0):,} ({100*sum(1 for x in product_counts if x > 0)/len(product_counts):.1f}%)
    """)
    
    # 5. Temporal Distribution
    print("="*80)
    print("5. TEMPORAL DISTRIBUTION")
    print("="*80)
    
    years = train_stats['years']
    year_counts = Counter(years)
    
    print("\n   Recent years (training set):")
    for year in sorted(year_counts.keys())[-6:]:
        count = year_counts[year]
        pct = 100 * count / len(years)
        bar = "█" * int(pct / 2)
        print(f"   {year}: {count:>8,} ({pct:>5.1f}%) {bar}")
    
    # 6. Data Quality Checks
    print("\n" + "="*80)
    print("6. DATA QUALITY CHECKS")
    print("="*80)
    
    issues = []
    
    # Check for NONE class
    none_count = train_stats['severity_dist'].get('NONE', 0)
    if none_count > 0 and none_count < 100:
        issues.append(f"⚠️ NONE class has only {none_count} samples - will be excluded from training")
    
    # Check reference coverage
    refs_pct = train_stats['refs_coverage'] / train_stats['total']
    if refs_pct < 0.5:
        issues.append(f"⚠️ Only {refs_pct*100:.1f}% records have references")
    
    # Check CWE coverage
    cwe_pct = train_stats['cwe_coverage'] / train_stats['total']
    if cwe_pct < 0.7:
        issues.append(f"⚠️ Only {cwe_pct*100:.1f}% records have CWE - multi-modal may not help much")
    
    # Check for very short descriptions
    short_descs = sum(1 for x in desc_lens if x < 5)
    if short_descs > 100:
        issues.append(f"⚠️ {short_descs} records have very short descriptions (<5 words)")
    
    if issues:
        print("\n   Issues Found:")
        for issue in issues:
            print(f"   {issue}")
    else:
        print("\n   ✅ No data quality issues found!")
    
    # 7. Final Recommendation
    print("\n" + "="*80)
    print("7. RECOMMENDATION")
    print("="*80)
    
    # Determine recommendation
    cwe_good = train_stats['cwe_coverage'] / train_stats['total'] > 0.7
    refs_good = train_stats['refs_coverage'] / train_stats['total'] > 0.5
    balanced = all_balanced
    
    if cwe_good and refs_good and balanced:
        print("""
   ✅ DATA IS READY FOR MULTI-MODAL TRAINING!
   
   All checks passed:
   - Class distribution is balanced across splits
   - CWE coverage is sufficient (>70%)
   - References are available (>50%)
   - No major quality issues
   
   Run: python ml/04_train_multimodal_v2.py --data-dir data/fixed_splits --epochs 10
        """)
    elif cwe_good:
        print("""
   ✅ DATA IS READY, but with notes:
   
   - CWE coverage is good - multi-modal should help
   - Some features have lower coverage - will use defaults
   
   Run: python ml/04_train_multimodal_v2.py --data-dir data/fixed_splits --epochs 10
        """)
    else:
        print("""
   ⚠️ CONSIDER TEXT-ONLY MODEL
   
   - CWE coverage is low - metadata features may not help much
   - Consider running text-only improved model first
   
   Run: python ml/04_train_improved.py --epochs 10
        """)


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Verify fixed data before training")
    parser.add_argument("--data-dir", type=str, default="./data/fixed_splits")
    
    args = parser.parse_args()
    
    data_dir = Path(args.data_dir)
    
    # Load all splits
    logger.info("Loading data splits...")
    train_records = load_split(data_dir / "train.jsonl")
    val_records = load_split(data_dir / "val.jsonl")
    test_records = load_split(data_dir / "test.jsonl")
    
    logger.info(f"Train: {len(train_records):,}, Val: {len(val_records):,}, Test: {len(test_records):,}")
    
    # Analyze each split
    logger.info("Analyzing splits...")
    train_stats = analyze_split(train_records, "train")
    val_stats = analyze_split(val_records, "val")
    test_stats = analyze_split(test_records, "test")
    
    # Print report
    print_report(train_stats, val_stats, test_stats)


if __name__ == "__main__":
    main()
