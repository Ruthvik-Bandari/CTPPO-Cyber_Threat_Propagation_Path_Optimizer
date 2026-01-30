#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CTPPO v2.0 - Fix Data Issues
=============================

Fixes identified issues:
1. Adds references back to cleaned data
2. Removes duplicate descriptions
3. Re-creates train/val/test splits

Run AFTER: analyze_metadata.py reveals issues
Run BEFORE: 04_train_multimodal.py

Usage:
    python ml/fix_data_issues.py

Author: Ruthvik
Date: January 2026
"""

import json
import logging
import hashlib
from pathlib import Path
from collections import Counter
from typing import Dict, Set
import numpy as np

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def load_original_data(path: str) -> Dict[str, Dict]:
    """Load original data and index by CVE ID."""
    logger.info(f"Loading original data from {path}...")
    
    data = {}
    with open(path, 'r') as f:
        for line in f:
            record = json.loads(line)
            cve_id = record.get('cve_id')
            if cve_id:
                data[cve_id] = record
    
    logger.info(f"Loaded {len(data):,} records")
    return data


def fix_cleaned_data(
    cleaned_path: str,
    original_path: str,
    output_path: str
) -> Dict[str, int]:
    """
    Fix cleaned data by:
    1. Adding references back from original
    2. Removing duplicate descriptions
    """
    
    # Load original data for references
    original_data = load_original_data(original_path)
    
    logger.info(f"Processing cleaned data from {cleaned_path}...")
    
    # Track duplicates
    seen_descriptions: Set[str] = set()
    stats = {
        'total_input': 0,
        'duplicates_removed': 0,
        'references_added': 0,
        'total_output': 0
    }
    
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    
    with open(cleaned_path, 'r') as f_in, open(output_path, 'w') as f_out:
        for line in f_in:
            stats['total_input'] += 1
            record = json.loads(line)
            
            # Get description hash for duplicate detection
            desc = record.get('description', '')
            # Use hash of first 200 chars to detect duplicates
            desc_hash = hashlib.md5(desc[:200].encode()).hexdigest()
            
            # Skip duplicates
            if desc_hash in seen_descriptions:
                stats['duplicates_removed'] += 1
                continue
            seen_descriptions.add(desc_hash)
            
            # Add references from original data
            cve_id = record.get('cve_id')
            if cve_id in original_data:
                original = original_data[cve_id]
                refs = original.get('references', [])
                record['references'] = refs
                record['affected_products'] = original.get('affected_products', [])
                if refs:
                    stats['references_added'] += 1
            else:
                record['references'] = []
                record['affected_products'] = []
            
            # Write fixed record
            f_out.write(json.dumps(record) + '\n')
            stats['total_output'] += 1
    
    return stats


def stratified_split(
    input_path: str,
    output_dir: str,
    train_ratio: float = 0.8,
    val_ratio: float = 0.1,
    test_ratio: float = 0.1,
    seed: int = 42
) -> Dict[str, int]:
    """Create stratified train/val/test splits."""
    
    np.random.seed(seed)
    
    logger.info(f"Loading data from {input_path}...")
    
    # Group by severity
    by_severity = {}
    with open(input_path, 'r') as f:
        for line in f:
            record = json.loads(line)
            severity = record.get('severity', 'UNKNOWN')
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(record)
    
    logger.info(f"Severity distribution: {[(k, len(v)) for k, v in by_severity.items()]}")
    
    # Split each class
    train_records = []
    val_records = []
    test_records = []
    
    for severity, records in by_severity.items():
        indices = np.random.permutation(len(records))
        shuffled = [records[i] for i in indices]
        
        n = len(shuffled)
        train_end = int(n * train_ratio)
        val_end = int(n * (train_ratio + val_ratio))
        
        train_records.extend(shuffled[:train_end])
        val_records.extend(shuffled[train_end:val_end])
        test_records.extend(shuffled[val_end:])
    
    # Final shuffle
    train_records = [train_records[i] for i in np.random.permutation(len(train_records))]
    val_records = [val_records[i] for i in np.random.permutation(len(val_records))]
    test_records = [test_records[i] for i in np.random.permutation(len(test_records))]
    
    # Save
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    for name, data in [('train', train_records), ('val', val_records), ('test', test_records)]:
        path = output_dir / f'{name}.jsonl'
        with open(path, 'w') as f:
            for record in data:
                f.write(json.dumps(record) + '\n')
        logger.info(f"Saved {name}: {len(data):,} records")
    
    # Save class weights
    class_counts = Counter(r['severity'] for r in train_records)
    total = sum(class_counts.values())
    n_classes = len(class_counts)
    
    weights = {}
    for sev, count in class_counts.items():
        weights[sev] = total / (n_classes * count)
    
    min_w = min(weights.values())
    weights = {k: v/min_w for k, v in weights.items()}
    
    with open(output_dir / 'class_weights.json', 'w') as f:
        json.dump(weights, f, indent=2)
    
    return {
        'train': len(train_records),
        'val': len(val_records),
        'test': len(test_records)
    }


def verify_no_leakage(splits_dir: str) -> bool:
    """Verify no data leakage between splits."""
    
    logger.info("Verifying no data leakage...")
    
    def load_descriptions(path):
        descs = set()
        with open(path, 'r') as f:
            for line in f:
                record = json.loads(line)
                desc = record.get('description', '')[:200]
                descs.add(hashlib.md5(desc.encode()).hexdigest())
        return descs
    
    train_descs = load_descriptions(f"{splits_dir}/train.jsonl")
    val_descs = load_descriptions(f"{splits_dir}/val.jsonl")
    test_descs = load_descriptions(f"{splits_dir}/test.jsonl")
    
    train_val_overlap = len(train_descs & val_descs)
    train_test_overlap = len(train_descs & test_descs)
    val_test_overlap = len(val_descs & test_descs)
    
    logger.info(f"Train-Val overlap: {train_val_overlap}")
    logger.info(f"Train-Test overlap: {train_test_overlap}")
    logger.info(f"Val-Test overlap: {val_test_overlap}")
    
    if train_val_overlap > 0 or train_test_overlap > 0 or val_test_overlap > 0:
        logger.warning("⚠️ Data leakage detected!")
        return False
    
    logger.info("✅ No data leakage!")
    return True


def print_report(fix_stats: Dict, split_stats: Dict):
    """Print fix report."""
    
    print("""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                       DATA ISSUES FIXED                                       ║
╚═══════════════════════════════════════════════════════════════════════════════╝
    """)
    
    print("="*80)
    print("1. DUPLICATE REMOVAL")
    print("="*80)
    print(f"""
   📊 Input Records:    {fix_stats['total_input']:,}
   ❌ Duplicates Removed: {fix_stats['duplicates_removed']:,}
   ✅ Output Records:   {fix_stats['total_output']:,}
    """)
    
    print("="*80)
    print("2. REFERENCES RESTORED")
    print("="*80)
    print(f"""
   📊 Records with references added: {fix_stats['references_added']:,}
    """)
    
    print("="*80)
    print("3. NEW DATA SPLITS (No Leakage)")
    print("="*80)
    print(f"""
   📁 Train: {split_stats['train']:,} records
   📁 Val:   {split_stats['val']:,} records
   📁 Test:  {split_stats['test']:,} records
    """)
    
    print("="*80)
    print("✅ DATA READY FOR MULTI-MODAL TRAINING!")
    print("="*80)
    print("""
   Next steps:
   1. Verify metadata: python ml/analyze_metadata.py --input data/fixed/cleaned_fixed.jsonl
   2. Train multi-modal: python ml/04_train_multimodal.py --data-dir data/fixed_splits
    """)


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Fix data issues")
    parser.add_argument("--original", default="./data/nvd_full/all_cves.jsonl")
    parser.add_argument("--cleaned", default="./data/cleaned/cleaned_cves.jsonl")
    parser.add_argument("--output", default="./data/fixed/cleaned_fixed.jsonl")
    parser.add_argument("--splits-dir", default="./data/fixed_splits")
    
    args = parser.parse_args()
    
    # Step 1: Fix cleaned data
    logger.info("Step 1: Fixing cleaned data...")
    fix_stats = fix_cleaned_data(
        cleaned_path=args.cleaned,
        original_path=args.original,
        output_path=args.output
    )
    
    # Step 2: Create new splits
    logger.info("\nStep 2: Creating stratified splits...")
    split_stats = stratified_split(
        input_path=args.output,
        output_dir=args.splits_dir
    )
    
    # Step 3: Verify no leakage
    logger.info("\nStep 3: Verifying no data leakage...")
    verify_no_leakage(args.splits_dir)
    
    # Print report
    print_report(fix_stats, split_stats)


if __name__ == "__main__":
    main()
