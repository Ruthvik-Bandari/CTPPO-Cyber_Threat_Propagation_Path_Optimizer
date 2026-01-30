#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CTPPO v3.0 - Data Cleaning and Label Generation
=================================================

Cleans NVD data and creates consistent labels:
1. Removes records without CVSS scores
2. Removes records with empty descriptions
3. Generates consistent severity labels from CVSS scores
4. Encodes CVSS components as categorical features
5. Creates stratified train/val/test splits

Usage:
    python ml/03_clean_and_label.py --input data/nvd_complete/nvd_complete.jsonl --output data/clean_v3

Author: Ruthvik
Date: January 2026
"""

import json
import logging
import random
from pathlib import Path
from collections import Counter, defaultdict
from typing import Dict, List, Any, Tuple
import argparse

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class DataCleanerAndLabeler:
    """
    Cleans NVD data and creates consistent labels.
    """
    
    # CVSS Score to Severity mapping (official thresholds)
    SEVERITY_THRESHOLDS = {
        'CRITICAL': (9.0, 10.0),
        'HIGH': (7.0, 8.9),
        'MEDIUM': (4.0, 6.9),
        'LOW': (0.1, 3.9)
    }
    
    # CVSS v3 component encodings
    CVSS_ENCODINGS = {
        'attackVector': {'NETWORK': 0, 'ADJACENT_NETWORK': 1, 'LOCAL': 2, 'PHYSICAL': 3},
        'attackComplexity': {'LOW': 0, 'HIGH': 1},
        'privilegesRequired': {'NONE': 0, 'LOW': 1, 'HIGH': 2},
        'userInteraction': {'NONE': 0, 'REQUIRED': 1},
        'scope': {'UNCHANGED': 0, 'CHANGED': 1},
        'confidentialityImpact': {'NONE': 0, 'LOW': 1, 'HIGH': 2},
        'integrityImpact': {'NONE': 0, 'LOW': 1, 'HIGH': 2},
        'availabilityImpact': {'NONE': 0, 'LOW': 1, 'HIGH': 2}
    }
    
    # CVSS v2 to v3 equivalent mapping (approximate)
    CVSS_V2_MAPPINGS = {
        'accessVector': {'NETWORK': 'NETWORK', 'ADJACENT_NETWORK': 'ADJACENT_NETWORK', 
                        'LOCAL': 'LOCAL'},
        'accessComplexity': {'LOW': 'LOW', 'MEDIUM': 'LOW', 'HIGH': 'HIGH'},
        'authentication': {'NONE': 'NONE', 'SINGLE': 'LOW', 'MULTIPLE': 'HIGH'}
    }
    
    def __init__(self, input_path: str, output_dir: str):
        self.input_path = input_path
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.records = []
        self.cleaned_records = []
        self.stats = defaultdict(int)
    
    def load_data(self):
        """Load raw data."""
        logger.info(f"Loading data from {self.input_path}...")
        
        with open(self.input_path, 'r') as f:
            for line in f:
                self.records.append(json.loads(line))
        
        logger.info(f"Loaded {len(self.records):,} records")
        self.stats['total_raw'] = len(self.records)
    
    def compute_severity_from_score(self, score: float) -> str:
        """Compute severity label from CVSS score."""
        if score is None:
            return None
        
        if score >= 9.0:
            return 'CRITICAL'
        elif score >= 7.0:
            return 'HIGH'
        elif score >= 4.0:
            return 'MEDIUM'
        elif score > 0:
            return 'LOW'
        else:
            return 'NONE'
    
    def encode_cvss_v3_components(self, cvss_v3: Dict) -> Dict[str, int]:
        """Encode CVSS v3 components as integers."""
        encoded = {}
        
        for component, mapping in self.CVSS_ENCODINGS.items():
            value = cvss_v3.get(component)
            if value and value in mapping:
                encoded[f'cvss_{component}'] = mapping[value]
            else:
                encoded[f'cvss_{component}'] = -1  # Unknown/missing
        
        return encoded
    
    def convert_v2_to_v3_features(self, cvss_v2: Dict) -> Dict[str, int]:
        """Convert CVSS v2 components to v3-equivalent features."""
        encoded = {}
        
        # Attack Vector (from accessVector)
        av = cvss_v2.get('accessVector')
        if av in self.CVSS_V2_MAPPINGS['accessVector']:
            v3_av = self.CVSS_V2_MAPPINGS['accessVector'][av]
            encoded['cvss_attackVector'] = self.CVSS_ENCODINGS['attackVector'].get(v3_av, -1)
        else:
            encoded['cvss_attackVector'] = -1
        
        # Attack Complexity (from accessComplexity)
        ac = cvss_v2.get('accessComplexity')
        if ac in self.CVSS_V2_MAPPINGS['accessComplexity']:
            v3_ac = self.CVSS_V2_MAPPINGS['accessComplexity'][ac]
            encoded['cvss_attackComplexity'] = self.CVSS_ENCODINGS['attackComplexity'].get(v3_ac, -1)
        else:
            encoded['cvss_attackComplexity'] = -1
        
        # Privileges Required (from authentication)
        auth = cvss_v2.get('authentication')
        if auth in self.CVSS_V2_MAPPINGS['authentication']:
            v3_pr = self.CVSS_V2_MAPPINGS['authentication'][auth]
            encoded['cvss_privilegesRequired'] = self.CVSS_ENCODINGS['privilegesRequired'].get(v3_pr, -1)
        else:
            encoded['cvss_privilegesRequired'] = -1
        
        # User Interaction - v2 doesn't have this, assume NONE
        encoded['cvss_userInteraction'] = 0  # NONE
        
        # Scope - v2 doesn't have this, assume UNCHANGED
        encoded['cvss_scope'] = 0  # UNCHANGED
        
        # Impact metrics (same in v2 and v3)
        for impact in ['confidentialityImpact', 'integrityImpact', 'availabilityImpact']:
            value = cvss_v2.get(impact)
            if value and value in self.CVSS_ENCODINGS[impact]:
                encoded[f'cvss_{impact}'] = self.CVSS_ENCODINGS[impact][value]
            else:
                encoded[f'cvss_{impact}'] = -1
        
        return encoded
    
    def clean_record(self, record: Dict) -> Tuple[Dict, str]:
        """
        Clean a single record and return (cleaned_record, rejection_reason).
        
        Returns (None, reason) if record should be rejected.
        """
        
        # Check description
        description = record.get('description', '').strip()
        if not description or len(description) < 20:
            return None, 'empty_description'
        
        # Check for rejected descriptions
        reject_phrases = [
            '** RESERVED **',
            '** REJECT **',
            'DO NOT USE THIS CANDIDATE NUMBER',
            'not a vulnerability'
        ]
        desc_lower = description.lower()
        for phrase in reject_phrases:
            if phrase.lower() in desc_lower:
                return None, 'rejected_description'
        
        # Get CVSS data
        cvss_v3 = record.get('cvss_v3', {})
        cvss_v2 = record.get('cvss_v2', {})
        
        v3_score = cvss_v3.get('baseScore')
        v2_score = cvss_v2.get('baseScore')
        
        # Must have at least one CVSS score
        if v3_score is None and v2_score is None:
            return None, 'no_cvss'
        
        # Determine primary score and encode features
        if v3_score is not None:
            primary_score = v3_score
            cvss_encoded = self.encode_cvss_v3_components(cvss_v3)
            exploitability_score = cvss_v3.get('exploitabilityScore')
            impact_score = cvss_v3.get('impactScore')
            cvss_version = cvss_v3.get('version', '3.x')
        else:
            primary_score = v2_score
            cvss_encoded = self.convert_v2_to_v3_features(cvss_v2)
            exploitability_score = cvss_v2.get('exploitabilityScore')
            impact_score = cvss_v2.get('impactScore')
            cvss_version = '2.0'
        
        # Compute consistent severity label
        severity = self.compute_severity_from_score(primary_score)
        if severity == 'NONE' or severity is None:
            return None, 'zero_score'
        
        # Build cleaned record
        cleaned = {
            # Identifiers
            'cve_id': record.get('cve_id'),
            
            # Text features
            'description': description,
            
            # TARGET LABEL (computed from score for consistency)
            'severity': severity,
            
            # CVSS scores
            'cvss_score': primary_score,
            'cvss_version': cvss_version,
            'exploitability_score': exploitability_score,
            'impact_score': impact_score,
            
            # CVSS component features (encoded as integers)
            **cvss_encoded,
            
            # CWE
            'cwe_ids': record.get('cwe_ids', []),
            'primary_cwe': record.get('cwe_ids', [None])[0] if record.get('cwe_ids') else None,
            
            # Reference features
            'reference_count': record.get('reference_count', 0),
            'has_exploit': record.get('has_exploit', False),
            'has_patch': record.get('has_patch', False),
            'has_vendor_advisory': record.get('has_vendor_advisory', False),
            
            # Product features
            'affected_vendors': record.get('affected_vendors', []),
            'affected_products': record.get('affected_products', []),
            'product_count': record.get('product_count', 0),
            
            # Dates
            'published_date': record.get('published_date'),
            
            # Original NVD severity (for comparison)
            'nvd_original_severity': record.get('nvd_severity')
        }
        
        return cleaned, None
    
    def clean_all_records(self):
        """Clean all records."""
        logger.info("Cleaning records...")
        
        rejection_reasons = Counter()
        
        for record in self.records:
            cleaned, reason = self.clean_record(record)
            
            if cleaned:
                self.cleaned_records.append(cleaned)
            else:
                rejection_reasons[reason] += 1
        
        self.stats['cleaned'] = len(self.cleaned_records)
        self.stats['rejected'] = len(self.records) - len(self.cleaned_records)
        self.stats['rejection_reasons'] = dict(rejection_reasons)
        
        logger.info(f"Cleaned: {len(self.cleaned_records):,} records")
        logger.info(f"Rejected: {self.stats['rejected']:,} records")
        
        for reason, count in rejection_reasons.most_common():
            logger.info(f"  - {reason}: {count:,}")
    
    def remove_duplicates(self):
        """Remove duplicate CVE IDs."""
        logger.info("Removing duplicates...")
        
        seen = set()
        unique = []
        duplicates = 0
        
        for record in self.cleaned_records:
            cve_id = record['cve_id']
            if cve_id not in seen:
                seen.add(cve_id)
                unique.append(record)
            else:
                duplicates += 1
        
        self.cleaned_records = unique
        self.stats['duplicates_removed'] = duplicates
        self.stats['after_dedup'] = len(self.cleaned_records)
        
        logger.info(f"Removed {duplicates:,} duplicates")
        logger.info(f"Unique records: {len(self.cleaned_records):,}")
    
    def analyze_label_distribution(self):
        """Analyze final label distribution."""
        
        severity_counts = Counter(r['severity'] for r in self.cleaned_records)
        
        print("\n" + "="*60)
        print("LABEL DISTRIBUTION (Computed from CVSS Scores)")
        print("="*60)
        
        total = len(self.cleaned_records)
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = severity_counts.get(sev, 0)
            pct = 100 * count / total
            bar = '█' * int(pct)
            print(f"   {sev:<10} {count:>7,} ({pct:>5.1f}%) {bar}")
        
        self.stats['severity_distribution'] = dict(severity_counts)
        
        # Compare with original NVD labels
        matches = 0
        mismatches = Counter()
        
        for r in self.cleaned_records:
            computed = r['severity']
            original = r.get('nvd_original_severity')
            
            if computed == original:
                matches += 1
            elif original:
                mismatches[f"{original} → {computed}"] += 1
        
        print(f"\n   Label Consistency Check:")
        print(f"   Matches NVD original: {matches:,} ({100*matches/total:.1f}%)")
        print(f"   Corrected labels:     {total - matches:,} ({100*(total-matches)/total:.1f}%)")
        
        if mismatches:
            print(f"\n   Top corrections made:")
            for pattern, count in mismatches.most_common(5):
                print(f"      {pattern}: {count:,}")
    
    def create_stratified_splits(self, train_ratio=0.8, val_ratio=0.1, test_ratio=0.1):
        """Create stratified train/val/test splits."""
        logger.info("Creating stratified splits...")
        
        # Group by severity
        by_severity = defaultdict(list)
        for record in self.cleaned_records:
            by_severity[record['severity']].append(record)
        
        train, val, test = [], [], []
        
        for severity, records in by_severity.items():
            random.shuffle(records)
            n = len(records)
            
            train_end = int(n * train_ratio)
            val_end = train_end + int(n * val_ratio)
            
            train.extend(records[:train_end])
            val.extend(records[train_end:val_end])
            test.extend(records[val_end:])
        
        # Shuffle each split
        random.shuffle(train)
        random.shuffle(val)
        random.shuffle(test)
        
        logger.info(f"Train: {len(train):,}, Val: {len(val):,}, Test: {len(test):,}")
        
        # Verify stratification
        print("\n" + "="*60)
        print("SPLIT VERIFICATION")
        print("="*60)
        
        for name, split in [('Train', train), ('Val', val), ('Test', test)]:
            counts = Counter(r['severity'] for r in split)
            total = len(split)
            print(f"\n   {name} ({total:,} samples):")
            for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                count = counts.get(sev, 0)
                pct = 100 * count / total
                print(f"      {sev}: {count:,} ({pct:.1f}%)")
        
        self.stats['splits'] = {
            'train': len(train),
            'val': len(val),
            'test': len(test)
        }
        
        return train, val, test
    
    def save_splits(self, train: List, val: List, test: List):
        """Save splits to files."""
        
        splits_dir = self.output_dir / "splits"
        splits_dir.mkdir(exist_ok=True)
        
        for name, data in [('train', train), ('val', val), ('test', test)]:
            filepath = splits_dir / f"{name}.jsonl"
            with open(filepath, 'w') as f:
                for record in data:
                    f.write(json.dumps(record) + '\n')
            logger.info(f"Saved {filepath}")
        
        # Save combined clean data
        combined_path = self.output_dir / "clean_data.jsonl"
        with open(combined_path, 'w') as f:
            for record in self.cleaned_records:
                f.write(json.dumps(record) + '\n')
        logger.info(f"Saved {combined_path}")
        
        # Save stats
        stats_path = self.output_dir / "cleaning_stats.json"
        with open(stats_path, 'w') as f:
            json.dump(self.stats, f, indent=2)
        logger.info(f"Saved {stats_path}")
        
        # Save feature encodings for model
        encodings_path = self.output_dir / "feature_encodings.json"
        with open(encodings_path, 'w') as f:
            json.dump({
                'cvss_encodings': self.CVSS_ENCODINGS,
                'severity_thresholds': {k: list(v) for k, v in self.SEVERITY_THRESHOLDS.items()}
            }, f, indent=2)
        logger.info(f"Saved {encodings_path}")
    
    def run(self):
        """Run complete cleaning pipeline."""
        
        print("""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                    DATA CLEANING AND LABEL GENERATION                         ║
╚═══════════════════════════════════════════════════════════════════════════════╝
        """)
        
        self.load_data()
        self.clean_all_records()
        self.remove_duplicates()
        self.analyze_label_distribution()
        
        train, val, test = self.create_stratified_splits()
        self.save_splits(train, val, test)
        
        print("\n" + "="*60)
        print("CLEANING SUMMARY")
        print("="*60)
        print(f"""
   Input records:        {self.stats['total_raw']:,}
   After cleaning:       {self.stats['cleaned']:,}
   After deduplication:  {self.stats['after_dedup']:,}
   
   Rejection reasons:
""")
        for reason, count in self.stats['rejection_reasons'].items():
            print(f"      {reason}: {count:,}")
        
        print(f"""
   Final splits:
      Train: {self.stats['splits']['train']:,}
      Val:   {self.stats['splits']['val']:,}
      Test:  {self.stats['splits']['test']:,}
   
   Output directory: {self.output_dir}
   
   Key improvements:
   ✓ Consistent labels from CVSS scores (not inconsistent NVD labels)
   ✓ All CVSS components encoded as features
   ✓ Exploit/patch indicators from reference tags
   ✓ No duplicates, no empty descriptions
        """)


def main():
    parser = argparse.ArgumentParser(description="Clean NVD data and generate labels")
    
    parser.add_argument("--input", type=str, default="./data/nvd_complete/nvd_complete.jsonl",
                       help="Input JSONL file")
    parser.add_argument("--output", type=str, default="./data/clean_v3",
                       help="Output directory")
    parser.add_argument("--seed", type=int, default=42,
                       help="Random seed for reproducibility")
    
    args = parser.parse_args()
    
    random.seed(args.seed)
    
    cleaner = DataCleanerAndLabeler(args.input, args.output)
    cleaner.run()


if __name__ == "__main__":
    main()
