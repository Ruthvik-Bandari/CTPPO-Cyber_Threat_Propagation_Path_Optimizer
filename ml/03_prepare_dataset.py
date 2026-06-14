#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CTPPO v2.0 - Step 3: Prepare Dataset
=====================================

Creates train/val/test splits with:
1. Stratified sampling (maintains class distribution)
2. Class distribution analysis
3. Class imbalance handling options
4. Dataset statistics

Run AFTER: 02_preprocess_data.py
Run BEFORE: 04_train_model.py

Usage:
    python ml/03_prepare_dataset.py
    python ml/03_prepare_dataset.py --input data/cleaned/cleaned_cves.jsonl
    python ml/03_prepare_dataset.py --train-ratio 0.8 --val-ratio 0.1

Author: Ruthvik
Date: January 2026
"""

import os
import sys
import json
import logging
import numpy as np
from pathlib import Path
from collections import Counter
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class DatasetPreparer:
    """
    Prepare train/val/test datasets with stratified sampling.
    
    Handles:
    - Stratified splits (maintain class distribution)
    - Class imbalance analysis
    - Dataset statistics
    """
    
    # Severity order for consistent reporting
    SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE']
    
    # Label to integer mapping
    LABEL_MAP = {
        'CRITICAL': 0,
        'HIGH': 1,
        'MEDIUM': 2,
        'LOW': 3,
        'NONE': 4
    }
    
    def __init__(
        self,
        train_ratio: float = 0.8,
        val_ratio: float = 0.1,
        test_ratio: float = 0.1,
        random_seed: int = 42
    ):
        """
        Initialize dataset preparer.
        
        Args:
            train_ratio: Proportion for training (default 0.8)
            val_ratio: Proportion for validation (default 0.1)
            test_ratio: Proportion for testing (default 0.1)
            random_seed: Random seed for reproducibility
        """
        assert abs(train_ratio + val_ratio + test_ratio - 1.0) < 0.001, \
            "Ratios must sum to 1.0"
        
        self.train_ratio = train_ratio
        self.val_ratio = val_ratio
        self.test_ratio = test_ratio
        self.random_seed = random_seed
        
        np.random.seed(random_seed)
    
    def load_data(self, input_path: str) -> List[Dict]:
        """Load preprocessed data."""
        logger.info(f"Loading data from {input_path}...")
        
        records = []
        with open(input_path, 'r') as f:
            for line in f:
                records.append(json.loads(line))
        
        logger.info(f"Loaded {len(records):,} records")
        return records
    
    def stratified_split(
        self,
        records: List[Dict]
    ) -> Tuple[List[Dict], List[Dict], List[Dict]]:
        """
        Perform stratified train/val/test split.
        
        Stratified = each split has same class distribution as original.
        
        Args:
            records: List of records to split
            
        Returns:
            Tuple of (train, val, test) record lists
        """
        logger.info("Performing stratified split...")
        
        # Group by severity
        by_severity = {}
        for record in records:
            severity = record.get('severity', 'UNKNOWN')
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(record)
        
        train_records = []
        val_records = []
        test_records = []
        
        # Split each class separately
        for severity, class_records in by_severity.items():
            # Shuffle within class
            indices = np.random.permutation(len(class_records))
            shuffled = [class_records[i] for i in indices]
            
            # Calculate split points
            n = len(shuffled)
            train_end = int(n * self.train_ratio)
            val_end = int(n * (self.train_ratio + self.val_ratio))
            
            # Split
            train_records.extend(shuffled[:train_end])
            val_records.extend(shuffled[train_end:val_end])
            test_records.extend(shuffled[val_end:])
        
        # Final shuffle of each set
        train_records = [train_records[i] for i in np.random.permutation(len(train_records))]
        val_records = [val_records[i] for i in np.random.permutation(len(val_records))]
        test_records = [test_records[i] for i in np.random.permutation(len(test_records))]
        
        logger.info(f"Train: {len(train_records):,}, Val: {len(val_records):,}, Test: {len(test_records):,}")
        
        return train_records, val_records, test_records
    
    def calculate_class_weights(self, records: List[Dict]) -> Dict[str, float]:
        """
        Calculate class weights for handling imbalance.
        
        Uses inverse frequency: weight = total / (n_classes * class_count)
        
        Args:
            records: Training records
            
        Returns:
            Dictionary of severity -> weight
        """
        counts = Counter(r.get('severity') for r in records)
        total = sum(counts.values())
        n_classes = len(counts)
        
        weights = {}
        for severity, count in counts.items():
            # Inverse frequency weighting
            weights[severity] = total / (n_classes * count)
        
        # Normalize so minimum weight = 1.0
        min_weight = min(weights.values())
        weights = {k: v / min_weight for k, v in weights.items()}
        
        return weights
    
    def get_distribution(self, records: List[Dict]) -> Dict[str, Dict]:
        """Get class distribution statistics."""
        counts = Counter(r.get('severity') for r in records)
        total = len(records)
        
        distribution = {}
        for severity in self.SEVERITY_ORDER:
            if severity in counts:
                distribution[severity] = {
                    'count': counts[severity],
                    'percentage': round(100 * counts[severity] / total, 2)
                }
        
        return distribution
    
    def save_datasets(
        self,
        train: List[Dict],
        val: List[Dict],
        test: List[Dict],
        output_dir: str
    ) -> Dict[str, str]:
        """
        Save datasets to files.
        
        Creates:
        - train.jsonl
        - val.jsonl  
        - test.jsonl
        - label_map.json
        - class_weights.json
        - dataset_stats.json
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        paths = {}
        
        # Save data splits
        for name, data in [('train', train), ('val', val), ('test', test)]:
            path = output_dir / f'{name}.jsonl'
            with open(path, 'w') as f:
                for record in data:
                    f.write(json.dumps(record) + '\n')
            paths[name] = str(path)
            logger.info(f"Saved {name}: {len(data):,} records to {path}")
        
        # Save label map
        label_map_path = output_dir / 'label_map.json'
        with open(label_map_path, 'w') as f:
            json.dump(self.LABEL_MAP, f, indent=2)
        paths['label_map'] = str(label_map_path)
        
        # Calculate and save class weights
        class_weights = self.calculate_class_weights(train)
        weights_path = output_dir / 'class_weights.json'
        with open(weights_path, 'w') as f:
            json.dump(class_weights, f, indent=2)
        paths['class_weights'] = str(weights_path)
        
        # Save comprehensive statistics
        stats = {
            'timestamp': datetime.now().isoformat(),
            'random_seed': self.random_seed,
            'split_ratios': {
                'train': self.train_ratio,
                'val': self.val_ratio,
                'test': self.test_ratio
            },
            'sizes': {
                'train': len(train),
                'val': len(val),
                'test': len(test),
                'total': len(train) + len(val) + len(test)
            },
            'distributions': {
                'train': self.get_distribution(train),
                'val': self.get_distribution(val),
                'test': self.get_distribution(test)
            },
            'class_weights': class_weights,
            'label_map': self.LABEL_MAP,
            'files': paths
        }
        
        stats_path = output_dir / 'dataset_stats.json'
        with open(stats_path, 'w') as f:
            json.dump(stats, f, indent=2)
        paths['stats'] = str(stats_path)
        
        return paths
    
    def prepare(
        self,
        input_path: str,
        output_dir: str
    ) -> Dict[str, Any]:
        """
        Full preparation pipeline.
        
        Args:
            input_path: Path to cleaned data
            output_dir: Output directory for datasets
            
        Returns:
            Statistics dictionary
        """
        # Load
        records = self.load_data(input_path)
        
        # Split
        train, val, test = self.stratified_split(records)
        
        # Save
        paths = self.save_datasets(train, val, test, output_dir)
        
        # Compile stats
        stats = {
            'input_file': input_path,
            'output_dir': output_dir,
            'total_records': len(records),
            'splits': {
                'train': len(train),
                'val': len(val),
                'test': len(test)
            },
            'distributions': {
                'train': self.get_distribution(train),
                'val': self.get_distribution(val),
                'test': self.get_distribution(test)
            },
            'class_weights': self.calculate_class_weights(train),
            'files': paths
        }
        
        return stats
    
    def print_report(self, stats: Dict[str, Any]):
        """Print preparation report."""
        
        print("""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                     DATASET PREPARATION REPORT                                ║
║                  Step 3: Create Train/Val/Test Splits                         ║
╚═══════════════════════════════════════════════════════════════════════════════╝
        """)
        
        # Overview
        print("="*80)
        print("1. DATASET SIZES")
        print("="*80)
        
        splits = stats.get('splits', {})
        total = stats.get('total_records', 0)
        
        print(f"\n   📊 Total Records: {total:,}")
        print(f"\n   📁 Splits:")
        print(f"      Train: {splits.get('train', 0):>10,} ({100*splits.get('train', 0)/total:.1f}%)")
        print(f"      Val:   {splits.get('val', 0):>10,} ({100*splits.get('val', 0)/total:.1f}%)")
        print(f"      Test:  {splits.get('test', 0):>10,} ({100*splits.get('test', 0)/total:.1f}%)")
        
        # Class Distribution
        print("\n" + "="*80)
        print("2. CLASS DISTRIBUTION (Stratified)")
        print("="*80)
        
        distributions = stats.get('distributions', {})
        
        print("\n   📊 Distribution by Split:")
        print(f"\n   {'Severity':<12} {'Train':>12} {'Val':>12} {'Test':>12}")
        print("   " + "-"*50)
        
        for severity in self.SEVERITY_ORDER:
            train_pct = distributions.get('train', {}).get(severity, {}).get('percentage', 0)
            val_pct = distributions.get('val', {}).get(severity, {}).get('percentage', 0)
            test_pct = distributions.get('test', {}).get(severity, {}).get('percentage', 0)
            
            if train_pct > 0 or val_pct > 0 or test_pct > 0:
                print(f"   {severity:<12} {train_pct:>11.1f}% {val_pct:>11.1f}% {test_pct:>11.1f}%")
        
        # Class Weights
        print("\n" + "="*80)
        print("3. CLASS WEIGHTS (for Training)")
        print("="*80)
        
        weights = stats.get('class_weights', {})
        
        print("\n   ⚖️  Weights to handle imbalance:")
        for severity in self.SEVERITY_ORDER:
            if severity in weights:
                weight = weights[severity]
                bar = "█" * int(weight * 2)
                print(f"      {severity:<10}: {weight:>6.2f}x {bar}")
        
        print("""
   💡 Use these weights in training:
      - PyTorch: CrossEntropyLoss(weight=torch.tensor([...]))
      - Sklearn: class_weight='balanced' or class_weight={...}
        """)
        
        # Training Data Details
        print("\n" + "="*80)
        print("4. TRAINING DATA DETAILS")
        print("="*80)
        
        train_dist = distributions.get('train', {})
        
        print("\n   📊 Training Set Class Counts:")
        for severity in self.SEVERITY_ORDER:
            if severity in train_dist:
                count = train_dist[severity]['count']
                pct = train_dist[severity]['percentage']
                bar = "█" * int(pct / 2)
                print(f"      {severity:<10}: {count:>8,} ({pct:>5.1f}%) {bar}")
        
        # Files Created
        print("\n" + "="*80)
        print("5. FILES CREATED")
        print("="*80)
        
        files = stats.get('files', {})
        
        print(f"""
   📁 Data Files:
      {files.get('train')}
      {files.get('val')}
      {files.get('test')}
   
   📋 Metadata Files:
      {files.get('label_map')}
      {files.get('class_weights')}
      {files.get('stats')}
        """)
        
        # Summary
        print("\n" + "="*80)
        print("✅ Dataset preparation complete!")
        print("="*80)
        
        print(f"""
   🎯 Ready for training with:
      - {splits.get('train', 0):,} training samples
      - {splits.get('val', 0):,} validation samples
      - {splits.get('test', 0):,} test samples
   
   📊 Class weights calculated to handle imbalance
   
   Next Step: Run 04_train_model.py to train the classifier
        """)


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Prepare train/val/test datasets with stratified sampling",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Default preparation (80/10/10 split)
  python ml/03_prepare_dataset.py
  
  # Custom split ratios
  python ml/03_prepare_dataset.py --train-ratio 0.7 --val-ratio 0.15 --test-ratio 0.15
  
  # Custom paths
  python ml/03_prepare_dataset.py --input data/cleaned/cleaned_cves.jsonl --output data/splits
        """
    )
    
    parser.add_argument(
        "--input", "-i",
        type=str,
        default="./data/cleaned/cleaned_cves.jsonl",
        help="Input cleaned data file"
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default="./data/splits",
        help="Output directory for datasets"
    )
    parser.add_argument(
        "--train-ratio",
        type=float,
        default=0.8,
        help="Training set ratio (default: 0.8)"
    )
    parser.add_argument(
        "--val-ratio",
        type=float,
        default=0.1,
        help="Validation set ratio (default: 0.1)"
    )
    parser.add_argument(
        "--test-ratio",
        type=float,
        default=0.1,
        help="Test set ratio (default: 0.1)"
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducibility"
    )
    
    args = parser.parse_args()
    
    # Validate ratios
    total_ratio = args.train_ratio + args.val_ratio + args.test_ratio
    if abs(total_ratio - 1.0) > 0.001:
        logger.error(f"Split ratios must sum to 1.0, got {total_ratio}")
        sys.exit(1)
    
    # Create preparer
    preparer = DatasetPreparer(
        train_ratio=args.train_ratio,
        val_ratio=args.val_ratio,
        test_ratio=args.test_ratio,
        random_seed=args.seed
    )
    
    # Prepare
    try:
        stats = preparer.prepare(
            input_path=args.input,
            output_dir=args.output
        )
        
        # Print report
        preparer.print_report(stats)
        
    except FileNotFoundError as e:
        logger.error(f"File not found: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error: {e}")
        raise


if __name__ == "__main__":
    main()
