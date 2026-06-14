#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CTPPO v2.0 - Full Dataset Loader and Trainer
=============================================

Loads ALL fetched CVE data and runs the complete training pipeline.

Usage:
    # Step 1: Fetch all CVEs first
    python ml/fetch_all_cves.py --api-key YOUR_KEY
    
    # Step 2: Train on full dataset
    python ml/train_full_dataset.py
    
    # Or train on a subset for testing
    python ml/train_full_dataset.py --max-samples 10000

Author: Ruthvik
Date: January 2026
"""

import os
import sys
import json
import logging
import argparse
from pathlib import Path
from collections import Counter
from datetime import datetime
from typing import List, Dict, Optional, Tuple
import numpy as np
import pandas as pd

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class FullDatasetLoader:
    """
    Loads the complete CVE dataset from JSON Lines file.
    """
    
    def __init__(self, data_dir: Path = Path("./data/nvd_full")):
        """
        Initialize loader.
        
        Args:
            data_dir: Directory containing fetched CVE data
        """
        self.data_dir = Path(data_dir)
        self.data_file = self.data_dir / "all_cves.jsonl"
        self.stats_file = self.data_dir / "fetch_stats.json"
        
        if not self.data_file.exists():
            raise FileNotFoundError(
                f"Data file not found: {self.data_file}\n"
                f"Run 'python ml/fetch_all_cves.py' first to download CVE data."
            )
    
    def get_stats(self) -> Dict:
        """Get dataset statistics."""
        if self.stats_file.exists():
            with open(self.stats_file, 'r') as f:
                return json.load(f)
        return {}
    
    def count_records(self) -> int:
        """Count total records without loading all data."""
        count = 0
        with open(self.data_file, 'r') as f:
            for _ in f:
                count += 1
        return count
    
    def load_all(
        self,
        max_samples: Optional[int] = None,
        filter_unknown: bool = True,
        require_cvss: bool = True,
        min_description_length: int = 20
    ) -> List[Dict]:
        """
        Load all CVE records from file.
        
        Args:
            max_samples: Maximum samples to load (None = all)
            filter_unknown: Remove records with UNKNOWN severity
            require_cvss: Only include records with CVSS scores
            min_description_length: Minimum description length
            
        Returns:
            List of CVE records
        """
        records = []
        skipped = {"unknown": 0, "no_cvss": 0, "short_desc": 0}
        
        logger.info(f"Loading data from {self.data_file}")
        
        with open(self.data_file, 'r') as f:
            for line in f:
                if max_samples and len(records) >= max_samples:
                    break
                
                record = json.loads(line)
                
                # Filter checks
                if filter_unknown and record.get("severity") == "UNKNOWN":
                    skipped["unknown"] += 1
                    continue
                
                if require_cvss and record.get("cvss_score") is None:
                    skipped["no_cvss"] += 1
                    continue
                
                desc = record.get("description", "")
                if len(desc) < min_description_length:
                    skipped["short_desc"] += 1
                    continue
                
                records.append(record)
        
        logger.info(f"Loaded {len(records):,} records")
        logger.info(f"Skipped - Unknown severity: {skipped['unknown']:,}")
        logger.info(f"Skipped - No CVSS score: {skipped['no_cvss']:,}")
        logger.info(f"Skipped - Short description: {skipped['short_desc']:,}")
        
        return records
    
    def load_balanced(
        self,
        samples_per_class: int = 10000,
        classes: List[str] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    ) -> List[Dict]:
        """
        Load a balanced dataset with equal samples per class.
        
        Args:
            samples_per_class: Number of samples per severity class
            classes: Severity classes to include
            
        Returns:
            Balanced list of CVE records
        """
        # Collect samples per class
        class_samples = {cls: [] for cls in classes}
        
        logger.info(f"Loading balanced dataset: {samples_per_class} per class")
        
        with open(self.data_file, 'r') as f:
            for line in f:
                # Check if we have enough samples
                if all(len(samples) >= samples_per_class for samples in class_samples.values()):
                    break
                
                record = json.loads(line)
                severity = record.get("severity")
                
                if severity in classes:
                    if len(class_samples[severity]) < samples_per_class:
                        # Basic validation
                        if record.get("cvss_score") is not None and len(record.get("description", "")) >= 20:
                            class_samples[severity].append(record)
        
        # Combine all samples
        records = []
        for cls, samples in class_samples.items():
            logger.info(f"  {cls}: {len(samples)} samples")
            records.extend(samples)
        
        # Shuffle
        np.random.seed(42)
        np.random.shuffle(records)
        
        logger.info(f"Total balanced samples: {len(records):,}")
        return records
    
    def analyze_distribution(self) -> Dict:
        """Analyze severity distribution of full dataset."""
        severity_counts = Counter()
        cvss_scores = []
        years = Counter()
        
        with open(self.data_file, 'r') as f:
            for line in f:
                record = json.loads(line)
                severity_counts[record.get("severity", "UNKNOWN")] += 1
                
                if record.get("cvss_score"):
                    cvss_scores.append(record["cvss_score"])
                
                pub_date = record.get("published_date")
                if pub_date:
                    try:
                        year = pub_date[:4]
                        years[year] += 1
                    except:
                        pass
        
        return {
            "total": sum(severity_counts.values()),
            "severity_distribution": dict(severity_counts),
            "cvss_stats": {
                "count": len(cvss_scores),
                "mean": np.mean(cvss_scores) if cvss_scores else 0,
                "std": np.std(cvss_scores) if cvss_scores else 0,
                "min": min(cvss_scores) if cvss_scores else 0,
                "max": max(cvss_scores) if cvss_scores else 0
            },
            "records_by_year": dict(sorted(years.items()))
        }


def prepare_for_training(
    records: List[Dict],
    test_size: float = 0.15,
    val_size: float = 0.15
) -> Dict:
    """
    Prepare loaded records for training pipeline.
    
    Args:
        records: List of CVE records
        test_size: Fraction for test set
        val_size: Fraction for validation set
        
    Returns:
        Dictionary with train/val/test splits
    """
    from sklearn.model_selection import train_test_split
    
    # Extract texts and labels
    texts = [r["description"] for r in records]
    labels = [r["severity"] for r in records]
    
    # Create indices
    indices = list(range(len(records)))
    
    # Stratified split
    logger.info("Performing stratified split...")
    
    # First split: separate test set
    train_val_idx, test_idx, train_val_labels, test_labels = train_test_split(
        indices, labels,
        test_size=test_size,
        stratify=labels,
        random_state=42
    )
    
    # Second split: separate validation from training
    val_fraction = val_size / (1 - test_size)
    train_idx, val_idx, train_labels, val_labels = train_test_split(
        train_val_idx, train_val_labels,
        test_size=val_fraction,
        stratify=train_val_labels,
        random_state=42
    )
    
    # Prepare data dictionaries
    train_data = {
        "records": [records[i] for i in train_idx],
        "texts": [texts[i] for i in train_idx],
        "labels": train_labels
    }
    
    val_data = {
        "records": [records[i] for i in val_idx],
        "texts": [texts[i] for i in val_idx],
        "labels": val_labels
    }
    
    test_data = {
        "records": [records[i] for i in test_idx],
        "texts": [texts[i] for i in test_idx],
        "labels": test_labels
    }
    
    # Log distribution
    logger.info(f"Train: {len(train_data['texts']):,} samples")
    logger.info(f"  Distribution: {dict(Counter(train_labels))}")
    logger.info(f"Val: {len(val_data['texts']):,} samples")
    logger.info(f"  Distribution: {dict(Counter(val_labels))}")
    logger.info(f"Test: {len(test_data['texts']):,} samples")
    logger.info(f"  Distribution: {dict(Counter(test_labels))}")
    
    return {
        "train": train_data,
        "val": val_data,
        "test": test_data,
        "label_map": {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    }


def compute_class_weights(labels: List[str]) -> Dict[str, float]:
    """Compute class weights for imbalanced data."""
    counts = Counter(labels)
    total = len(labels)
    n_classes = len(counts)
    
    weights = {}
    for label, count in counts.items():
        weights[label] = total / (n_classes * count)
    
    return weights


def main():
    parser = argparse.ArgumentParser(description="Load and prepare full CVE dataset")
    parser.add_argument("--data-dir", type=str, default="./data/nvd_full",
                       help="Directory containing fetched CVE data")
    parser.add_argument("--max-samples", type=int, default=None,
                       help="Maximum samples to load (None = all)")
    parser.add_argument("--balanced", action="store_true",
                       help="Load balanced dataset")
    parser.add_argument("--samples-per-class", type=int, default=10000,
                       help="Samples per class for balanced loading")
    parser.add_argument("--analyze", action="store_true",
                       help="Just analyze distribution, don't load")
    parser.add_argument("--output-dir", type=str, default="./data/prepared",
                       help="Directory to save prepared data")
    
    args = parser.parse_args()
    
    try:
        loader = FullDatasetLoader(Path(args.data_dir))
    except FileNotFoundError as e:
        print(f"\nError: {e}")
        print("\nTo fetch CVE data, run:")
        print("  python ml/fetch_all_cves.py --api-key YOUR_API_KEY")
        print("\nGet a free API key at: https://nvd.nist.gov/developers/request-an-api-key")
        sys.exit(1)
    
    if args.analyze:
        # Just analyze distribution
        logger.info("Analyzing full dataset distribution...")
        stats = loader.analyze_distribution()
        
        print("\n" + "="*60)
        print("DATASET ANALYSIS")
        print("="*60)
        print(f"\nTotal records: {stats['total']:,}")
        
        print("\nSeverity Distribution:")
        for sev, count in sorted(stats['severity_distribution'].items()):
            pct = 100 * count / stats['total']
            bar = "█" * int(pct / 2)
            print(f"  {sev:<10}: {count:>8,} ({pct:>5.1f}%) {bar}")
        
        print(f"\nCVSS Score Statistics:")
        cvss = stats['cvss_stats']
        print(f"  Mean: {cvss['mean']:.2f}")
        print(f"  Std:  {cvss['std']:.2f}")
        print(f"  Min:  {cvss['min']:.1f}")
        print(f"  Max:  {cvss['max']:.1f}")
        
        print(f"\nRecords by Year (recent):")
        years = stats['records_by_year']
        for year in sorted(years.keys())[-10:]:
            print(f"  {year}: {years[year]:,}")
        
        return
    
    # Load data
    if args.balanced:
        records = loader.load_balanced(samples_per_class=args.samples_per_class)
    else:
        records = loader.load_all(max_samples=args.max_samples)
    
    if not records:
        print("No records loaded!")
        sys.exit(1)
    
    # Prepare for training
    prepared = prepare_for_training(records)
    
    # Compute class weights
    weights = compute_class_weights(prepared["train"]["labels"])
    prepared["class_weights"] = weights
    logger.info(f"Class weights: {weights}")
    
    # Save prepared data
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Save as JSON for inspection
    summary = {
        "train_samples": len(prepared["train"]["texts"]),
        "val_samples": len(prepared["val"]["texts"]),
        "test_samples": len(prepared["test"]["texts"]),
        "train_distribution": dict(Counter(prepared["train"]["labels"])),
        "val_distribution": dict(Counter(prepared["val"]["labels"])),
        "test_distribution": dict(Counter(prepared["test"]["labels"])),
        "class_weights": weights,
        "label_map": prepared["label_map"],
        "created_at": datetime.now().isoformat()
    }
    
    with open(output_dir / "dataset_summary.json", 'w') as f:
        json.dump(summary, f, indent=2)
    
    # Save train/val/test as JSON Lines
    for split_name in ["train", "val", "test"]:
        output_file = output_dir / f"{split_name}.jsonl"
        with open(output_file, 'w') as f:
            for record in prepared[split_name]["records"]:
                f.write(json.dumps(record) + '\n')
        logger.info(f"Saved {split_name} to {output_file}")
    
    print("\n" + "="*60)
    print("DATASET PREPARED SUCCESSFULLY")
    print("="*60)
    print(f"\nOutput directory: {output_dir}")
    print(f"Train samples: {summary['train_samples']:,}")
    print(f"Val samples: {summary['val_samples']:,}")
    print(f"Test samples: {summary['test_samples']:,}")
    print("\nNext step: Run training with:")
    print(f"  python ml/training_pipeline.py --data-dir {output_dir}")


if __name__ == "__main__":
    main()
