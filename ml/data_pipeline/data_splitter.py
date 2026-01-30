# -*- coding: utf-8 -*-
"""
CTPPO v2.0 - Data Splitter
==========================

Proper train/validation/test splitting with:
- Stratified splitting (preserves class distribution)
- Cross-validation support
- Temporal splitting option
- Reproducibility (random seeds)
- Class balance reporting

Author: Ruthvik (Fixed by Claude)
Date: January 2026
"""

import numpy as np
import logging
from typing import List, Dict, Any, Optional, Tuple, Generator
from dataclasses import dataclass, field
from collections import Counter
from sklearn.model_selection import (
    train_test_split,
    StratifiedKFold,
    TimeSeriesSplit
)
from sklearn.utils.class_weight import compute_class_weight

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class DataSplit:
    """Container for a data split."""
    
    # Indices into the original dataset
    train_indices: np.ndarray
    val_indices: np.ndarray
    test_indices: Optional[np.ndarray] = None
    
    # Actual data (optional, populated by split methods)
    train_data: List[Any] = field(default_factory=list)
    val_data: List[Any] = field(default_factory=list)
    test_data: List[Any] = field(default_factory=list)
    
    # Labels for each split
    train_labels: np.ndarray = field(default_factory=lambda: np.array([]))
    val_labels: np.ndarray = field(default_factory=lambda: np.array([]))
    test_labels: np.ndarray = field(default_factory=lambda: np.array([]))
    
    # Metadata
    split_method: str = "stratified"
    random_state: int = 42
    
    def get_class_distribution(self) -> Dict[str, Dict[str, float]]:
        """Get class distribution for each split."""
        result = {}
        
        for name, labels in [
            ('train', self.train_labels),
            ('val', self.val_labels),
            ('test', self.test_labels)
        ]:
            if len(labels) > 0:
                counts = Counter(labels)
                total = len(labels)
                result[name] = {
                    str(k): {
                        'count': v,
                        'percentage': round(100 * v / total, 2)
                    }
                    for k, v in sorted(counts.items())
                }
        
        return result


@dataclass
class CrossValidationSplit:
    """Container for cross-validation folds."""
    
    folds: List[Tuple[np.ndarray, np.ndarray]]  # List of (train_idx, val_idx)
    n_folds: int
    split_method: str
    
    def __iter__(self) -> Generator[Tuple[np.ndarray, np.ndarray], None, None]:
        """Iterate over folds."""
        for train_idx, val_idx in self.folds:
            yield train_idx, val_idx


class DataSplitter:
    """
    Comprehensive data splitting utility.
    
    Provides:
    - Stratified train/val/test splitting
    - K-fold cross-validation
    - Temporal splitting
    - Class balance analysis
    - Class weight computation
    """
    
    def __init__(self, random_state: int = 42):
        """
        Initialize splitter.
        
        Args:
            random_state: Random seed for reproducibility
        """
        self.random_state = random_state
        np.random.seed(random_state)
    
    def stratified_split(
        self,
        data: List[Any],
        labels: np.ndarray,
        test_size: float = 0.15,
        val_size: float = 0.15,
        include_test: bool = True
    ) -> DataSplit:
        """
        Perform stratified train/val/test split.
        
        CRITICAL: This preserves class distribution across all splits,
        which is essential for imbalanced datasets like CVE severity.
        
        Args:
            data: List of data samples
            labels: Array of labels (same length as data)
            test_size: Fraction for test set (0-1)
            val_size: Fraction for validation set (0-1)
            include_test: Whether to create a test set
            
        Returns:
            DataSplit object with indices and data
        """
        if len(data) != len(labels):
            raise ValueError(f"Data ({len(data)}) and labels ({len(labels)}) must have same length")
        
        labels = np.array(labels)
        indices = np.arange(len(data))
        
        if include_test:
            # First split: separate test set
            train_val_idx, test_idx = train_test_split(
                indices,
                test_size=test_size,
                stratify=labels,
                random_state=self.random_state
            )
            train_val_labels = labels[train_val_idx]
            
            # Second split: separate validation from training
            # Adjust val_size to account for removed test data
            adjusted_val_size = val_size / (1 - test_size)
            train_idx, val_idx = train_test_split(
                train_val_idx,
                test_size=adjusted_val_size,
                stratify=train_val_labels,
                random_state=self.random_state
            )
        else:
            # Just train/val split
            train_idx, val_idx = train_test_split(
                indices,
                test_size=val_size,
                stratify=labels,
                random_state=self.random_state
            )
            test_idx = np.array([], dtype=int)
        
        # Extract data for each split
        train_data = [data[i] for i in train_idx]
        val_data = [data[i] for i in val_idx]
        test_data = [data[i] for i in test_idx] if len(test_idx) > 0 else []
        
        split = DataSplit(
            train_indices=train_idx,
            val_indices=val_idx,
            test_indices=test_idx if len(test_idx) > 0 else None,
            train_data=train_data,
            val_data=val_data,
            test_data=test_data,
            train_labels=labels[train_idx],
            val_labels=labels[val_idx],
            test_labels=labels[test_idx] if len(test_idx) > 0 else np.array([]),
            split_method="stratified",
            random_state=self.random_state
        )
        
        # Log split info
        logger.info(f"Stratified Split Results:")
        logger.info(f"  Train: {len(train_idx)} samples ({100*len(train_idx)/len(data):.1f}%)")
        logger.info(f"  Val:   {len(val_idx)} samples ({100*len(val_idx)/len(data):.1f}%)")
        if include_test:
            logger.info(f"  Test:  {len(test_idx)} samples ({100*len(test_idx)/len(data):.1f}%)")
        
        # Log class distribution
        dist = split.get_class_distribution()
        logger.info(f"Class Distribution:")
        for split_name, classes in dist.items():
            logger.info(f"  {split_name}: {classes}")
        
        return split
    
    def stratified_kfold(
        self,
        labels: np.ndarray,
        n_folds: int = 5,
        shuffle: bool = True
    ) -> CrossValidationSplit:
        """
        Create stratified K-fold cross-validation splits.
        
        Args:
            labels: Array of labels
            n_folds: Number of folds
            shuffle: Whether to shuffle before splitting
            
        Returns:
            CrossValidationSplit object with fold indices
        """
        skf = StratifiedKFold(
            n_splits=n_folds,
            shuffle=shuffle,
            random_state=self.random_state if shuffle else None
        )
        
        folds = list(skf.split(np.zeros(len(labels)), labels))
        
        logger.info(f"Created {n_folds}-fold stratified cross-validation")
        
        return CrossValidationSplit(
            folds=folds,
            n_folds=n_folds,
            split_method="stratified_kfold"
        )
    
    def temporal_split(
        self,
        data: List[Any],
        dates: List[Any],
        labels: np.ndarray,
        test_size: float = 0.15,
        val_size: float = 0.15
    ) -> DataSplit:
        """
        Split data temporally (training on older, testing on newer).
        
        Useful when you want to simulate real-world deployment
        where model trains on historical data and predicts on new data.
        
        Args:
            data: List of data samples
            dates: List of dates for each sample
            labels: Array of labels
            test_size: Fraction for test set
            val_size: Fraction for validation set
            
        Returns:
            DataSplit object with temporally-ordered splits
        """
        # Sort by date
        sorted_indices = np.argsort(dates)
        
        n = len(data)
        n_test = int(n * test_size)
        n_val = int(n * val_size)
        n_train = n - n_test - n_val
        
        # Older data for training, newer for validation, newest for testing
        train_idx = sorted_indices[:n_train]
        val_idx = sorted_indices[n_train:n_train + n_val]
        test_idx = sorted_indices[n_train + n_val:]
        
        split = DataSplit(
            train_indices=train_idx,
            val_indices=val_idx,
            test_indices=test_idx,
            train_data=[data[i] for i in train_idx],
            val_data=[data[i] for i in val_idx],
            test_data=[data[i] for i in test_idx],
            train_labels=labels[train_idx],
            val_labels=labels[val_idx],
            test_labels=labels[test_idx],
            split_method="temporal",
            random_state=self.random_state
        )
        
        logger.info(f"Temporal Split Results:")
        logger.info(f"  Train (oldest): {len(train_idx)} samples")
        logger.info(f"  Val (middle):   {len(val_idx)} samples")
        logger.info(f"  Test (newest):  {len(test_idx)} samples")
        
        return split
    
    @staticmethod
    def compute_class_weights(
        labels: np.ndarray,
        method: str = 'balanced'
    ) -> Dict[int, float]:
        """
        Compute class weights for handling imbalance.
        
        Args:
            labels: Array of labels
            method: 'balanced' or 'sqrt' (square root balanced)
            
        Returns:
            Dictionary mapping class labels to weights
        """
        classes = np.unique(labels)
        
        if method == 'balanced':
            weights = compute_class_weight(
                'balanced',
                classes=classes,
                y=labels
            )
        elif method == 'sqrt':
            # Square root balanced - less aggressive
            balanced_weights = compute_class_weight(
                'balanced',
                classes=classes,
                y=labels
            )
            weights = np.sqrt(balanced_weights)
        else:
            raise ValueError(f"Unknown method: {method}")
        
        weight_dict = {cls: w for cls, w in zip(classes, weights)}
        
        logger.info(f"Class Weights ({method}):")
        for cls, w in sorted(weight_dict.items()):
            logger.info(f"  Class {cls}: {w:.4f}")
        
        return weight_dict
    
    @staticmethod
    def get_class_distribution(labels: np.ndarray) -> Dict[str, Any]:
        """
        Analyze class distribution.
        
        Args:
            labels: Array of labels
            
        Returns:
            Distribution statistics
        """
        counts = Counter(labels)
        total = len(labels)
        
        distribution = {}
        for cls, count in sorted(counts.items()):
            distribution[str(cls)] = {
                'count': count,
                'percentage': round(100 * count / total, 2),
                'ratio_to_max': round(count / max(counts.values()), 4)
            }
        
        # Compute imbalance ratio
        max_count = max(counts.values())
        min_count = min(counts.values())
        imbalance_ratio = max_count / min_count if min_count > 0 else float('inf')
        
        return {
            'distribution': distribution,
            'n_classes': len(counts),
            'total_samples': total,
            'imbalance_ratio': round(imbalance_ratio, 2),
            'is_imbalanced': imbalance_ratio > 3
        }
    
    @staticmethod
    def validate_split(
        train_labels: np.ndarray,
        val_labels: np.ndarray,
        test_labels: Optional[np.ndarray] = None
    ) -> Dict[str, Any]:
        """
        Validate that splits maintain class distribution.
        
        Args:
            train_labels: Training set labels
            val_labels: Validation set labels
            test_labels: Test set labels (optional)
            
        Returns:
            Validation results
        """
        def get_dist(labels):
            counts = Counter(labels)
            total = len(labels)
            return {k: count/total for k, count in counts.items()}
        
        train_dist = get_dist(train_labels)
        val_dist = get_dist(val_labels)
        
        # Compare distributions
        max_deviation = 0
        deviations = {}
        
        for cls in train_dist:
            if cls in val_dist:
                dev = abs(train_dist[cls] - val_dist[cls])
                deviations[cls] = round(dev, 4)
                max_deviation = max(max_deviation, dev)
        
        result = {
            'train_distribution': train_dist,
            'val_distribution': val_dist,
            'deviations': deviations,
            'max_deviation': round(max_deviation, 4),
            'is_valid': max_deviation < 0.05  # Less than 5% deviation
        }
        
        if test_labels is not None and len(test_labels) > 0:
            test_dist = get_dist(test_labels)
            result['test_distribution'] = test_dist
        
        return result


# Example usage
if __name__ == "__main__":
    # Create sample data
    np.random.seed(42)
    
    n_samples = 1000
    
    # Simulate imbalanced dataset
    # CRITICAL: 5%, HIGH: 20%, MEDIUM: 50%, LOW: 25%
    labels = np.concatenate([
        np.full(50, 3),    # CRITICAL
        np.full(200, 2),   # HIGH
        np.full(500, 1),   # MEDIUM
        np.full(250, 0)    # LOW
    ])
    np.random.shuffle(labels)
    
    data = [f"sample_{i}" for i in range(n_samples)]
    
    # Initialize splitter
    splitter = DataSplitter(random_state=42)
    
    # Analyze original distribution
    print("Original Data Distribution:")
    dist = splitter.get_class_distribution(labels)
    print(f"  Total samples: {dist['total_samples']}")
    print(f"  Imbalance ratio: {dist['imbalance_ratio']}")
    for cls, info in dist['distribution'].items():
        print(f"  Class {cls}: {info['count']} ({info['percentage']}%)")
    
    # Stratified split
    print("\n" + "="*50)
    print("Stratified Split:")
    split = splitter.stratified_split(data, labels, test_size=0.15, val_size=0.15)
    
    # Validate split
    print("\nSplit Validation:")
    validation = splitter.validate_split(
        split.train_labels,
        split.val_labels,
        split.test_labels
    )
    print(f"  Max deviation: {validation['max_deviation']}")
    print(f"  Valid split: {validation['is_valid']}")
    
    # Compute class weights
    print("\n" + "="*50)
    print("Class Weights:")
    weights = splitter.compute_class_weights(split.train_labels)
    
    # K-fold cross-validation
    print("\n" + "="*50)
    print("5-Fold Cross-Validation:")
    cv_splits = splitter.stratified_kfold(labels, n_folds=5)
    for fold_idx, (train_idx, val_idx) in enumerate(cv_splits):
        print(f"  Fold {fold_idx + 1}: Train={len(train_idx)}, Val={len(val_idx)}")
