#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CTPPO v2.0 - Feature Scaler
============================

Feature scaling is CRITICAL for neural network performance!

Why Scaling Matters:
- Neural networks learn through gradient descent
- Large feature values → large gradients → unstable training
- Different scales → some features dominate others
- Properly scaled features → faster convergence, better results

Scaling Methods:
1. StandardScaler: Mean=0, Std=1 (for normally distributed data)
2. MinMaxScaler: Range [0, 1] (for bounded data)
3. RobustScaler: Uses median/IQR (robust to outliers)

Author: Ruthvik
Date: January 2026
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
import json
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class ScalerStats:
    """Statistics for a single feature."""
    feature_name: str
    method: str  # 'standard', 'minmax', 'robust'
    
    # For StandardScaler
    mean: Optional[float] = None
    std: Optional[float] = None
    
    # For MinMaxScaler
    min_val: Optional[float] = None
    max_val: Optional[float] = None
    
    # For RobustScaler
    median: Optional[float] = None
    q1: Optional[float] = None
    q3: Optional[float] = None
    iqr: Optional[float] = None


class FeatureScaler:
    """
    Scales numerical features for neural network training.
    
    IMPORTANT: 
    - Fit ONLY on training data
    - Transform train, val, and test with same stats
    - This prevents data leakage!
    """
    
    def __init__(self, method: str = 'standard'):
        """
        Initialize scaler.
        
        Args:
            method: 'standard', 'minmax', or 'robust'
        """
        if method not in ['standard', 'minmax', 'robust']:
            raise ValueError(f"Unknown method: {method}. Use 'standard', 'minmax', or 'robust'")
        
        self.method = method
        self.stats: Dict[str, ScalerStats] = {}
        self.is_fitted = False
    
    def fit(self, X: np.ndarray, feature_names: Optional[List[str]] = None) -> 'FeatureScaler':
        """
        Compute scaling statistics from training data.
        
        IMPORTANT: Only call this on TRAINING data!
        
        Args:
            X: Feature matrix of shape (n_samples, n_features)
            feature_names: Names of features (optional)
            
        Returns:
            self
        """
        if X.ndim == 1:
            X = X.reshape(-1, 1)
        
        n_features = X.shape[1]
        
        if feature_names is None:
            feature_names = [f"feature_{i}" for i in range(n_features)]
        
        if len(feature_names) != n_features:
            raise ValueError(f"feature_names length ({len(feature_names)}) != number of features ({n_features})")
        
        logger.info(f"Fitting {self.method} scaler on {X.shape[0]} samples, {n_features} features")
        
        self.stats = {}
        
        for i, name in enumerate(feature_names):
            col = X[:, i]
            
            # Remove NaN for statistics computation
            col_clean = col[~np.isnan(col)]
            
            if len(col_clean) == 0:
                logger.warning(f"Feature '{name}' has all NaN values, skipping")
                continue
            
            stats = ScalerStats(feature_name=name, method=self.method)
            
            if self.method == 'standard':
                stats.mean = float(np.mean(col_clean))
                stats.std = float(np.std(col_clean))
                # Prevent division by zero
                if stats.std == 0:
                    stats.std = 1.0
                    logger.warning(f"Feature '{name}' has zero std, setting to 1.0")
            
            elif self.method == 'minmax':
                stats.min_val = float(np.min(col_clean))
                stats.max_val = float(np.max(col_clean))
                # Prevent division by zero
                if stats.max_val == stats.min_val:
                    stats.max_val = stats.min_val + 1.0
                    logger.warning(f"Feature '{name}' has zero range, setting range to 1.0")
            
            elif self.method == 'robust':
                stats.median = float(np.median(col_clean))
                stats.q1 = float(np.percentile(col_clean, 25))
                stats.q3 = float(np.percentile(col_clean, 75))
                stats.iqr = stats.q3 - stats.q1
                # Prevent division by zero
                if stats.iqr == 0:
                    stats.iqr = 1.0
                    logger.warning(f"Feature '{name}' has zero IQR, setting to 1.0")
            
            self.stats[name] = stats
        
        self.is_fitted = True
        logger.info(f"Fitted scaler for {len(self.stats)} features")
        
        return self
    
    def transform(self, X: np.ndarray, feature_names: Optional[List[str]] = None) -> np.ndarray:
        """
        Transform features using fitted statistics.
        
        Args:
            X: Feature matrix of shape (n_samples, n_features)
            feature_names: Names of features (must match fit)
            
        Returns:
            Scaled feature matrix
        """
        if not self.is_fitted:
            raise RuntimeError("Scaler not fitted! Call fit() first on training data.")
        
        if X.ndim == 1:
            X = X.reshape(-1, 1)
        
        n_features = X.shape[1]
        
        if feature_names is None:
            feature_names = [f"feature_{i}" for i in range(n_features)]
        
        X_scaled = np.zeros_like(X, dtype=np.float32)
        
        for i, name in enumerate(feature_names):
            col = X[:, i]
            
            if name not in self.stats:
                logger.warning(f"Feature '{name}' not in fitted stats, passing through unchanged")
                X_scaled[:, i] = col
                continue
            
            stats = self.stats[name]
            
            if self.method == 'standard':
                # X_new = (X - mean) / std
                X_scaled[:, i] = (col - stats.mean) / stats.std
            
            elif self.method == 'minmax':
                # X_new = (X - min) / (max - min)
                X_scaled[:, i] = (col - stats.min_val) / (stats.max_val - stats.min_val)
            
            elif self.method == 'robust':
                # X_new = (X - median) / IQR
                X_scaled[:, i] = (col - stats.median) / stats.iqr
        
        # Handle NaN values (set to 0 after scaling)
        X_scaled = np.nan_to_num(X_scaled, nan=0.0)
        
        return X_scaled
    
    def fit_transform(self, X: np.ndarray, feature_names: Optional[List[str]] = None) -> np.ndarray:
        """
        Fit and transform in one step.
        
        Args:
            X: Feature matrix
            feature_names: Feature names
            
        Returns:
            Scaled feature matrix
        """
        self.fit(X, feature_names)
        return self.transform(X, feature_names)
    
    def inverse_transform(self, X_scaled: np.ndarray, feature_names: Optional[List[str]] = None) -> np.ndarray:
        """
        Convert scaled features back to original scale.
        
        Args:
            X_scaled: Scaled feature matrix
            feature_names: Feature names
            
        Returns:
            Original scale feature matrix
        """
        if not self.is_fitted:
            raise RuntimeError("Scaler not fitted!")
        
        if X_scaled.ndim == 1:
            X_scaled = X_scaled.reshape(-1, 1)
        
        n_features = X_scaled.shape[1]
        
        if feature_names is None:
            feature_names = [f"feature_{i}" for i in range(n_features)]
        
        X_original = np.zeros_like(X_scaled, dtype=np.float32)
        
        for i, name in enumerate(feature_names):
            col = X_scaled[:, i]
            
            if name not in self.stats:
                X_original[:, i] = col
                continue
            
            stats = self.stats[name]
            
            if self.method == 'standard':
                X_original[:, i] = col * stats.std + stats.mean
            
            elif self.method == 'minmax':
                X_original[:, i] = col * (stats.max_val - stats.min_val) + stats.min_val
            
            elif self.method == 'robust':
                X_original[:, i] = col * stats.iqr + stats.median
        
        return X_original
    
    def save(self, path: Path):
        """Save scaler statistics to JSON."""
        path = Path(path)
        
        data = {
            'method': self.method,
            'is_fitted': self.is_fitted,
            'stats': {name: asdict(stats) for name, stats in self.stats.items()}
        }
        
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"Saved scaler to {path}")
    
    @classmethod
    def load(cls, path: Path) -> 'FeatureScaler':
        """Load scaler from JSON."""
        path = Path(path)
        
        with open(path, 'r') as f:
            data = json.load(f)
        
        scaler = cls(method=data['method'])
        scaler.is_fitted = data['is_fitted']
        scaler.stats = {
            name: ScalerStats(**stats_dict) 
            for name, stats_dict in data['stats'].items()
        }
        
        logger.info(f"Loaded scaler from {path}")
        return scaler
    
    def get_feature_stats_df(self) -> pd.DataFrame:
        """Get statistics as a DataFrame for inspection."""
        if not self.is_fitted:
            raise RuntimeError("Scaler not fitted!")
        
        rows = []
        for name, stats in self.stats.items():
            row = {'feature': name, 'method': stats.method}
            
            if self.method == 'standard':
                row['mean'] = stats.mean
                row['std'] = stats.std
            elif self.method == 'minmax':
                row['min'] = stats.min_val
                row['max'] = stats.max_val
            elif self.method == 'robust':
                row['median'] = stats.median
                row['q1'] = stats.q1
                row['q3'] = stats.q3
                row['iqr'] = stats.iqr
            
            rows.append(row)
        
        return pd.DataFrame(rows)


class FeatureProcessor:
    """
    Complete feature processing pipeline:
    1. Feature extraction
    2. Feature scaling
    3. Label encoding
    
    Ensures no data leakage by fitting ONLY on training data.
    """
    
    def __init__(
        self,
        scaling_method: str = 'standard',
        label_map: Optional[Dict[str, int]] = None
    ):
        """
        Initialize processor.
        
        Args:
            scaling_method: 'standard', 'minmax', or 'robust'
            label_map: Mapping from string labels to integers
        """
        self.scaler = FeatureScaler(method=scaling_method)
        self.label_map = label_map or {
            'LOW': 0,
            'MEDIUM': 1,
            'HIGH': 2,
            'CRITICAL': 3
        }
        self.inverse_label_map = {v: k for k, v in self.label_map.items()}
        self.feature_names: List[str] = []
    
    def fit(
        self,
        train_features: np.ndarray,
        feature_names: List[str]
    ) -> 'FeatureProcessor':
        """
        Fit the processor on training data.
        
        Args:
            train_features: Training feature matrix
            feature_names: Names of features
            
        Returns:
            self
        """
        self.feature_names = feature_names
        self.scaler.fit(train_features, feature_names)
        return self
    
    def transform_features(self, features: np.ndarray) -> np.ndarray:
        """Transform features using fitted scaler."""
        return self.scaler.transform(features, self.feature_names)
    
    def encode_labels(self, labels: List[str]) -> np.ndarray:
        """Convert string labels to integers."""
        return np.array([self.label_map.get(l, 1) for l in labels])
    
    def decode_labels(self, label_ids: np.ndarray) -> List[str]:
        """Convert integer labels back to strings."""
        return [self.inverse_label_map.get(int(i), 'UNKNOWN') for i in label_ids]
    
    def process_train(
        self,
        features: np.ndarray,
        labels: List[str],
        feature_names: List[str]
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        Process training data (fit + transform).
        
        Args:
            features: Feature matrix
            labels: String labels
            feature_names: Feature names
            
        Returns:
            (scaled_features, encoded_labels)
        """
        self.fit(features, feature_names)
        X = self.transform_features(features)
        y = self.encode_labels(labels)
        return X, y
    
    def process_eval(
        self,
        features: np.ndarray,
        labels: List[str]
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        Process validation/test data (transform only).
        
        Args:
            features: Feature matrix
            labels: String labels
            
        Returns:
            (scaled_features, encoded_labels)
        """
        X = self.transform_features(features)
        y = self.encode_labels(labels)
        return X, y
    
    def save(self, path: Path):
        """Save processor state."""
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)
        
        # Save scaler
        self.scaler.save(path / 'scaler.json')
        
        # Save metadata
        metadata = {
            'label_map': self.label_map,
            'feature_names': self.feature_names
        }
        with open(path / 'processor_metadata.json', 'w') as f:
            json.dump(metadata, f, indent=2)
    
    @classmethod
    def load(cls, path: Path) -> 'FeatureProcessor':
        """Load processor from saved state."""
        path = Path(path)
        
        # Load metadata
        with open(path / 'processor_metadata.json', 'r') as f:
            metadata = json.load(f)
        
        processor = cls(label_map=metadata['label_map'])
        processor.feature_names = metadata['feature_names']
        processor.scaler = FeatureScaler.load(path / 'scaler.json')
        
        return processor


# =============================================================================
# Demonstration
# =============================================================================

def demonstrate_scaling():
    """Demonstrate why scaling is important."""
    
    print("""
    ╔═══════════════════════════════════════════════════════════════════════╗
    ║              WHY FEATURE SCALING IS CRITICAL                          ║
    ╚═══════════════════════════════════════════════════════════════════════╝
    """)
    
    # Create sample data with different scales
    np.random.seed(42)
    
    # Feature 1: CVSS scores (0-10)
    cvss_scores = np.random.uniform(0, 10, 100)
    
    # Feature 2: Description length (50-5000)
    desc_lengths = np.random.uniform(50, 5000, 100)
    
    # Feature 3: Days since published (0-3650)
    days_old = np.random.uniform(0, 3650, 100)
    
    X = np.column_stack([cvss_scores, desc_lengths, days_old])
    feature_names = ['cvss_score', 'desc_length', 'days_old']
    
    print("BEFORE SCALING:")
    print("─" * 50)
    print(f"{'Feature':<15} {'Min':>10} {'Max':>10} {'Mean':>10} {'Std':>10}")
    print("─" * 50)
    for i, name in enumerate(feature_names):
        print(f"{name:<15} {X[:, i].min():>10.2f} {X[:, i].max():>10.2f} {X[:, i].mean():>10.2f} {X[:, i].std():>10.2f}")
    
    print("""
    
    PROBLEM: Features have wildly different scales!
    - cvss_score: 0-10
    - desc_length: 50-5000
    - days_old: 0-3650
    
    Neural network will be dominated by desc_length and days_old!
    """)
    
    # Apply standard scaling
    scaler = FeatureScaler(method='standard')
    X_scaled = scaler.fit_transform(X, feature_names)
    
    print("\nAFTER STANDARD SCALING (mean=0, std=1):")
    print("─" * 50)
    print(f"{'Feature':<15} {'Min':>10} {'Max':>10} {'Mean':>10} {'Std':>10}")
    print("─" * 50)
    for i, name in enumerate(feature_names):
        print(f"{name:<15} {X_scaled[:, i].min():>10.2f} {X_scaled[:, i].max():>10.2f} {X_scaled[:, i].mean():>10.2f} {X_scaled[:, i].std():>10.2f}")
    
    print("""
    
    AFTER SCALING: All features now have similar scale!
    - Mean ≈ 0
    - Std ≈ 1
    - Neural network treats all features equally
    """)
    
    # Show MinMax scaling too
    scaler_minmax = FeatureScaler(method='minmax')
    X_minmax = scaler_minmax.fit_transform(X, feature_names)
    
    print("\nAFTER MINMAX SCALING (range 0-1):")
    print("─" * 50)
    print(f"{'Feature':<15} {'Min':>10} {'Max':>10} {'Mean':>10} {'Std':>10}")
    print("─" * 50)
    for i, name in enumerate(feature_names):
        print(f"{name:<15} {X_minmax[:, i].min():>10.2f} {X_minmax[:, i].max():>10.2f} {X_minmax[:, i].mean():>10.2f} {X_minmax[:, i].std():>10.2f}")
    
    print("""
    
    KEY RULES:
    ══════════
    1. FIT scaler ONLY on training data
    2. TRANSFORM train, val, AND test with same statistics
    3. This prevents DATA LEAKAGE
    
    Example:
    ────────
    scaler = FeatureScaler('standard')
    
    # Fit ONLY on training data
    X_train_scaled = scaler.fit_transform(X_train)
    
    # Transform val/test with SAME statistics
    X_val_scaled = scaler.transform(X_val)    # No fit!
    X_test_scaled = scaler.transform(X_test)  # No fit!
    """)


if __name__ == "__main__":
    demonstrate_scaling()
