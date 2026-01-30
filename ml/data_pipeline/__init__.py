# -*- coding: utf-8 -*-
"""
CTPPO v2.0 - Data Pipeline Module
==================================

Complete ML pipeline following STANDARD WORKFLOW:

Phase 1: Data Acquisition & Understanding
- data_collector: Fetch CVE data with GROUND TRUTH labels
- eda: Exploratory Data Analysis

Phase 2: Data Preparation (Preprocessing)
- data_cleaner: Clean and normalize text
- feature_engineer: Extract rich features (40+)
- data_splitter: Stratified train/val/test splitting
- feature_scaler: Normalization/Standardization (CRITICAL!)

Phase 3-5: Model Training
- dataset: PyTorch datasets for training

Key Principles:
- No data leakage (CVSS = ground truth, not model predictions)
- Stratified splitting (preserves class distribution)
- Class balancing (weights for imbalanced data)
- Feature scaling (fit on train only!)

Author: Ruthvik
Date: January 2026
"""

# Phase 1: Data Collection
from .data_collector import CVEDataCollector

# Phase 2: Data Preparation
from .data_cleaner import TextCleaner, CVECleaner
from .feature_engineer import FeatureEngineer
from .data_splitter import DataSplitter
from .feature_scaler import FeatureScaler, FeatureProcessor

# Phase 3: Dataset Creation
from .dataset import CVEDataset, AttackGraphDataset

# Optional: EDA
try:
    from .eda import CVEDataAnalyzer, run_eda
    _eda_available = True
except ImportError:
    _eda_available = False

__all__ = [
    # Phase 1
    'CVEDataCollector',
    # Phase 2
    'TextCleaner',
    'CVECleaner', 
    'FeatureEngineer',
    'DataSplitter',
    'FeatureScaler',
    'FeatureProcessor',
    # Phase 3
    'CVEDataset',
    'AttackGraphDataset',
]

if _eda_available:
    __all__.extend(['CVEDataAnalyzer', 'run_eda'])
