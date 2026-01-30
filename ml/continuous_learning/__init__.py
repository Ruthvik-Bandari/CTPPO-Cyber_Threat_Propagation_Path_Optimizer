# -*- coding: utf-8 -*-
"""
CTPPO v2.0 - Continuous Learning Module
========================================

Real-time model updates to detect the LATEST malware and attack paths.

Components:
- DriftDetector: Detects when model becomes stale
- ContinuousLearningEngine: Manages incremental model updates
- CVEStreamProcessor: Real-time CVE monitoring

Why Continuous Learning?
────────────────────────
Models trained on 2024 data may fail on 2026 data because:
- New attack types emerge (zero-days)
- Software ecosystem evolves
- Attacker techniques change

Without continuous learning, model accuracy degrades over time (MODEL ROT).

Usage:
──────
# Set up continuous learning
from ml.continuous_learning import DriftDetector, ContinuousLearningEngine, CVEStreamProcessor

# Initialize components
detector = DriftDetector()
engine = ContinuousLearningEngine(model_dir="./models")
processor = CVEStreamProcessor(auto_update=True)

# Connect them
processor.set_drift_detector(detector)
processor.set_learning_engine(engine)

# Start real-time monitoring
processor.start()

Author: Ruthvik
Date: January 2026
"""

from .drift_detector import (
    DriftDetector,
    DriftAlert,
    DriftReport,
    DriftSeverity
)

from .learning_engine import (
    ContinuousLearningEngine,
    UpdateConfig,
    UpdateResult,
    UpdateMode,
    TriggerType,
    ModelVersion,
    DataBuffer
)

from .stream_processor import (
    CVEStreamProcessor,
    CVEEvent,
    PredictionResult,
    StreamStats
)

__all__ = [
    # Drift Detection
    'DriftDetector',
    'DriftAlert',
    'DriftReport',
    'DriftSeverity',
    
    # Continuous Learning
    'ContinuousLearningEngine',
    'UpdateConfig',
    'UpdateResult',
    'UpdateMode',
    'TriggerType',
    'ModelVersion',
    'DataBuffer',
    
    # Stream Processing
    'CVEStreamProcessor',
    'CVEEvent',
    'PredictionResult',
    'StreamStats',
]
