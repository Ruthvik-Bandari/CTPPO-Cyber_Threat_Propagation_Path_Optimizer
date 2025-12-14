"""
CTPPO ML Integration
====================

Simple import:
    from ml import CTPPOPipeline
    
    pipeline = CTPPOPipeline()
    results = pipeline.analyze(scan_results)
"""

from .ctppo_ml import (
    CTPPOPipeline,
    SeverityClassifier,
    GNNWrapper,
    RLWrapper,
    cvss_to_severity,
    Severity
)

__all__ = [
    'CTPPOPipeline',
    'SeverityClassifier', 
    'GNNWrapper',
    'RLWrapper',
    'cvss_to_severity',
    'Severity'
]
