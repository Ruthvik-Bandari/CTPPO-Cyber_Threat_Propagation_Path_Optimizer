"""
CTPPO ML Integration
====================

Simple import:
    from ml import CTPPOPipeline
    
    pipeline = CTPPOPipeline()
    results = pipeline.analyze(scan_results)
"""

__all__ = [
    'CTPPOPipeline',
    'GNNWrapper',
    'RLWrapper',
]


def __getattr__(name):
    """Lazy import so `import ml.gnn...` doesn't pull in heavy ctppo_ml deps."""
    if name in __all__:
        from . import ctppo_ml
        return getattr(ctppo_ml, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
