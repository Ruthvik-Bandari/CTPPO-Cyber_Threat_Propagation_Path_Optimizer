"""
Simplified Research Logging System for CTPPO
============================================

A streamlined logging system that works without external dependencies.
Use this for environments where rich/loguru are not available.

Author: Ruthvik
Date: November 2025
"""

import os
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field, asdict
from enum import Enum
import functools
import traceback


LOG_DIR = Path(__file__).parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)


class LogLevel(Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    ALGORITHM = "ALGORITHM"
    EXPERIMENT = "EXPERIMENT"
    METRIC = "METRIC"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


@dataclass
class LogEntry:
    timestamp: str
    level: str
    category: str
    message: str
    data: Dict[str, Any] = field(default_factory=dict)
    duration_ms: Optional[float] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, default=str)


class ResearchLogger:
    """Simplified research logger without external dependencies."""
    
    def __init__(
        self,
        name: str,
        log_dir: Optional[Path] = None,
        console_output: bool = True,
        file_output: bool = True,
        experiment_id: Optional[str] = None
    ):
        self.name = name
        self.log_dir = log_dir or LOG_DIR
        self.console_output = console_output
        self.file_output = file_output
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.experiment_id = experiment_id or f"exp_{timestamp}"
        
        self.experiment_dir = self.log_dir / self.experiment_id
        self.experiment_dir.mkdir(parents=True, exist_ok=True)
        
        self.log_file = self.experiment_dir / "full_log.jsonl"
        self.metrics_file = self.experiment_dir / "metrics.jsonl"
        self.algorithm_file = self.experiment_dir / "algorithm_decisions.jsonl"
        
        self.entries: List[LogEntry] = []
        self.metrics: List[Dict[str, Any]] = []
        self.algorithm_decisions: List[Dict[str, Any]] = []
    
    def _create_entry(
        self,
        level: LogLevel,
        category: str,
        message: str,
        data: Optional[Dict[str, Any]] = None
    ) -> LogEntry:
        return LogEntry(
            timestamp=datetime.now().isoformat(),
            level=level.value,
            category=category,
            message=message,
            data=data or {}
        )
    
    def _write_entry(self, entry: LogEntry):
        self.entries.append(entry)
        
        if self.file_output:
            with open(self.log_file, "a") as f:
                f.write(entry.to_json() + "\n")
            
            if entry.level == LogLevel.METRIC.value:
                self.metrics.append(entry.to_dict())
                with open(self.metrics_file, "a") as f:
                    f.write(entry.to_json() + "\n")
            elif entry.level == LogLevel.ALGORITHM.value:
                self.algorithm_decisions.append(entry.to_dict())
                with open(self.algorithm_file, "a") as f:
                    f.write(entry.to_json() + "\n")
        
        if self.console_output:
            level_symbols = {
                "DEBUG": "·",
                "INFO": "ℹ",
                "ALGORITHM": "⚙",
                "EXPERIMENT": "🧪",
                "METRIC": "📊",
                "WARNING": "⚠",
                "ERROR": "✗",
                "CRITICAL": "🔥"
            }
            symbol = level_symbols.get(entry.level, "•")
            print(f"[{symbol} {entry.level}] {entry.category}: {entry.message}")
            if entry.data and entry.level in ["ALGORITHM", "EXPERIMENT", "METRIC"]:
                for k, v in entry.data.items():
                    print(f"    {k}: {v}")
    
    def debug(self, category: str, message: str, data: Optional[Dict] = None):
        entry = self._create_entry(LogLevel.DEBUG, category, message, data)
        self._write_entry(entry)
    
    def info(self, category: str, message: str, data: Optional[Dict] = None):
        entry = self._create_entry(LogLevel.INFO, category, message, data)
        self._write_entry(entry)
    
    def algorithm(self, category: str, message: str, data: Optional[Dict] = None):
        entry = self._create_entry(LogLevel.ALGORITHM, category, message, data)
        self._write_entry(entry)
    
    def experiment(self, category: str, message: str, data: Optional[Dict] = None):
        entry = self._create_entry(LogLevel.EXPERIMENT, category, message, data)
        self._write_entry(entry)
    
    def metric(self, category: str, message: str, data: Optional[Dict] = None):
        entry = self._create_entry(LogLevel.METRIC, category, message, data)
        self._write_entry(entry)
    
    def warning(self, category: str, message: str, data: Optional[Dict] = None):
        entry = self._create_entry(LogLevel.WARNING, category, message, data)
        self._write_entry(entry)
    
    def error(self, category: str, message: str, data: Optional[Dict] = None):
        entry = self._create_entry(LogLevel.ERROR, category, message, data)
        self._write_entry(entry)
    
    def timer(self, category: str, operation: str):
        return TimerContext(self, category, operation)
    
    def track_algorithm(self, algorithm_name: str, parameters: Dict[str, Any]):
        return AlgorithmTracker(self, algorithm_name, parameters)
    
    def export_for_paper(self, output_dir: Optional[Path] = None) -> Dict[str, Path]:
        output_dir = output_dir or self.experiment_dir / "paper_export"
        output_dir.mkdir(exist_ok=True)
        
        summary = {
            "experiment_id": self.experiment_id,
            "total_entries": len(self.entries),
            "metrics_count": len(self.metrics),
            "algorithm_decisions_count": len(self.algorithm_decisions)
        }
        
        summary_json = output_dir / "experiment_summary.json"
        with open(summary_json, "w") as f:
            json.dump(summary, f, indent=2, default=str)
        
        return {"summary_json": summary_json}


class TimerContext:
    def __init__(self, logger: ResearchLogger, category: str, operation: str):
        self.logger = logger
        self.category = category
        self.operation = operation
        self.start_time = None
    
    def __enter__(self):
        self.start_time = time.perf_counter()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        duration_ms = (time.perf_counter() - self.start_time) * 1000
        if exc_type is None:
            self.logger.metric(
                self.category,
                f"Completed: {self.operation}",
                {"duration_ms": round(duration_ms, 2), "operation": self.operation}
            )
        else:
            self.logger.error(
                self.category,
                f"Failed: {self.operation}",
                {"duration_ms": round(duration_ms, 2), "error": str(exc_val)}
            )
        return False


class AlgorithmTracker:
    def __init__(self, logger: ResearchLogger, algorithm_name: str, parameters: Dict[str, Any]):
        self.logger = logger
        self.algorithm_name = algorithm_name
        self.parameters = parameters
        self.start_time = None
        self.iterations = 0
    
    def __enter__(self):
        self.start_time = time.perf_counter()
        self.logger.algorithm(
            "ALGORITHM_START",
            f"Starting: {self.algorithm_name}",
            {"parameters": self.parameters}
        )
        return self
    
    def log_iteration(self, iteration: int, data: Dict[str, Any]):
        self.iterations = iteration
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        duration_ms = (time.perf_counter() - self.start_time) * 1000
        self.logger.algorithm(
            "ALGORITHM_END",
            f"Completed: {self.algorithm_name}",
            {
                "duration_ms": round(duration_ms, 2),
                "iterations": self.iterations,
                "success": exc_type is None
            }
        )
        return False


# Default logger
_default_logger: Optional[ResearchLogger] = None

def get_default_logger() -> ResearchLogger:
    global _default_logger
    if _default_logger is None:
        _default_logger = ResearchLogger("CTPPO", console_output=False)
    return _default_logger

def set_default_logger(logger: ResearchLogger):
    global _default_logger
    _default_logger = logger

def log_function(category: str = "FUNCTION"):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)
        return wrapper
    return decorator

def progress_bar(iterable, description: str = "Processing"):
    return iterable
