"""
Research Logging System for CTPPO
================================

This module provides comprehensive logging capabilities for research documentation.
All algorithmic decisions, experimental results, and runtime metrics are logged
for later inclusion in research papers.

Author: Ruthvik
Date: November 2025
"""

import os
import json
import time
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
import functools
import traceback
import logging

# Try to import rich for beautiful console output, fall back to simple output
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.logging import RichHandler
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None

# Configure base logging
LOG_DIR = Path(__file__).parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)


class LogLevel(Enum):
    """Log levels with research-specific categories"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    ALGORITHM = "ALGORITHM"      # Algorithmic decisions
    EXPERIMENT = "EXPERIMENT"    # Experimental results
    METRIC = "METRIC"            # Performance metrics
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


@dataclass
class LogEntry:
    """Structured log entry for research documentation"""
    timestamp: str
    level: str
    category: str
    message: str
    data: Dict[str, Any] = field(default_factory=dict)
    duration_ms: Optional[float] = None
    memory_mb: Optional[float] = None
    context: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, default=str)


class ResearchLogger:
    """
    Comprehensive logger for research documentation.
    
    Maintains structured logs that can be exported for:
    - Research paper appendices
    - Reproducibility documentation
    - Experimental analysis
    """
    
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
        
        # Generate unique experiment ID
        self.experiment_id = experiment_id or self._generate_experiment_id()
        
        # Create experiment-specific log directory
        self.experiment_dir = self.log_dir / self.experiment_id
        self.experiment_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize log files
        self.log_file = self.experiment_dir / "full_log.jsonl"
        self.metrics_file = self.experiment_dir / "metrics.jsonl"
        self.algorithm_file = self.experiment_dir / "algorithm_decisions.jsonl"
        
        # In-memory log storage for analysis
        self.entries: List[LogEntry] = []
        self.metrics: List[Dict[str, Any]] = []
        self.algorithm_decisions: List[Dict[str, Any]] = []
        
        # Timing contexts
        self._timing_stack: List[tuple] = []
        
        # Log session start
        self._log_session_start()
    
    def _generate_experiment_id(self) -> str:
        """Generate unique experiment identifier"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        hash_suffix = hashlib.md5(str(time.time()).encode()).hexdigest()[:6]
        return f"exp_{timestamp}_{hash_suffix}"
    
    def _log_session_start(self):
        """Log the start of a new session"""
        self.info(
            "SESSION_START",
            f"Started logging session for {self.name}",
            {
                "experiment_id": self.experiment_id,
                "log_directory": str(self.experiment_dir),
                "python_version": os.popen("python --version").read().strip(),
                "start_time": datetime.now().isoformat()
            }
        )
    
    def _create_entry(
        self,
        level: LogLevel,
        category: str,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        duration_ms: Optional[float] = None
    ) -> LogEntry:
        """Create a structured log entry"""
        memory_mb = None
        try:
            import psutil
            memory_mb = psutil.Process().memory_info().rss / 1024 / 1024
        except ImportError:
            pass
        
        return LogEntry(
            timestamp=datetime.now().isoformat(),
            level=level.value,
            category=category,
            message=message,
            data=data or {},
            duration_ms=duration_ms,
            memory_mb=memory_mb,
            context={
                "experiment_id": self.experiment_id,
                "logger_name": self.name
            }
        )
    
    def _write_entry(self, entry: LogEntry):
        """Write entry to appropriate files"""
        self.entries.append(entry)
        
        if self.file_output:
            # Write to main log
            with open(self.log_file, "a") as f:
                f.write(entry.to_json() + "\n")
            
            # Write to category-specific files
            if entry.level == LogLevel.METRIC.value:
                self.metrics.append(entry.to_dict())
                with open(self.metrics_file, "a") as f:
                    f.write(entry.to_json() + "\n")
            elif entry.level == LogLevel.ALGORITHM.value:
                self.algorithm_decisions.append(entry.to_dict())
                with open(self.algorithm_file, "a") as f:
                    f.write(entry.to_json() + "\n")
        
        if self.console_output:
            self._console_output(entry)
    
    def _console_output(self, entry: LogEntry):
        """Pretty print to console"""
        if RICH_AVAILABLE and console:
            level_colors = {
                "DEBUG": "dim",
                "INFO": "blue",
                "ALGORITHM": "cyan",
                "EXPERIMENT": "green",
                "METRIC": "yellow",
                "WARNING": "orange1",
                "ERROR": "red",
                "CRITICAL": "bold red"
            }
            
            color = level_colors.get(entry.level, "white")
            
            console.print(
                f"[{color}][{entry.level}][/{color}] "
                f"[bold]{entry.category}[/bold]: {entry.message}"
            )
            
            if entry.data and entry.level in ["ALGORITHM", "EXPERIMENT", "METRIC"]:
                console.print(Panel(
                    json.dumps(entry.data, indent=2, default=str),
                    title="Data",
                    border_style=color
                ))
        else:
            # Simple console output without rich
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
    
    # Logging methods
    def debug(self, category: str, message: str, data: Optional[Dict] = None):
        entry = self._create_entry(LogLevel.DEBUG, category, message, data)
        self._write_entry(entry)
    
    def info(self, category: str, message: str, data: Optional[Dict] = None):
        entry = self._create_entry(LogLevel.INFO, category, message, data)
        self._write_entry(entry)
    
    def algorithm(self, category: str, message: str, data: Optional[Dict] = None):
        """Log algorithmic decisions for research documentation"""
        entry = self._create_entry(LogLevel.ALGORITHM, category, message, data)
        self._write_entry(entry)
    
    def experiment(self, category: str, message: str, data: Optional[Dict] = None):
        """Log experimental results"""
        entry = self._create_entry(LogLevel.EXPERIMENT, category, message, data)
        self._write_entry(entry)
    
    def metric(self, category: str, message: str, data: Optional[Dict] = None):
        """Log performance metrics"""
        entry = self._create_entry(LogLevel.METRIC, category, message, data)
        self._write_entry(entry)
    
    def warning(self, category: str, message: str, data: Optional[Dict] = None):
        entry = self._create_entry(LogLevel.WARNING, category, message, data)
        self._write_entry(entry)
    
    def error(self, category: str, message: str, data: Optional[Dict] = None):
        entry = self._create_entry(LogLevel.ERROR, category, message, data)
        self._write_entry(entry)
    
    def critical(self, category: str, message: str, data: Optional[Dict] = None):
        entry = self._create_entry(LogLevel.CRITICAL, category, message, data)
        self._write_entry(entry)
    
    # Context managers for timing
    def timer(self, category: str, operation: str):
        """Context manager for timing operations"""
        return TimerContext(self, category, operation)
    
    def track_algorithm(self, algorithm_name: str, parameters: Dict[str, Any]):
        """Decorator/context manager for tracking algorithm execution"""
        return AlgorithmTracker(self, algorithm_name, parameters)
    
    # Export methods for research
    def export_for_paper(self, output_dir: Optional[Path] = None) -> Dict[str, Path]:
        """Export logs in formats suitable for research papers"""
        output_dir = output_dir or self.experiment_dir / "paper_export"
        output_dir.mkdir(exist_ok=True)
        
        # Export metrics as CSV
        if self.metrics:
            try:
                import pandas as pd
                metrics_df = pd.DataFrame([m["data"] for m in self.metrics])
                metrics_csv = output_dir / "metrics.csv"
                metrics_df.to_csv(metrics_csv, index=False)
            except ImportError:
                # Simple CSV export without pandas
                metrics_csv = output_dir / "metrics.csv"
                if self.metrics:
                    keys = list(self.metrics[0]["data"].keys())
                    with open(metrics_csv, "w") as f:
                        f.write(",".join(keys) + "\n")
                        for m in self.metrics:
                            values = [str(m["data"].get(k, "")) for k in keys]
                            f.write(",".join(values) + "\n")
        
        # Export algorithm decisions as markdown table
        if self.algorithm_decisions:
            alg_md = output_dir / "algorithm_decisions.md"
            with open(alg_md, "w") as f:
                f.write("# Algorithm Decisions Log\n\n")
                for decision in self.algorithm_decisions:
                    f.write(f"## {decision['category']}\n")
                    f.write(f"**Time:** {decision['timestamp']}\n\n")
                    f.write(f"**Message:** {decision['message']}\n\n")
                    f.write(f"**Data:**\n```json\n{json.dumps(decision['data'], indent=2)}\n```\n\n")
                    f.write("---\n\n")
        
        # Export summary statistics
        summary = self._generate_summary()
        summary_json = output_dir / "experiment_summary.json"
        with open(summary_json, "w") as f:
            json.dump(summary, f, indent=2, default=str)
        
        self.info("EXPORT", f"Exported logs for paper to {output_dir}")
        
        return {
            "metrics_csv": output_dir / "metrics.csv",
            "algorithm_md": output_dir / "algorithm_decisions.md",
            "summary_json": summary_json
        }
    
    def _generate_summary(self) -> Dict[str, Any]:
        """Generate summary statistics for the experiment"""
        return {
            "experiment_id": self.experiment_id,
            "total_entries": len(self.entries),
            "metrics_count": len(self.metrics),
            "algorithm_decisions_count": len(self.algorithm_decisions),
            "log_levels": {
                level.value: sum(1 for e in self.entries if e.level == level.value)
                for level in LogLevel
            },
            "categories": list(set(e.category for e in self.entries)),
            "start_time": self.entries[0].timestamp if self.entries else None,
            "end_time": self.entries[-1].timestamp if self.entries else None
        }


class TimerContext:
    """Context manager for timing operations"""
    
    def __init__(self, logger: ResearchLogger, category: str, operation: str):
        self.logger = logger
        self.category = category
        self.operation = operation
        self.start_time = None
    
    def __enter__(self):
        self.start_time = time.perf_counter()
        self.logger.debug(self.category, f"Starting: {self.operation}")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        duration_ms = (time.perf_counter() - self.start_time) * 1000
        
        if exc_type is None:
            self.logger.metric(
                self.category,
                f"Completed: {self.operation}",
                {"duration_ms": duration_ms, "operation": self.operation}
            )
        else:
            self.logger.error(
                self.category,
                f"Failed: {self.operation}",
                {
                    "duration_ms": duration_ms,
                    "error": str(exc_val),
                    "traceback": traceback.format_exc()
                }
            )
        return False


class AlgorithmTracker:
    """Context manager for tracking algorithm execution"""
    
    def __init__(
        self,
        logger: ResearchLogger,
        algorithm_name: str,
        parameters: Dict[str, Any]
    ):
        self.logger = logger
        self.algorithm_name = algorithm_name
        self.parameters = parameters
        self.start_time = None
        self.iterations = 0
        self.intermediate_results: List[Dict] = []
    
    def __enter__(self):
        self.start_time = time.perf_counter()
        self.logger.algorithm(
            "ALGORITHM_START",
            f"Starting algorithm: {self.algorithm_name}",
            {"parameters": self.parameters}
        )
        return self
    
    def log_iteration(self, iteration: int, data: Dict[str, Any]):
        """Log intermediate iteration data"""
        self.iterations = iteration
        self.intermediate_results.append({
            "iteration": iteration,
            "time_elapsed_ms": (time.perf_counter() - self.start_time) * 1000,
            **data
        })
        self.logger.debug(
            "ITERATION",
            f"{self.algorithm_name} - Iteration {iteration}",
            data
        )
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        duration_ms = (time.perf_counter() - self.start_time) * 1000
        
        self.logger.algorithm(
            "ALGORITHM_END",
            f"Completed algorithm: {self.algorithm_name}",
            {
                "parameters": self.parameters,
                "duration_ms": duration_ms,
                "total_iterations": self.iterations,
                "success": exc_type is None,
                "error": str(exc_val) if exc_val else None
            }
        )
        return False


def log_function(category: str = "FUNCTION"):
    """Decorator for logging function calls"""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Get logger from first argument if it has one, else use default
            logger = getattr(args[0], 'logger', None) if args else None
            if logger is None:
                logger = get_default_logger()
            
            start_time = time.perf_counter()
            logger.debug(category, f"Calling {func.__name__}", {"args": str(args[1:])[:200], "kwargs": str(kwargs)[:200]})
            
            try:
                result = func(*args, **kwargs)
                duration_ms = (time.perf_counter() - start_time) * 1000
                logger.debug(category, f"Completed {func.__name__}", {"duration_ms": duration_ms})
                return result
            except Exception as e:
                duration_ms = (time.perf_counter() - start_time) * 1000
                logger.error(category, f"Failed {func.__name__}", {
                    "duration_ms": duration_ms,
                    "error": str(e),
                    "traceback": traceback.format_exc()
                })
                raise
        return wrapper
    return decorator


# Default logger instance
_default_logger: Optional[ResearchLogger] = None


def get_default_logger() -> ResearchLogger:
    """Get or create the default logger instance"""
    global _default_logger
    if _default_logger is None:
        _default_logger = ResearchLogger("CTPPO")
    return _default_logger


def set_default_logger(logger: ResearchLogger):
    """Set the default logger instance"""
    global _default_logger
    _default_logger = logger


# Utility function to display progress
def progress_bar(iterable, description: str = "Processing"):
    """Create a progress bar (rich if available, else simple)"""
    if RICH_AVAILABLE:
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
        )
    else:
        return iterable


if __name__ == "__main__":
    # Test the logging system
    logger = ResearchLogger("TEST")
    
    logger.info("TEST", "Testing logging system", {"test_param": 123})
    
    with logger.timer("TEST", "Sample operation"):
        time.sleep(0.1)
    
    with logger.track_algorithm("TestAlgorithm", {"param1": 10, "param2": "value"}) as tracker:
        for i in range(5):
            tracker.log_iteration(i, {"loss": 1.0 / (i + 1)})
            time.sleep(0.05)
    
    logger.metric("PERFORMANCE", "Test metric", {"accuracy": 0.95, "f1_score": 0.92})
    
    # Export for paper
    logger.export_for_paper()
    
    print("\n✓ Logging test completed!")
