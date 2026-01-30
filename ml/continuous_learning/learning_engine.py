#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CTPPO v2.0 - Continuous Learning Engine
========================================

Real-time model updates to detect the LATEST malware and attack paths.

Learning Modes:
1. INCREMENTAL UPDATE (Fast - minutes)
   - Update only classification head
   - Keep BERT frozen
   - Use for small drift

2. FINE-TUNE (Medium - hours)
   - Unfreeze last BERT layers
   - Train on new + sample of old data
   - Use for moderate drift

3. FULL RETRAIN (Slow - days)
   - Complete retraining
   - Use for major drift or periodically

Triggered by:
- Scheduled intervals (e.g., daily/weekly)
- Drift detection alerts
- Performance degradation
- Manual trigger

Author: Ruthvik
Date: January 2026
"""

import os
import sys
import json
import time
import logging
import numpy as np
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Callable
from dataclasses import dataclass, asdict, field
from enum import Enum
from collections import deque
import threading
import queue

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Optional imports for PyTorch
try:
    import torch
    import torch.nn as nn
    from torch.utils.data import DataLoader, Dataset
    from torch.optim import AdamW
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    logger.warning("PyTorch not available - some features disabled")


class UpdateMode(Enum):
    """Model update strategies."""
    INCREMENTAL = "incremental"  # Fast: update classifier only
    FINE_TUNE = "fine_tune"      # Medium: unfreeze last layers
    FULL_RETRAIN = "full_retrain"  # Slow: complete retraining


class TriggerType(Enum):
    """What triggered the update."""
    SCHEDULED = "scheduled"
    DRIFT_DETECTED = "drift_detected"
    PERFORMANCE_DECAY = "performance_decay"
    MANUAL = "manual"
    NEW_DATA_THRESHOLD = "new_data_threshold"


@dataclass
class UpdateConfig:
    """Configuration for model updates."""
    mode: UpdateMode = UpdateMode.INCREMENTAL
    learning_rate: float = 1e-5
    epochs: int = 3
    batch_size: int = 16
    max_samples: int = 5000  # Max samples for incremental update
    include_old_samples: bool = True
    old_sample_ratio: float = 0.3  # 30% old data for stability
    freeze_bert_layers: int = -1  # -1 = all frozen, 0 = none frozen
    early_stopping_patience: int = 2
    validation_split: float = 0.1
    gradient_accumulation_steps: int = 1


@dataclass
class UpdateResult:
    """Result of a model update."""
    timestamp: datetime
    trigger: TriggerType
    mode: UpdateMode
    success: bool
    old_accuracy: float
    new_accuracy: float
    improvement: float
    training_time_seconds: float
    samples_used: int
    model_version: str
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            **asdict(self),
            'timestamp': self.timestamp.isoformat(),
            'trigger': self.trigger.value,
            'mode': self.mode.value
        }


@dataclass
class ModelVersion:
    """Track model versions."""
    version: str
    timestamp: datetime
    accuracy: float
    f1_score: float
    training_samples: int
    update_mode: UpdateMode
    checkpoint_path: str
    is_active: bool = False
    
    def to_dict(self) -> Dict:
        return {
            **asdict(self),
            'timestamp': self.timestamp.isoformat(),
            'update_mode': self.update_mode.value
        }


class DataBuffer:
    """
    Buffer for accumulating new data samples.
    
    Supports:
    - Accumulating new samples until threshold
    - Sampling from buffer for training
    - FIFO eviction when full
    """
    
    def __init__(self, max_size: int = 100000):
        """
        Initialize buffer.
        
        Args:
            max_size: Maximum samples to store
        """
        self.max_size = max_size
        self.samples: deque = deque(maxlen=max_size)
        self.labels: deque = deque(maxlen=max_size)
        self.timestamps: deque = deque(maxlen=max_size)
        self.lock = threading.Lock()
    
    def add(self, sample: Dict, label: int):
        """Add a sample to the buffer."""
        with self.lock:
            self.samples.append(sample)
            self.labels.append(label)
            self.timestamps.append(datetime.now())
    
    def add_batch(self, samples: List[Dict], labels: List[int]):
        """Add multiple samples."""
        with self.lock:
            for sample, label in zip(samples, labels):
                self.samples.append(sample)
                self.labels.append(label)
                self.timestamps.append(datetime.now())
    
    def get_recent(self, n: int) -> Tuple[List[Dict], List[int]]:
        """Get n most recent samples."""
        with self.lock:
            samples = list(self.samples)[-n:]
            labels = list(self.labels)[-n:]
            return samples, labels
    
    def get_all(self) -> Tuple[List[Dict], List[int]]:
        """Get all samples."""
        with self.lock:
            return list(self.samples), list(self.labels)
    
    def sample_random(self, n: int) -> Tuple[List[Dict], List[int]]:
        """Randomly sample n items from buffer."""
        with self.lock:
            if len(self.samples) <= n:
                return list(self.samples), list(self.labels)
            
            indices = np.random.choice(len(self.samples), n, replace=False)
            samples = [self.samples[i] for i in indices]
            labels = [self.labels[i] for i in indices]
            return samples, labels
    
    def clear(self):
        """Clear the buffer."""
        with self.lock:
            self.samples.clear()
            self.labels.clear()
            self.timestamps.clear()
    
    def __len__(self):
        return len(self.samples)
    
    @property
    def size(self) -> int:
        return len(self.samples)


class ContinuousLearningEngine:
    """
    Engine for continuous model updates.
    
    Features:
    - Multiple update modes (incremental, fine-tune, full)
    - Data buffering for new samples
    - Model versioning and rollback
    - Automatic trigger based on drift/performance
    - Integration with drift detector
    """
    
    def __init__(
        self,
        model_dir: Path,
        reference_data_dir: Optional[Path] = None,
        new_data_buffer_size: int = 100000,
        update_threshold: int = 1000,  # Minimum new samples before update
        max_versions_to_keep: int = 5
    ):
        """
        Initialize the continuous learning engine.
        
        Args:
            model_dir: Directory for model checkpoints
            reference_data_dir: Directory with reference/training data
            new_data_buffer_size: Buffer size for new samples
            update_threshold: Min samples to trigger update
            max_versions_to_keep: Max model versions to retain
        """
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        
        self.reference_data_dir = Path(reference_data_dir) if reference_data_dir else None
        self.update_threshold = update_threshold
        self.max_versions_to_keep = max_versions_to_keep
        
        # Data buffer for new samples
        self.data_buffer = DataBuffer(max_size=new_data_buffer_size)
        
        # Model state
        self.model = None
        self.tokenizer = None
        self.current_version: Optional[ModelVersion] = None
        self.version_history: List[ModelVersion] = []
        
        # Update history
        self.update_history: List[UpdateResult] = []
        
        # State file
        self.state_file = self.model_dir / "continuous_learning_state.json"
        
        # Load existing state if available
        self._load_state()
    
    def _load_state(self):
        """Load engine state from disk."""
        if self.state_file.exists():
            with open(self.state_file, 'r') as f:
                state = json.load(f)
            
            self.version_history = [
                ModelVersion(
                    version=v['version'],
                    timestamp=datetime.fromisoformat(v['timestamp']),
                    accuracy=v['accuracy'],
                    f1_score=v['f1_score'],
                    training_samples=v['training_samples'],
                    update_mode=UpdateMode(v['update_mode']),
                    checkpoint_path=v['checkpoint_path'],
                    is_active=v['is_active']
                )
                for v in state.get('version_history', [])
            ]
            
            # Find active version
            for v in self.version_history:
                if v.is_active:
                    self.current_version = v
                    break
            
            logger.info(f"Loaded state with {len(self.version_history)} versions")
    
    def _save_state(self):
        """Save engine state to disk."""
        state = {
            'version_history': [v.to_dict() for v in self.version_history],
            'update_history': [u.to_dict() for u in self.update_history[-100:]],  # Keep last 100
            'buffer_size': len(self.data_buffer)
        }
        
        with open(self.state_file, 'w') as f:
            json.dump(state, f, indent=2)
    
    def _generate_version(self) -> str:
        """Generate new version string."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        count = len(self.version_history) + 1
        return f"v{count}_{timestamp}"
    
    def load_model(self, checkpoint_path: Optional[str] = None):
        """
        Load model from checkpoint.
        
        Args:
            checkpoint_path: Path to checkpoint (uses active version if None)
        """
        if not TORCH_AVAILABLE:
            logger.error("PyTorch not available")
            return
        
        if checkpoint_path is None and self.current_version:
            checkpoint_path = self.current_version.checkpoint_path
        
        if checkpoint_path is None:
            logger.warning("No checkpoint to load")
            return
        
        checkpoint_path = Path(checkpoint_path)
        if not checkpoint_path.exists():
            logger.error(f"Checkpoint not found: {checkpoint_path}")
            return
        
        # Load checkpoint
        checkpoint = torch.load(checkpoint_path, map_location='cpu')
        
        # Initialize model architecture
        # (In real implementation, this would load the actual model)
        logger.info(f"Loaded model from {checkpoint_path}")
    
    def add_sample(self, sample: Dict, label: int):
        """
        Add a new sample to the buffer.
        
        Args:
            sample: CVE data dictionary
            label: Severity label (0-3)
        """
        self.data_buffer.add(sample, label)
        
        # Check if we should trigger update
        if len(self.data_buffer) >= self.update_threshold:
            logger.info(f"Buffer reached threshold ({len(self.data_buffer)} samples)")
    
    def add_batch(self, samples: List[Dict], labels: List[int]):
        """Add multiple samples."""
        self.data_buffer.add_batch(samples, labels)
    
    def should_update(
        self,
        drift_severity: Optional[str] = None,
        performance_drop: Optional[float] = None
    ) -> Tuple[bool, UpdateMode, TriggerType]:
        """
        Determine if model should be updated and how.
        
        Args:
            drift_severity: Drift severity from detector
            performance_drop: Accuracy drop percentage
            
        Returns:
            (should_update, mode, trigger_type)
        """
        # Check buffer size
        buffer_size = len(self.data_buffer)
        
        # Determine based on drift severity
        if drift_severity == "critical":
            return True, UpdateMode.FULL_RETRAIN, TriggerType.DRIFT_DETECTED
        
        if drift_severity == "high":
            return True, UpdateMode.FINE_TUNE, TriggerType.DRIFT_DETECTED
        
        if drift_severity in ["medium", "low"]:
            if buffer_size >= self.update_threshold:
                return True, UpdateMode.INCREMENTAL, TriggerType.DRIFT_DETECTED
        
        # Check performance drop
        if performance_drop is not None:
            if performance_drop > 0.15:
                return True, UpdateMode.FULL_RETRAIN, TriggerType.PERFORMANCE_DECAY
            if performance_drop > 0.10:
                return True, UpdateMode.FINE_TUNE, TriggerType.PERFORMANCE_DECAY
            if performance_drop > 0.05:
                if buffer_size >= self.update_threshold:
                    return True, UpdateMode.INCREMENTAL, TriggerType.PERFORMANCE_DECAY
        
        # Check buffer threshold
        if buffer_size >= self.update_threshold * 2:
            return True, UpdateMode.INCREMENTAL, TriggerType.NEW_DATA_THRESHOLD
        
        return False, UpdateMode.INCREMENTAL, TriggerType.SCHEDULED
    
    def _prepare_training_data(
        self,
        config: UpdateConfig
    ) -> Tuple[List[Dict], List[int], List[Dict], List[int]]:
        """
        Prepare data for training.
        
        Args:
            config: Update configuration
            
        Returns:
            (train_samples, train_labels, val_samples, val_labels)
        """
        # Get new samples from buffer
        new_samples, new_labels = self.data_buffer.get_all()
        
        # Limit samples if needed
        if len(new_samples) > config.max_samples:
            indices = np.random.choice(len(new_samples), config.max_samples, replace=False)
            new_samples = [new_samples[i] for i in indices]
            new_labels = [new_labels[i] for i in indices]
        
        # Include old samples for stability
        if config.include_old_samples and self.reference_data_dir:
            n_old = int(len(new_samples) * config.old_sample_ratio)
            old_samples, old_labels = self._sample_reference_data(n_old)
            
            all_samples = old_samples + new_samples
            all_labels = old_labels + new_labels
        else:
            all_samples = new_samples
            all_labels = new_labels
        
        # Shuffle
        indices = np.random.permutation(len(all_samples))
        all_samples = [all_samples[i] for i in indices]
        all_labels = [all_labels[i] for i in indices]
        
        # Split train/val
        val_size = int(len(all_samples) * config.validation_split)
        
        val_samples = all_samples[:val_size]
        val_labels = all_labels[:val_size]
        train_samples = all_samples[val_size:]
        train_labels = all_labels[val_size:]
        
        logger.info(f"Prepared {len(train_samples)} train, {len(val_samples)} val samples")
        
        return train_samples, train_labels, val_samples, val_labels
    
    def _sample_reference_data(self, n: int) -> Tuple[List[Dict], List[int]]:
        """Sample from reference training data."""
        if not self.reference_data_dir:
            return [], []
        
        # Load from reference data file
        ref_file = self.reference_data_dir / "train.jsonl"
        if not ref_file.exists():
            return [], []
        
        samples = []
        labels = []
        
        with open(ref_file, 'r') as f:
            all_lines = f.readlines()
        
        if len(all_lines) <= n:
            selected_lines = all_lines
        else:
            indices = np.random.choice(len(all_lines), n, replace=False)
            selected_lines = [all_lines[i] for i in indices]
        
        label_map = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}
        
        for line in selected_lines:
            record = json.loads(line)
            samples.append(record)
            labels.append(label_map.get(record.get('severity', 'MEDIUM'), 1))
        
        return samples, labels
    
    def update_model(
        self,
        config: Optional[UpdateConfig] = None,
        trigger: TriggerType = TriggerType.MANUAL,
        mode: Optional[UpdateMode] = None
    ) -> UpdateResult:
        """
        Update the model with new data.
        
        Args:
            config: Update configuration
            trigger: What triggered the update
            mode: Override update mode
            
        Returns:
            UpdateResult with details
        """
        start_time = time.time()
        
        if config is None:
            config = UpdateConfig()
        
        if mode is not None:
            config.mode = mode
        
        logger.info(f"Starting model update - Mode: {config.mode.value}, Trigger: {trigger.value}")
        
        # Get current accuracy (placeholder - would use actual evaluation)
        old_accuracy = self.current_version.accuracy if self.current_version else 0.75
        
        try:
            # Prepare training data
            train_samples, train_labels, val_samples, val_labels = self._prepare_training_data(config)
            
            if len(train_samples) == 0:
                return UpdateResult(
                    timestamp=datetime.now(),
                    trigger=trigger,
                    mode=config.mode,
                    success=False,
                    old_accuracy=old_accuracy,
                    new_accuracy=old_accuracy,
                    improvement=0,
                    training_time_seconds=0,
                    samples_used=0,
                    model_version=self.current_version.version if self.current_version else "none",
                    error_message="No training data available"
                )
            
            # Training logic would go here
            # For now, simulate training
            logger.info(f"Training with {len(train_samples)} samples...")
            
            # Simulate training time based on mode
            if config.mode == UpdateMode.INCREMENTAL:
                # Fast: only update classifier
                simulated_time = len(train_samples) * 0.001  # ~1ms per sample
                new_accuracy = min(0.95, old_accuracy + np.random.uniform(0.01, 0.03))
            elif config.mode == UpdateMode.FINE_TUNE:
                # Medium: fine-tune last layers
                simulated_time = len(train_samples) * 0.01
                new_accuracy = min(0.95, old_accuracy + np.random.uniform(0.02, 0.05))
            else:
                # Slow: full retrain
                simulated_time = len(train_samples) * 0.1
                new_accuracy = min(0.95, old_accuracy + np.random.uniform(0.03, 0.08))
            
            time.sleep(min(2, simulated_time))  # Cap at 2 seconds for demo
            
            # Generate new version
            new_version_str = self._generate_version()
            checkpoint_path = self.model_dir / f"model_{new_version_str}.pt"
            
            # Save checkpoint (placeholder)
            checkpoint_data = {
                'version': new_version_str,
                'accuracy': new_accuracy,
                'timestamp': datetime.now().isoformat()
            }
            with open(checkpoint_path, 'w') as f:
                json.dump(checkpoint_data, f)
            
            # Create version record
            new_version = ModelVersion(
                version=new_version_str,
                timestamp=datetime.now(),
                accuracy=new_accuracy,
                f1_score=new_accuracy * 0.95,  # Approximate
                training_samples=len(train_samples),
                update_mode=config.mode,
                checkpoint_path=str(checkpoint_path),
                is_active=True
            )
            
            # Deactivate old version
            if self.current_version:
                self.current_version.is_active = False
            
            # Update state
            self.current_version = new_version
            self.version_history.append(new_version)
            
            # Cleanup old versions
            self._cleanup_old_versions()
            
            # Clear buffer after successful update
            self.data_buffer.clear()
            
            # Save state
            self._save_state()
            
            training_time = time.time() - start_time
            
            result = UpdateResult(
                timestamp=datetime.now(),
                trigger=trigger,
                mode=config.mode,
                success=True,
                old_accuracy=old_accuracy,
                new_accuracy=new_accuracy,
                improvement=new_accuracy - old_accuracy,
                training_time_seconds=training_time,
                samples_used=len(train_samples),
                model_version=new_version_str
            )
            
            self.update_history.append(result)
            
            logger.info(f"Update complete! Version: {new_version_str}")
            logger.info(f"Accuracy: {old_accuracy:.2%} → {new_accuracy:.2%} (+{(new_accuracy-old_accuracy)*100:.1f}%)")
            
            return result
            
        except Exception as e:
            logger.error(f"Update failed: {e}")
            return UpdateResult(
                timestamp=datetime.now(),
                trigger=trigger,
                mode=config.mode,
                success=False,
                old_accuracy=old_accuracy,
                new_accuracy=old_accuracy,
                improvement=0,
                training_time_seconds=time.time() - start_time,
                samples_used=0,
                model_version=self.current_version.version if self.current_version else "none",
                error_message=str(e)
            )
    
    def _cleanup_old_versions(self):
        """Remove old model versions beyond max_versions_to_keep."""
        if len(self.version_history) <= self.max_versions_to_keep:
            return
        
        # Sort by timestamp, keep most recent
        sorted_versions = sorted(self.version_history, key=lambda v: v.timestamp, reverse=True)
        
        versions_to_keep = sorted_versions[:self.max_versions_to_keep]
        versions_to_remove = sorted_versions[self.max_versions_to_keep:]
        
        for v in versions_to_remove:
            # Delete checkpoint file
            checkpoint_path = Path(v.checkpoint_path)
            if checkpoint_path.exists():
                checkpoint_path.unlink()
                logger.info(f"Removed old checkpoint: {checkpoint_path}")
        
        self.version_history = versions_to_keep
    
    def rollback(self, version: Optional[str] = None) -> bool:
        """
        Rollback to a previous model version.
        
        Args:
            version: Version to rollback to (previous if None)
            
        Returns:
            True if successful
        """
        if len(self.version_history) < 2:
            logger.warning("No previous version to rollback to")
            return False
        
        if version is None:
            # Find previous version
            sorted_versions = sorted(self.version_history, key=lambda v: v.timestamp, reverse=True)
            target_version = sorted_versions[1]  # Second most recent
        else:
            # Find specified version
            target_version = None
            for v in self.version_history:
                if v.version == version:
                    target_version = v
                    break
            
            if target_version is None:
                logger.error(f"Version {version} not found")
                return False
        
        # Deactivate current
        if self.current_version:
            self.current_version.is_active = False
        
        # Activate target
        target_version.is_active = True
        self.current_version = target_version
        
        # Load model
        self.load_model(target_version.checkpoint_path)
        
        self._save_state()
        
        logger.info(f"Rolled back to version {target_version.version}")
        return True
    
    def get_status(self) -> Dict:
        """Get current engine status."""
        return {
            'current_version': self.current_version.to_dict() if self.current_version else None,
            'buffer_size': len(self.data_buffer),
            'buffer_threshold': self.update_threshold,
            'total_versions': len(self.version_history),
            'total_updates': len(self.update_history),
            'last_update': self.update_history[-1].to_dict() if self.update_history else None
        }


def demonstrate_continuous_learning():
    """Demonstrate the continuous learning engine."""
    
    print("""
╔═══════════════════════════════════════════════════════════════════════╗
║              CONTINUOUS LEARNING ENGINE DEMONSTRATION                  ║
╚═══════════════════════════════════════════════════════════════════════╝
    """)
    
    # Create engine
    engine = ContinuousLearningEngine(
        model_dir=Path("./demo_models"),
        update_threshold=100
    )
    
    print("Engine initialized")
    print(f"Update threshold: {engine.update_threshold} samples")
    
    # Simulate initial model
    initial_version = ModelVersion(
        version="v1_initial",
        timestamp=datetime.now(),
        accuracy=0.82,
        f1_score=0.80,
        training_samples=10000,
        update_mode=UpdateMode.FULL_RETRAIN,
        checkpoint_path="./demo_models/model_v1.pt",
        is_active=True
    )
    engine.current_version = initial_version
    engine.version_history.append(initial_version)
    
    print(f"\nInitial model: {initial_version.version}")
    print(f"Initial accuracy: {initial_version.accuracy:.2%}")
    
    # Simulate new CVE data arriving
    print("\n" + "="*60)
    print("SIMULATING NEW DATA ARRIVAL")
    print("="*60)
    
    # Add samples to buffer
    for i in range(150):
        sample = {
            'cve_id': f'CVE-2026-{10000+i}',
            'description': f'A new vulnerability in component {i}',
            'cvss_score': np.random.uniform(4, 10),
            'severity': np.random.choice(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])
        }
        label = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}[sample['severity']]
        engine.add_sample(sample, label)
    
    print(f"Added 150 new samples to buffer")
    print(f"Buffer size: {len(engine.data_buffer)}")
    
    # Check if should update
    should_update, mode, trigger = engine.should_update()
    print(f"\nShould update: {should_update}")
    print(f"Recommended mode: {mode.value}")
    print(f"Trigger type: {trigger.value}")
    
    # Perform update
    if should_update:
        print("\n" + "="*60)
        print("PERFORMING INCREMENTAL UPDATE")
        print("="*60)
        
        result = engine.update_model(trigger=trigger, mode=mode)
        
        print(f"\nUpdate successful: {result.success}")
        print(f"New version: {result.model_version}")
        print(f"Accuracy: {result.old_accuracy:.2%} → {result.new_accuracy:.2%}")
        print(f"Improvement: +{result.improvement*100:.1f}%")
        print(f"Training time: {result.training_time_seconds:.2f}s")
        print(f"Samples used: {result.samples_used}")
    
    # Show status
    print("\n" + "="*60)
    print("ENGINE STATUS")
    print("="*60)
    
    status = engine.get_status()
    print(f"Current version: {status['current_version']['version']}")
    print(f"Buffer size: {status['buffer_size']}")
    print(f"Total versions: {status['total_versions']}")
    print(f"Total updates: {status['total_updates']}")
    
    # Simulate drift detection triggering update
    print("\n" + "="*60)
    print("SIMULATING DRIFT-TRIGGERED UPDATE")
    print("="*60)
    
    # Add more samples
    for i in range(200):
        sample = {
            'cve_id': f'CVE-2026-{20000+i}',
            'description': f'Critical zero-day in component {i}',
            'cvss_score': np.random.uniform(7, 10),  # More severe!
            'severity': np.random.choice(['HIGH', 'CRITICAL'], p=[0.4, 0.6])
        }
        label = {'HIGH': 2, 'CRITICAL': 3}[sample['severity']]
        engine.add_sample(sample, label)
    
    should_update, mode, trigger = engine.should_update(
        drift_severity='high',
        performance_drop=0.08
    )
    
    print(f"Drift detected: HIGH severity")
    print(f"Should update: {should_update}")
    print(f"Recommended mode: {mode.value}")
    
    if should_update:
        result = engine.update_model(trigger=trigger, mode=mode)
        print(f"\nFine-tune update complete!")
        print(f"New accuracy: {result.new_accuracy:.2%}")
    
    # Show version history
    print("\n" + "="*60)
    print("VERSION HISTORY")
    print("="*60)
    
    for v in engine.version_history:
        active = "← ACTIVE" if v.is_active else ""
        print(f"  {v.version}: accuracy={v.accuracy:.2%}, mode={v.update_mode.value} {active}")
    
    # Cleanup
    import shutil
    if Path("./demo_models").exists():
        shutil.rmtree("./demo_models")


if __name__ == "__main__":
    demonstrate_continuous_learning()
