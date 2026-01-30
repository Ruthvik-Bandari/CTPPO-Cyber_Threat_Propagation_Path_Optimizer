#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CTPPO v2.0 - Data Drift Detection
==================================

Detects when the model becomes stale due to changes in data distribution.

Types of Drift:
1. Feature Drift - Input data distribution changes
2. Prediction Drift - Model confidence/output distribution changes  
3. Label Drift - Target distribution changes (concept drift)

Why Drift Matters:
- Model trained on 2024 data may fail on 2026 data
- New attack types emerge (zero-days)
- Software ecosystem evolves
- Without detection, model silently degrades

Detection Methods:
1. Statistical Tests (KS test, Chi-squared)
2. Population Stability Index (PSI)
3. Prediction Confidence Monitoring
4. Performance Decay Tracking

Author: Ruthvik
Date: January 2026
"""

import numpy as np
import pandas as pd
from scipy import stats
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import deque
import json
import logging
from pathlib import Path
from enum import Enum

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DriftSeverity(Enum):
    """Severity levels for detected drift."""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class DriftAlert:
    """Alert generated when drift is detected."""
    timestamp: datetime
    drift_type: str  # 'feature', 'prediction', 'label', 'performance'
    severity: DriftSeverity
    feature_name: Optional[str]
    metric_name: str
    baseline_value: float
    current_value: float
    threshold: float
    message: str
    recommended_action: str
    
    def to_dict(self) -> Dict:
        return {
            'timestamp': self.timestamp.isoformat(),
            'drift_type': self.drift_type,
            'severity': self.severity.value,
            'feature_name': self.feature_name,
            'metric_name': self.metric_name,
            'baseline_value': self.baseline_value,
            'current_value': self.current_value,
            'threshold': self.threshold,
            'message': self.message,
            'recommended_action': self.recommended_action
        }


@dataclass
class DriftReport:
    """Complete drift analysis report."""
    timestamp: datetime
    overall_drift_detected: bool
    overall_severity: DriftSeverity
    feature_drift: Dict[str, Any]
    prediction_drift: Dict[str, Any]
    label_drift: Dict[str, Any]
    performance_drift: Dict[str, Any]
    alerts: List[DriftAlert]
    recommendations: List[str]
    
    def to_dict(self) -> Dict:
        return {
            'timestamp': self.timestamp.isoformat(),
            'overall_drift_detected': self.overall_drift_detected,
            'overall_severity': self.overall_severity.value,
            'feature_drift': self.feature_drift,
            'prediction_drift': self.prediction_drift,
            'label_drift': self.label_drift,
            'performance_drift': self.performance_drift,
            'alerts': [a.to_dict() for a in self.alerts],
            'recommendations': self.recommendations
        }


class DriftDetector:
    """
    Comprehensive drift detection for ML models.
    
    Monitors:
    1. Feature distributions (input drift)
    2. Prediction distributions (model drift)
    3. Label distributions (concept drift)
    4. Model performance (accuracy decay)
    """
    
    def __init__(
        self,
        reference_window_size: int = 10000,
        detection_window_size: int = 1000,
        feature_drift_threshold: float = 0.1,
        prediction_drift_threshold: float = 0.15,
        label_drift_threshold: float = 0.2,
        performance_decay_threshold: float = 0.05,
        confidence_drop_threshold: float = 0.1
    ):
        """
        Initialize drift detector.
        
        Args:
            reference_window_size: Number of samples for baseline
            detection_window_size: Number of samples for comparison
            feature_drift_threshold: PSI threshold for feature drift
            prediction_drift_threshold: Threshold for prediction distribution change
            label_drift_threshold: Threshold for label distribution change
            performance_decay_threshold: Accuracy drop to trigger alert
            confidence_drop_threshold: Confidence score drop to trigger alert
        """
        self.reference_window_size = reference_window_size
        self.detection_window_size = detection_window_size
        
        # Thresholds
        self.feature_drift_threshold = feature_drift_threshold
        self.prediction_drift_threshold = prediction_drift_threshold
        self.label_drift_threshold = label_drift_threshold
        self.performance_decay_threshold = performance_decay_threshold
        self.confidence_drop_threshold = confidence_drop_threshold
        
        # Reference distributions (baseline)
        self.reference_features: Optional[np.ndarray] = None
        self.reference_predictions: Optional[np.ndarray] = None
        self.reference_labels: Optional[np.ndarray] = None
        self.reference_confidences: Optional[np.ndarray] = None
        self.reference_accuracy: Optional[float] = None
        
        # Feature statistics
        self.feature_names: List[str] = []
        self.feature_stats: Dict[str, Dict] = {}
        
        # Sliding windows for online detection
        self.feature_window: deque = deque(maxlen=detection_window_size)
        self.prediction_window: deque = deque(maxlen=detection_window_size)
        self.label_window: deque = deque(maxlen=detection_window_size)
        self.confidence_window: deque = deque(maxlen=detection_window_size)
        self.correct_window: deque = deque(maxlen=detection_window_size)
        
        # Alert history
        self.alerts: List[DriftAlert] = []
        
        self.is_initialized = False
    
    def set_reference(
        self,
        features: np.ndarray,
        predictions: np.ndarray,
        labels: np.ndarray,
        confidences: np.ndarray,
        feature_names: Optional[List[str]] = None,
        accuracy: Optional[float] = None
    ):
        """
        Set reference (baseline) distributions from training data.
        
        Args:
            features: Feature matrix from training
            predictions: Model predictions on training/validation
            labels: True labels
            confidences: Prediction confidence scores
            feature_names: Names of features
            accuracy: Baseline accuracy
        """
        self.reference_features = features
        self.reference_predictions = predictions
        self.reference_labels = labels
        self.reference_confidences = confidences
        
        if feature_names:
            self.feature_names = feature_names
        else:
            self.feature_names = [f"feature_{i}" for i in range(features.shape[1])]
        
        # Compute feature statistics
        self._compute_feature_stats(features)
        
        # Compute baseline accuracy
        if accuracy is not None:
            self.reference_accuracy = accuracy
        else:
            self.reference_accuracy = np.mean(predictions == labels)
        
        self.is_initialized = True
        logger.info(f"Reference set with {len(features)} samples, {len(self.feature_names)} features")
        logger.info(f"Baseline accuracy: {self.reference_accuracy:.4f}")
    
    def _compute_feature_stats(self, features: np.ndarray):
        """Compute statistics for each feature."""
        for i, name in enumerate(self.feature_names):
            col = features[:, i]
            self.feature_stats[name] = {
                'mean': np.mean(col),
                'std': np.std(col),
                'min': np.min(col),
                'max': np.max(col),
                'q25': np.percentile(col, 25),
                'q50': np.percentile(col, 50),
                'q75': np.percentile(col, 75),
                'histogram': np.histogram(col, bins=10)[0] / len(col)
            }
    
    def add_sample(
        self,
        features: np.ndarray,
        prediction: int,
        label: Optional[int],
        confidence: float
    ):
        """
        Add a single sample for online drift detection.
        
        Args:
            features: Feature vector for one sample
            prediction: Model prediction
            label: True label (if available)
            confidence: Prediction confidence
        """
        self.feature_window.append(features)
        self.prediction_window.append(prediction)
        self.confidence_window.append(confidence)
        
        if label is not None:
            self.label_window.append(label)
            self.correct_window.append(int(prediction == label))
    
    def add_batch(
        self,
        features: np.ndarray,
        predictions: np.ndarray,
        labels: Optional[np.ndarray],
        confidences: np.ndarray
    ):
        """Add a batch of samples."""
        for i in range(len(features)):
            label = labels[i] if labels is not None else None
            self.add_sample(features[i], predictions[i], label, confidences[i])
    
    @staticmethod
    def compute_psi(reference: np.ndarray, current: np.ndarray, bins: int = 10) -> float:
        """
        Compute Population Stability Index (PSI).
        
        PSI measures how much a distribution has shifted.
        PSI < 0.1: No significant change
        PSI 0.1-0.25: Moderate change
        PSI > 0.25: Significant change
        
        Args:
            reference: Reference distribution
            current: Current distribution
            bins: Number of bins for histogram
            
        Returns:
            PSI value
        """
        # Create bins from reference distribution
        _, bin_edges = np.histogram(reference, bins=bins)
        
        # Compute histograms
        ref_hist, _ = np.histogram(reference, bins=bin_edges)
        cur_hist, _ = np.histogram(current, bins=bin_edges)
        
        # Normalize to proportions
        ref_pct = ref_hist / len(reference)
        cur_pct = cur_hist / len(current)
        
        # Avoid division by zero
        ref_pct = np.where(ref_pct == 0, 0.0001, ref_pct)
        cur_pct = np.where(cur_pct == 0, 0.0001, cur_pct)
        
        # Compute PSI
        psi = np.sum((cur_pct - ref_pct) * np.log(cur_pct / ref_pct))
        
        return psi
    
    @staticmethod
    def ks_test(reference: np.ndarray, current: np.ndarray) -> Tuple[float, float]:
        """
        Kolmogorov-Smirnov test for distribution comparison.
        
        Returns:
            (statistic, p_value)
        """
        statistic, p_value = stats.ks_2samp(reference, current)
        return statistic, p_value
    
    @staticmethod
    def chi_squared_test(reference: np.ndarray, current: np.ndarray) -> Tuple[float, float]:
        """
        Chi-squared test for categorical distributions.
        
        Returns:
            (statistic, p_value)
        """
        # Get unique classes
        all_classes = np.unique(np.concatenate([reference, current]))
        
        # Count frequencies
        ref_counts = np.array([np.sum(reference == c) for c in all_classes])
        cur_counts = np.array([np.sum(current == c) for c in all_classes])
        
        # Normalize to expected frequencies
        ref_freq = ref_counts / len(reference)
        expected = ref_freq * len(current)
        
        # Avoid zero expected
        expected = np.where(expected == 0, 0.1, expected)
        
        # Chi-squared statistic
        chi2 = np.sum((cur_counts - expected) ** 2 / expected)
        p_value = 1 - stats.chi2.cdf(chi2, df=len(all_classes) - 1)
        
        return chi2, p_value
    
    def detect_feature_drift(self) -> Dict[str, Any]:
        """
        Detect drift in feature distributions.
        
        Returns:
            Dictionary with drift analysis for each feature
        """
        if not self.is_initialized:
            raise RuntimeError("Detector not initialized. Call set_reference() first.")
        
        if len(self.feature_window) < self.detection_window_size // 2:
            return {'status': 'insufficient_data', 'samples': len(self.feature_window)}
        
        current_features = np.array(list(self.feature_window))
        
        results = {
            'drifted_features': [],
            'feature_details': {},
            'overall_psi': 0.0
        }
        
        total_psi = 0
        for i, name in enumerate(self.feature_names):
            ref_col = self.reference_features[:, i]
            cur_col = current_features[:, i]
            
            # Compute PSI
            psi = self.compute_psi(ref_col, cur_col)
            
            # KS test
            ks_stat, ks_pvalue = self.ks_test(ref_col, cur_col)
            
            # Determine drift
            is_drifted = psi > self.feature_drift_threshold or ks_pvalue < 0.01
            
            results['feature_details'][name] = {
                'psi': psi,
                'ks_statistic': ks_stat,
                'ks_pvalue': ks_pvalue,
                'is_drifted': is_drifted,
                'ref_mean': self.feature_stats[name]['mean'],
                'cur_mean': np.mean(cur_col),
                'mean_shift': np.mean(cur_col) - self.feature_stats[name]['mean']
            }
            
            if is_drifted:
                results['drifted_features'].append(name)
            
            total_psi += psi
        
        results['overall_psi'] = total_psi / len(self.feature_names)
        results['drift_detected'] = len(results['drifted_features']) > 0
        results['drift_percentage'] = len(results['drifted_features']) / len(self.feature_names)
        
        return results
    
    def detect_prediction_drift(self) -> Dict[str, Any]:
        """
        Detect drift in model predictions and confidence.
        
        Returns:
            Dictionary with prediction drift analysis
        """
        if not self.is_initialized:
            raise RuntimeError("Detector not initialized.")
        
        if len(self.prediction_window) < self.detection_window_size // 2:
            return {'status': 'insufficient_data'}
        
        current_predictions = np.array(list(self.prediction_window))
        current_confidences = np.array(list(self.confidence_window))
        
        # Prediction distribution drift
        chi2, p_value = self.chi_squared_test(
            self.reference_predictions,
            current_predictions
        )
        
        # Confidence drift
        ref_conf_mean = np.mean(self.reference_confidences)
        cur_conf_mean = np.mean(current_confidences)
        conf_drop = ref_conf_mean - cur_conf_mean
        
        # Confidence distribution
        conf_psi = self.compute_psi(self.reference_confidences, current_confidences)
        
        prediction_drift = p_value < 0.01
        confidence_drift = conf_drop > self.confidence_drop_threshold
        
        return {
            'prediction_chi2': chi2,
            'prediction_pvalue': p_value,
            'prediction_drift': prediction_drift,
            'reference_confidence_mean': ref_conf_mean,
            'current_confidence_mean': cur_conf_mean,
            'confidence_drop': conf_drop,
            'confidence_psi': conf_psi,
            'confidence_drift': confidence_drift,
            'drift_detected': prediction_drift or confidence_drift
        }
    
    def detect_label_drift(self) -> Dict[str, Any]:
        """
        Detect drift in label distribution (concept drift).
        
        Returns:
            Dictionary with label drift analysis
        """
        if not self.is_initialized:
            raise RuntimeError("Detector not initialized.")
        
        if len(self.label_window) < self.detection_window_size // 2:
            return {'status': 'insufficient_data'}
        
        current_labels = np.array(list(self.label_window))
        
        # Chi-squared test for label distribution
        chi2, p_value = self.chi_squared_test(
            self.reference_labels,
            current_labels
        )
        
        # Compute distribution shift
        ref_dist = np.bincount(self.reference_labels, minlength=4) / len(self.reference_labels)
        cur_dist = np.bincount(current_labels, minlength=4) / len(current_labels)
        
        label_names = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        dist_comparison = {
            label_names[i]: {
                'reference': ref_dist[i] if i < len(ref_dist) else 0,
                'current': cur_dist[i] if i < len(cur_dist) else 0,
                'change': (cur_dist[i] if i < len(cur_dist) else 0) - (ref_dist[i] if i < len(ref_dist) else 0)
            }
            for i in range(4)
        }
        
        drift_detected = p_value < 0.01
        
        return {
            'chi2': chi2,
            'p_value': p_value,
            'drift_detected': drift_detected,
            'distribution_comparison': dist_comparison,
            'interpretation': 'Significant shift in CVE severity distribution' if drift_detected else 'No significant label drift'
        }
    
    def detect_performance_drift(self) -> Dict[str, Any]:
        """
        Detect performance degradation.
        
        Returns:
            Dictionary with performance drift analysis
        """
        if len(self.correct_window) < self.detection_window_size // 2:
            return {'status': 'insufficient_data'}
        
        current_accuracy = np.mean(list(self.correct_window))
        accuracy_drop = self.reference_accuracy - current_accuracy
        
        # Statistical test for performance drop
        # Using binomial test
        n_samples = len(self.correct_window)
        n_correct = sum(self.correct_window)
        
        # Test if current accuracy is significantly lower than reference
        p_value = stats.binom_test(
            n_correct, n_samples, 
            p=self.reference_accuracy,
            alternative='less'
        ) if hasattr(stats, 'binom_test') else 0.5
        
        drift_detected = accuracy_drop > self.performance_decay_threshold
        
        return {
            'reference_accuracy': self.reference_accuracy,
            'current_accuracy': current_accuracy,
            'accuracy_drop': accuracy_drop,
            'drop_percentage': 100 * accuracy_drop / self.reference_accuracy if self.reference_accuracy > 0 else 0,
            'p_value': p_value,
            'drift_detected': drift_detected,
            'interpretation': f'Accuracy dropped by {100*accuracy_drop:.1f}%' if drift_detected else 'Performance stable'
        }
    
    def _determine_severity(
        self,
        feature_drift: Dict,
        prediction_drift: Dict,
        label_drift: Dict,
        performance_drift: Dict
    ) -> DriftSeverity:
        """Determine overall drift severity."""
        
        # Count drift indicators
        drift_count = 0
        
        if feature_drift.get('drift_detected'):
            drift_pct = feature_drift.get('drift_percentage', 0)
            if drift_pct > 0.5:
                return DriftSeverity.CRITICAL
            elif drift_pct > 0.3:
                drift_count += 2
            else:
                drift_count += 1
        
        if prediction_drift.get('drift_detected'):
            if prediction_drift.get('confidence_drop', 0) > 0.2:
                return DriftSeverity.CRITICAL
            drift_count += 1
        
        if label_drift.get('drift_detected'):
            drift_count += 2  # Label drift is serious
        
        if performance_drift.get('drift_detected'):
            drop = performance_drift.get('accuracy_drop', 0)
            if drop > 0.15:
                return DriftSeverity.CRITICAL
            elif drop > 0.1:
                return DriftSeverity.HIGH
            drift_count += 1
        
        # Determine severity
        if drift_count >= 4:
            return DriftSeverity.HIGH
        elif drift_count >= 2:
            return DriftSeverity.MEDIUM
        elif drift_count >= 1:
            return DriftSeverity.LOW
        return DriftSeverity.NONE
    
    def _generate_recommendations(
        self,
        severity: DriftSeverity,
        feature_drift: Dict,
        prediction_drift: Dict,
        label_drift: Dict,
        performance_drift: Dict
    ) -> List[str]:
        """Generate actionable recommendations based on drift analysis."""
        
        recommendations = []
        
        if severity == DriftSeverity.CRITICAL:
            recommendations.append("🔴 CRITICAL: Immediate model retraining required!")
            recommendations.append("Consider rolling back to a previous model version temporarily")
        
        if severity in [DriftSeverity.HIGH, DriftSeverity.CRITICAL]:
            recommendations.append("Schedule full model retraining with recent data")
            recommendations.append("Investigate root cause of drift (new attack types? new software?)")
        
        if feature_drift.get('drift_detected'):
            drifted = feature_drift.get('drifted_features', [])
            if drifted:
                recommendations.append(f"Feature drift detected in: {', '.join(drifted[:5])}")
                recommendations.append("Consider re-engineering these features or adding new ones")
        
        if prediction_drift.get('confidence_drift'):
            recommendations.append("Model confidence has dropped - may indicate distribution shift")
            recommendations.append("Consider incremental fine-tuning on recent data")
        
        if label_drift.get('drift_detected'):
            recommendations.append("Label distribution has shifted - new CVE severity patterns detected")
            recommendations.append("This may indicate emergence of new attack types")
            recommendations.append("Recompute class weights for training")
        
        if performance_drift.get('drift_detected'):
            drop = performance_drift.get('accuracy_drop', 0)
            recommendations.append(f"Accuracy has dropped by {100*drop:.1f}%")
            if drop > 0.1:
                recommendations.append("Incremental update recommended")
            else:
                recommendations.append("Monitor closely, prepare for retraining")
        
        if severity == DriftSeverity.NONE:
            recommendations.append("✅ No significant drift detected - model is healthy")
            recommendations.append("Continue monitoring")
        
        return recommendations
    
    def generate_report(self) -> DriftReport:
        """
        Generate comprehensive drift report.
        
        Returns:
            DriftReport with all analysis results
        """
        # Run all drift detections
        feature_drift = self.detect_feature_drift()
        prediction_drift = self.detect_prediction_drift()
        label_drift = self.detect_label_drift()
        performance_drift = self.detect_performance_drift()
        
        # Determine severity
        severity = self._determine_severity(
            feature_drift, prediction_drift, label_drift, performance_drift
        )
        
        # Generate recommendations
        recommendations = self._generate_recommendations(
            severity, feature_drift, prediction_drift, label_drift, performance_drift
        )
        
        # Check if any drift detected
        overall_drift = any([
            feature_drift.get('drift_detected', False),
            prediction_drift.get('drift_detected', False),
            label_drift.get('drift_detected', False),
            performance_drift.get('drift_detected', False)
        ])
        
        # Create alerts for detected drifts
        alerts = []
        
        if feature_drift.get('drift_detected'):
            alerts.append(DriftAlert(
                timestamp=datetime.now(),
                drift_type='feature',
                severity=DriftSeverity.MEDIUM if feature_drift.get('drift_percentage', 0) < 0.3 else DriftSeverity.HIGH,
                feature_name=None,
                metric_name='feature_psi',
                baseline_value=0,
                current_value=feature_drift.get('overall_psi', 0),
                threshold=self.feature_drift_threshold,
                message=f"Feature drift detected in {len(feature_drift.get('drifted_features', []))} features",
                recommended_action='Investigate feature distributions and consider retraining'
            ))
        
        if performance_drift.get('drift_detected'):
            alerts.append(DriftAlert(
                timestamp=datetime.now(),
                drift_type='performance',
                severity=DriftSeverity.HIGH if performance_drift.get('accuracy_drop', 0) > 0.1 else DriftSeverity.MEDIUM,
                feature_name=None,
                metric_name='accuracy',
                baseline_value=self.reference_accuracy,
                current_value=performance_drift.get('current_accuracy', 0),
                threshold=self.performance_decay_threshold,
                message=f"Accuracy dropped from {100*self.reference_accuracy:.1f}% to {100*performance_drift.get('current_accuracy', 0):.1f}%",
                recommended_action='Retrain model with recent data'
            ))
        
        self.alerts.extend(alerts)
        
        return DriftReport(
            timestamp=datetime.now(),
            overall_drift_detected=overall_drift,
            overall_severity=severity,
            feature_drift=feature_drift,
            prediction_drift=prediction_drift,
            label_drift=label_drift,
            performance_drift=performance_drift,
            alerts=alerts,
            recommendations=recommendations
        )
    
    def save_state(self, path: Path):
        """Save detector state for persistence."""
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)
        
        state = {
            'feature_names': self.feature_names,
            'feature_stats': self.feature_stats,
            'reference_accuracy': self.reference_accuracy,
            'thresholds': {
                'feature_drift': self.feature_drift_threshold,
                'prediction_drift': self.prediction_drift_threshold,
                'label_drift': self.label_drift_threshold,
                'performance_decay': self.performance_decay_threshold,
                'confidence_drop': self.confidence_drop_threshold
            }
        }
        
        with open(path / 'drift_detector_state.json', 'w') as f:
            json.dump(state, f, indent=2)
        
        # Save reference arrays
        if self.reference_features is not None:
            np.save(path / 'reference_features.npy', self.reference_features)
        if self.reference_predictions is not None:
            np.save(path / 'reference_predictions.npy', self.reference_predictions)
        if self.reference_labels is not None:
            np.save(path / 'reference_labels.npy', self.reference_labels)
        if self.reference_confidences is not None:
            np.save(path / 'reference_confidences.npy', self.reference_confidences)
        
        logger.info(f"Drift detector state saved to {path}")


def demonstrate_drift_detection():
    """Demonstrate drift detection with synthetic data."""
    
    print("""
╔═══════════════════════════════════════════════════════════════════════╗
║              DATA DRIFT DETECTION DEMONSTRATION                        ║
╚═══════════════════════════════════════════════════════════════════════╝
    """)
    
    np.random.seed(42)
    
    # Create reference (training) data
    n_ref = 5000
    ref_features = np.column_stack([
        np.random.normal(5, 2, n_ref),      # CVSS-like (centered at 5)
        np.random.normal(500, 200, n_ref),  # Description length
        np.random.normal(100, 50, n_ref)    # Days old
    ])
    ref_predictions = np.random.choice([0, 1, 2, 3], n_ref, p=[0.25, 0.50, 0.20, 0.05])
    ref_labels = ref_predictions.copy()  # Perfect predictions for baseline
    ref_confidences = np.random.uniform(0.7, 0.95, n_ref)
    
    # Initialize detector
    detector = DriftDetector(
        reference_window_size=5000,
        detection_window_size=1000
    )
    
    detector.set_reference(
        ref_features, ref_predictions, ref_labels, ref_confidences,
        feature_names=['cvss_score', 'desc_length', 'days_old']
    )
    
    print("Reference data set (5000 samples)")
    print(f"Baseline accuracy: {detector.reference_accuracy:.2%}")
    
    # Simulate NO DRIFT scenario
    print("\n" + "="*60)
    print("SCENARIO 1: NO DRIFT (similar distribution)")
    print("="*60)
    
    current_features = np.column_stack([
        np.random.normal(5.1, 2, 1000),     # Slight shift
        np.random.normal(510, 200, 1000),
        np.random.normal(105, 50, 1000)
    ])
    current_predictions = np.random.choice([0, 1, 2, 3], 1000, p=[0.24, 0.51, 0.20, 0.05])
    current_labels = current_predictions.copy()
    current_labels[np.random.choice(1000, 50, replace=False)] = np.random.choice([0,1,2,3], 50)  # 5% errors
    current_confidences = np.random.uniform(0.68, 0.93, 1000)
    
    detector.add_batch(current_features, current_predictions, current_labels, current_confidences)
    
    report = detector.generate_report()
    print(f"Drift detected: {report.overall_drift_detected}")
    print(f"Severity: {report.overall_severity.value}")
    for rec in report.recommendations:
        print(f"  • {rec}")
    
    # Simulate DRIFT scenario
    print("\n" + "="*60)
    print("SCENARIO 2: SIGNIFICANT DRIFT (new attack patterns!)")
    print("="*60)
    
    # Reset windows
    detector.feature_window.clear()
    detector.prediction_window.clear()
    detector.label_window.clear()
    detector.confidence_window.clear()
    detector.correct_window.clear()
    
    # Simulate drift: higher CVSS scores, more CRITICAL vulnerabilities
    drifted_features = np.column_stack([
        np.random.normal(7, 1.5, 1000),     # Higher CVSS (new severe vulns!)
        np.random.normal(800, 300, 1000),   # Longer descriptions
        np.random.normal(30, 20, 1000)      # More recent CVEs
    ])
    drifted_predictions = np.random.choice([0, 1, 2, 3], 1000, p=[0.10, 0.30, 0.35, 0.25])  # More severe!
    drifted_labels = np.random.choice([0, 1, 2, 3], 1000, p=[0.10, 0.30, 0.35, 0.25])
    # Model struggles with new distribution
    drifted_labels[np.random.choice(1000, 200, replace=False)] = np.random.choice([0,1,2,3], 200)
    drifted_confidences = np.random.uniform(0.5, 0.8, 1000)  # Lower confidence
    
    detector.add_batch(drifted_features, drifted_predictions, drifted_labels, drifted_confidences)
    
    report = detector.generate_report()
    print(f"Drift detected: {report.overall_drift_detected}")
    print(f"Severity: {report.overall_severity.value}")
    print("\nRecommendations:")
    for rec in report.recommendations:
        print(f"  • {rec}")
    
    if report.alerts:
        print("\nAlerts:")
        for alert in report.alerts:
            print(f"  🚨 {alert.message}")


if __name__ == "__main__":
    demonstrate_drift_detection()
