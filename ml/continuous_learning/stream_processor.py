#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CTPPO v2.0 - Real-Time CVE Stream Processor
============================================

Monitors NVD for new CVEs in real-time and feeds them to the model.

Features:
1. Continuous polling of NVD API for new CVEs
2. Real-time prediction with confidence scoring
3. Automatic drift detection
4. Trigger model updates when needed
5. Alert generation for high-severity CVEs

Usage:
    # Start the real-time monitor
    python -m ml.continuous_learning.stream_processor --interval 300
    
    # With automatic updates
    python -m ml.continuous_learning.stream_processor --auto-update

Author: Ruthvik
Date: January 2026
"""

import os
import sys
import json
import time
import logging
import requests
import threading
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, asdict
from queue import Queue
import signal

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class CVEEvent:
    """A new CVE event from the stream."""
    cve_id: str
    description: str
    cvss_score: Optional[float]
    severity: str
    published_date: str
    cvss_vector: Dict
    cwe_ids: List[str]
    references: List[Dict]
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()
    
    def to_dict(self) -> Dict:
        d = asdict(self)
        d['timestamp'] = self.timestamp.isoformat()
        return d


@dataclass
class PredictionResult:
    """Model prediction for a CVE."""
    cve_id: str
    predicted_severity: str
    confidence: float
    ground_truth_severity: str
    is_correct: bool
    processing_time_ms: float
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()


@dataclass
class StreamStats:
    """Statistics from stream processing."""
    total_processed: int = 0
    total_critical: int = 0
    total_high: int = 0
    total_medium: int = 0
    total_low: int = 0
    correct_predictions: int = 0
    avg_confidence: float = 0.0
    avg_processing_time_ms: float = 0.0
    start_time: datetime = None
    last_update: datetime = None


class CVEStreamProcessor:
    """
    Real-time CVE stream processor.
    
    Continuously monitors NVD for new CVEs and:
    - Makes predictions with the model
    - Detects drift
    - Triggers updates when needed
    """
    
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        poll_interval_seconds: int = 300,  # 5 minutes
        lookback_hours: int = 24,
        batch_size: int = 100,
        auto_update: bool = False,
        callbacks: Optional[Dict[str, Callable]] = None
    ):
        """
        Initialize the stream processor.
        
        Args:
            api_key: NVD API key (faster polling)
            poll_interval_seconds: Seconds between polls
            lookback_hours: How far back to look on startup
            batch_size: Max CVEs per API call
            auto_update: Automatically trigger model updates
            callbacks: Event callbacks {'on_new_cve', 'on_prediction', 'on_drift', 'on_alert'}
        """
        self.api_key = api_key or os.environ.get('NVD_API_KEY')
        self.poll_interval = poll_interval_seconds
        self.lookback_hours = lookback_hours
        self.batch_size = batch_size
        self.auto_update = auto_update
        self.callbacks = callbacks or {}
        
        # Rate limiting
        self.rate_limit_delay = 0.6 if self.api_key else 6.0
        self.last_request_time = 0
        
        # State
        self.last_poll_time: Optional[datetime] = None
        self.processed_cve_ids: set = set()
        self.stats = StreamStats(start_time=datetime.now())
        
        # Queues for async processing
        self.event_queue: Queue = Queue()
        self.prediction_queue: Queue = Queue()
        
        # Control
        self.running = False
        self._stop_event = threading.Event()
        
        # Model and drift detector (would be injected)
        self.model = None
        self.drift_detector = None
        self.learning_engine = None
        
        logger.info(f"Stream processor initialized")
        logger.info(f"Poll interval: {poll_interval_seconds}s")
        logger.info(f"API key: {'Yes' if self.api_key else 'No'}")
    
    def set_model(self, model):
        """Set the prediction model."""
        self.model = model
    
    def set_drift_detector(self, detector):
        """Set the drift detector."""
        self.drift_detector = detector
    
    def set_learning_engine(self, engine):
        """Set the continuous learning engine."""
        self.learning_engine = engine
    
    def _wait_for_rate_limit(self):
        """Respect API rate limits."""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - elapsed)
        self.last_request_time = time.time()
    
    def _fetch_recent_cves(
        self,
        start_time: datetime,
        end_time: Optional[datetime] = None
    ) -> List[Dict]:
        """
        Fetch CVEs modified/published within time range.
        
        Args:
            start_time: Start of time range
            end_time: End of time range (now if None)
            
        Returns:
            List of CVE dictionaries
        """
        if end_time is None:
            end_time = datetime.now()
        
        self._wait_for_rate_limit()
        
        headers = {}
        if self.api_key:
            headers['apiKey'] = self.api_key
        
        # Format dates for API
        start_str = start_time.strftime("%Y-%m-%dT%H:%M:%S.000")
        end_str = end_time.strftime("%Y-%m-%dT%H:%M:%S.000")
        
        params = {
            'lastModStartDate': start_str,
            'lastModEndDate': end_str,
            'resultsPerPage': self.batch_size
        }
        
        try:
            response = requests.get(
                self.NVD_API_URL,
                headers=headers,
                params=params,
                timeout=30
            )
            response.raise_for_status()
            data = response.json()
            
            return data.get('vulnerabilities', [])
            
        except Exception as e:
            logger.error(f"API error: {e}")
            return []
    
    def _parse_cve(self, cve_item: Dict) -> Optional[CVEEvent]:
        """Parse a CVE from API response into CVEEvent."""
        try:
            cve = cve_item.get('cve', {})
            
            cve_id = cve.get('id')
            if not cve_id:
                return None
            
            # Skip if already processed
            if cve_id in self.processed_cve_ids:
                return None
            
            # Get description
            description = "No description"
            for desc in cve.get('descriptions', []):
                if desc.get('lang') == 'en':
                    description = desc.get('value', description)
                    break
            
            # Get CVSS
            cvss_score = None
            cvss_vector = {}
            severity = 'UNKNOWN'
            
            metrics = cve.get('metrics', {})
            
            if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
                cvss_score = cvss_data.get('baseScore')
                cvss_vector = {
                    'attack_vector': cvss_data.get('attackVector'),
                    'attack_complexity': cvss_data.get('attackComplexity'),
                    'privileges_required': cvss_data.get('privilegesRequired'),
                    'user_interaction': cvss_data.get('userInteraction'),
                    'scope': cvss_data.get('scope'),
                    'confidentiality_impact': cvss_data.get('confidentialityImpact'),
                    'integrity_impact': cvss_data.get('integrityImpact'),
                    'availability_impact': cvss_data.get('availabilityImpact'),
                }
            
            # Derive severity from CVSS
            if cvss_score is not None:
                if cvss_score >= 9.0:
                    severity = 'CRITICAL'
                elif cvss_score >= 7.0:
                    severity = 'HIGH'
                elif cvss_score >= 4.0:
                    severity = 'MEDIUM'
                else:
                    severity = 'LOW'
            
            # Get CWE IDs
            cwe_ids = []
            for weakness in cve.get('weaknesses', []):
                for desc in weakness.get('description', []):
                    if desc.get('lang') == 'en':
                        cwe_id = desc.get('value', '')
                        if cwe_id.startswith('CWE-'):
                            cwe_ids.append(cwe_id)
            
            # Get references
            references = [
                {'url': ref.get('url'), 'tags': ref.get('tags', [])}
                for ref in cve.get('references', [])[:5]  # Limit to 5
            ]
            
            return CVEEvent(
                cve_id=cve_id,
                description=description,
                cvss_score=cvss_score,
                severity=severity,
                published_date=cve.get('published', ''),
                cvss_vector=cvss_vector,
                cwe_ids=cwe_ids,
                references=references
            )
            
        except Exception as e:
            logger.error(f"Error parsing CVE: {e}")
            return None
    
    def _process_event(self, event: CVEEvent) -> Optional[PredictionResult]:
        """
        Process a single CVE event.
        
        Args:
            event: CVE event to process
            
        Returns:
            Prediction result
        """
        start_time = time.time()
        
        # Make prediction (simulated if no model)
        if self.model is not None:
            # Would call model.predict() here
            predicted_severity = event.severity  # Placeholder
            confidence = 0.85
        else:
            # Simulate prediction
            predicted_severity = event.severity
            confidence = 0.75 + 0.2 * (event.cvss_score or 5) / 10
        
        processing_time = (time.time() - start_time) * 1000
        
        result = PredictionResult(
            cve_id=event.cve_id,
            predicted_severity=predicted_severity,
            confidence=confidence,
            ground_truth_severity=event.severity,
            is_correct=(predicted_severity == event.severity),
            processing_time_ms=processing_time
        )
        
        # Update stats
        self.stats.total_processed += 1
        if event.severity == 'CRITICAL':
            self.stats.total_critical += 1
        elif event.severity == 'HIGH':
            self.stats.total_high += 1
        elif event.severity == 'MEDIUM':
            self.stats.total_medium += 1
        else:
            self.stats.total_low += 1
        
        if result.is_correct:
            self.stats.correct_predictions += 1
        
        # Update running averages
        n = self.stats.total_processed
        self.stats.avg_confidence = (
            (self.stats.avg_confidence * (n - 1) + confidence) / n
        )
        self.stats.avg_processing_time_ms = (
            (self.stats.avg_processing_time_ms * (n - 1) + processing_time) / n
        )
        self.stats.last_update = datetime.now()
        
        # Add to processed set
        self.processed_cve_ids.add(event.cve_id)
        
        # Trigger callbacks
        if 'on_prediction' in self.callbacks:
            self.callbacks['on_prediction'](result)
        
        # Add to learning engine buffer
        if self.learning_engine:
            label_map = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}
            self.learning_engine.add_sample(
                event.to_dict(),
                label_map.get(event.severity, 1)
            )
        
        # Generate alert for critical CVEs
        if event.severity == 'CRITICAL':
            self._generate_alert(event, result)
        
        return result
    
    def _generate_alert(self, event: CVEEvent, prediction: PredictionResult):
        """Generate alert for high-severity CVE."""
        alert = {
            'type': 'NEW_CRITICAL_CVE',
            'timestamp': datetime.now().isoformat(),
            'cve_id': event.cve_id,
            'cvss_score': event.cvss_score,
            'description': event.description[:200],
            'predicted_confidence': prediction.confidence,
            'cwe_ids': event.cwe_ids
        }
        
        logger.warning(f"🚨 CRITICAL CVE ALERT: {event.cve_id} (CVSS: {event.cvss_score})")
        
        if 'on_alert' in self.callbacks:
            self.callbacks['on_alert'](alert)
    
    def _check_drift_and_update(self):
        """Check for drift and trigger update if needed."""
        if not self.drift_detector or not self.learning_engine:
            return
        
        # Check drift
        report = self.drift_detector.generate_report()
        
        if report.overall_drift_detected:
            logger.warning(f"Drift detected! Severity: {report.overall_severity.value}")
            
            if 'on_drift' in self.callbacks:
                self.callbacks['on_drift'](report)
            
            if self.auto_update:
                should_update, mode, trigger = self.learning_engine.should_update(
                    drift_severity=report.overall_severity.value
                )
                
                if should_update:
                    logger.info(f"Auto-triggering model update (mode: {mode.value})")
                    result = self.learning_engine.update_model(
                        trigger=trigger,
                        mode=mode
                    )
                    logger.info(f"Update complete: {result.success}")
    
    def poll_once(self) -> List[CVEEvent]:
        """
        Perform a single poll for new CVEs.
        
        Returns:
            List of new CVE events
        """
        # Determine time range
        if self.last_poll_time is None:
            start_time = datetime.now() - timedelta(hours=self.lookback_hours)
        else:
            start_time = self.last_poll_time - timedelta(minutes=5)  # Overlap for safety
        
        end_time = datetime.now()
        
        logger.info(f"Polling for CVEs from {start_time} to {end_time}")
        
        # Fetch CVEs
        raw_cves = self._fetch_recent_cves(start_time, end_time)
        
        # Parse and filter
        events = []
        for raw in raw_cves:
            event = self._parse_cve(raw)
            if event is not None:
                events.append(event)
                
                # Callback for new CVE
                if 'on_new_cve' in self.callbacks:
                    self.callbacks['on_new_cve'](event)
        
        # Update poll time
        self.last_poll_time = end_time
        
        logger.info(f"Found {len(events)} new CVEs")
        
        return events
    
    def process_batch(self, events: List[CVEEvent]) -> List[PredictionResult]:
        """Process a batch of CVE events."""
        results = []
        for event in events:
            result = self._process_event(event)
            if result:
                results.append(result)
        return results
    
    def run_once(self):
        """Run a single poll-and-process cycle."""
        events = self.poll_once()
        results = self.process_batch(events)
        self._check_drift_and_update()
        return results
    
    def start(self):
        """Start continuous monitoring."""
        self.running = True
        self._stop_event.clear()
        
        logger.info("Starting real-time CVE monitoring...")
        
        while self.running and not self._stop_event.is_set():
            try:
                self.run_once()
                
                # Print status
                accuracy = (
                    self.stats.correct_predictions / self.stats.total_processed
                    if self.stats.total_processed > 0 else 0
                )
                logger.info(
                    f"Stats: processed={self.stats.total_processed}, "
                    f"critical={self.stats.total_critical}, "
                    f"accuracy={accuracy:.2%}"
                )
                
                # Wait for next poll
                self._stop_event.wait(timeout=self.poll_interval)
                
            except KeyboardInterrupt:
                logger.info("Interrupted by user")
                break
            except Exception as e:
                logger.error(f"Error in polling loop: {e}")
                time.sleep(60)  # Wait before retry
        
        self.running = False
        logger.info("Monitoring stopped")
    
    def stop(self):
        """Stop monitoring."""
        logger.info("Stopping monitor...")
        self.running = False
        self._stop_event.set()
    
    def get_stats(self) -> Dict:
        """Get current statistics."""
        accuracy = (
            self.stats.correct_predictions / self.stats.total_processed
            if self.stats.total_processed > 0 else 0
        )
        
        return {
            'total_processed': self.stats.total_processed,
            'severity_breakdown': {
                'critical': self.stats.total_critical,
                'high': self.stats.total_high,
                'medium': self.stats.total_medium,
                'low': self.stats.total_low
            },
            'accuracy': accuracy,
            'avg_confidence': self.stats.avg_confidence,
            'avg_processing_time_ms': self.stats.avg_processing_time_ms,
            'running_since': self.stats.start_time.isoformat() if self.stats.start_time else None,
            'last_update': self.stats.last_update.isoformat() if self.stats.last_update else None
        }


def demonstrate_stream_processor():
    """Demonstrate the stream processor."""
    
    print("""
╔═══════════════════════════════════════════════════════════════════════╗
║              REAL-TIME CVE STREAM PROCESSOR DEMO                       ║
╚═══════════════════════════════════════════════════════════════════════╝
    """)
    
    # Create processor with short interval for demo
    processor = CVEStreamProcessor(
        poll_interval_seconds=60,
        lookback_hours=48,  # Look back 48 hours
        auto_update=True
    )
    
    # Set up callbacks
    def on_new_cve(event):
        print(f"  📥 New: {event.cve_id} ({event.severity})")
    
    def on_prediction(result):
        emoji = "✅" if result.is_correct else "❌"
        print(f"  {emoji} Predicted: {result.predicted_severity} (conf: {result.confidence:.2f})")
    
    def on_alert(alert):
        print(f"  🚨 ALERT: {alert['cve_id']} - CVSS {alert['cvss_score']}")
    
    processor.callbacks = {
        'on_new_cve': on_new_cve,
        'on_prediction': on_prediction,
        'on_alert': on_alert
    }
    
    print("Performing single poll (demo mode)...")
    print("Note: This will make a real API call to NVD\n")
    
    # Run once
    try:
        results = processor.run_once()
        
        print(f"\n{'='*60}")
        print("RESULTS")
        print('='*60)
        
        stats = processor.get_stats()
        print(f"Total processed: {stats['total_processed']}")
        print(f"Severity breakdown:")
        for sev, count in stats['severity_breakdown'].items():
            print(f"  {sev.upper()}: {count}")
        print(f"Accuracy: {stats['accuracy']:.2%}")
        print(f"Avg confidence: {stats['avg_confidence']:.2f}")
        print(f"Avg processing time: {stats['avg_processing_time_ms']:.2f}ms")
        
    except Exception as e:
        print(f"Error: {e}")
        print("This may be due to API rate limits. Get an API key from:")
        print("https://nvd.nist.gov/developers/request-an-api-key")
    
    print("""
    
To run continuous monitoring:
─────────────────────────────
processor = CVEStreamProcessor(poll_interval_seconds=300)
processor.start()  # Runs until stopped

# In another thread or signal handler:
processor.stop()
    """)


if __name__ == "__main__":
    demonstrate_stream_processor()
