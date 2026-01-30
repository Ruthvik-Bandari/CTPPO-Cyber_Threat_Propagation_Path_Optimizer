#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CTPPO v2.0 - Step 5: Evaluate Model
====================================

Evaluates the trained model on the test set with:
1. Overall metrics (accuracy, F1, precision, recall)
2. Per-class metrics
3. Confusion matrix
4. Error analysis
5. Sample predictions

Run AFTER: 04_train_model.py

Usage:
    python ml/05_evaluate_model.py
    python ml/05_evaluate_model.py --model models/severity_classifier

Author: Ruthvik
Date: January 2026
"""

import os
import sys
import json
import logging
import numpy as np
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from collections import Counter

import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from transformers import DistilBertTokenizer, DistilBertModel
from sklearn.metrics import (
    accuracy_score, 
    f1_score, 
    precision_score, 
    recall_score,
    classification_report,
    confusion_matrix
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# =============================================================================
# MODEL (same as training)
# =============================================================================

class SeverityClassifier(nn.Module):
    """DistilBERT-based severity classifier."""
    
    def __init__(
        self,
        model_name: str = "distilbert-base-uncased",
        num_classes: int = 4,
        dropout: float = 0.3
    ):
        super().__init__()
        
        self.bert = DistilBertModel.from_pretrained(model_name)
        hidden_size = self.bert.config.hidden_size
        
        self.classifier = nn.Sequential(
            nn.Dropout(dropout),
            nn.Linear(hidden_size, 256),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(256, num_classes)
        )
    
    def forward(self, input_ids, attention_mask):
        outputs = self.bert(input_ids=input_ids, attention_mask=attention_mask)
        cls_output = outputs.last_hidden_state[:, 0, :]
        logits = self.classifier(cls_output)
        return logits


# =============================================================================
# DATASET (same as training)
# =============================================================================

class CVEDataset(Dataset):
    """PyTorch Dataset for CVE severity classification."""
    
    LABEL_MAP = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    LABEL_NAMES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    
    def __init__(self, data_path: str, tokenizer, max_length: int = 256):
        self.tokenizer = tokenizer
        self.max_length = max_length
        
        self.records = []
        with open(data_path, 'r') as f:
            for line in f:
                record = json.loads(line)
                severity = record.get('severity', 'UNKNOWN')
                if severity in self.LABEL_MAP:
                    self.records.append(record)
        
        logger.info(f"Loaded {len(self.records)} records from {data_path}")
    
    def __len__(self):
        return len(self.records)
    
    def __getitem__(self, idx):
        record = self.records[idx]
        text = record.get('description', '')
        severity = record.get('severity')
        label = self.LABEL_MAP[severity]
        
        encoding = self.tokenizer(
            text,
            truncation=True,
            padding='max_length',
            max_length=self.max_length,
            return_tensors='pt'
        )
        
        return {
            'input_ids': encoding['input_ids'].squeeze(0),
            'attention_mask': encoding['attention_mask'].squeeze(0),
            'label': torch.tensor(label, dtype=torch.long),
            'cve_id': record.get('cve_id', ''),
            'text': text[:200]  # First 200 chars for display
        }


# =============================================================================
# EVALUATOR
# =============================================================================

class ModelEvaluator:
    """Evaluate trained model on test set."""
    
    LABEL_NAMES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    
    def __init__(
        self,
        model_dir: str,
        test_data_path: str,
        batch_size: int = 32,
        device: str = None
    ):
        self.model_dir = Path(model_dir)
        self.test_data_path = test_data_path
        self.batch_size = batch_size
        self.device = torch.device(
            device or ("cuda" if torch.cuda.is_available() else 
                      "mps" if torch.backends.mps.is_available() else "cpu")
        )
        
        logger.info(f"Using device: {self.device}")
        
        # Load tokenizer
        self.tokenizer = DistilBertTokenizer.from_pretrained(
            self.model_dir / "tokenizer"
        )
        
        # Load model
        self.model = self._load_model()
    
    def _load_model(self) -> SeverityClassifier:
        """Load trained model from checkpoint."""
        
        # Load checkpoint
        checkpoint_path = self.model_dir / "checkpoint_best.pt"
        checkpoint = torch.load(checkpoint_path, map_location=self.device)
        
        # Get config
        config = checkpoint.get('config', {})
        
        # Create model
        model = SeverityClassifier(
            model_name=config.get('model_name', 'distilbert-base-uncased'),
            num_classes=config.get('num_classes', 4),
            dropout=config.get('dropout', 0.3)
        )
        
        # Load weights
        model.load_state_dict(checkpoint['model_state_dict'])
        model.to(self.device)
        model.eval()
        
        logger.info(f"Loaded model from {checkpoint_path}")
        logger.info(f"Best Val F1 during training: {checkpoint.get('best_val_f1', 'N/A'):.4f}")
        
        return model
    
    def evaluate(self) -> Dict[str, Any]:
        """Run full evaluation on test set."""
        
        # Create dataset and dataloader
        test_dataset = CVEDataset(
            self.test_data_path,
            self.tokenizer
        )
        
        test_loader = DataLoader(
            test_dataset,
            batch_size=self.batch_size,
            shuffle=False
        )
        
        # Collect predictions
        all_preds = []
        all_labels = []
        all_probs = []
        sample_predictions = []
        
        logger.info("Running evaluation...")
        
        with torch.no_grad():
            for batch_idx, batch in enumerate(test_loader):
                input_ids = batch['input_ids'].to(self.device)
                attention_mask = batch['attention_mask'].to(self.device)
                labels = batch['label']
                
                # Forward pass
                logits = self.model(input_ids, attention_mask)
                probs = torch.softmax(logits, dim=1)
                preds = torch.argmax(logits, dim=1)
                
                all_preds.extend(preds.cpu().numpy())
                all_labels.extend(labels.numpy())
                all_probs.extend(probs.cpu().numpy())
                
                # Collect sample predictions (first 50)
                if len(sample_predictions) < 50:
                    for i in range(len(preds)):
                        if len(sample_predictions) >= 50:
                            break
                        sample_predictions.append({
                            'cve_id': batch['cve_id'][i],
                            'text': batch['text'][i],
                            'true_label': self.LABEL_NAMES[labels[i].item()],
                            'pred_label': self.LABEL_NAMES[preds[i].item()],
                            'confidence': probs[i][preds[i]].item(),
                            'correct': preds[i].item() == labels[i].item()
                        })
                
                if (batch_idx + 1) % 100 == 0:
                    logger.info(f"Processed {batch_idx + 1}/{len(test_loader)} batches")
        
        # Calculate metrics
        all_preds = np.array(all_preds)
        all_labels = np.array(all_labels)
        all_probs = np.array(all_probs)
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'test_samples': len(all_labels),
            'metrics': self._calculate_metrics(all_labels, all_preds),
            'confusion_matrix': confusion_matrix(all_labels, all_preds).tolist(),
            'per_class_report': classification_report(
                all_labels, all_preds,
                target_names=self.LABEL_NAMES,
                output_dict=True,
                zero_division=0
            ),
            'error_analysis': self._analyze_errors(all_labels, all_preds, all_probs),
            'sample_predictions': sample_predictions
        }
        
        # Save results
        results_path = self.model_dir / "test_results.json"
        with open(results_path, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        logger.info(f"Results saved to {results_path}")
        
        return results
    
    def _calculate_metrics(self, labels, preds) -> Dict[str, float]:
        """Calculate overall metrics."""
        return {
            'accuracy': accuracy_score(labels, preds),
            'f1_weighted': f1_score(labels, preds, average='weighted'),
            'f1_macro': f1_score(labels, preds, average='macro'),
            'precision_weighted': precision_score(labels, preds, average='weighted', zero_division=0),
            'recall_weighted': recall_score(labels, preds, average='weighted', zero_division=0)
        }
    
    def _analyze_errors(self, labels, preds, probs) -> Dict[str, Any]:
        """Analyze prediction errors."""
        
        errors = labels != preds
        error_indices = np.where(errors)[0]
        
        # Error breakdown by class
        error_by_class = {}
        for i, name in enumerate(self.LABEL_NAMES):
            class_mask = labels == i
            class_errors = errors[class_mask].sum()
            class_total = class_mask.sum()
            error_by_class[name] = {
                'total': int(class_total),
                'errors': int(class_errors),
                'error_rate': float(class_errors / class_total) if class_total > 0 else 0
            }
        
        # Most common misclassifications
        misclass_counter = Counter()
        for idx in error_indices:
            true_label = self.LABEL_NAMES[labels[idx]]
            pred_label = self.LABEL_NAMES[preds[idx]]
            misclass_counter[(true_label, pred_label)] += 1
        
        common_errors = [
            {'true': t, 'predicted': p, 'count': c}
            for (t, p), c in misclass_counter.most_common(10)
        ]
        
        # Confidence analysis
        correct_probs = probs[~errors].max(axis=1)
        error_probs = probs[errors].max(axis=1) if errors.any() else []
        
        return {
            'total_errors': int(errors.sum()),
            'error_rate': float(errors.mean()),
            'error_by_class': error_by_class,
            'common_misclassifications': common_errors,
            'avg_confidence_correct': float(correct_probs.mean()) if len(correct_probs) > 0 else 0,
            'avg_confidence_errors': float(np.mean(error_probs)) if len(error_probs) > 0 else 0
        }
    
    def print_report(self, results: Dict[str, Any]):
        """Print evaluation report."""
        
        print("""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                       TEST SET EVALUATION REPORT                              ║
║                    Step 5: Final Model Evaluation                             ║
╚═══════════════════════════════════════════════════════════════════════════════╝
        """)
        
        # Overall Metrics
        print("="*80)
        print("1. OVERALL METRICS")
        print("="*80)
        
        m = results['metrics']
        print(f"""
   📊 Test Samples: {results['test_samples']:,}
   
   🎯 Accuracy:          {m['accuracy']:.4f} ({m['accuracy']*100:.2f}%)
   🎯 F1 (Weighted):     {m['f1_weighted']:.4f}
   🎯 F1 (Macro):        {m['f1_macro']:.4f}
   🎯 Precision:         {m['precision_weighted']:.4f}
   🎯 Recall:            {m['recall_weighted']:.4f}
        """)
        
        # Per-Class Metrics
        print("="*80)
        print("2. PER-CLASS METRICS")
        print("="*80)
        
        report = results['per_class_report']
        
        print(f"\n   {'Class':<12} {'Precision':>10} {'Recall':>10} {'F1':>10} {'Support':>10}")
        print("   " + "-"*55)
        
        for label in self.LABEL_NAMES:
            if label in report:
                r = report[label]
                print(f"   {label:<12} {r['precision']:>10.4f} {r['recall']:>10.4f} {r['f1-score']:>10.4f} {r['support']:>10.0f}")
        
        # Confusion Matrix
        print("\n" + "="*80)
        print("3. CONFUSION MATRIX")
        print("="*80)
        
        cm = np.array(results['confusion_matrix'])
        
        print(f"\n   {'Predicted →':<12}", end="")
        for label in self.LABEL_NAMES:
            print(f"{label[:8]:>10}", end="")
        print("\n   " + "-"*55)
        
        for i, label in enumerate(self.LABEL_NAMES):
            print(f"   {label:<12}", end="")
            for j in range(len(self.LABEL_NAMES)):
                print(f"{cm[i][j]:>10}", end="")
            print()
        
        # Error Analysis
        print("\n" + "="*80)
        print("4. ERROR ANALYSIS")
        print("="*80)
        
        ea = results['error_analysis']
        
        print(f"""
   ❌ Total Errors: {ea['total_errors']:,} / {results['test_samples']:,}
   📉 Error Rate: {ea['error_rate']*100:.2f}%
   
   🎯 Avg Confidence (Correct): {ea['avg_confidence_correct']:.4f}
   🎯 Avg Confidence (Errors):  {ea['avg_confidence_errors']:.4f}
        """)
        
        print("\n   📊 Error Rate by Class:")
        for label, data in ea['error_by_class'].items():
            bar = "█" * int(data['error_rate'] * 30)
            print(f"      {label:<10}: {data['error_rate']*100:>5.1f}% ({data['errors']}/{data['total']}) {bar}")
        
        print("\n   🔄 Most Common Misclassifications:")
        for err in ea['common_misclassifications'][:5]:
            print(f"      {err['true']} → {err['predicted']}: {err['count']} times")
        
        # Sample Predictions
        print("\n" + "="*80)
        print("5. SAMPLE PREDICTIONS")
        print("="*80)
        
        print("\n   ✅ Correct Predictions:")
        correct = [s for s in results['sample_predictions'] if s['correct']][:3]
        for s in correct:
            print(f"      {s['cve_id']}: {s['true_label']} (conf: {s['confidence']:.2f})")
            print(f"         \"{s['text'][:80]}...\"")
        
        print("\n   ❌ Incorrect Predictions:")
        incorrect = [s for s in results['sample_predictions'] if not s['correct']][:3]
        for s in incorrect:
            print(f"      {s['cve_id']}: True={s['true_label']}, Pred={s['pred_label']} (conf: {s['confidence']:.2f})")
            print(f"         \"{s['text'][:80]}...\"")
        
        # Summary
        print("\n" + "="*80)
        print("✅ EVALUATION COMPLETE!")
        print("="*80)
        
        print(f"""
   🏆 Final Test Results:
      Accuracy: {m['accuracy']*100:.2f}%
      F1 Score: {m['f1_weighted']:.4f}
   
   📁 Results saved to: {self.model_dir}/test_results.json
   
   🚀 Model is ready for production use!
        """)


# =============================================================================
# MAIN
# =============================================================================

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Evaluate trained model on test set")
    
    parser.add_argument(
        "--model", "-m",
        type=str,
        default="./models/severity_classifier",
        help="Path to model directory"
    )
    parser.add_argument(
        "--test-data", "-t",
        type=str,
        default="./data/splits/test.jsonl",
        help="Path to test data"
    )
    parser.add_argument(
        "--batch-size", "-b",
        type=int,
        default=32,
        help="Batch size for evaluation"
    )
    
    args = parser.parse_args()
    
    # Create evaluator
    evaluator = ModelEvaluator(
        model_dir=args.model,
        test_data_path=args.test_data,
        batch_size=args.batch_size
    )
    
    # Evaluate
    try:
        results = evaluator.evaluate()
        evaluator.print_report(results)
        
    except FileNotFoundError as e:
        logger.error(f"File not found: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Evaluation error: {e}")
        raise


if __name__ == "__main__":
    main()
