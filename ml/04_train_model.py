#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CTPPO v2.0 - Step 4: Train Model
=================================

Trains a DistilBERT-based severity classifier with:
1. Pre-trained transformer (DistilBERT)
2. Class weights for imbalance handling
3. Early stopping
4. Learning rate scheduling
5. Checkpoint saving

Run AFTER: 03_prepare_dataset.py
Run BEFORE: 05_evaluate_model.py

Usage:
    python ml/04_train_model.py
    python ml/04_train_model.py --epochs 5 --batch-size 32
    python ml/04_train_model.py --quick  # Fast test run

Author: Ruthvik
Date: January 2026
"""

import os
import sys
import json
import logging
import time
import numpy as np
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple

import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from torch.optim import AdamW
from torch.optim.lr_scheduler import ReduceLROnPlateau
from transformers import DistilBertTokenizer, DistilBertModel, get_linear_schedule_with_warmup
from sklearn.metrics import accuracy_score, f1_score, classification_report

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# =============================================================================
# CONFIGURATION
# =============================================================================

class TrainingConfig:
    """Training configuration."""
    
    def __init__(
        self,
        # Model
        model_name: str = "distilbert-base-uncased",
        num_classes: int = 4,  # CRITICAL, HIGH, MEDIUM, LOW (exclude NONE)
        dropout: float = 0.3,
        
        # Training
        epochs: int = 5,
        batch_size: int = 32,
        learning_rate: float = 2e-5,
        weight_decay: float = 0.01,
        warmup_ratio: float = 0.1,
        max_length: int = 256,
        
        # Early stopping
        patience: int = 3,
        min_delta: float = 0.001,
        
        # Paths
        data_dir: str = "./data/splits",
        output_dir: str = "./models/severity_classifier",
        
        # Hardware
        device: str = None,
        num_workers: int = 0,
        
        # Options
        use_class_weights: bool = True,
        exclude_none_class: bool = True,
    ):
        self.model_name = model_name
        self.num_classes = num_classes
        self.dropout = dropout
        
        self.epochs = epochs
        self.batch_size = batch_size
        self.learning_rate = learning_rate
        self.weight_decay = weight_decay
        self.warmup_ratio = warmup_ratio
        self.max_length = max_length
        
        self.patience = patience
        self.min_delta = min_delta
        
        self.data_dir = data_dir
        self.output_dir = output_dir
        
        self.device = device or ("cuda" if torch.cuda.is_available() else "mps" if torch.backends.mps.is_available() else "cpu")
        self.num_workers = num_workers
        
        self.use_class_weights = use_class_weights
        self.exclude_none_class = exclude_none_class
    
    def to_dict(self) -> Dict:
        return {k: v for k, v in self.__dict__.items()}


# =============================================================================
# DATASET
# =============================================================================

class CVEDataset(Dataset):
    """
    PyTorch Dataset for CVE severity classification.
    """
    
    # Label mapping (excluding NONE)
    LABEL_MAP = {
        'CRITICAL': 0,
        'HIGH': 1,
        'MEDIUM': 2,
        'LOW': 3
    }
    
    LABEL_NAMES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    
    def __init__(
        self,
        data_path: str,
        tokenizer: DistilBertTokenizer,
        max_length: int = 256,
        exclude_none: bool = True
    ):
        """
        Initialize dataset.
        
        Args:
            data_path: Path to JSONL file
            tokenizer: HuggingFace tokenizer
            max_length: Maximum sequence length
            exclude_none: Exclude NONE class (too few samples)
        """
        self.tokenizer = tokenizer
        self.max_length = max_length
        self.exclude_none = exclude_none
        
        # Load data
        self.records = []
        with open(data_path, 'r') as f:
            for line in f:
                record = json.loads(line)
                severity = record.get('severity', 'UNKNOWN')
                
                # Skip NONE class if configured
                if exclude_none and severity == 'NONE':
                    continue
                
                # Skip unknown
                if severity not in self.LABEL_MAP:
                    continue
                
                self.records.append(record)
        
        logger.info(f"Loaded {len(self.records)} records from {data_path}")
    
    def __len__(self) -> int:
        return len(self.records)
    
    def __getitem__(self, idx: int) -> Dict[str, torch.Tensor]:
        record = self.records[idx]
        
        # Get text (use cleaned description)
        text = record.get('description', '')
        
        # Get label
        severity = record.get('severity')
        label = self.LABEL_MAP[severity]
        
        # Tokenize
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
            'label': torch.tensor(label, dtype=torch.long)
        }
    
    def get_class_counts(self) -> Dict[str, int]:
        """Get class distribution."""
        from collections import Counter
        counts = Counter(r.get('severity') for r in self.records)
        return dict(counts)


# =============================================================================
# MODEL
# =============================================================================

class SeverityClassifier(nn.Module):
    """
    DistilBERT-based severity classifier.
    
    Architecture:
        DistilBERT -> [CLS] pooling -> Dropout -> FC -> Softmax
    """
    
    def __init__(
        self,
        model_name: str = "distilbert-base-uncased",
        num_classes: int = 4,
        dropout: float = 0.3,
        freeze_bert: bool = False
    ):
        super().__init__()
        
        # Load pre-trained DistilBERT
        self.bert = DistilBertModel.from_pretrained(model_name)
        
        # Optionally freeze BERT layers
        if freeze_bert:
            for param in self.bert.parameters():
                param.requires_grad = False
        
        # Classification head
        hidden_size = self.bert.config.hidden_size  # 768 for distilbert
        
        self.classifier = nn.Sequential(
            nn.Dropout(dropout),
            nn.Linear(hidden_size, 256),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(256, num_classes)
        )
    
    def forward(
        self,
        input_ids: torch.Tensor,
        attention_mask: torch.Tensor
    ) -> torch.Tensor:
        """
        Forward pass.
        
        Args:
            input_ids: Token IDs [batch, seq_len]
            attention_mask: Attention mask [batch, seq_len]
            
        Returns:
            Logits [batch, num_classes]
        """
        # Get BERT outputs
        outputs = self.bert(
            input_ids=input_ids,
            attention_mask=attention_mask
        )
        
        # Use [CLS] token representation
        cls_output = outputs.last_hidden_state[:, 0, :]
        
        # Classify
        logits = self.classifier(cls_output)
        
        return logits


# =============================================================================
# TRAINER
# =============================================================================

class Trainer:
    """
    Training loop with early stopping, checkpointing, and metrics tracking.
    """
    
    def __init__(self, config: TrainingConfig):
        self.config = config
        self.device = torch.device(config.device)
        
        logger.info(f"Using device: {self.device}")
        
        # Create output directory
        Path(config.output_dir).mkdir(parents=True, exist_ok=True)
        
        # Initialize tokenizer
        self.tokenizer = DistilBertTokenizer.from_pretrained(config.model_name)
        
        # Initialize model
        self.model = SeverityClassifier(
            model_name=config.model_name,
            num_classes=config.num_classes,
            dropout=config.dropout
        ).to(self.device)
        
        # Training history
        self.history = {
            'train_loss': [],
            'val_loss': [],
            'val_accuracy': [],
            'val_f1': [],
            'learning_rates': []
        }
        
        # Best model tracking
        self.best_val_f1 = 0
        self.best_epoch = 0
        self.epochs_without_improvement = 0
    
    def _create_dataloaders(self) -> Tuple[DataLoader, DataLoader]:
        """Create train and validation dataloaders."""
        
        train_dataset = CVEDataset(
            data_path=f"{self.config.data_dir}/train.jsonl",
            tokenizer=self.tokenizer,
            max_length=self.config.max_length,
            exclude_none=self.config.exclude_none_class
        )
        
        val_dataset = CVEDataset(
            data_path=f"{self.config.data_dir}/val.jsonl",
            tokenizer=self.tokenizer,
            max_length=self.config.max_length,
            exclude_none=self.config.exclude_none_class
        )
        
        train_loader = DataLoader(
            train_dataset,
            batch_size=self.config.batch_size,
            shuffle=True,
            num_workers=self.config.num_workers,
            pin_memory=True if self.device.type == 'cuda' else False
        )
        
        val_loader = DataLoader(
            val_dataset,
            batch_size=self.config.batch_size,
            shuffle=False,
            num_workers=self.config.num_workers,
            pin_memory=True if self.device.type == 'cuda' else False
        )
        
        return train_loader, val_loader, train_dataset.get_class_counts()
    
    def _create_optimizer_and_scheduler(
        self,
        num_training_steps: int
    ) -> Tuple[torch.optim.Optimizer, Any]:
        """Create optimizer and learning rate scheduler."""
        
        # AdamW optimizer with weight decay
        optimizer = AdamW(
            self.model.parameters(),
            lr=self.config.learning_rate,
            weight_decay=self.config.weight_decay
        )
        
        # Linear warmup scheduler
        num_warmup_steps = int(num_training_steps * self.config.warmup_ratio)
        scheduler = get_linear_schedule_with_warmup(
            optimizer,
            num_warmup_steps=num_warmup_steps,
            num_training_steps=num_training_steps
        )
        
        return optimizer, scheduler
    
    def _calculate_class_weights(self, class_counts: Dict[str, int]) -> torch.Tensor:
        """Calculate class weights for imbalanced data."""
        
        # Order: CRITICAL, HIGH, MEDIUM, LOW
        counts = [
            class_counts.get('CRITICAL', 0),
            class_counts.get('HIGH', 0),
            class_counts.get('MEDIUM', 0),
            class_counts.get('LOW', 0)
        ]
        
        total = sum(counts)
        n_classes = len(counts)
        
        # Inverse frequency weighting
        weights = [total / (n_classes * c) if c > 0 else 0 for c in counts]
        
        # Normalize
        min_weight = min(w for w in weights if w > 0)
        weights = [w / min_weight for w in weights]
        
        return torch.tensor(weights, dtype=torch.float32).to(self.device)
    
    def _train_epoch(
        self,
        train_loader: DataLoader,
        optimizer: torch.optim.Optimizer,
        scheduler: Any,
        criterion: nn.Module,
        epoch: int
    ) -> float:
        """Train for one epoch."""
        
        self.model.train()
        total_loss = 0
        num_batches = len(train_loader)
        
        for batch_idx, batch in enumerate(train_loader):
            # Move to device
            input_ids = batch['input_ids'].to(self.device)
            attention_mask = batch['attention_mask'].to(self.device)
            labels = batch['label'].to(self.device)
            
            # Forward pass
            optimizer.zero_grad()
            logits = self.model(input_ids, attention_mask)
            loss = criterion(logits, labels)
            
            # Backward pass
            loss.backward()
            torch.nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)
            optimizer.step()
            scheduler.step()
            
            total_loss += loss.item()
            
            # Progress logging
            if (batch_idx + 1) % 100 == 0:
                avg_loss = total_loss / (batch_idx + 1)
                current_lr = scheduler.get_last_lr()[0]
                logger.info(
                    f"Epoch {epoch+1} | Batch {batch_idx+1}/{num_batches} | "
                    f"Loss: {avg_loss:.4f} | LR: {current_lr:.2e}"
                )
        
        return total_loss / num_batches
    
    def _validate(
        self,
        val_loader: DataLoader,
        criterion: nn.Module
    ) -> Tuple[float, float, float, Dict]:
        """Validate model."""
        
        self.model.eval()
        total_loss = 0
        all_preds = []
        all_labels = []
        
        with torch.no_grad():
            for batch in val_loader:
                input_ids = batch['input_ids'].to(self.device)
                attention_mask = batch['attention_mask'].to(self.device)
                labels = batch['label'].to(self.device)
                
                logits = self.model(input_ids, attention_mask)
                loss = criterion(logits, labels)
                
                total_loss += loss.item()
                
                preds = torch.argmax(logits, dim=1)
                all_preds.extend(preds.cpu().numpy())
                all_labels.extend(labels.cpu().numpy())
        
        # Calculate metrics
        avg_loss = total_loss / len(val_loader)
        accuracy = accuracy_score(all_labels, all_preds)
        f1 = f1_score(all_labels, all_preds, average='weighted')
        
        # Per-class report
        report = classification_report(
            all_labels,
            all_preds,
            target_names=CVEDataset.LABEL_NAMES,
            output_dict=True,
            zero_division=0
        )
        
        return avg_loss, accuracy, f1, report
    
    def _save_checkpoint(self, epoch: int, is_best: bool = False):
        """Save model checkpoint."""
        
        checkpoint = {
            'epoch': epoch,
            'model_state_dict': self.model.state_dict(),
            'config': self.config.to_dict(),
            'history': self.history,
            'best_val_f1': self.best_val_f1
        }
        
        # Save latest
        torch.save(checkpoint, f"{self.config.output_dir}/checkpoint_latest.pt")
        
        # Save best
        if is_best:
            torch.save(checkpoint, f"{self.config.output_dir}/checkpoint_best.pt")
            
            # Also save just the model for inference
            torch.save(
                self.model.state_dict(),
                f"{self.config.output_dir}/model_best.pt"
            )
            
            # Save tokenizer
            self.tokenizer.save_pretrained(f"{self.config.output_dir}/tokenizer")
    
    def train(self) -> Dict[str, Any]:
        """
        Full training loop.
        
        Returns:
            Training results dictionary
        """
        logger.info("="*60)
        logger.info("Starting training...")
        logger.info("="*60)
        
        # Create dataloaders
        train_loader, val_loader, class_counts = self._create_dataloaders()
        
        logger.info(f"Training samples: {len(train_loader.dataset):,}")
        logger.info(f"Validation samples: {len(val_loader.dataset):,}")
        logger.info(f"Class distribution: {class_counts}")
        
        # Calculate class weights
        if self.config.use_class_weights:
            class_weights = self._calculate_class_weights(class_counts)
            logger.info(f"Class weights: {class_weights.tolist()}")
            criterion = nn.CrossEntropyLoss(weight=class_weights)
        else:
            criterion = nn.CrossEntropyLoss()
        
        # Create optimizer and scheduler
        num_training_steps = len(train_loader) * self.config.epochs
        optimizer, scheduler = self._create_optimizer_and_scheduler(num_training_steps)
        
        # Training loop
        start_time = time.time()
        
        for epoch in range(self.config.epochs):
            epoch_start = time.time()
            
            logger.info(f"\n{'='*60}")
            logger.info(f"Epoch {epoch + 1}/{self.config.epochs}")
            logger.info(f"{'='*60}")
            
            # Train
            train_loss = self._train_epoch(
                train_loader, optimizer, scheduler, criterion, epoch
            )
            
            # Validate
            val_loss, val_accuracy, val_f1, val_report = self._validate(
                val_loader, criterion
            )
            
            # Record history
            self.history['train_loss'].append(train_loss)
            self.history['val_loss'].append(val_loss)
            self.history['val_accuracy'].append(val_accuracy)
            self.history['val_f1'].append(val_f1)
            self.history['learning_rates'].append(scheduler.get_last_lr()[0])
            
            # Log results
            epoch_time = time.time() - epoch_start
            logger.info(f"\nEpoch {epoch + 1} Results:")
            logger.info(f"  Train Loss: {train_loss:.4f}")
            logger.info(f"  Val Loss:   {val_loss:.4f}")
            logger.info(f"  Val Acc:    {val_accuracy:.4f}")
            logger.info(f"  Val F1:     {val_f1:.4f}")
            logger.info(f"  Time:       {epoch_time:.1f}s")
            
            # Per-class metrics
            logger.info("\n  Per-class F1:")
            for label in CVEDataset.LABEL_NAMES:
                if label in val_report:
                    f1_class = val_report[label]['f1-score']
                    logger.info(f"    {label}: {f1_class:.4f}")
            
            # Check for improvement
            is_best = val_f1 > self.best_val_f1 + self.config.min_delta
            
            if is_best:
                self.best_val_f1 = val_f1
                self.best_epoch = epoch + 1
                self.epochs_without_improvement = 0
                logger.info(f"  ✓ New best model! F1: {val_f1:.4f}")
            else:
                self.epochs_without_improvement += 1
                logger.info(f"  No improvement for {self.epochs_without_improvement} epoch(s)")
            
            # Save checkpoint
            self._save_checkpoint(epoch + 1, is_best)
            
            # Early stopping
            if self.epochs_without_improvement >= self.config.patience:
                logger.info(f"\nEarly stopping triggered after {epoch + 1} epochs")
                break
        
        # Training complete
        total_time = time.time() - start_time
        
        # Final results
        results = {
            'training_time_seconds': total_time,
            'epochs_trained': epoch + 1,
            'best_epoch': self.best_epoch,
            'best_val_f1': self.best_val_f1,
            'final_train_loss': self.history['train_loss'][-1],
            'final_val_loss': self.history['val_loss'][-1],
            'final_val_accuracy': self.history['val_accuracy'][-1],
            'final_val_f1': self.history['val_f1'][-1],
            'history': self.history,
            'config': self.config.to_dict()
        }
        
        # Save results
        with open(f"{self.config.output_dir}/training_results.json", 'w') as f:
            json.dump(results, f, indent=2)
        
        return results
    
    def print_report(self, results: Dict[str, Any]):
        """Print training report."""
        
        print("""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                        TRAINING REPORT                                        ║
║                  Step 4: Model Training Complete                              ║
╚═══════════════════════════════════════════════════════════════════════════════╝
        """)
        
        print("="*80)
        print("1. TRAINING SUMMARY")
        print("="*80)
        
        minutes = results['training_time_seconds'] / 60
        print(f"""
   ⏱️  Training Time: {minutes:.1f} minutes
   📊 Epochs Trained: {results['epochs_trained']}
   🏆 Best Epoch: {results['best_epoch']}
        """)
        
        print("="*80)
        print("2. FINAL METRICS")
        print("="*80)
        
        print(f"""
   📉 Train Loss: {results['final_train_loss']:.4f}
   📉 Val Loss:   {results['final_val_loss']:.4f}
   
   🎯 Val Accuracy: {results['final_val_accuracy']:.4f} ({results['final_val_accuracy']*100:.1f}%)
   🎯 Val F1 Score: {results['final_val_f1']:.4f}
   
   🏆 Best Val F1:  {results['best_val_f1']:.4f}
        """)
        
        print("="*80)
        print("3. TRAINING HISTORY")
        print("="*80)
        
        print("\n   Epoch | Train Loss | Val Loss | Val Acc | Val F1")
        print("   " + "-"*55)
        
        for i, (tl, vl, va, vf) in enumerate(zip(
            results['history']['train_loss'],
            results['history']['val_loss'],
            results['history']['val_accuracy'],
            results['history']['val_f1']
        )):
            marker = " ✓" if (i + 1) == results['best_epoch'] else ""
            print(f"   {i+1:^5} | {tl:^10.4f} | {vl:^8.4f} | {va:^7.1%} | {vf:^6.4f}{marker}")
        
        print("\n" + "="*80)
        print("4. MODEL SAVED")
        print("="*80)
        
        print(f"""
   📁 Output Directory: {self.config.output_dir}
   
   Files:
      checkpoint_best.pt     - Best model checkpoint
      model_best.pt          - Model weights only
      tokenizer/             - Tokenizer files
      training_results.json  - Training metrics
        """)
        
        print("="*80)
        print("✅ Training complete!")
        print("="*80)
        
        print(f"""
   Next Step: Run 05_evaluate_model.py to evaluate on test set
   
   Quick test:
      python ml/05_evaluate_model.py --model {self.config.output_dir}
        """)


# =============================================================================
# MAIN
# =============================================================================

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Train CVE severity classifier",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Default training
  python ml/04_train_model.py
  
  # Custom epochs and batch size
  python ml/04_train_model.py --epochs 10 --batch-size 16
  
  # Quick test run (small epochs, sample data)
  python ml/04_train_model.py --quick
  
  # Resume from checkpoint (TODO)
  python ml/04_train_model.py --resume models/severity_classifier/checkpoint_latest.pt
        """
    )
    
    parser.add_argument("--epochs", type=int, default=5, help="Number of epochs")
    parser.add_argument("--batch-size", type=int, default=32, help="Batch size")
    parser.add_argument("--learning-rate", type=float, default=2e-5, help="Learning rate")
    parser.add_argument("--max-length", type=int, default=256, help="Max sequence length")
    parser.add_argument("--data-dir", type=str, default="./data/splits", help="Data directory")
    parser.add_argument("--output-dir", type=str, default="./models/severity_classifier", help="Output directory")
    parser.add_argument("--patience", type=int, default=3, help="Early stopping patience")
    parser.add_argument("--no-class-weights", action="store_true", help="Disable class weights")
    parser.add_argument("--quick", action="store_true", help="Quick test run (1 epoch)")
    
    args = parser.parse_args()
    
    # Quick mode overrides
    if args.quick:
        args.epochs = 1
        args.batch_size = 64
        logger.info("Quick mode: 1 epoch for testing")
    
    # Create config
    config = TrainingConfig(
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.learning_rate,
        max_length=args.max_length,
        data_dir=args.data_dir,
        output_dir=args.output_dir,
        patience=args.patience,
        use_class_weights=not args.no_class_weights
    )
    
    logger.info(f"Configuration: {config.to_dict()}")
    
    # Create trainer
    trainer = Trainer(config)
    
    # Train
    try:
        results = trainer.train()
        trainer.print_report(results)
        
    except KeyboardInterrupt:
        logger.info("\nTraining interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Training error: {e}")
        raise


if __name__ == "__main__":
    main()
