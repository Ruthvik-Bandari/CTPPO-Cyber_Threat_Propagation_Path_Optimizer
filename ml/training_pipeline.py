# -*- coding: utf-8 -*-
"""
CTPPO v2.0 - Training Pipeline
==============================

Complete training pipeline with proper ML methodology:
- No data leakage
- CVSS-based ground truth
- Stratified splitting
- Class balancing
- Comprehensive evaluation
- Experiment tracking

Author: Ruthvik (Fixed by Claude)
Date: January 2026
"""

import os
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple

import torch
import torch.nn as nn
from torch.optim import AdamW
from torch.utils.data import DataLoader
from transformers import (
    DistilBertTokenizer,
    get_linear_schedule_with_warmup
)
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    classification_report,
    confusion_matrix
)
from tqdm import tqdm

# Import our fixed data pipeline
from ml.data_pipeline.data_collector import CVEDataCollector, Severity
from ml.data_pipeline.data_cleaner import CVECleaner, TextCleaner
from ml.data_pipeline.feature_engineer import FeatureEngineer
from ml.data_pipeline.data_splitter import DataSplitter
from ml.data_pipeline.dataset import CVEDataset, create_dataloaders

# Import model
from models.severity_classifier.model import SeverityClassifier

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TrainingConfig:
    """Training configuration."""
    
    def __init__(
        self,
        # Data
        num_samples: int = 5000,
        test_size: float = 0.15,
        val_size: float = 0.15,
        
        # Model
        model_name: str = "distilbert-base-uncased",
        num_classes: int = 4,
        dropout_rate: float = 0.3,
        freeze_bert: bool = False,
        
        # Training
        epochs: int = 5,
        batch_size: int = 16,
        learning_rate: float = 2e-5,
        weight_decay: float = 0.01,
        warmup_ratio: float = 0.1,
        max_grad_norm: float = 1.0,
        
        # Class balancing
        use_class_weights: bool = True,
        class_weight_method: str = 'balanced',  # 'balanced' or 'sqrt'
        
        # Early stopping
        patience: int = 3,
        min_delta: float = 0.001,
        
        # Paths
        output_dir: str = "./ml/models/severity_classifier_v2",
        data_cache_dir: str = "./data/cache",
        
        # Misc
        random_seed: int = 42,
        device: str = "auto"
    ):
        self.num_samples = num_samples
        self.test_size = test_size
        self.val_size = val_size
        
        self.model_name = model_name
        self.num_classes = num_classes
        self.dropout_rate = dropout_rate
        self.freeze_bert = freeze_bert
        
        self.epochs = epochs
        self.batch_size = batch_size
        self.learning_rate = learning_rate
        self.weight_decay = weight_decay
        self.warmup_ratio = warmup_ratio
        self.max_grad_norm = max_grad_norm
        
        self.use_class_weights = use_class_weights
        self.class_weight_method = class_weight_method
        
        self.patience = patience
        self.min_delta = min_delta
        
        self.output_dir = Path(output_dir)
        self.data_cache_dir = Path(data_cache_dir)
        
        self.random_seed = random_seed
        
        # Auto-detect device
        if device == "auto":
            if torch.cuda.is_available():
                self.device = "cuda"
            elif torch.backends.mps.is_available():
                self.device = "mps"
            else:
                self.device = "cpu"
        else:
            self.device = device
    
    def to_dict(self) -> Dict[str, Any]:
        return {k: str(v) if isinstance(v, Path) else v 
                for k, v in self.__dict__.items()}


class TrainingPipeline:
    """
    Complete training pipeline for CVE severity classification.
    
    This pipeline:
    1. Collects data from NVD API
    2. Cleans and preprocesses text
    3. Engineers features
    4. Splits data with stratification
    5. Trains model with class balancing
    6. Evaluates with proper metrics
    7. Saves model and results
    """
    
    SEVERITY_LABELS = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    
    def __init__(self, config: TrainingConfig):
        """Initialize pipeline with configuration."""
        self.config = config
        
        # Set random seeds for reproducibility
        torch.manual_seed(config.random_seed)
        np.random.seed(config.random_seed)
        
        # Create output directories
        self.config.output_dir.mkdir(parents=True, exist_ok=True)
        self.config.data_cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Training history
        self.history = {
            'train_loss': [],
            'val_loss': [],
            'val_accuracy': [],
            'val_f1': [],
            'learning_rates': []
        }
        
        logger.info(f"Training Pipeline initialized")
        logger.info(f"Device: {config.device}")
        logger.info(f"Output: {config.output_dir}")
    
    def collect_data(self, api_key: Optional[str] = None) -> List[Dict]:
        """
        Step 1: Collect CVE data with GROUND TRUTH labels.
        
        CRITICAL: Labels come from CVSS scores, never from predictions!
        """
        logger.info("="*60)
        logger.info("STEP 1: Data Collection")
        logger.info("="*60)
        
        collector = CVEDataCollector(
            api_key=api_key,
            cache_dir=self.config.data_cache_dir
        )
        
        # Fetch balanced dataset to help with class imbalance
        samples_per_class = self.config.num_samples // 4
        records = collector.fetch_balanced_dataset(
            samples_per_class=samples_per_class
        )
        
        # Convert to dictionaries
        data = [r.to_dict() for r in records]
        
        # Log statistics
        stats = collector.get_statistics(records)
        logger.info(f"Collected {len(data)} CVEs")
        logger.info(f"Severity distribution: {stats['severity_distribution']}")
        
        return data
    
    def clean_data(self, data: List[Dict]) -> List[Dict]:
        """
        Step 2: Clean and preprocess text.
        """
        logger.info("="*60)
        logger.info("STEP 2: Data Cleaning")
        logger.info("="*60)
        
        cleaner = CVECleaner(TextCleaner(
            lowercase=True,
            lemmatize=True,
            remove_stopwords=False  # Keep stopwords for BERT
        ))
        
        cleaned_data = cleaner.clean_records(data)
        
        logger.info(f"Cleaned {len(cleaned_data)} records")
        
        return cleaned_data
    
    def engineer_features(self, data: List[Dict]) -> Tuple[List[str], List[str], np.ndarray]:
        """
        Step 3: Engineer features.
        
        Returns:
            texts: List of cleaned text
            labels: List of severity labels (GROUND TRUTH)
            features: Numerical feature matrix
        """
        logger.info("="*60)
        logger.info("STEP 3: Feature Engineering")
        logger.info("="*60)
        
        engineer = FeatureEngineer()
        feature_sets = engineer.engineer_batch(data)
        
        # Extract components
        texts = [fs.text for fs in feature_sets]
        labels = [fs.severity_label for fs in feature_sets]
        features = np.array([fs.feature_vector for fs in feature_sets])
        
        # Filter out unknown labels
        valid_indices = [i for i, l in enumerate(labels) if l in self.SEVERITY_LABELS]
        texts = [texts[i] for i in valid_indices]
        labels = [labels[i] for i in valid_indices]
        features = features[valid_indices]
        
        logger.info(f"Engineered features for {len(texts)} samples")
        logger.info(f"Feature vector dimension: {features.shape[1]}")
        
        return texts, labels, features
    
    def split_data(
        self, 
        texts: List[str], 
        labels: List[str], 
        features: np.ndarray
    ) -> Dict[str, Any]:
        """
        Step 4: Split data with stratification.
        """
        logger.info("="*60)
        logger.info("STEP 4: Data Splitting")
        logger.info("="*60)
        
        splitter = DataSplitter(random_state=self.config.random_seed)
        
        # Create indices array
        indices = list(range(len(texts)))
        
        # Stratified split
        split = splitter.stratified_split(
            data=indices,
            labels=np.array(labels),
            test_size=self.config.test_size,
            val_size=self.config.val_size
        )
        
        # Extract data for each split
        result = {
            'train': {
                'texts': [texts[i] for i in split.train_indices],
                'labels': [labels[i] for i in split.train_indices],
                'features': features[split.train_indices]
            },
            'val': {
                'texts': [texts[i] for i in split.val_indices],
                'labels': [labels[i] for i in split.val_indices],
                'features': features[split.val_indices]
            },
            'test': {
                'texts': [texts[i] for i in split.test_indices],
                'labels': [labels[i] for i in split.test_indices],
                'features': features[split.test_indices]
            } if split.test_indices is not None else None
        }
        
        # Compute class weights
        if self.config.use_class_weights:
            label_to_id = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}
            train_label_ids = np.array([label_to_id[l] for l in result['train']['labels']])
            result['class_weights'] = splitter.compute_class_weights(
                train_label_ids,
                method=self.config.class_weight_method
            )
        
        return result
    
    def create_datasets(
        self, 
        split_data: Dict[str, Any],
        tokenizer
    ) -> Tuple[CVEDataset, CVEDataset, Optional[CVEDataset]]:
        """
        Step 5: Create PyTorch datasets.
        """
        logger.info("="*60)
        logger.info("STEP 5: Creating Datasets")
        logger.info("="*60)
        
        train_dataset = CVEDataset(
            texts=split_data['train']['texts'],
            labels=split_data['train']['labels'],
            tokenizer=tokenizer,
            feature_vectors=split_data['train']['features']
        )
        
        val_dataset = CVEDataset(
            texts=split_data['val']['texts'],
            labels=split_data['val']['labels'],
            tokenizer=tokenizer,
            feature_vectors=split_data['val']['features']
        )
        
        test_dataset = None
        if split_data.get('test'):
            test_dataset = CVEDataset(
                texts=split_data['test']['texts'],
                labels=split_data['test']['labels'],
                tokenizer=tokenizer,
                feature_vectors=split_data['test']['features']
            )
        
        logger.info(f"Train dataset: {len(train_dataset)} samples")
        logger.info(f"Val dataset: {len(val_dataset)} samples")
        if test_dataset:
            logger.info(f"Test dataset: {len(test_dataset)} samples")
        
        return train_dataset, val_dataset, test_dataset
    
    def train_epoch(
        self,
        model: nn.Module,
        train_loader: DataLoader,
        optimizer,
        scheduler,
        criterion: nn.Module,
        device: str
    ) -> float:
        """Train for one epoch."""
        model.train()
        total_loss = 0
        
        progress = tqdm(train_loader, desc="Training")
        
        for batch in progress:
            input_ids = batch['input_ids'].to(device)
            attention_mask = batch['attention_mask'].to(device)
            labels = batch['labels'].to(device)
            
            optimizer.zero_grad()
            
            logits = model(input_ids, attention_mask)
            loss = criterion(logits, labels)
            
            loss.backward()
            
            # Gradient clipping
            torch.nn.utils.clip_grad_norm_(
                model.parameters(),
                self.config.max_grad_norm
            )
            
            optimizer.step()
            scheduler.step()
            
            total_loss += loss.item()
            progress.set_postfix({'loss': loss.item()})
        
        return total_loss / len(train_loader)
    
    def evaluate(
        self,
        model: nn.Module,
        data_loader: DataLoader,
        criterion: nn.Module,
        device: str
    ) -> Dict[str, Any]:
        """Evaluate model."""
        model.eval()
        
        total_loss = 0
        all_preds = []
        all_labels = []
        
        with torch.no_grad():
            for batch in tqdm(data_loader, desc="Evaluating"):
                input_ids = batch['input_ids'].to(device)
                attention_mask = batch['attention_mask'].to(device)
                labels = batch['labels'].to(device)
                
                logits = model(input_ids, attention_mask)
                loss = criterion(logits, labels)
                
                total_loss += loss.item()
                
                preds = torch.argmax(logits, dim=1)
                all_preds.extend(preds.cpu().numpy())
                all_labels.extend(labels.cpu().numpy())
        
        # Compute metrics
        accuracy = accuracy_score(all_labels, all_preds)
        precision, recall, f1, _ = precision_recall_fscore_support(
            all_labels, all_preds, average='weighted', zero_division=0
        )
        
        # Per-class metrics
        class_report = classification_report(
            all_labels, all_preds,
            target_names=self.SEVERITY_LABELS,
            output_dict=True,
            zero_division=0
        )
        
        # Confusion matrix
        conf_matrix = confusion_matrix(all_labels, all_preds)
        
        return {
            'loss': total_loss / len(data_loader),
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'classification_report': class_report,
            'confusion_matrix': conf_matrix.tolist()
        }
    
    def train(
        self,
        train_loader: DataLoader,
        val_loader: DataLoader,
        model: nn.Module,
        class_weights: Optional[Dict[int, float]] = None
    ) -> Dict[str, Any]:
        """
        Step 6: Train the model.
        """
        logger.info("="*60)
        logger.info("STEP 6: Model Training")
        logger.info("="*60)
        
        device = self.config.device
        model = model.to(device)
        
        # Loss function with class weights
        if class_weights:
            weights = torch.tensor(
                [class_weights.get(i, 1.0) for i in range(self.config.num_classes)],
                dtype=torch.float32
            ).to(device)
            criterion = nn.CrossEntropyLoss(weight=weights)
            logger.info(f"Using class weights: {weights.tolist()}")
        else:
            criterion = nn.CrossEntropyLoss()
        
        # Optimizer
        optimizer = AdamW(
            model.parameters(),
            lr=self.config.learning_rate,
            weight_decay=self.config.weight_decay
        )
        
        # Learning rate scheduler with warmup
        total_steps = len(train_loader) * self.config.epochs
        warmup_steps = int(total_steps * self.config.warmup_ratio)
        
        scheduler = get_linear_schedule_with_warmup(
            optimizer,
            num_warmup_steps=warmup_steps,
            num_training_steps=total_steps
        )
        
        # Training loop
        best_val_f1 = 0
        patience_counter = 0
        
        for epoch in range(self.config.epochs):
            logger.info(f"\nEpoch {epoch + 1}/{self.config.epochs}")
            
            # Train
            train_loss = self.train_epoch(
                model, train_loader, optimizer, scheduler, criterion, device
            )
            
            # Evaluate
            val_results = self.evaluate(model, val_loader, criterion, device)
            
            # Log results
            logger.info(f"Train Loss: {train_loss:.4f}")
            logger.info(f"Val Loss: {val_results['loss']:.4f}")
            logger.info(f"Val Accuracy: {val_results['accuracy']:.4f}")
            logger.info(f"Val F1: {val_results['f1']:.4f}")
            
            # Update history
            self.history['train_loss'].append(train_loss)
            self.history['val_loss'].append(val_results['loss'])
            self.history['val_accuracy'].append(val_results['accuracy'])
            self.history['val_f1'].append(val_results['f1'])
            self.history['learning_rates'].append(
                optimizer.param_groups[0]['lr']
            )
            
            # Save best model
            if val_results['f1'] > best_val_f1 + self.config.min_delta:
                best_val_f1 = val_results['f1']
                patience_counter = 0
                
                self._save_checkpoint(model, optimizer, epoch, val_results)
                logger.info(f"Saved best model (F1: {best_val_f1:.4f})")
            else:
                patience_counter += 1
            
            # Early stopping
            if patience_counter >= self.config.patience:
                logger.info(f"Early stopping at epoch {epoch + 1}")
                break
        
        return self.history
    
    def _save_checkpoint(
        self,
        model: nn.Module,
        optimizer,
        epoch: int,
        metrics: Dict
    ):
        """Save model checkpoint."""
        checkpoint = {
            'epoch': epoch,
            'model_state_dict': model.state_dict(),
            'optimizer_state_dict': optimizer.state_dict(),
            'metrics': metrics,
            'config': self.config.to_dict(),
            'history': self.history
        }
        
        torch.save(checkpoint, self.config.output_dir / "best_model.pt")
    
    def run(self, api_key: Optional[str] = None) -> Dict[str, Any]:
        """
        Run the complete training pipeline.
        
        Args:
            api_key: Optional NVD API key
            
        Returns:
            Training results and metrics
        """
        start_time = datetime.now()
        logger.info(f"Starting training pipeline at {start_time}")
        
        # Step 1: Collect data
        raw_data = self.collect_data(api_key)
        
        # Step 2: Clean data
        cleaned_data = self.clean_data(raw_data)
        
        # Step 3: Engineer features
        texts, labels, features = self.engineer_features(cleaned_data)
        
        # Step 4: Split data
        split_data = self.split_data(texts, labels, features)
        
        # Step 5: Create datasets
        tokenizer = DistilBertTokenizer.from_pretrained(self.config.model_name)
        train_dataset, val_dataset, test_dataset = self.create_datasets(
            split_data, tokenizer
        )
        
        # Create dataloaders
        train_loader, val_loader, test_loader = create_dataloaders(
            train_dataset, val_dataset, test_dataset,
            batch_size=self.config.batch_size
        )
        
        # Initialize model
        model = SeverityClassifier(
            num_classes=self.config.num_classes,
            dropout_rate=self.config.dropout_rate,
            freeze_bert=self.config.freeze_bert
        )
        
        # Step 6: Train
        history = self.train(
            train_loader, val_loader, model,
            class_weights=split_data.get('class_weights')
        )
        
        # Step 7: Final evaluation on test set
        results = {}
        if test_loader:
            logger.info("="*60)
            logger.info("STEP 7: Final Test Evaluation")
            logger.info("="*60)
            
            # Load best model
            checkpoint = torch.load(self.config.output_dir / "best_model.pt")
            model.load_state_dict(checkpoint['model_state_dict'])
            model = model.to(self.config.device)
            
            criterion = nn.CrossEntropyLoss()
            test_results = self.evaluate(model, test_loader, criterion, self.config.device)
            
            logger.info(f"\nTest Results:")
            logger.info(f"  Accuracy: {test_results['accuracy']:.4f}")
            logger.info(f"  F1: {test_results['f1']:.4f}")
            logger.info(f"  Precision: {test_results['precision']:.4f}")
            logger.info(f"  Recall: {test_results['recall']:.4f}")
            
            results['test'] = test_results
        
        # Save final results
        end_time = datetime.now()
        results['history'] = history
        results['config'] = self.config.to_dict()
        results['training_time'] = str(end_time - start_time)
        
        with open(self.config.output_dir / "results.json", 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        logger.info(f"\nTraining completed in {end_time - start_time}")
        logger.info(f"Results saved to {self.config.output_dir}")
        
        return results


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Train CVE Severity Classifier v2.0")
    parser.add_argument("--api-key", type=str, default=os.environ.get("NVD_API_KEY"))
    parser.add_argument("--samples", type=int, default=2000)
    parser.add_argument("--epochs", type=int, default=5)
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--lr", type=float, default=2e-5)
    parser.add_argument("--output-dir", type=str, default="./ml/models/severity_classifier_v2")
    
    args = parser.parse_args()
    
    config = TrainingConfig(
        num_samples=args.samples,
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.lr,
        output_dir=args.output_dir
    )
    
    pipeline = TrainingPipeline(config)
    results = pipeline.run(api_key=args.api_key)
    
    return results


if __name__ == "__main__":
    main()
