#!/usr/bin/env python3
"""
Severity Classifier Model
=========================

DistilBERT-based text classifier for vulnerability severity prediction.
Predicts: CRITICAL, HIGH, MEDIUM, LOW from CVE descriptions.

Author: Ruthvik
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import Dataset, DataLoader
from transformers import (
    DistilBertTokenizer,
    DistilBertModel,
    DistilBertConfig,
    get_linear_schedule_with_warmup
)
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    classification_report,
    confusion_matrix
)
import numpy as np
import json
import gzip
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import logging
from tqdm import tqdm

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Label mapping
SEVERITY_LABELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
LABEL_TO_ID = {label: i for i, label in enumerate(SEVERITY_LABELS)}
ID_TO_LABEL = {i: label for label, i in LABEL_TO_ID.items()}


class CVEDataset(Dataset):
    """PyTorch Dataset for CVE severity classification."""
    
    def __init__(
        self,
        texts: List[str],
        labels: List[str],
        tokenizer: DistilBertTokenizer,
        max_length: int = 256
    ):
        self.texts = texts
        self.labels = [LABEL_TO_ID[label] for label in labels]
        self.tokenizer = tokenizer
        self.max_length = max_length
    
    def __len__(self):
        return len(self.texts)
    
    def __getitem__(self, idx):
        text = self.texts[idx]
        label = self.labels[idx]
        
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


class SeverityClassifier(nn.Module):
    """
    DistilBERT-based severity classifier.
    
    Architecture:
    - DistilBERT encoder (pre-trained)
    - Dropout for regularization
    - Dense layer for classification
    
    Can also use a simpler architecture with frozen BERT.
    """
    
    def __init__(
        self,
        num_classes: int = 4,
        dropout_rate: float = 0.3,
        freeze_bert: bool = False,
        model_name: str = "distilbert-base-uncased"
    ):
        super().__init__()
        
        self.num_classes = num_classes
        self.model_name = model_name
        
        # Load pre-trained DistilBERT
        self.bert = DistilBertModel.from_pretrained(model_name)
        
        # Optionally freeze BERT layers
        if freeze_bert:
            for param in self.bert.parameters():
                param.requires_grad = False
        
        # Classification head
        hidden_size = self.bert.config.hidden_size  # 768 for base model
        
        self.classifier = nn.Sequential(
            nn.Dropout(dropout_rate),
            nn.Linear(hidden_size, 256),
            nn.ReLU(),
            nn.Dropout(dropout_rate),
            nn.Linear(256, num_classes)
        )
        
        # Initialize weights
        self._init_weights()
    
    def _init_weights(self):
        """Initialize classification head weights."""
        for module in self.classifier.modules():
            if isinstance(module, nn.Linear):
                nn.init.xavier_uniform_(module.weight)
                if module.bias is not None:
                    nn.init.zeros_(module.bias)
    
    def forward(
        self,
        input_ids: torch.Tensor,
        attention_mask: torch.Tensor
    ) -> torch.Tensor:
        """
        Forward pass.
        
        Args:
            input_ids: Token IDs [batch_size, seq_length]
            attention_mask: Attention mask [batch_size, seq_length]
        
        Returns:
            Logits [batch_size, num_classes]
        """
        # Get BERT outputs
        outputs = self.bert(
            input_ids=input_ids,
            attention_mask=attention_mask
        )
        
        # Use [CLS] token representation
        cls_output = outputs.last_hidden_state[:, 0, :]
        
        # Classification
        logits = self.classifier(cls_output)
        
        return logits
    
    def predict(
        self,
        input_ids: torch.Tensor,
        attention_mask: torch.Tensor
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Get predictions with probabilities.
        
        Returns:
            Tuple of (predicted_labels, probabilities)
        """
        logits = self.forward(input_ids, attention_mask)
        probs = F.softmax(logits, dim=-1)
        predictions = torch.argmax(probs, dim=-1)
        
        return predictions, probs


class LightweightClassifier(nn.Module):
    """
    Lightweight classifier using TF-IDF features instead of BERT.
    Faster training and inference, suitable for quick experiments.
    """
    
    def __init__(
        self,
        input_size: int = 10000,
        hidden_sizes: List[int] = [512, 256],
        num_classes: int = 4,
        dropout_rate: float = 0.3
    ):
        super().__init__()
        
        layers = []
        prev_size = input_size
        
        for hidden_size in hidden_sizes:
            layers.extend([
                nn.Linear(prev_size, hidden_size),
                nn.ReLU(),
                nn.BatchNorm1d(hidden_size),
                nn.Dropout(dropout_rate)
            ])
            prev_size = hidden_size
        
        layers.append(nn.Linear(prev_size, num_classes))
        
        self.network = nn.Sequential(*layers)
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.network(x)


class SeverityTrainer:
    """Trainer class for severity classifier."""
    
    def __init__(
        self,
        model: SeverityClassifier,
        device: str = "mps" if torch.backends.mps.is_available() else "cpu",
        learning_rate: float = 2e-5,
        weight_decay: float = 0.01
    ):
        self.model = model.to(device)
        self.device = device
        self.learning_rate = learning_rate
        self.weight_decay = weight_decay
        
        # Will be initialized in train()
        self.optimizer = None
        self.scheduler = None
        self.criterion = nn.CrossEntropyLoss()
        
        # Training history
        self.history = {
            'train_loss': [],
            'val_loss': [],
            'train_acc': [],
            'val_acc': [],
            'val_f1': []
        }
    
    def train(
        self,
        train_loader: DataLoader,
        val_loader: DataLoader,
        epochs: int = 5,
        warmup_steps: int = 0,
        save_dir: Optional[Path] = None,
        early_stopping_patience: int = 3
    ) -> Dict:
        """
        Train the model.
        
        Args:
            train_loader: Training data loader
            val_loader: Validation data loader
            epochs: Number of training epochs
            warmup_steps: Learning rate warmup steps
            save_dir: Directory to save checkpoints
            early_stopping_patience: Stop if no improvement for N epochs
        
        Returns:
            Training history dictionary
        """
        logger.info(f"Training on {self.device}")
        logger.info(f"Train samples: {len(train_loader.dataset)}")
        logger.info(f"Val samples: {len(val_loader.dataset)}")
        
        # Initialize optimizer
        self.optimizer = torch.optim.AdamW(
            self.model.parameters(),
            lr=self.learning_rate,
            weight_decay=self.weight_decay
        )
        
        # Initialize scheduler
        total_steps = len(train_loader) * epochs
        self.scheduler = get_linear_schedule_with_warmup(
            self.optimizer,
            num_warmup_steps=warmup_steps,
            num_training_steps=total_steps
        )
        
        best_val_f1 = 0
        patience_counter = 0
        
        for epoch in range(epochs):
            logger.info(f"\nEpoch {epoch + 1}/{epochs}")
            
            # Training
            train_loss, train_acc = self._train_epoch(train_loader)
            self.history['train_loss'].append(train_loss)
            self.history['train_acc'].append(train_acc)
            
            # Validation
            val_loss, val_acc, val_f1, val_report = self._validate(val_loader)
            self.history['val_loss'].append(val_loss)
            self.history['val_acc'].append(val_acc)
            self.history['val_f1'].append(val_f1)
            
            logger.info(f"Train Loss: {train_loss:.4f}, Train Acc: {train_acc:.4f}")
            logger.info(f"Val Loss: {val_loss:.4f}, Val Acc: {val_acc:.4f}, Val F1: {val_f1:.4f}")
            
            # Save best model
            if val_f1 > best_val_f1:
                best_val_f1 = val_f1
                patience_counter = 0
                
                if save_dir:
                    self.save_checkpoint(save_dir / "best_model.pt")
                    logger.info(f"Saved best model (F1: {val_f1:.4f})")
            else:
                patience_counter += 1
            
            # Early stopping
            if patience_counter >= early_stopping_patience:
                logger.info(f"Early stopping after {epoch + 1} epochs")
                break
        
        return self.history
    
    def _train_epoch(self, train_loader: DataLoader) -> Tuple[float, float]:
        """Train for one epoch."""
        self.model.train()
        
        total_loss = 0
        correct = 0
        total = 0
        
        progress_bar = tqdm(train_loader, desc="Training")
        
        for batch in progress_bar:
            input_ids = batch['input_ids'].to(self.device)
            attention_mask = batch['attention_mask'].to(self.device)
            labels = batch['label'].to(self.device)
            
            self.optimizer.zero_grad()
            
            logits = self.model(input_ids, attention_mask)
            loss = self.criterion(logits, labels)
            
            loss.backward()
            torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
            
            self.optimizer.step()
            self.scheduler.step()
            
            total_loss += loss.item()
            predictions = torch.argmax(logits, dim=-1)
            correct += (predictions == labels).sum().item()
            total += labels.size(0)
            
            progress_bar.set_postfix({
                'loss': loss.item(),
                'acc': correct / total
            })
        
        return total_loss / len(train_loader), correct / total
    
    def _validate(self, val_loader: DataLoader) -> Tuple[float, float, float, str]:
        """Validate the model."""
        self.model.eval()
        
        total_loss = 0
        all_predictions = []
        all_labels = []
        
        with torch.no_grad():
            for batch in tqdm(val_loader, desc="Validating"):
                input_ids = batch['input_ids'].to(self.device)
                attention_mask = batch['attention_mask'].to(self.device)
                labels = batch['label'].to(self.device)
                
                logits = self.model(input_ids, attention_mask)
                loss = self.criterion(logits, labels)
                
                total_loss += loss.item()
                predictions = torch.argmax(logits, dim=-1)
                
                all_predictions.extend(predictions.cpu().numpy())
                all_labels.extend(labels.cpu().numpy())
        
        # Calculate metrics
        accuracy = accuracy_score(all_labels, all_predictions)
        precision, recall, f1, _ = precision_recall_fscore_support(
            all_labels, all_predictions, average='weighted'
        )
        
        report = classification_report(
            all_labels, all_predictions,
            target_names=SEVERITY_LABELS
        )
        
        return total_loss / len(val_loader), accuracy, f1, report
    
    def evaluate(self, test_loader: DataLoader) -> Dict:
        """Comprehensive evaluation on test set."""
        self.model.eval()
        
        all_predictions = []
        all_labels = []
        all_probs = []
        
        with torch.no_grad():
            for batch in tqdm(test_loader, desc="Evaluating"):
                input_ids = batch['input_ids'].to(self.device)
                attention_mask = batch['attention_mask'].to(self.device)
                labels = batch['label'].to(self.device)
                
                predictions, probs = self.model.predict(input_ids, attention_mask)
                
                all_predictions.extend(predictions.cpu().numpy())
                all_labels.extend(labels.cpu().numpy())
                all_probs.extend(probs.cpu().numpy())
        
        # Calculate metrics
        accuracy = accuracy_score(all_labels, all_predictions)
        precision, recall, f1, support = precision_recall_fscore_support(
            all_labels, all_predictions, average=None
        )
        
        weighted_precision, weighted_recall, weighted_f1, _ = precision_recall_fscore_support(
            all_labels, all_predictions, average='weighted'
        )
        
        conf_matrix = confusion_matrix(all_labels, all_predictions)
        
        report = classification_report(
            all_labels, all_predictions,
            target_names=SEVERITY_LABELS,
            output_dict=True
        )
        
        results = {
            'accuracy': accuracy,
            'weighted_precision': weighted_precision,
            'weighted_recall': weighted_recall,
            'weighted_f1': weighted_f1,
            'per_class_precision': dict(zip(SEVERITY_LABELS, precision)),
            'per_class_recall': dict(zip(SEVERITY_LABELS, recall)),
            'per_class_f1': dict(zip(SEVERITY_LABELS, f1)),
            'per_class_support': dict(zip(SEVERITY_LABELS, support.tolist())),
            'confusion_matrix': conf_matrix.tolist(),
            'classification_report': report
        }
        
        return results
    
    def save_checkpoint(self, path: Path):
        """Save model checkpoint."""
        path.parent.mkdir(parents=True, exist_ok=True)
        
        checkpoint = {
            'model_state_dict': self.model.state_dict(),
            'model_config': {
                'num_classes': self.model.num_classes,
                'model_name': self.model.model_name
            },
            'history': self.history
        }
        
        torch.save(checkpoint, path)
    
    def load_checkpoint(self, path: Path):
        """Load model checkpoint."""
        checkpoint = torch.load(path, map_location=self.device)
        self.model.load_state_dict(checkpoint['model_state_dict'])
        self.history = checkpoint.get('history', self.history)


def load_split_data(split_file: Path) -> Tuple[List[str], List[str]]:
    """Load a data split from file."""
    with gzip.open(split_file, 'rt', encoding='utf-8') as f:
        data = json.load(f)
    return data['texts'], data['labels']


def main():
    """Training pipeline for severity classifier."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Train severity classifier")
    parser.add_argument("--data-dir", type=str, required=True, help="Data directory with splits")
    parser.add_argument("--output-dir", type=str, required=True, help="Output directory")
    parser.add_argument("--epochs", type=int, default=5, help="Number of epochs")
    parser.add_argument("--batch-size", type=int, default=16, help="Batch size")
    parser.add_argument("--lr", type=float, default=2e-5, help="Learning rate")
    parser.add_argument("--max-length", type=int, default=256, help="Max sequence length")
    parser.add_argument("--freeze-bert", action="store_true", help="Freeze BERT layers")
    
    args = parser.parse_args()
    
    data_dir = Path(args.data_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Load tokenizer
    logger.info("Loading tokenizer...")
    tokenizer = DistilBertTokenizer.from_pretrained("distilbert-base-uncased")
    
    # Load data
    logger.info("Loading data...")
    train_texts, train_labels = load_split_data(data_dir / "severity_train.json.gz")
    val_texts, val_labels = load_split_data(data_dir / "severity_val.json.gz")
    test_texts, test_labels = load_split_data(data_dir / "severity_test.json.gz")
    
    # Create datasets
    train_dataset = CVEDataset(train_texts, train_labels, tokenizer, args.max_length)
    val_dataset = CVEDataset(val_texts, val_labels, tokenizer, args.max_length)
    test_dataset = CVEDataset(test_texts, test_labels, tokenizer, args.max_length)
    
    # Create data loaders
    train_loader = DataLoader(train_dataset, batch_size=args.batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=args.batch_size)
    test_loader = DataLoader(test_dataset, batch_size=args.batch_size)
    
    # Initialize model
    logger.info("Initializing model...")
    model = SeverityClassifier(
        num_classes=4,
        freeze_bert=args.freeze_bert
    )
    
    # Train
    trainer = SeverityTrainer(model, learning_rate=args.lr)
    history = trainer.train(
        train_loader,
        val_loader,
        epochs=args.epochs,
        save_dir=output_dir
    )
    
    # Evaluate
    logger.info("\nEvaluating on test set...")
    results = trainer.evaluate(test_loader)
    
    logger.info(f"\nTest Results:")
    logger.info(f"Accuracy: {results['accuracy']:.4f}")
    logger.info(f"Weighted F1: {results['weighted_f1']:.4f}")
    logger.info(f"\nPer-class F1:")
    for label in SEVERITY_LABELS:
        logger.info(f"  {label}: {results['per_class_f1'][label]:.4f}")
    
    # Save results
    results_file = output_dir / "test_results.json"
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    logger.info(f"\nResults saved to {results_file}")
    logger.info(f"Best model saved to {output_dir / 'best_model.pt'}")


if __name__ == "__main__":
    main()
