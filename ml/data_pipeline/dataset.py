# -*- coding: utf-8 -*-
"""
CTPPO v2.0 - PyTorch Datasets
=============================

Custom PyTorch datasets for CVE severity classification and attack graph prediction.

Datasets:
1. CVEDataset - For text-based severity classification
2. AttackGraphDataset - For GNN-based path prediction

Author: Ruthvik (Fixed by Claude)
Date: January 2026
"""

import torch
from torch.utils.data import Dataset, DataLoader
import numpy as np
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CVEDataset(Dataset):
    """
    PyTorch Dataset for CVE severity classification.
    
    Supports both text-based (for transformers) and feature-based
    (for traditional ML) approaches.
    
    IMPORTANT: Labels come from CVSS scores (ground truth),
    never from model predictions!
    """
    
    # Label mapping
    LABEL_TO_ID = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}
    ID_TO_LABEL = {v: k for k, v in LABEL_TO_ID.items()}
    
    def __init__(
        self,
        texts: List[str],
        labels: List[str],
        tokenizer: Optional[Any] = None,
        max_length: int = 256,
        feature_vectors: Optional[np.ndarray] = None,
        return_text: bool = False
    ):
        """
        Initialize dataset.
        
        Args:
            texts: List of cleaned CVE descriptions
            labels: List of severity labels (GROUND TRUTH from CVSS)
            tokenizer: HuggingFace tokenizer for text encoding
            max_length: Maximum sequence length for tokenization
            feature_vectors: Optional numerical features for hybrid models
            return_text: Whether to return raw text in addition to tokens
        """
        assert len(texts) == len(labels), "Texts and labels must have same length"
        
        self.texts = texts
        self.labels = labels
        self.tokenizer = tokenizer
        self.max_length = max_length
        self.feature_vectors = feature_vectors
        self.return_text = return_text
        
        # Convert string labels to IDs
        self.label_ids = [
            self.LABEL_TO_ID.get(label, 1)  # Default to MEDIUM if unknown
            for label in labels
        ]
        
        # Pre-tokenize if tokenizer provided
        self.encodings = None
        if tokenizer is not None:
            logger.info(f"Pre-tokenizing {len(texts)} texts...")
            self.encodings = tokenizer(
                texts,
                truncation=True,
                padding=True,
                max_length=max_length,
                return_tensors='pt'
            )
            logger.info("Tokenization complete.")
    
    def __len__(self) -> int:
        return len(self.texts)
    
    def __getitem__(self, idx: int) -> Dict[str, torch.Tensor]:
        """
        Get a single sample.
        
        Returns:
            Dictionary with input_ids, attention_mask, labels, and optionally
            feature_vector and text.
        """
        item = {'labels': torch.tensor(self.label_ids[idx], dtype=torch.long)}
        
        # Text encoding
        if self.encodings is not None:
            item['input_ids'] = self.encodings['input_ids'][idx]
            item['attention_mask'] = self.encodings['attention_mask'][idx]
        elif self.tokenizer is not None:
            # Tokenize on-the-fly (slower but more memory efficient)
            encoding = self.tokenizer(
                self.texts[idx],
                truncation=True,
                padding='max_length',
                max_length=self.max_length,
                return_tensors='pt'
            )
            item['input_ids'] = encoding['input_ids'].squeeze(0)
            item['attention_mask'] = encoding['attention_mask'].squeeze(0)
        
        # Additional features
        if self.feature_vectors is not None:
            item['features'] = torch.tensor(
                self.feature_vectors[idx],
                dtype=torch.float32
            )
        
        if self.return_text:
            item['text'] = self.texts[idx]
        
        return item
    
    def get_class_weights(self) -> torch.Tensor:
        """
        Compute class weights for handling imbalance.
        
        Returns:
            Tensor of class weights
        """
        from collections import Counter
        
        counts = Counter(self.label_ids)
        total = len(self.label_ids)
        n_classes = len(self.LABEL_TO_ID)
        
        weights = []
        for i in range(n_classes):
            count = counts.get(i, 1)
            weight = total / (n_classes * count)
            weights.append(weight)
        
        return torch.tensor(weights, dtype=torch.float32)
    
    def get_label_distribution(self) -> Dict[str, int]:
        """Get distribution of labels in dataset."""
        from collections import Counter
        return dict(Counter(self.labels))
    
    @classmethod
    def from_feature_sets(
        cls,
        feature_sets: List[Any],
        tokenizer: Optional[Any] = None,
        max_length: int = 256,
        include_features: bool = True
    ) -> 'CVEDataset':
        """
        Create dataset from FeatureSet objects.
        
        Args:
            feature_sets: List of FeatureSet objects from FeatureEngineer
            tokenizer: HuggingFace tokenizer
            max_length: Maximum sequence length
            include_features: Whether to include numerical features
            
        Returns:
            CVEDataset instance
        """
        texts = [fs.text for fs in feature_sets]
        labels = [fs.severity_label or 'MEDIUM' for fs in feature_sets]
        
        feature_vectors = None
        if include_features:
            feature_vectors = np.array([
                fs.feature_vector for fs in feature_sets
            ])
        
        return cls(
            texts=texts,
            labels=labels,
            tokenizer=tokenizer,
            max_length=max_length,
            feature_vectors=feature_vectors
        )


class AttackGraphDataset(Dataset):
    """
    PyTorch Geometric-compatible dataset for attack graphs.
    
    Used for GNN-based attack path prediction.
    """
    
    def __init__(self, graphs: List[Dict[str, Any]]):
        """
        Initialize dataset.
        
        Args:
            graphs: List of graph dictionaries with nodes and edges
        """
        self.graphs = graphs
        self.data_list = self._process_graphs()
    
    def _process_graphs(self) -> List[Any]:
        """Convert graphs to PyTorch Geometric format."""
        try:
            from torch_geometric.data import Data
        except ImportError:
            logger.warning("torch_geometric not installed. Using dict format.")
            return self._process_graphs_dict()
        
        data_list = []
        
        for graph in self.graphs:
            nodes = graph.get('nodes', [])
            edges = graph.get('edges', [])
            
            # Node features
            x = torch.tensor(
                [node.get('features', [0]*10) for node in nodes],
                dtype=torch.float
            )
            
            # Edge index (COO format)
            if edges:
                edge_index = torch.tensor(
                    [[e['source'] for e in edges], [e['target'] for e in edges]],
                    dtype=torch.long
                )
                edge_attr = torch.tensor(
                    [[e.get('weight', 1.0)] for e in edges],
                    dtype=torch.float
                )
            else:
                edge_index = torch.zeros((2, 0), dtype=torch.long)
                edge_attr = torch.zeros((0, 1), dtype=torch.float)
            
            # Graph-level label
            risk_score = graph.get('risk_score', 5.0)
            y = torch.tensor([risk_score / 10.0], dtype=torch.float)
            
            # Risk class
            risk_label = graph.get('risk_label', 'MEDIUM')
            risk_class_map = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}
            risk_class = torch.tensor(
                [risk_class_map.get(risk_label, 1)],
                dtype=torch.long
            )
            
            data = Data(
                x=x,
                edge_index=edge_index,
                edge_attr=edge_attr,
                y=y,
                risk_class=risk_class,
                num_nodes=len(nodes)
            )
            
            data_list.append(data)
        
        return data_list
    
    def _process_graphs_dict(self) -> List[Dict]:
        """Fallback processing without PyTorch Geometric."""
        processed = []
        
        for graph in self.graphs:
            nodes = graph.get('nodes', [])
            edges = graph.get('edges', [])
            
            processed.append({
                'x': torch.tensor(
                    [node.get('features', [0]*10) for node in nodes],
                    dtype=torch.float
                ),
                'edge_index': torch.tensor(
                    [[e['source'] for e in edges], [e['target'] for e in edges]],
                    dtype=torch.long
                ) if edges else torch.zeros((2, 0), dtype=torch.long),
                'y': torch.tensor([graph.get('risk_score', 5.0) / 10.0]),
                'num_nodes': len(nodes)
            })
        
        return processed
    
    def __len__(self) -> int:
        return len(self.data_list)
    
    def __getitem__(self, idx: int):
        return self.data_list[idx]


def create_dataloaders(
    train_dataset: Dataset,
    val_dataset: Dataset,
    test_dataset: Optional[Dataset] = None,
    batch_size: int = 16,
    num_workers: int = 0
) -> Tuple[DataLoader, DataLoader, Optional[DataLoader]]:
    """
    Create DataLoaders for training.
    
    Args:
        train_dataset: Training dataset
        val_dataset: Validation dataset
        test_dataset: Test dataset (optional)
        batch_size: Batch size for training
        num_workers: Number of worker processes
        
    Returns:
        Tuple of (train_loader, val_loader, test_loader)
    """
    train_loader = DataLoader(
        train_dataset,
        batch_size=batch_size,
        shuffle=True,
        num_workers=num_workers,
        pin_memory=torch.cuda.is_available()
    )
    
    val_loader = DataLoader(
        val_dataset,
        batch_size=batch_size,
        shuffle=False,
        num_workers=num_workers,
        pin_memory=torch.cuda.is_available()
    )
    
    test_loader = None
    if test_dataset is not None:
        test_loader = DataLoader(
            test_dataset,
            batch_size=batch_size,
            shuffle=False,
            num_workers=num_workers,
            pin_memory=torch.cuda.is_available()
        )
    
    logger.info(f"Created DataLoaders:")
    logger.info(f"  Train: {len(train_loader)} batches")
    logger.info(f"  Val:   {len(val_loader)} batches")
    if test_loader:
        logger.info(f"  Test:  {len(test_loader)} batches")
    
    return train_loader, val_loader, test_loader


# Example usage
if __name__ == "__main__":
    # Test CVEDataset
    print("Testing CVEDataset...")
    
    texts = [
        "buffer overflow allows remote code execution",
        "sql injection in login page",
        "denial of service via crafted packet",
        "information disclosure in api endpoint",
        "cross site scripting in user input"
    ]
    
    # GROUND TRUTH labels from CVSS scores
    labels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'HIGH']
    
    # Without tokenizer (feature-based only)
    dataset = CVEDataset(
        texts=texts,
        labels=labels,
        feature_vectors=np.random.randn(5, 10)  # Dummy features
    )
    
    print(f"Dataset size: {len(dataset)}")
    print(f"Label distribution: {dataset.get_label_distribution()}")
    print(f"Class weights: {dataset.get_class_weights()}")
    
    # Test __getitem__
    sample = dataset[0]
    print(f"\nSample keys: {sample.keys()}")
    print(f"Labels: {sample['labels']}")
    if 'features' in sample:
        print(f"Features shape: {sample['features'].shape}")
