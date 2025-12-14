#!/usr/bin/env python3
"""
GNN Predictor Model
===================

Graph Neural Network for attack graph risk prediction.
Uses GraphSAGE architecture to learn node and graph-level representations.

Tasks:
1. Node-level: Predict vulnerability severity
2. Graph-level: Predict overall network risk score

Author: Ruthvik
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import Dataset
from torch_geometric.data import Data, DataLoader, Batch
from torch_geometric.nn import (
    SAGEConv,
    GATConv,
    GCNConv,
    global_mean_pool,
    global_max_pool,
    global_add_pool
)
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    mean_squared_error,
    mean_absolute_error,
    r2_score
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

# Risk labels
RISK_LABELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
RISK_LABEL_TO_ID = {label: i for i, label in enumerate(RISK_LABELS)}


class AttackGraphDataset(Dataset):
    """PyTorch Dataset for attack graphs."""
    
    def __init__(self, graphs: List[Dict]):
        self.graphs = graphs
        self.data_list = self._process_graphs()
    
    def _process_graphs(self) -> List[Data]:
        """Convert graphs to PyTorch Geometric format."""
        data_list = []
        
        for graph in self.graphs:
            nodes = graph["nodes"]
            edges = graph["edges"]
            
            # Node features
            x = torch.tensor(
                [node["features"] for node in nodes],
                dtype=torch.float
            )
            
            # Edge index (COO format)
            if edges:
                edge_index = torch.tensor(
                    [[e["source"] for e in edges], [e["target"] for e in edges]],
                    dtype=torch.long
                )
                
                # Edge weights
                edge_attr = torch.tensor(
                    [[e.get("weight", 1.0)] for e in edges],
                    dtype=torch.float
                )
            else:
                edge_index = torch.zeros((2, 0), dtype=torch.long)
                edge_attr = torch.zeros((0, 1), dtype=torch.float)
            
            # Graph-level label (risk score)
            risk_score = graph.get("risk_score", 5.0)
            y = torch.tensor([risk_score / 10.0], dtype=torch.float)  # Normalize to [0, 1]
            
            # Risk class label
            risk_label = graph.get("risk_label", "MEDIUM")
            risk_class = torch.tensor([RISK_LABEL_TO_ID[risk_label]], dtype=torch.long)
            
            # Node labels (vulnerability severity)
            node_labels = []
            for node in nodes:
                if node["type"] == "vulnerability":
                    # Feature index 5 is normalized CVSS for vulnerability nodes
                    cvss = node["features"][5] * 10 if len(node["features"]) > 5 else 5.0
                    if cvss >= 9.0:
                        node_labels.append(3)  # CRITICAL
                    elif cvss >= 7.0:
                        node_labels.append(2)  # HIGH
                    elif cvss >= 4.0:
                        node_labels.append(1)  # MEDIUM
                    else:
                        node_labels.append(0)  # LOW
                else:
                    node_labels.append(-1)  # Not a vulnerability
            
            node_y = torch.tensor(node_labels, dtype=torch.long)
            
            data = Data(
                x=x,
                edge_index=edge_index,
                edge_attr=edge_attr,
                y=y,
                risk_class=risk_class,
                node_y=node_y,
                num_nodes=len(nodes)
            )
            
            data_list.append(data)
        
        return data_list
    
    def __len__(self):
        return len(self.data_list)
    
    def __getitem__(self, idx):
        return self.data_list[idx]


class GraphSAGEEncoder(nn.Module):
    """GraphSAGE encoder for node embeddings."""
    
    def __init__(
        self,
        in_channels: int,
        hidden_channels: int,
        out_channels: int,
        num_layers: int = 3,
        dropout: float = 0.3
    ):
        super().__init__()
        
        self.num_layers = num_layers
        self.dropout = dropout
        
        self.convs = nn.ModuleList()
        self.batch_norms = nn.ModuleList()
        
        # First layer
        self.convs.append(SAGEConv(in_channels, hidden_channels))
        self.batch_norms.append(nn.BatchNorm1d(hidden_channels))
        
        # Hidden layers
        for _ in range(num_layers - 2):
            self.convs.append(SAGEConv(hidden_channels, hidden_channels))
            self.batch_norms.append(nn.BatchNorm1d(hidden_channels))
        
        # Output layer
        self.convs.append(SAGEConv(hidden_channels, out_channels))
        self.batch_norms.append(nn.BatchNorm1d(out_channels))
    
    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor
    ) -> torch.Tensor:
        """
        Forward pass.
        
        Args:
            x: Node features [num_nodes, in_channels]
            edge_index: Edge indices [2, num_edges]
        
        Returns:
            Node embeddings [num_nodes, out_channels]
        """
        for i, (conv, bn) in enumerate(zip(self.convs, self.batch_norms)):
            x = conv(x, edge_index)
            x = bn(x)
            if i < self.num_layers - 1:
                x = F.relu(x)
                x = F.dropout(x, p=self.dropout, training=self.training)
        
        return x


class GATEncoder(nn.Module):
    """Graph Attention Network encoder."""
    
    def __init__(
        self,
        in_channels: int,
        hidden_channels: int,
        out_channels: int,
        num_layers: int = 3,
        heads: int = 4,
        dropout: float = 0.3
    ):
        super().__init__()
        
        self.num_layers = num_layers
        self.dropout = dropout
        
        self.convs = nn.ModuleList()
        
        # First layer
        self.convs.append(GATConv(in_channels, hidden_channels, heads=heads, dropout=dropout))
        
        # Hidden layers
        for _ in range(num_layers - 2):
            self.convs.append(GATConv(hidden_channels * heads, hidden_channels, heads=heads, dropout=dropout))
        
        # Output layer
        self.convs.append(GATConv(hidden_channels * heads, out_channels, heads=1, concat=False, dropout=dropout))
    
    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor
    ) -> torch.Tensor:
        for i, conv in enumerate(self.convs):
            x = conv(x, edge_index)
            if i < self.num_layers - 1:
                x = F.elu(x)
                x = F.dropout(x, p=self.dropout, training=self.training)
        
        return x


class GNNPredictor(nn.Module):
    """
    GNN model for attack graph risk prediction.
    
    Supports both node-level and graph-level prediction:
    - Node-level: Vulnerability severity classification
    - Graph-level: Network risk score regression/classification
    """
    
    def __init__(
        self,
        in_channels: int = 10,
        hidden_channels: int = 128,
        out_channels: int = 64,
        num_layers: int = 3,
        num_node_classes: int = 4,
        num_graph_classes: int = 4,
        encoder_type: str = "sage",
        dropout: float = 0.3,
        pooling: str = "mean"
    ):
        super().__init__()
        
        self.in_channels = in_channels
        self.out_channels = out_channels
        self.pooling = pooling
        
        # Node encoder
        if encoder_type == "sage":
            self.encoder = GraphSAGEEncoder(
                in_channels, hidden_channels, out_channels, num_layers, dropout
            )
        elif encoder_type == "gat":
            self.encoder = GATEncoder(
                in_channels, hidden_channels, out_channels, num_layers, dropout=dropout
            )
        else:
            raise ValueError(f"Unknown encoder type: {encoder_type}")
        
        # Node-level classifier (for vulnerability severity)
        self.node_classifier = nn.Sequential(
            nn.Linear(out_channels, 64),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(64, num_node_classes)
        )
        
        # Graph-level classifier (for risk level)
        pool_channels = out_channels * 2 if pooling == "mean_max" else out_channels
        
        self.graph_classifier = nn.Sequential(
            nn.Linear(pool_channels, 64),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(64, num_graph_classes)
        )
        
        # Graph-level regressor (for risk score)
        self.graph_regressor = nn.Sequential(
            nn.Linear(pool_channels, 64),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(64, 1),
            nn.Sigmoid()  # Output in [0, 1]
        )
    
    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        batch: Optional[torch.Tensor] = None
    ) -> Dict[str, torch.Tensor]:
        """
        Forward pass.
        
        Args:
            x: Node features [num_nodes, in_channels]
            edge_index: Edge indices [2, num_edges]
            batch: Batch assignment [num_nodes]
        
        Returns:
            Dictionary with predictions
        """
        # Encode nodes
        node_embeddings = self.encoder(x, edge_index)
        
        # Node-level predictions
        node_logits = self.node_classifier(node_embeddings)
        
        # Graph-level pooling
        if batch is None:
            batch = torch.zeros(x.size(0), dtype=torch.long, device=x.device)
        
        if self.pooling == "mean":
            graph_embedding = global_mean_pool(node_embeddings, batch)
        elif self.pooling == "max":
            graph_embedding = global_max_pool(node_embeddings, batch)
        elif self.pooling == "mean_max":
            mean_pool = global_mean_pool(node_embeddings, batch)
            max_pool = global_max_pool(node_embeddings, batch)
            graph_embedding = torch.cat([mean_pool, max_pool], dim=-1)
        else:
            graph_embedding = global_add_pool(node_embeddings, batch)
        
        # Graph-level predictions
        graph_logits = self.graph_classifier(graph_embedding)
        graph_score = self.graph_regressor(graph_embedding)
        
        return {
            'node_embeddings': node_embeddings,
            'node_logits': node_logits,
            'graph_embedding': graph_embedding,
            'graph_logits': graph_logits,
            'graph_score': graph_score
        }
    
    def predict_risk(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        batch: Optional[torch.Tensor] = None
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Predict risk score and class.
        
        Returns:
            Tuple of (risk_score, risk_class)
        """
        outputs = self.forward(x, edge_index, batch)
        
        risk_score = outputs['graph_score'] * 10  # Scale back to [0, 10]
        risk_class = torch.argmax(outputs['graph_logits'], dim=-1)
        
        return risk_score, risk_class


class GNNTrainer:
    """Trainer class for GNN model."""
    
    def __init__(
        self,
        model: GNNPredictor,
        device: str = "mps" if torch.backends.mps.is_available() else "cpu",
        learning_rate: float = 1e-3,
        weight_decay: float = 1e-4
    ):
        self.model = model.to(device)
        self.device = device
        self.learning_rate = learning_rate
        self.weight_decay = weight_decay
        
        self.optimizer = torch.optim.Adam(
            model.parameters(),
            lr=learning_rate,
            weight_decay=weight_decay
        )
        
        # Loss functions
        self.node_criterion = nn.CrossEntropyLoss(ignore_index=-1)  # Ignore non-vuln nodes
        self.graph_class_criterion = nn.CrossEntropyLoss()
        self.graph_reg_criterion = nn.MSELoss()
        
        # History
        self.history = {
            'train_loss': [],
            'val_loss': [],
            'val_node_acc': [],
            'val_graph_acc': [],
            'val_mse': []
        }
    
    def train(
        self,
        train_loader: DataLoader,
        val_loader: DataLoader,
        epochs: int = 100,
        save_dir: Optional[Path] = None,
        early_stopping_patience: int = 10,
        loss_weights: Dict[str, float] = None
    ) -> Dict:
        """Train the GNN model."""
        
        if loss_weights is None:
            loss_weights = {
                'node': 0.3,
                'graph_class': 0.4,
                'graph_reg': 0.3
            }
        
        logger.info(f"Training on {self.device}")
        logger.info(f"Train graphs: {len(train_loader.dataset)}")
        logger.info(f"Val graphs: {len(val_loader.dataset)}")
        
        best_val_loss = float('inf')
        patience_counter = 0
        
        for epoch in range(epochs):
            # Training
            train_loss = self._train_epoch(train_loader, loss_weights)
            self.history['train_loss'].append(train_loss)
            
            # Validation
            val_metrics = self._validate(val_loader, loss_weights)
            self.history['val_loss'].append(val_metrics['loss'])
            self.history['val_node_acc'].append(val_metrics['node_acc'])
            self.history['val_graph_acc'].append(val_metrics['graph_acc'])
            self.history['val_mse'].append(val_metrics['mse'])
            
            if (epoch + 1) % 10 == 0:
                logger.info(
                    f"Epoch {epoch + 1}/{epochs} - "
                    f"Train Loss: {train_loss:.4f}, Val Loss: {val_metrics['loss']:.4f}, "
                    f"Graph Acc: {val_metrics['graph_acc']:.4f}, MSE: {val_metrics['mse']:.4f}"
                )
            
            # Save best model
            if val_metrics['loss'] < best_val_loss:
                best_val_loss = val_metrics['loss']
                patience_counter = 0
                
                if save_dir:
                    self.save_checkpoint(save_dir / "best_gnn_model.pt")
            else:
                patience_counter += 1
            
            if patience_counter >= early_stopping_patience:
                logger.info(f"Early stopping at epoch {epoch + 1}")
                break
        
        return self.history
    
    def _train_epoch(
        self,
        train_loader: DataLoader,
        loss_weights: Dict[str, float]
    ) -> float:
        """Train for one epoch."""
        self.model.train()
        total_loss = 0
        
        for batch in train_loader:
            batch = batch.to(self.device)
            
            self.optimizer.zero_grad()
            
            outputs = self.model(batch.x, batch.edge_index, batch.batch)
            
            # Node-level loss (only for vulnerability nodes)
            node_loss = self.node_criterion(outputs['node_logits'], batch.node_y)
            
            # Graph-level classification loss
            graph_class_loss = self.graph_class_criterion(
                outputs['graph_logits'], batch.risk_class.squeeze()
            )
            
            # Graph-level regression loss
            graph_reg_loss = self.graph_reg_criterion(
                outputs['graph_score'].squeeze(), batch.y.squeeze()
            )
            
            # Combined loss
            loss = (
                loss_weights['node'] * node_loss +
                loss_weights['graph_class'] * graph_class_loss +
                loss_weights['graph_reg'] * graph_reg_loss
            )
            
            loss.backward()
            torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
            self.optimizer.step()
            
            total_loss += loss.item()
        
        return total_loss / len(train_loader)
    
    def _validate(
        self,
        val_loader: DataLoader,
        loss_weights: Dict[str, float]
    ) -> Dict:
        """Validate the model."""
        self.model.eval()
        
        total_loss = 0
        all_node_preds = []
        all_node_labels = []
        all_graph_preds = []
        all_graph_labels = []
        all_scores = []
        all_score_labels = []
        
        with torch.no_grad():
            for batch in val_loader:
                batch = batch.to(self.device)
                
                outputs = self.model(batch.x, batch.edge_index, batch.batch)
                
                # Calculate loss
                node_loss = self.node_criterion(outputs['node_logits'], batch.node_y)
                graph_class_loss = self.graph_class_criterion(
                    outputs['graph_logits'], batch.risk_class.squeeze()
                )
                graph_reg_loss = self.graph_reg_criterion(
                    outputs['graph_score'].squeeze(), batch.y.squeeze()
                )
                
                loss = (
                    loss_weights['node'] * node_loss +
                    loss_weights['graph_class'] * graph_class_loss +
                    loss_weights['graph_reg'] * graph_reg_loss
                )
                
                total_loss += loss.item()
                
                # Collect predictions
                node_preds = torch.argmax(outputs['node_logits'], dim=-1)
                mask = batch.node_y != -1
                all_node_preds.extend(node_preds[mask].cpu().numpy())
                all_node_labels.extend(batch.node_y[mask].cpu().numpy())
                
                graph_preds = torch.argmax(outputs['graph_logits'], dim=-1)
                all_graph_preds.extend(graph_preds.cpu().numpy())
                all_graph_labels.extend(batch.risk_class.squeeze().cpu().numpy())
                
                all_scores.extend(outputs['graph_score'].squeeze().cpu().numpy())
                all_score_labels.extend(batch.y.squeeze().cpu().numpy())
        
        # Calculate metrics
        node_acc = accuracy_score(all_node_labels, all_node_preds) if all_node_labels else 0
        graph_acc = accuracy_score(all_graph_labels, all_graph_preds)
        mse = mean_squared_error(all_score_labels, all_scores)
        
        return {
            'loss': total_loss / len(val_loader),
            'node_acc': node_acc,
            'graph_acc': graph_acc,
            'mse': mse
        }
    
    def evaluate(self, test_loader: DataLoader) -> Dict:
        """Comprehensive evaluation on test set."""
        self.model.eval()
        
        all_node_preds = []
        all_node_labels = []
        all_graph_preds = []
        all_graph_labels = []
        all_scores = []
        all_score_labels = []
        
        with torch.no_grad():
            for batch in tqdm(test_loader, desc="Evaluating"):
                batch = batch.to(self.device)
                
                outputs = self.model(batch.x, batch.edge_index, batch.batch)
                
                # Node predictions
                node_preds = torch.argmax(outputs['node_logits'], dim=-1)
                mask = batch.node_y != -1
                all_node_preds.extend(node_preds[mask].cpu().numpy())
                all_node_labels.extend(batch.node_y[mask].cpu().numpy())
                
                # Graph predictions
                graph_preds = torch.argmax(outputs['graph_logits'], dim=-1)
                all_graph_preds.extend(graph_preds.cpu().numpy())
                all_graph_labels.extend(batch.risk_class.squeeze().cpu().numpy())
                
                all_scores.extend(outputs['graph_score'].squeeze().cpu().numpy() * 10)
                all_score_labels.extend(batch.y.squeeze().cpu().numpy() * 10)
        
        # Node-level metrics
        node_acc = accuracy_score(all_node_labels, all_node_preds)
        node_precision, node_recall, node_f1, _ = precision_recall_fscore_support(
            all_node_labels, all_node_preds, average='weighted', zero_division=0
        )
        
        # Graph-level classification metrics
        graph_acc = accuracy_score(all_graph_labels, all_graph_preds)
        graph_precision, graph_recall, graph_f1, _ = precision_recall_fscore_support(
            all_graph_labels, all_graph_preds, average='weighted', zero_division=0
        )
        
        # Graph-level regression metrics
        mse = mean_squared_error(all_score_labels, all_scores)
        mae = mean_absolute_error(all_score_labels, all_scores)
        r2 = r2_score(all_score_labels, all_scores)
        
        results = {
            'node_classification': {
                'accuracy': node_acc,
                'precision': node_precision,
                'recall': node_recall,
                'f1': node_f1
            },
            'graph_classification': {
                'accuracy': graph_acc,
                'precision': graph_precision,
                'recall': graph_recall,
                'f1': graph_f1
            },
            'graph_regression': {
                'mse': mse,
                'rmse': np.sqrt(mse),
                'mae': mae,
                'r2': r2
            }
        }
        
        return results
    
    def save_checkpoint(self, path: Path):
        """Save model checkpoint."""
        path.parent.mkdir(parents=True, exist_ok=True)
        
        checkpoint = {
            'model_state_dict': self.model.state_dict(),
            'optimizer_state_dict': self.optimizer.state_dict(),
            'history': self.history
        }
        
        torch.save(checkpoint, path)
    
    def load_checkpoint(self, path: Path):
        """Load model checkpoint."""
        checkpoint = torch.load(path, map_location=self.device)
        self.model.load_state_dict(checkpoint['model_state_dict'])
        self.optimizer.load_state_dict(checkpoint['optimizer_state_dict'])
        self.history = checkpoint.get('history', self.history)


def load_graph_data(file_path: Path) -> List[Dict]:
    """Load graph data from file."""
    with gzip.open(file_path, 'rt', encoding='utf-8') as f:
        return json.load(f)


def main():
    """Training pipeline for GNN predictor."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Train GNN predictor")
    parser.add_argument("--data-dir", type=str, required=True, help="Data directory")
    parser.add_argument("--output-dir", type=str, required=True, help="Output directory")
    parser.add_argument("--epochs", type=int, default=100, help="Number of epochs")
    parser.add_argument("--batch-size", type=int, default=32, help="Batch size")
    parser.add_argument("--lr", type=float, default=1e-3, help="Learning rate")
    parser.add_argument("--hidden-dim", type=int, default=128, help="Hidden dimension")
    parser.add_argument("--encoder", type=str, default="sage", choices=["sage", "gat"])
    
    args = parser.parse_args()
    
    data_dir = Path(args.data_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Load data
    logger.info("Loading graph data...")
    train_graphs = load_graph_data(data_dir / "gnn_train.json.gz")
    val_graphs = load_graph_data(data_dir / "gnn_val.json.gz")
    test_graphs = load_graph_data(data_dir / "gnn_test.json.gz")
    
    # Create datasets
    train_dataset = AttackGraphDataset(train_graphs)
    val_dataset = AttackGraphDataset(val_graphs)
    test_dataset = AttackGraphDataset(test_graphs)
    
    # Create data loaders
    train_loader = DataLoader(train_dataset, batch_size=args.batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=args.batch_size)
    test_loader = DataLoader(test_dataset, batch_size=args.batch_size)
    
    # Initialize model
    logger.info("Initializing GNN model...")
    model = GNNPredictor(
        in_channels=10,
        hidden_channels=args.hidden_dim,
        out_channels=64,
        encoder_type=args.encoder,
        pooling="mean_max"
    )
    
    # Train
    trainer = GNNTrainer(model, learning_rate=args.lr)
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
    logger.info(f"Node Classification - Accuracy: {results['node_classification']['accuracy']:.4f}, F1: {results['node_classification']['f1']:.4f}")
    logger.info(f"Graph Classification - Accuracy: {results['graph_classification']['accuracy']:.4f}, F1: {results['graph_classification']['f1']:.4f}")
    logger.info(f"Graph Regression - RMSE: {results['graph_regression']['rmse']:.4f}, R2: {results['graph_regression']['r2']:.4f}")
    
    # Save results
    results_file = output_dir / "gnn_test_results.json"
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    logger.info(f"\nResults saved to {results_file}")


if __name__ == "__main__":
    main()
