"""GCN model for per-node exploitability prediction (Kipf & Welling, 2017).

Hand-rolled message passing in pure torch (dense adjacency) — no torch_geometric, so it
runs anywhere torch is installed. Attack graphs are small, so dense adjacency is fine.
"""

from __future__ import annotations

import torch
import torch.nn as nn
import torch.nn.functional as F


class GCNLayer(nn.Module):
    """One graph-convolution layer: H' = Â · (H W)."""

    def __init__(self, in_features: int, out_features: int):
        super().__init__()
        self.lin = nn.Linear(in_features, out_features)

    def forward(self, x: torch.Tensor, adj_norm: torch.Tensor) -> torch.Tensor:
        return adj_norm @ self.lin(x)


class ExploitabilityGNN(nn.Module):
    """Stacked GCN -> per-node exploitability score in [0, 1].

    Args:
        in_features: node feature dimension.
        hidden: hidden width.
        num_layers: number of GCN layers (receptive field = num_layers hops).
        dropout: dropout probability between layers.
    """

    def __init__(self, in_features: int, hidden: int = 32,
                 num_layers: int = 2, dropout: float = 0.1):
        super().__init__()
        dims = [in_features] + [hidden] * num_layers
        self.layers = nn.ModuleList(
            GCNLayer(dims[i], dims[i + 1]) for i in range(num_layers)
        )
        self.head = nn.Linear(hidden, 1)
        self.dropout = dropout

    def forward(self, x: torch.Tensor, adj_norm: torch.Tensor) -> torch.Tensor:
        h = x
        for gc in self.layers:
            h = F.relu(gc(h, adj_norm))
            h = F.dropout(h, p=self.dropout, training=self.training)
        return torch.sigmoid(self.head(h)).squeeze(-1)  # (N,)
