"""Training loop for the exploitability GNN.

Trains on synthetic labelled graphs for now (verifiable end-to-end). Real attack-graph
datasets + EPSS targets get wired in for Phase 4; the loop is dataset-agnostic — pass any
list of ``GraphSample``.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import List, Tuple

import torch
import torch.nn as nn

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ml.gnn.model import ExploitabilityGNN
from ml.gnn.data import GraphSample, synthetic_graph


def train_gnn(samples: List[GraphSample], in_features: int, hidden: int = 32,
              epochs: int = 100, lr: float = 0.01,
              seed: int = 0) -> Tuple[ExploitabilityGNN, List[float]]:
    """Train the GNN; returns (model, per-epoch mean loss)."""
    torch.manual_seed(seed)
    model = ExploitabilityGNN(in_features, hidden=hidden)
    opt = torch.optim.Adam(model.parameters(), lr=lr)
    loss_fn = nn.MSELoss()
    history: List[float] = []
    for _ in range(epochs):
        model.train()
        total = 0.0
        for s in samples:
            opt.zero_grad()
            pred = model(s.x, s.adj_norm)
            loss = loss_fn(pred, s.y)
            loss.backward()
            opt.step()
            total += loss.item()
        history.append(total / max(1, len(samples)))
    return model, history


if __name__ == "__main__":
    N_FEAT = 8
    train_set = [synthetic_graph(n_features=N_FEAT, seed=i) for i in range(20)]
    model, hist = train_gnn(train_set, in_features=N_FEAT, epochs=80)
    print(f"epochs={len(hist)}  loss: {hist[0]:.4f} -> {hist[-1]:.4f} "
          f"({(1 - hist[-1] / hist[0]) * 100:.0f}% reduction)")
