"""Tests for the exploitability GNN (requires torch; skipped cleanly if absent)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import torch  # noqa: E402

from ml.gnn.model import ExploitabilityGNN  # noqa: E402
from ml.gnn.data import synthetic_graph, normalize_adjacency  # noqa: E402
from ml.gnn.train import train_gnn  # noqa: E402


def test_forward_shape_and_range():
    s = synthetic_graph(n_nodes=10, n_features=8, seed=1)
    model = ExploitabilityGNN(8)
    out = model(s.x, s.adj_norm)
    assert out.shape == (10,)
    assert float(out.min()) >= 0.0 and float(out.max()) <= 1.0


def test_normalize_adjacency_symmetric():
    A = torch.tensor([[0.0, 1.0, 0.0], [1.0, 0.0, 1.0], [0.0, 1.0, 0.0]])
    adj = normalize_adjacency(A)
    assert torch.allclose(adj, adj.t(), atol=1e-6)   # symmetric
    assert float(adj.diagonal().min()) > 0.0          # self-loops added


def test_training_reduces_loss():
    samples = [synthetic_graph(n_features=8, seed=i) for i in range(8)]
    _, hist = train_gnn(samples, in_features=8, epochs=60)
    assert hist[-1] < hist[0] * 0.8   # learns the own+neighbour signal


if __name__ == "__main__":
    test_forward_shape_and_range()
    test_normalize_adjacency_symmetric()
    test_training_reduces_loss()
    print("3 tests passed.")
