"""Tests for the PIGNN external-validation conversion + training plumbing (roadmap A3-A).

Uses tiny in-memory tensor dicts shaped like the real PIGNN .pt files, so the test runs
without the 9 GB (git-ignored) dataset. Verifies the edge-tensor -> node-classification
reduction and that the train/eval loop produces an in-range ROC-AUC.
"""

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

logging.disable(logging.CRITICAL)

import torch  # noqa: E402

from evaluation.pignn_validation import to_sample, _train, _eval_auc, PignnSample  # noqa: E402


def _fake_graph(n=6, feats=19, path_edge=(0, 1), seed=0):
    g = torch.Generator().manual_seed(seed)
    adj = (torch.rand(n, n, 16, generator=g) < 0.1).float()
    X = torch.rand(n, feats, generator=g)
    Y = torch.zeros(n, n, dtype=torch.int64)
    Y[path_edge[0], path_edge[1]] = 1                     # one attack-path edge
    return {"adj_tensor": adj, "X_matrix": X, "Y_matrix": Y}


def test_to_sample_shapes_and_node_label():
    s = to_sample(_fake_graph(n=6, path_edge=(0, 1)))
    assert s.x.shape == (6, 19)
    assert s.adj_norm.shape == (6, 6)
    assert s.y.shape == (6,)
    # exactly the two endpoints of the single path edge are positive
    assert s.y[0] == 1.0 and s.y[1] == 1.0
    assert float(s.y.sum()) == 2.0


def test_train_eval_produces_valid_auc():
    samples = [to_sample(_fake_graph(n=8, path_edge=(i % 7, (i + 1) % 7), seed=i))
               for i in range(6)]
    model = _train(samples, in_features=19, identity_adj=False, epochs=5,
                   hidden=8, lr=0.01, pos_weight=10.0, seed=0)
    auc = _eval_auc(model, samples, identity_adj=False)
    assert 0.0 <= auc <= 1.0


if __name__ == "__main__":
    test_to_sample_shapes_and_node_label()
    test_train_eval_produces_valid_auc()
    print("2 tests passed.")
