"""Tests for the C2 attack-path-recovery harness — tiny in-memory fakes, no 9 GB dataset."""

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
logging.disable(logging.CRITICAL)

import torch  # noqa: E402

from evaluation.pignn_path_recovery import (  # noqa: E402
    to_path_sample, _train, _node_scored, _counts_node, _counts_edge, _best_threshold, _prf,
)


def _fake(n=8, feats=19, path_edge=(0, 1), seed=0):
    g = torch.Generator().manual_seed(seed)
    adj = (torch.rand(n, n, 16, generator=g) < 0.15).float()
    adj[path_edge[0], path_edge[1], 0] = 1.0          # ensure the path edge exists in adjacency
    X = torch.rand(n, feats, generator=g)
    Y = torch.zeros(n, n, dtype=torch.int64)
    Y[path_edge[0], path_edge[1]] = 1
    return {"adj_tensor": adj, "X_matrix": X, "Y_matrix": Y}


def test_to_path_sample_shapes_and_labels():
    s = to_path_sample(_fake(n=6, path_edge=(0, 1)))
    assert s.x.shape == (6, 19) and s.adj_norm.shape == (6, 6) and s.y.shape == (6,)
    assert s.adj_any.shape == (6, 6) and s.Y.shape == (6, 6)
    assert s.y[0] == 1.0 and s.y[1] == 1.0          # both endpoints of the path edge
    assert float(s.Y.sum()) == 1.0                  # exactly one ground-truth path edge
    assert s.adj_any[0, 1] == 1.0                   # that edge is a candidate


def test_prf_math():
    p, r, f = _prf(8, 2, 2)
    assert abs(p - 0.8) < 1e-9 and abs(r - 0.8) < 1e-9 and abs(f - 0.8) < 1e-9
    assert _prf(0, 0, 0) == (0.0, 0.0, 0.0)


def test_path_recovery_metrics_in_range():
    samples = [to_path_sample(_fake(n=8, path_edge=(i % 7, (i + 1) % 7), seed=i)) for i in range(6)]
    model = _train(samples, in_features=19, identity_adj=False, epochs=5,
                   hidden=8, lr=0.01, pos_weight=10.0, seed=0)
    scored = _node_scored(model, samples)
    tn, te = _best_threshold(scored, _counts_node), _best_threshold(scored, _counts_edge)
    assert 0.0 < tn < 1.0 and 0.0 < te < 1.0
    for counts in (_counts_node, _counts_edge):
        p, r, f = _prf(*counts(scored, 0.5))
        assert 0.0 <= p <= 1.0 and 0.0 <= r <= 1.0 and 0.0 <= f <= 1.0


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"PASS  {fn.__name__}")
    print(f"\n{len(fns)} tests passed.")
