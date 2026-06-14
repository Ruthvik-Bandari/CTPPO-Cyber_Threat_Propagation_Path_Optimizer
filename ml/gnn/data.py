"""Graph data utilities for the exploitability GNN.

- ``normalize_adjacency``: symmetric-normalized adjacency with self-loops (GCN renorm trick).
- ``synthetic_graph``: a labelled synthetic graph whose node labels depend on BOTH a node's
  own features and its neighbours' — so a GCN genuinely beats a feature-only MLP. Used for
  verifiable training until real attack-graph datasets are wired in (Phase 4).
- ``attack_graph_to_features``: convert a real ``core.AttackGraph`` into model inputs
  (node-type features + normalized adjacency), so the trained GNN can score live graphs.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

import torch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


@dataclass
class GraphSample:
    x: torch.Tensor          # (N, F) node features
    adj_norm: torch.Tensor   # (N, N) normalized adjacency
    y: torch.Tensor          # (N,) per-node target in [0, 1]


def normalize_adjacency(A: torch.Tensor) -> torch.Tensor:
    """Â = D^-1/2 (A + I) D^-1/2 (Kipf & Welling renormalization)."""
    n = A.shape[0]
    A = A + torch.eye(n, dtype=A.dtype)
    deg = A.sum(dim=1)
    d_inv_sqrt = torch.pow(deg, -0.5)
    d_inv_sqrt[torch.isinf(d_inv_sqrt)] = 0.0
    D = torch.diag(d_inv_sqrt)
    return D @ A @ D


def synthetic_graph(n_nodes: int = 20, n_features: int = 8,
                    edge_prob: float = 0.2, seed: int = 0) -> GraphSample:
    """Random undirected graph with labels = f(own features, neighbour features)."""
    g = torch.Generator().manual_seed(seed)
    x = torch.rand(n_nodes, n_features, generator=g)
    A = (torch.rand(n_nodes, n_nodes, generator=g) < edge_prob).float()
    A = ((A + A.t()) > 0).float()
    A.fill_diagonal_(0)
    adj = normalize_adjacency(A)
    w = torch.linspace(-1.0, 1.0, n_features)
    neigh = adj @ x                               # neighbourhood aggregate
    logits = 0.6 * (x @ w) + 0.8 * (neigh @ w)    # own + neighbour signal
    y = torch.sigmoid(logits + 0.1 * torch.randn(n_nodes, generator=g))
    return GraphSample(x=x, adj_norm=adj, y=y)


def attack_graph_to_features(graph):
    """Convert a core ``AttackGraph`` to (x, adj_norm, node_ids) for inference.

    Features are a one-hot of the node type (a minimal, dependency-free encoding). Returns
    node_ids in row order so predictions can be mapped back to graph nodes.
    """
    node_ids = list(graph.nodes.keys())
    idx = {nid: i for i, nid in enumerate(node_ids)}
    types = sorted({graph.nodes[nid].node_type.name for nid in node_ids})
    tindex = {t: i for i, t in enumerate(types)}

    n, f = len(node_ids), max(1, len(types))
    x = torch.zeros(n, f)
    for nid in node_ids:
        x[idx[nid], tindex[graph.nodes[nid].node_type.name]] = 1.0

    A = torch.zeros(n, n)
    for src, targets in graph.adjacency.items():
        if src not in idx:
            continue
        for tgt in targets:
            if tgt in idx:
                A[idx[src], idx[tgt]] = 1.0
    return x, normalize_adjacency(A), node_ids
