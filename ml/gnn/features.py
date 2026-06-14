"""Stable per-node feature vectors for the exploitability GNN.

The original ``attack_graph_to_features`` produced a node-type one-hot whose width
varied per graph — unusable for a saved checkpoint. This builder is FIXED-WIDTH
(global node-type one-hot + grounded numeric features), so a model trained on
generated graphs (roadmap A3) can score any CTPPO ``AttackGraph``, including the
live scan path wired in A1.

Feature layout (FEATURE_DIM = 13):
  [0:7]  node-type one-hot, in NodeType enum order
  [7]    EPSS probability of the node's CVE      (vuln nodes; 0 otherwise)
  [8]    CISA KEV membership flag                (vuln nodes; 0 otherwise)
  [9]    CVSS exploitability sub-score / 3.89     (vuln nodes; 0 otherwise)
  [10]   CVSS base score / 10                     (vuln nodes; 0 otherwise)
  [11]   asset criticality / 10                   (asset nodes; 0 otherwise)
  [12]   privilege level / 9                       (entry/exploit/goal/privilege; 0 otherwise)

EPSS/KEV are read from the node's metadata first (set by the generator) and fall
back to a ThreatDataProvider lookup by CVE id, so features stay grounded in real data.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import List, Optional, Tuple

import torch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.node_types import (
    NodeType, AssetNode, VulnerabilityNode, ExploitNode,
    PrivilegeNode, EntryPointNode, GoalNode,
)
from ml.gnn.data import normalize_adjacency

_NODE_TYPES = list(NodeType)              # stable enum order (7 types)
_N_TYPE = len(_NODE_TYPES)
_N_NUMERIC = 6
FEATURE_DIM = _N_TYPE + _N_NUMERIC        # 13
_MAX_EXPL = 3.89                          # max CVSS v3.1 exploitability sub-score
_MAX_PRIV = 9.0                           # PrivilegeLevel.SYSTEM.value


def node_feature_vector(node, provider=None) -> List[float]:
    """Fixed-width feature vector for one node. See module docstring for the layout."""
    v = [0.0] * FEATURE_DIM
    v[_NODE_TYPES.index(node.node_type)] = 1.0
    b = _N_TYPE
    if isinstance(node, VulnerabilityNode):
        epss = node.metadata.get("epss")
        if epss is None and provider is not None and node.cve_id:
            epss = provider.epss(node.cve_id)
        v[b + 0] = float(epss or 0.0)
        kev = node.metadata.get("kev")
        if kev is None and provider is not None and node.cve_id:
            kev = provider.is_kev(node.cve_id)
        v[b + 1] = 1.0 if kev else 0.0
        v[b + 2] = min(1.0, node.exploitability_score / _MAX_EXPL)
        v[b + 3] = min(1.0, (node.cvss_score or 0.0) / 10.0)
    elif isinstance(node, AssetNode):
        v[b + 4] = min(1.0, node.criticality / 10.0)
    elif isinstance(node, ExploitNode):
        v[b + 5] = node.gained_privileges.value / _MAX_PRIV
    elif isinstance(node, EntryPointNode):
        v[b + 5] = node.access_level.value / _MAX_PRIV
    elif isinstance(node, GoalNode):
        v[b + 5] = node.required_privileges.value / _MAX_PRIV
    elif isinstance(node, PrivilegeNode):
        v[b + 5] = node.level.value / _MAX_PRIV
    return v


def graph_features(graph, provider=None) -> Tuple[torch.Tensor, torch.Tensor, List[str]]:
    """Build (x, adj_norm, node_ids) for a CTPPO ``AttackGraph``.

    x is (N, FEATURE_DIM); adj_norm is the symmetric-normalized adjacency; node_ids
    gives row order so predictions map back to graph nodes.
    """
    node_ids = list(graph.nodes.keys())
    idx = {nid: i for i, nid in enumerate(node_ids)}
    x = torch.tensor(
        [node_feature_vector(graph.nodes[nid], provider) for nid in node_ids],
        dtype=torch.float32,
    )
    n = len(node_ids)
    A = torch.zeros(n, n)
    for src, targets in graph.adjacency.items():
        if src in idx:
            for tgt in targets:
                if tgt in idx:
                    A[idx[src], idx[tgt]] = 1.0
    return x, normalize_adjacency(A), node_ids
