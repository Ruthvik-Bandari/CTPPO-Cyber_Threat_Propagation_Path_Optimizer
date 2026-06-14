"""Tests for the synthetic CTPPO attack-graph generator + labeller (roadmap A3.1).

Verifies: feature width is fixed, generated graphs are valid CTPPO AttackGraphs with
real EPSS on vulns, labels are seed-reproducible, and the ground-truth label genuinely
depends on topology (beta term) — the property that makes the GNN-vs-rule ablation
meaningful.
"""

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

logging.disable(logging.CRITICAL)

import torch  # noqa: E402

from core.threat_data import ThreatDataProvider  # noqa: E402
from core.node_types import VulnerabilityNode  # noqa: E402
from ml.gnn.features import FEATURE_DIM, graph_features  # noqa: E402
from ml.gnn.synth_graphs import (  # noqa: E402
    make_dataset, generate_attack_graph, true_exploitability, lateral_operator,
    _cve_pool, _N_TYPE,
)

_PROVIDER = ThreatDataProvider(offline=True)


def test_feature_dim_is_fixed_across_graphs():
    ds = make_dataset(4, seed=3, provider=_PROVIDER)
    widths = {lg.sample.x.shape[1] for lg in ds}
    assert widths == {FEATURE_DIM}                       # same width regardless of graph


def test_generated_graph_is_valid_with_real_epss():
    ds = make_dataset(3, seed=5, provider=_PROVIDER)
    lg = ds[0]
    g = lg.graph
    assert g.num_nodes > 0 and g.num_edges > 0
    assert g.entry_points and g.goal_nodes
    assert int(lg.is_vuln.sum()) >= 1
    # vuln nodes carry a real EPSS in [0,1] in metadata
    for nid in g.nodes:
        node = g.nodes[nid]
        if isinstance(node, VulnerabilityNode):
            assert 0.0 <= float(node.metadata["epss"]) <= 1.0
            assert node.cve_id


def test_labels_are_reproducible_from_seed():
    a = make_dataset(3, seed=7, provider=_PROVIDER)
    b = make_dataset(3, seed=7, provider=_PROVIDER)
    for la, lb in zip(a, b):
        assert torch.allclose(la.sample.y, lb.sample.y)
        assert torch.allclose(la.sample.x, lb.sample.x)


def test_label_depends_on_topology():
    # Same graph features, beta=0 (own-only) vs beta>0 (topology) must differ — proves
    # the label carries information the per-node rule prior cannot capture.
    pool = _cve_pool(_PROVIDER, seed=9)
    import random
    g = generate_attack_graph(random.Random(9), pool, _PROVIDER)
    x, _, node_ids = graph_features(g, _PROVIDER)
    base = x[:, _N_TYPE].clone()
    lateral = lateral_operator(g, node_ids)
    gen = torch.Generator().manual_seed(0)
    y_flat = true_exploitability(base, lateral, beta=0.0, noise=0.0, generator=gen)
    gen = torch.Generator().manual_seed(0)
    y_topo = true_exploitability(base, lateral, beta=3.0, noise=0.0, generator=gen)
    assert not torch.allclose(y_flat, y_topo)
    assert float(y_topo.min()) >= 0.0 and float(y_topo.max()) <= 1.0
    # lateral operator is self-loop-free: no node mixes in its own value
    assert float(lateral.diagonal().abs().max()) == 0.0


if __name__ == "__main__":
    test_feature_dim_is_fixed_across_graphs()
    test_generated_graph_is_valid_with_real_epss()
    test_labels_are_reproducible_from_seed()
    test_label_depends_on_topology()
    print("4 tests passed.")
