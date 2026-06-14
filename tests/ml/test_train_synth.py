"""Fast tests for the A3 trainer + ablation (roadmap A3.2).

Verifies the pipeline, not the research outcome: the ROC-AUC helper is correct, a small
training run reduces loss and yields valid in-range ablation metrics, and a saved
checkpoint round-trips into refine.py's loader. Does NOT assert the GNN beats the rule
prior — that verdict is the (honestly reported) experiment result in
docs/RESEARCH/A3_GNN_ABLATION.md.
"""

import logging
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

logging.disable(logging.CRITICAL)

import torch  # noqa: E402

from core.threat_data import ThreatDataProvider  # noqa: E402
from ml.gnn.model import ExploitabilityGNN  # noqa: E402
from ml.gnn.features import FEATURE_DIM, graph_features  # noqa: E402
from ml.gnn.train_synth import roc_auc, run  # noqa: E402
from ml.gnn.refine import _load_checkpoint, gnn_exploitability_scores  # noqa: E402
from ml.gnn.synth_graphs import make_dataset  # noqa: E402

_PROVIDER = ThreatDataProvider(offline=True)


def test_roc_auc_matches_known_values():
    # Perfect separation -> 1.0; reversed -> 0.0; tie split -> ~0.5.
    s = torch.tensor([0.1, 0.2, 0.8, 0.9])
    lab = torch.tensor([0, 0, 1, 1])
    assert abs(roc_auc(s, lab) - 1.0) < 1e-9
    assert abs(roc_auc(-s, lab) - 0.0) < 1e-9
    assert abs(roc_auc(torch.tensor([0.5, 0.5, 0.5, 0.5]), lab) - 0.5) < 1e-9


def test_run_produces_valid_ablation_metrics():
    r = run(n_graphs=24, epochs=20, hidden=16, beta=3.0, seed=0,
            provider=_PROVIDER, save_checkpoint=False)
    assert r.loss_end < r.loss_start                      # learning happened
    for auc in (r.auc_gnn, r.auc_rule):
        assert 0.0 <= auc <= 1.0
    assert r.rmse_gnn >= 0.0 and r.rmse_rule_calibrated >= 0.0
    assert r.n_vuln_nodes > 0


def test_checkpoint_roundtrips_into_refine_loader():
    ds = make_dataset(2, seed=1, provider=_PROVIDER)
    g = ds[0].graph
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "ckpt.pt"
        torch.manual_seed(0)
        model = ExploitabilityGNN(in_features=FEATURE_DIM, hidden=16, num_layers=2)
        torch.save({"state_dict": model.state_dict(), "in_features": FEATURE_DIM,
                    "hidden": 16, "num_layers": 2}, path)
        loaded = _load_checkpoint(path)
        x, adj, _ = graph_features(g, _PROVIDER)
        model.eval(); loaded.eval()
        with torch.no_grad():
            assert torch.allclose(model(x, adj), loaded(x, adj))
        # and refine's scorer accepts the checkpoint path
        scores = gnn_exploitability_scores(g, checkpoint=str(path), provider=_PROVIDER)
        assert set(scores) == set(g.nodes)
        assert all(0.0 <= v <= 1.0 for v in scores.values())


if __name__ == "__main__":
    test_roc_auc_matches_known_values()
    test_run_produces_valid_ablation_metrics()
    test_checkpoint_roundtrips_into_refine_loader()
    print("3 tests passed.")
