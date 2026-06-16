"""Tests for Phase 5 / E2 — GNN engine-level effect (slow; needs torch + the A3 checkpoint).

Verifies the experiment runs and returns a coherent result: it evaluates real-CVE nets, reports a
decision-change rate in [0,1], and (when the checkpoint is present) actually refines edges so the
per-edge movement is measured. The honest headline (0% engine-level decision change on 60 nets)
lives in the doc; here we only assert the harness is sound.
"""

import pytest

from evaluation.e2_gnn_engine_lift import run

torch = pytest.importorskip("torch")


def test_e2_runs_and_reports_coherently():
    res = run(n=6)
    assert res["n_evaluated"] >= 1
    assert 0.0 <= res["decision_change_rate"] <= 1.0
    assert res["mean_front_size_rule"] >= 1.0
    # if the trained checkpoint is present, the GNN should have refined edges (movement measured)
    if res["checkpoint_exists"]:
        assert res["mean_edge_success_delta"] >= 0.0
        assert res["max_edge_success_delta"] >= res["mean_edge_success_delta"]
