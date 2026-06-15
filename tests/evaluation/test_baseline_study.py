"""Tests for the A2/A4 baseline study (evaluation/baseline_study.py).

Slow (auto-marked under tests/evaluation/): runs many NAMOA* searches. Uses the offline
EPSS snapshot for reproducibility.
"""

from core.threat_data import ThreatDataProvider
from evaluation import baseline_study as bs


def test_baselines_return_real_cve_from_net():
    provider = ThreatDataProvider(offline=True)
    hosts, vulns = bs.network(0, "neutral", provider)
    ids = {v.cve_id for v in vulns}
    for fn in (bs.baseline_cvss, bs.baseline_epss, bs.baseline_risk):
        assert fn(vulns, provider) in ids
    assert bs.baseline_mulval_reach(hosts, vulns, provider) in ids
    assert bs.baseline_pareto(hosts, vulns, provider) in ids


def test_on_path_filter_is_subset_including_chain():
    provider = ThreatDataProvider(offline=True)
    hosts, vulns = bs.network(1, "neutral", provider)
    onpath = bs._on_path_vulns(hosts, vulns)
    assert set(v.cve_id for v in onpath) <= set(v.cve_id for v in vulns)
    assert len(onpath) >= 1  # the guaranteed entry→crown chain is always on-path


def test_both_modes_run_and_pareto_beats_baselines():
    provider = ThreatDataProvider(offline=True)
    for mode in ("stacked", "neutral"):
        r = bs.run(n=12, mode=mode, provider=provider)
        assert r["n_evaluated"] >= 1
        par = r["recovery_pareto"]["point"]
        assert 0.0 <= par <= 1.0
        # the proposed method recovers at least as much oracle reduction as each baseline
        for b in ("cvss", "epss", "risk", "mulval_reach"):
            assert par >= r[f"recovery_{b}"]["point"] - 1e-9
        # and matches/beats CVSS in a clear majority of nets
        assert r["pareto_ge_cvss"]["point"] >= 0.5
