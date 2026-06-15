"""Tests for B4 (time-to-exploit validity) + B5 (asset-criticality sensitivity)."""

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
logging.disable(logging.CRITICAL)

from evaluation.b4b5_time_criticality import (  # noqa: E402
    time_construct_validity, time_external_validity, criticality_sensitivity,
    _spearman, load_real_cves,
)
from core.threat_data import ThreatDataProvider  # noqa: E402


def test_spearman_basic():
    assert _spearman([1, 2, 3, 4], [1, 2, 3, 4]) > 0.99      # perfect positive
    assert _spearman([1, 2, 3, 4], [4, 3, 2, 1]) < -0.99     # perfect negative


def test_time_proxy_construct_validity():
    c = time_construct_validity()
    assert c["av_monotonic"] is True             # time: network < adjacent < local < physical
    assert c["ac_monotonic"] is True             # low complexity faster than high
    assert abs(c["kev_speedup"] - 2.0) < 0.01     # KEV 0.5x factor (≈2.0x modulo 4-dp rounding)
    assert c["min_time"] > 0


def test_external_validity_runs_on_real_cves():
    assert len(load_real_cves()) >= 20           # NVD cache is present and parseable
    e = time_external_validity(ThreatDataProvider(offline=True))
    assert e["n"] >= 10
    assert -1.0 <= e["spearman_time_epss_all"] <= 1.0


def test_criticality_sensitivity_fracs_in_range():
    res = criticality_sensitivity(n=10)
    assert res["n_evaluated"] > 0
    for f in res["top_fix_stable_frac"].values():
        assert 0.0 <= f <= 1.0


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"PASS  {fn.__name__}")
    print(f"\n{len(fns)} tests passed.")
