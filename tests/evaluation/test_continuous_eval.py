"""Tests for the continuous-eval regression harness (evaluation/continuous_eval.py).

The regression-detection logic is pure (synthetic history records, no NAMOA*); one test runs
a small real cycle. Slow (auto-marked under tests/evaluation/).
"""

import json

from core.threat_data import ThreatDataProvider
from evaluation import continuous_eval as ce


def _rec(**metrics):
    return {"timestamp": "t", "n": 1, "metrics": metrics, "data": {}}


def test_regression_below_floor_flagged_on_first_record():
    hist = [_rec(pareto_recovery=0.0, pareto_ge_cvss=0.9)]
    flags = ce.detect_regressions(hist)
    assert any("pareto_recovery" in f and "floor" in f for f in flags)


def test_regression_drop_vs_previous_flagged():
    hist = [_rec(pareto_recovery=0.85, pareto_ge_cvss=0.9),
            _rec(pareto_recovery=0.70, pareto_ge_cvss=0.9)]   # 0.15 drop > 0.10 tol
    flags = ce.detect_regressions(hist)
    assert any("pareto_recovery" in f and "→" in f for f in flags)


def test_no_regression_when_stable_and_healthy():
    hist = [_rec(pareto_recovery=0.85, pareto_ge_cvss=0.92),
            _rec(pareto_recovery=0.84, pareto_ge_cvss=0.92)]
    assert ce.detect_regressions(hist) == []


def test_history_roundtrip(tmp_path):
    p = tmp_path / "h.json"
    ce.save_history([_rec(pareto_recovery=0.8)], p)
    loaded = ce.load_history(p)
    assert len(loaded) == 1 and loaded[0]["metrics"]["pareto_recovery"] == 0.8
    assert ce.load_history(tmp_path / "missing.json") == []


def test_run_cycle_appends_and_injected_regression_is_caught(tmp_path):
    provider = ThreatDataProvider(offline=True)
    p = tmp_path / "hist.json"
    rep1 = ce.run(n=8, history_path=p, provider=provider)
    assert rep1["history_len"] == 1
    assert 0.0 <= rep1["record"]["metrics"]["pareto_recovery"] <= 1.0

    rep2 = ce.run(n=8, history_path=p, provider=provider, inject_regression=True)
    assert rep2["history_len"] == 2
    assert rep2["record"]["metrics"]["pareto_recovery"] == 0.0
    assert rep2["regressions"]  # the injected regression is flagged
    # persisted
    assert len(json.loads(p.read_text())) == 2
