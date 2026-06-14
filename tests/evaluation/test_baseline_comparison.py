"""Offline tests for the baseline-comparison evaluation harness."""

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
logging.disable(logging.CRITICAL)  # quiet NAMOA* logs

from evaluation.baseline_comparison import (  # noqa: E402
    compare, cvss_ranking, illustrative_scenario, VulnSpec,
)
from core.threat_data import ThreatDataProvider  # noqa: E402


def test_cvss_ranking_orders_desc():
    vs = [VulnSpec("a", "x", "y", 5.0), VulnSpec("b", "x", "y", 9.0), VulnSpec("c", "x", "y", 7.0)]
    assert [v.cve_id for v in cvss_ranking(vs)] == ["b", "c", "a"]


def test_illustrative_scenario_diverges():
    hosts, vulns = illustrative_scenario()
    out = compare(hosts, vulns, provider=ThreatDataProvider(offline=True))
    # CVSS ranks the dead-end bug first...
    assert out["cvss_top"] == "CVE-DEADEND"
    # ...but it lies on no path to the crown jewel:
    assert "CVE-DEADEND" not in out["pareto_critical_counts"]
    # the real path-critical fix is one of the on-path bugs
    assert out["num_pareto_paths"] >= 1
    assert out["path_critical"] in {"CVE-ENTRY", "CVE-PIVOT"}
    assert out["diverge"] is True


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"PASS  {fn.__name__}")
    print(f"\n{len(fns)} tests passed.")
