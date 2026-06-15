"""Deterministic smoke tests for the Phase C evaluation harness (seeded → reproducible)."""

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
logging.disable(logging.CRITICAL)

from evaluation.phase_c_eval import random_network, reachability, run  # noqa: E402
from core.threat_data import ThreatDataProvider  # noqa: E402


def test_random_network_is_reproducible():
    a_hosts, a_vulns = random_network(7)
    b_hosts, b_vulns = random_network(7)
    assert [h.id for h in a_hosts] == [h.id for h in b_hosts]
    assert [v.cve_id for v in a_vulns] == [v.cve_id for v in b_vulns]
    # guaranteed entry + crown present
    assert any(h.is_entry for h in a_hosts) and any(h.is_goal for h in a_hosts)


def test_reachable_crown_has_positive_success():
    provider = ThreatDataProvider(offline=True)
    hosts, vulns = random_network(0)
    assert 0.0 < reachability(hosts, vulns, provider) <= 1.0


def test_pareto_recovers_more_than_cvss():
    res = run(n=40)
    assert res["n_evaluated"] > 0
    for k in ("divergence_rate", "recovery_cvss", "recovery_pareto", "pareto_ge_rate"):
        assert 0.0 <= res[k] <= 1.0
    # The thesis: the Pareto-critical fix recovers more of the oracle reduction than CVSS.
    assert res["recovery_pareto"] > res["recovery_cvss"]
    assert res["mean_red_pareto"] >= res["mean_red_cvss"]


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"PASS  {fn.__name__}")
    print(f"\n{len(fns)} tests passed.")
