"""
Tests for the data-grounded cost model and threat-data provider.

Runs fully offline — the ThreatDataProvider test seeds a tiny local cache instead of
hitting the network. Run with: python -m pytest tests/core/test_cost_model.py  (or
execute this file directly).
"""

import gzip
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.cost_model import (  # noqa: E402
    parse_cvss31_vector, exploitability_subscore, impact_subscore,
    success_probability, time_to_exploit_relative,
    build_edge_cost, EdgeCostInputs, SuccessParams,
)
from core.edge_costs import CostType  # noqa: E402
from core.threat_data import ThreatDataProvider  # noqa: E402

# Log4Shell vector: network, low complexity, no privs/UI, scope changed, full CIA.
LOG4SHELL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"


def test_parse_cvss_vector():
    m = parse_cvss31_vector(LOG4SHELL)
    assert m["AV"] == "N" and m["AC"] == "L" and m["S"] == "C" and m["C"] == "H"
    assert parse_cvss31_vector("") == {}


def test_cvss_subscores_match_spec():
    m = parse_cvss31_vector(LOG4SHELL)
    # Exploitability = 8.22 * 0.85 * 0.77 * 0.85 * 0.85 ~= 3.887
    assert abs(exploitability_subscore(m) - 3.887) < 0.01
    # Impact (scope changed) ~= 6.05 for full CIA
    assert abs(impact_subscore(m) - 6.05) < 0.05


def test_missing_metrics_return_none():
    assert exploitability_subscore({"AV": "N"}) is None
    assert impact_subscore({"C": "H"}) is None


def test_kev_floors_success_probability():
    flags = []
    # Low EPSS but KEV-listed -> existence floored to >= 0.90, times P(exec|AC:L)=0.90
    p = success_probability(epss=0.01, is_kev=True, ac="L", flags=flags)
    assert abs(p - 0.81) < 1e-6           # 0.90 * 0.90


def test_success_probability_records_fallbacks():
    flags = []
    p = success_probability(epss=None, is_kev=False, ac=None, flags=flags)
    assert 0.0 <= p <= 1.0
    assert any("epss_missing" in f for f in flags)
    assert any("ac_unknown" in f for f in flags)


def test_success_params_default_reproduces_shipped():
    # Default SuccessParams must reproduce the historical hard-coded constants exactly.
    assert success_probability(0.01, True, "L", [], SuccessParams()) == \
        success_probability(0.01, True, "L", [])


def test_success_params_override_changes_output():
    # Each knob, varied, must change the result (B6 sensitivity hook).
    base = success_probability(None, True, "L", [])                       # floor binds, prior moot
    no_floor = success_probability(None, True, "L", [],
                                   SuccessParams(kev_exist_floor=0.0))     # prior=0.05 now governs
    assert base > no_floor
    hi_prior = success_probability(None, False, "L", [],
                                   SuccessParams(epss_missing_prior=0.5))
    assert hi_prior > success_probability(None, False, "L", [])
    flat = success_probability(0.9, False, "H", [],
                               SuccessParams(p_exec_by_ac={"L": 0.7, "H": 0.7}))
    assert flat != success_probability(0.9, False, "H", [])               # AC:H factor differs


def test_build_edge_cost_threads_success_params():
    # A no-EPSS edge's success must track the missing-prior override end-to-end.
    inp = EdgeCostInputs(cve_id="CVE-2099-90001",
                         cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    lo = build_edge_cost(inp, success_params=SuccessParams(epss_missing_prior=0.005))
    hi = build_edge_cost(inp, success_params=SuccessParams(epss_missing_prior=0.50))
    assert hi.expected_values()[CostType.SUCCESS_PROBABILITY] > \
        lo.expected_values()[CostType.SUCCESS_PROBABILITY]


def test_time_kev_is_faster_than_non_kev():
    f1, f2 = [], []
    t_kev = time_to_exploit_relative(expl=3.0, is_kev=True, ac="L", flags=f1)
    t_plain = time_to_exploit_relative(expl=3.0, is_kev=False, ac="L", flags=f2)
    assert t_kev < t_plain


def test_build_edge_cost_grounded():
    inputs = EdgeCostInputs(cve_id="CVE-2021-44228", cvss_vector=LOG4SHELL,
                            cvss_score=10.0, epss=0.97, is_kev=True, asset_criticality=9.0)
    cost = build_edge_cost(inputs)
    vals = cost.expected_values()
    assert 0.0 <= vals[CostType.SUCCESS_PROBABILITY] <= 1.0
    assert vals[CostType.BUSINESS_IMPACT] > 7.0           # critical + high-crit asset
    assert cost.metadata["is_kev"] is True
    assert cost.metadata["data_grounded"]["epss"] is True
    assert cost.metadata["fallbacks"] == []              # everything was data-grounded


def test_build_edge_cost_fallbacks_when_no_data():
    # No vector, no EPSS, no KEV -> must not crash; flags should record the backoffs.
    cost = build_edge_cost(EdgeCostInputs(cve_id="CVE-0000-0000"))
    assert cost.metadata["data_grounded"]["cvss_vector"] is False
    assert len(cost.metadata["fallbacks"]) >= 1


def test_threat_provider_offline_parsing():
    with tempfile.TemporaryDirectory() as d:
        cache = Path(d)
        # seed EPSS csv.gz (with a '#' metadata line like the real feed)
        csv_text = "#model_version:v2025\ncve,epss,percentile\nCVE-2021-44228,0.97,0.99\n"
        (cache / "epss_scores-current.csv.gz").write_bytes(
            gzip.compress(csv_text.encode("utf-8"))
        )
        # seed KEV json
        (cache / "known_exploited_vulnerabilities.json").write_text(
            json.dumps({"vulnerabilities": [{"cveID": "CVE-2021-44228"}]})
        )
        p = ThreatDataProvider(cache_dir=cache, ttl_hours=1e9, offline=True)
        assert p.epss("CVE-2021-44228") == 0.97
        assert p.epss("cve-2021-44228") == 0.97          # case-insensitive
        assert p.is_kev("CVE-2021-44228") is True
        assert p.epss("CVE-9999-9999") is None           # unknown -> None, not a guess
        assert p.is_kev("CVE-9999-9999") is False


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"PASS  {fn.__name__}")
    print(f"\n{len(fns)} tests passed.")
