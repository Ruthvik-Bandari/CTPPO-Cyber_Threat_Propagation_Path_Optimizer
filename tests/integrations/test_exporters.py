"""Tests for Phase 6 / G2 — SIEM/EDR/ticketing exporters (pure, offline)."""

from integrations.exporters import to_ecs_events, to_cef, to_ticket, dispatch_webhook

_PARETO = {
    "paths": {"pareto_optimal": [
        {"path": ["internet", "web", "crown"],
         "cost": {"TIME_TO_EXPLOIT": 4.2, "SUCCESS_PROBABILITY": 0.46},
         "reachability_band": {"independence": 0.46, "comonotone": 0.8, "width_factor": 1.74, "n_edges": 4}},
    ]},
    "risk_summary": {"num_pareto_paths": 1},
}


def test_ecs_event_shape():
    events = to_ecs_events(_PARETO, recommended_fix="CVE-2021-44228")
    assert len(events) == 1
    e = events[0]
    assert e["event"]["module"] == "ctppo"
    assert e["event"]["dataset"] == "ctppo.attack_path"
    assert e["ctppo"]["recommended_fix"] == "CVE-2021-44228"
    assert e["ctppo"]["pareto_rank"] == 1
    assert e["ctppo"]["reachability_independence"] == 0.46
    assert "@timestamp" in e


def test_ecs_severity_from_reachability():
    hi = to_ecs_events({"paths": {"pareto_optimal": [
        {"path": ["a"], "cost": {}, "reachability_band": {"independence": 0.6}}]}})[0]
    lo = to_ecs_events({"paths": {"pareto_optimal": [
        {"path": ["a"], "cost": {}, "reachability_band": {"independence": 0.01}}]}})[0]
    assert hi["event"]["severity"] == "critical"
    assert lo["event"]["severity"] == "low"


def test_cef_header_has_literal_structural_pipes():
    e = to_ecs_events(_PARETO, recommended_fix="CVE-2021-44228")[0]
    cef = to_cef(e)
    assert cef.startswith("CEF:0|CTPPO|attack-path-engine|1.0|pareto_path|")
    # CEF header = 7 fields (version..severity) → 6 literal separator pipes, none escaped
    header = cef.split("|cs1Label")[0]
    assert header.count("|") == 6
    assert "\\|" not in header           # structural pipes are NOT escaped
    assert "cs2=CVE-2021-44228" in cef


def test_ticket_fields():
    t = to_ticket(_PARETO, recommended_fix="CVE-2021-44228", reachability_reduction=0.31)
    assert "CVE-2021-44228" in t["summary"]
    assert t["priority"] in {"Highest", "High", "Medium", "Low"}
    assert "ctppo" in t["labels"]
    assert t["fields"]["num_pareto_paths"] == 1


def test_webhook_noop_without_url():
    r = dispatch_webhook({"a": 1}, url=None)
    assert r["delivered"] is False
    assert "no webhook URL" in r["reason"]
    assert r["payload"] == {"a": 1}


def test_webhook_dispatches_with_injected_client():
    class _Resp:
        status_code = 202

    class _Client:
        def __init__(self): self.calls = []
        def post(self, url, json):
            self.calls.append((url, json)); return _Resp()

    client = _Client()
    r = dispatch_webhook({"a": 1}, url="https://siem.example/ingest", client=client)
    assert r["delivered"] is True and r["status_code"] == 202
    assert client.calls == [("https://siem.example/ingest", {"a": 1})]
