"""Replay of supported rules against regression and OTRF pools, on the pinned engine (synthetic data)."""

import json
import os
import zipfile

import pytest

from aegisbench.positives import otrf_events, run, sigma_events, supported_rules
from aegisbench.qc import SIGMA_REGRESSION, SIGMA_RULES, SYSMON_CHANNEL
from aegissec.detect.engine import Elasticsearch

ES_URL = os.environ.get("AEGIS_ES_URL", "http://127.0.0.1:9200")
CERTUTIL = "00000000-0000-4000-8000-000000000001"
RUNDLL = "00000000-0000-4000-8000-000000000002"
NEVER = "00000000-0000-4000-8000-000000000003"

RULE = """title: {title}
id: {rid}
logsource: {{category: process_creation, product: windows}}
detection:
  selection:
    Image|endswith: '{image}'
  condition: selection
"""


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def _sysmon(image, **extra):
    return {"Event": {"System": {"EventID": 1, "Channel": SYSMON_CHANNEL}, "EventData": {"Image": image, **extra}}}


@pytest.fixture
def root(tmp_path):
    sigma = tmp_path / "sigma"
    _write(sigma / SIGMA_RULES / "a.yml", RULE.format(title="certutil", rid=CERTUTIL, image="\\\\certutil.exe"))
    _write(sigma / SIGMA_RULES / "b.yml", RULE.format(title="rundll", rid=RUNDLL, image="\\\\rundll32.exe"))
    _write(sigma / SIGMA_RULES / "c.yml", RULE.format(title="never", rid=NEVER, image="\\\\nothing.exe"))
    _write(sigma / SIGMA_RULES / "d.yml", RULE.format(title="regex", rid="x", image="x").replace("|endswith", "|re"))
    case = sigma / SIGMA_REGRESSION / "certutil"
    _write(case / "info.yml", f"rule_metadata:\n  - id: {CERTUTIL}\n")
    # Two concatenated events; the second carries a field outside v1 that must be dropped.
    events = [_sysmon("C:\\Windows\\certutil.exe"), _sysmon("C:\\W\\CertUtil.exe", RuleName="-", Unused=3)]
    _write(case / f"{CERTUTIL}.json", "\n".join(json.dumps(e, indent=1) for e in events))
    # The rundll rule's recorded event does not match it, which must surface as a fidelity disagreement.
    case = sigma / SIGMA_REGRESSION / "rundll"
    _write(case / "info.yml", f"rule_metadata:\n  - id: {RUNDLL}\n")
    _write(case / f"{RUNDLL}.json", json.dumps(_sysmon("C:\\Windows\\regsvr32.exe")))
    archive = tmp_path / "otrf/datasets/atomic/windows/execution/host/rundll_test.zip"
    archive.parent.mkdir(parents=True)
    lines = [
        {"EventID": 1, "Channel": SYSMON_CHANNEL, "Image": "C:\\Windows\\System32\\rundll32.exe"},
        {"EventID": 1, "Channel": SYSMON_CHANNEL, "Image": "C:\\Windows\\System32\\rundll32.exe"},
        {"EventID": 4688, "Channel": "Security", "NewProcessName": "C:\\Windows\\System32\\rundll32.exe"},
    ]
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("rundll_test.json", "\n".join(json.dumps(x) for x in lines))
    return tmp_path


def test_pools_keep_only_v1_fields_and_sysmon_process_creation(root):
    sigma = list(sigma_events(root / "sigma"))
    assert [p.source for p in sigma] == [CERTUTIL, CERTUTIL, RUNDLL]
    assert all(set(p.event.data) <= {"Image"} for p in sigma)
    otrf = list(otrf_events(root / "otrf"))
    assert [p.event.event_id for p in otrf] == ["otrf:rundll_test:0", "otrf:rundll_test:1"]
    rules, rejected = supported_rules(root / "sigma")
    assert sorted(rules) == [CERTUTIL, RUNDLL, NEVER]
    assert rejected == {"unsupported_modifier": 1}


@pytest.mark.engine
def test_replay_reports_fidelity_and_candidates(root):
    es = Elasticsearch(ES_URL)
    try:
        report = run(root, es)
    finally:
        es.close()
    assert report["engine_errors"] == {}
    assert report["pool"] == {"sigma_events": 3, "otrf_events": 2}
    per_rule = report["per_rule"]
    assert per_rule[CERTUTIL] == {
        "own_regression_events": 2,
        "own_regression_matched": 2,
        "other_regression_matched": 0,
        "otrf_candidate_events": 0,
        "otrf_datasets": [],
    }
    assert per_rule[RUNDLL]["own_regression_matched"] == 0
    assert per_rule[RUNDLL]["otrf_datasets"] == ["rundll_test"]
    assert report["fidelity"] == {
        "rules_with_regression_events": 2,
        "rules_matching_all_own_events": 1,
        "rules_disagreeing": [RUNDLL],
    }
    assert report["summary"] == {
        "rules_with_any_positive": 2,
        "rules_with_2plus_positive_events": 2,
        "rules_with_otrf_candidates": 1,
    }
    assert "certutil.exe" not in json.dumps(report).lower()  # no event values in the report
