import json

import pytest

from aegisbench.qc import SIGMA_RULES
from aegisbench.split import SplitError, assign, build, family, freeze, groups, roots


def test_family_is_the_tool_named_after_the_prefix():
    assert family("rules/windows/process_creation/proc_creation_win_certutil_download.yml") == "certutil"
    assert family("rules/windows/process_creation/proc_creation_win_susp_lolbin_exec.yml") == "susp_lolbin"
    assert family("rules/windows/process_creation/proc_creation_win_hktl_mimikatz.yml") == "hktl_mimikatz"
    assert family("rules/windows/process_creation/other_name.yml") == "other_name"


def test_roots_count_only_own_regression_and_reviewed_malicious_events():
    report = {
        "per_rule": {
            "a": {"matched_event_ids": ["sigma:a:0", "sigma:b:0", "otrf:x:1", "otrf:x:2"]},
            "b": {"matched_event_ids": ["otrf:x:2"]},
            "c": {"matched_event_ids": ["otrf:x:3"]},
        }
    }
    # sigma:b:0 is b's recorded event, not a positive for a; otrf:x:3 was not labelled malicious.
    assert roots(report, {"otrf:x:2"}) == {"a": ["otrf:x:2", "sigma:a:0"], "b": ["otrf:x:2"]}


def test_groups_merge_families_and_shared_events():
    positives = {"r1": ["e1"], "r2": ["e2"], "r3": ["e1"], "r4": ["e4"]}
    paths = {
        r: f"{SIGMA_RULES}/proc_creation_win_{t}_x.yml" for r, t in (("r1", "a"), ("r2", "b"), ("r3", "c"), ("r4", "b"))
    }
    # r1+r3 share an event; r2+r4 share the family "b".
    assert groups(positives, paths) == [["r1", "r3"], ["r2", "r4"]]


def test_assign_keeps_groups_whole_and_is_deterministic():
    grouped = [[f"g{i}a", f"g{i}b"] for i in range(40)]
    splits = assign(grouped, "seed")
    assert splits == assign(grouped, "seed")
    assert [sum(len(g) for g in splits[n]) for n in ("test", "development", "train")] == [12, 12, 36]
    assert sum(len(g) for g in splits["reserve"]) == 20
    seen = [r for gs in splits.values() for g in gs for r in g]
    assert len(seen) == len(set(seen)) == 80
    assert assign(grouped, "other") != splits


def _sigma(tmp_path, n):
    for i in range(n):
        path = tmp_path / SIGMA_RULES / f"proc_creation_win_tool{i}_x.yml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"title: t{i}\nid: r{i}\n")
    return tmp_path


def test_build_and_freeze_once(tmp_path):
    sigma = _sigma(tmp_path / "sigma", 70)
    report = {"per_rule": {f"r{i}": {"matched_event_ids": [f"sigma:r{i}:0"]} for i in range(70)}}
    manifest = build(sigma, report, set(), "seed")
    assert manifest["eligible_roots"] == 70
    assert {k: v["roots"] for k, v in manifest["summary"].items()} == {
        "test": 12,
        "development": 12,
        "train": 36,
        "reserve": 10,
    }
    out = tmp_path / "benchmark/split-manifest.json"
    digest = freeze(manifest, sigma, out)
    assert len(digest) == 64
    first = json.loads(out.read_text())["splits"]["test"][0]["rules"][0]
    assert len(first["source_sha256"]) == 64
    with pytest.raises(SplitError, match="never overwritten"):
        freeze(manifest, sigma, out)


def test_build_refuses_roots_without_rule_files(tmp_path):
    sigma = _sigma(tmp_path / "sigma", 1)
    report = {"per_rule": {"r0": {"matched_event_ids": ["sigma:r0:0"]}, "zz": {"matched_event_ids": ["sigma:zz:0"]}}}
    with pytest.raises(SplitError, match="no file"):
        build(sigma, report, set(), "seed")


def test_natural_roots_join_and_group_by_shared_events(tmp_path):
    sigma = _sigma(tmp_path / "sigma", 3)
    report = {"per_rule": {"r0": {"matched_event_ids": ["sigma:r0:0"]}}}
    manifest = build(sigma, report, set(), "seed", extra={"r1": ["sigma:r0:0"], "r2": ["sigma:x:0"]})
    assert manifest["eligible_roots"] == 3 and manifest["natural_roots_added"] == 2
    groups = [sorted(r["id"] for r in g["rules"]) for gs in manifest["splits"].values() for g in gs]
    assert ["r0", "r1"] in groups  # r1's fix detects r0's recording, so they never split apart
