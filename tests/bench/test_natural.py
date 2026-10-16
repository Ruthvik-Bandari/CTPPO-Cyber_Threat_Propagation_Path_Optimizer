import json
import os
import subprocess

import pytest

from aegisbench.natural import build, classify, mine, summarize_mining, to_record
from aegisbench.qc import SIGMA_REGRESSION, SIGMA_RULES, SYSMON_CHANNEL
from aegissec.detect.engine import Elasticsearch
from aegissec.detect.rule import parse_rule

ES_URL = os.environ.get("AEGIS_ES_URL", "http://127.0.0.1:9200")
RID = "00000000-0000-4000-8000-0000000000cc"


def rule(values, condition="sel", extra="", description="d"):
    vals = ", ".join(f"'\\\\{v}'" for v in values)
    return (
        f"title: lolbin\nid: {RID}\ndescription: {description}\n"
        "logsource: {category: process_creation, product: windows}\n"
        f"detection:\n  sel: {{Image|endswith: [{vals}]}}\n{extra}  condition: {condition}\n"
    )


def _git(repo, *args):
    return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()


def _commit(repo, path, text, message):
    target = repo / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text)
    _git(repo, "add", "-A")
    _git(repo, "-c", "user.name=t", "-c", "user.email=t@example.org", "commit", "-q", "-m", message)
    return _git(repo, "rev-parse", "HEAD")


@pytest.fixture
def history(tmp_path):
    repo = tmp_path / "work"
    repo.mkdir()
    _git(repo, "init", "-q")
    path = f"{SIGMA_RULES}/proc_creation_win_lolbin.yml"
    _commit(repo, path, rule(["a.exe"]), "add rule")
    _commit(repo, path, rule(["a.exe", "b.exe"]), "fix: cover b.exe (FN)")
    _commit(repo, path, rule(["a.exe", "b.exe"], description="reworded"), "docs only")
    _git(repo, "mv", path, f"{SIGMA_RULES}/proc_creation_win_lolbin_exec.yml")
    _commit(
        repo,
        f"{SIGMA_RULES}/proc_creation_win_lolbin_exec.yml",
        rule(["a.exe", "b.exe"], "sel and not filter", "  filter: {User: 'NT AUTHORITY\\\\SYSTEM'}\n"),
        "rename + FP filter",
    )
    pinned = _commit(
        repo,
        f"{SIGMA_RULES}/proc_creation_win_lolbin_exec.yml",
        rule(["a.exe", "b.exe"], "sel and not filter", "  filter: {User|re: 'x'}\n"),
        "regex filter (outside the subset)",
    )
    bare = tmp_path / "sigma-history.git"
    subprocess.run(["git", "clone", "-q", "--bare", str(repo), str(bare)], check=True)
    return bare, pinned


def test_classify_change_kinds():
    base = parse_rule(rule(["a.exe"]))
    assert classify(base, parse_rule(rule(["a.exe", "b.exe"]))) == (("values_added",), 1, True)
    assert classify(parse_rule(rule(["a.exe", "b.exe"])), base) == (("values_removed",), 1, True)
    kinds, edits, within = classify(base, parse_rule(rule(["a.exe"], "sel and not f", "  f: {User: s}\n")))
    assert set(kinds) == {"condition", "selection_added"} and edits == 2 and within
    many = parse_rule(rule([f"x{i}.exe" for i in range(9)]))
    assert classify(base, many)[2] is False  # more than 8 values do not fit a candidate predicate
    swapped = parse_rule(rule(["a.exe"]).replace("Image|endswith", "Image|contains"))
    assert classify(base, swapped)[0] == ("modifier",)


def test_mine_follows_renames_and_skips_noise(history):
    bare, pinned = history
    changes, skipped = mine(bare, pinned, {RID})
    assert [c.subject for c in changes] == ["rename + FP filter", "fix: cover b.exe (FN)"]
    assert changes[1].kinds == ("values_added",) and changes[1].within_contract
    assert set(changes[0].kinds) == {"condition", "selection_added"}
    assert skipped == {"metadata_only": 1, "outside_supported_subset": 1}
    assert mine(bare, pinned, set())[0] == []  # unsupported at the pin
    summary = summarize_mining(changes, skipped, pinned)
    assert summary["detection_changes"] == 2 and summary["rules"] == 1
    assert json.loads(json.dumps(to_record(changes[0])))["rule_id"] == RID


@pytest.mark.engine
def test_build_keeps_only_fixes_verified_by_a_missed_positive(tmp_path, history):
    from aegisbench.evaluate import load_case

    bare, pinned = history
    changes, _ = mine(bare, pinned, {RID})
    root = tmp_path / "data"
    case = root / "sigma" / SIGMA_REGRESSION / "lolbin"
    case.mkdir(parents=True)
    (case / "info.yml").write_text(f"rule_metadata:\n  - id: {RID}\n")
    event = {"Event": {"System": {"EventID": 1, "Channel": SYSMON_CHANNEL}, "EventData": {"Image": "C:\\b.exe"}}}
    (case / f"{RID}.json").write_text(json.dumps(event))
    (root / "otrf/datasets/atomic/windows").mkdir(parents=True)
    manifest = {
        "splits": {
            "train": [{"rules": [{"id": RID, "path": "x", "positive_event_ids": [f"sigma:{RID}:0"]}]}],
            "reserve": [],
        }
    }
    es = Elasticsearch(ES_URL)
    try:
        result = build(root, [to_record(c) for c in changes], manifest, {"per_rule": {}}, benign=set(), es=es, seed="s")
    finally:
        es.close()
    # The b.exe coverage fix is observable on the positive; the FP filter is not (no benign evidence).
    # With no benign events in this pool, the FP filter changes nothing observable.
    assert result["verification"] == {"no_behavior_change": 1, "verified": 1}
    assert result["cases_by_split"] == {"train": 1}
    cases = list((root / "benchmark/cases/train").glob("*-natural-*"))
    assert len(cases) == 1
    manifest_case, _ = load_case(cases[0])
    assert manifest_case["provenance"] == "natural" and manifest_case["fault"]["kind"] == "natural"
    assert "fix: cover b.exe" in manifest_case["fault"]["detail"]


def test_history_script_pins_the_same_commit():
    from pathlib import Path

    from aegisbench.sources import by_name

    script = (Path(__file__).resolve().parents[2] / "hpc/fetch_history.sh").read_text()
    assert f"PINNED={by_name('sigma').commit}" in script
