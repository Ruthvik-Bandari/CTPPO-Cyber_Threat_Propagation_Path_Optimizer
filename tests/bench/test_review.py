import json
import stat
import sys
import zipfile

import pytest

from aegisbench.qc import SIGMA_RULES, SYSMON_CHANNEL
from aegisbench.review import ReviewError, status, write_sheet

RULE_A = "00000000-0000-4000-8000-00000000000a"
RULE_B = "00000000-0000-4000-8000-00000000000b"
E0 = "otrf:execution/host/demo:0"
E1 = "otrf:execution/host/demo:1"


@pytest.fixture
def root(tmp_path):
    for rid, title in ((RULE_A, "A"), (RULE_B, "B")):
        path = tmp_path / "sigma" / SIGMA_RULES / f"{title}.yml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            f"title: {title}\nid: {rid}\nlogsource: {{category: process_creation, product: windows}}\n"
            "detection:\n  sel: {Image|endswith: '\\\\x.exe'}\n  condition: sel\n"
        )
    archive = tmp_path / "otrf/datasets/atomic/windows/execution/host/demo.zip"
    archive.parent.mkdir(parents=True)
    rows = [{"EventID": 1, "Channel": SYSMON_CHANNEL, "Image": f"C:\\x{i}.exe"} for i in range(2)]
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("demo.json", "\n".join(json.dumps(r) for r in rows))
    return tmp_path


def _report(own_a=1):
    return {
        "per_rule": {
            RULE_A: {"own_regression_matched": own_a, "matched_event_ids": [f"sigma:{RULE_A}:0", E0]},
            RULE_B: {"own_regression_matched": 0, "matched_event_ids": [E0, E1]},
        }
    }


def test_sheet_is_private_lists_each_event_once_and_keeps_reviewer_work(root):
    assert write_sheet(root, _report()) == {
        "candidate_events": 2,
        "rules": 2,
        "datasets": 1,
        "labels_file_created": 1,
    }
    review = root / "review"
    lines = [json.loads(x) for x in (review / "candidates.jsonl").read_text().splitlines()]
    assert [c["event_id"] for c in lines] == [E0, E1]
    assert [r["rule_id"] for r in lines[0]["rules"]] == [RULE_A, RULE_B]
    assert lines[0]["rules"][0]["title"] == "A"
    if sys.platform != "win32":
        assert stat.S_IMODE(review.stat().st_mode) == 0o700
        assert stat.S_IMODE((review / "labels.csv").stat().st_mode) == 0o600
    (review / "labels.csv").write_text(f"event_id,label,rationale,reviewer\n{E0},malicious,atomic test,rb\n{E1},,,\n")
    assert write_sheet(root, _report())["labels_file_created"] == 0
    assert "malicious" in (review / "labels.csv").read_text()  # never overwritten


def test_status_counts_verified_roots(root):
    write_sheet(root, _report())
    (root / "review/labels.csv").write_text(
        f"event_id,label,rationale,reviewer\n{E0},malicious,atomic test,rb\n{E1},benign,updater,rb\n"
    )
    result = status(root, _report())
    assert result["reviewed"] == 2
    assert result["labels"] == {"benign": 1, "malicious": 1}
    assert result["problems"] == []
    # A: own regression + E0 malicious = 2; B: E0 malicious only (E1 benign) = 1.
    assert result["roots"] == {"with_1plus_verified_positive": 2, "with_2plus_verified_positives": 1}


@pytest.mark.parametrize(
    ("row", "problem"),
    [
        ("otrf:nope:9,malicious,x,rb", "row 2: unknown event id"),
        (f"{E0},evil,x,rb", "row 2: label must be one of malicious, benign, unknown"),
        (f"{E0},malicious,x,", "row 2: reviewer is required"),
        (f"{E0},benign,,rb", "row 2: rationale is required for benign"),
    ],
)
def test_status_reports_invalid_rows_without_values(root, row, problem):
    write_sheet(root, _report())
    (root / "review/labels.csv").write_text(f"event_id,label,rationale,reviewer\n{row}\n")
    assert status(root, _report())["problems"] == [problem]


def test_wrong_header_and_stale_report_fail(root):
    write_sheet(root, _report())
    (root / "review/labels.csv").write_text("id,label\n")
    with pytest.raises(ReviewError, match="header"):
        status(root, _report())
    stale = _report()
    stale["per_rule"][RULE_B]["matched_event_ids"].append("otrf:execution/host/demo:7")
    with pytest.raises(ReviewError, match="re-run replay"):
        write_sheet(root, stale)
