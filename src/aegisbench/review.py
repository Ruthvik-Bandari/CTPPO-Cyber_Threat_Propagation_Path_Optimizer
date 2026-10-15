"""Human review of OTRF candidate positives (plan section 11, "Label and license record").

``write_sheet`` resolves the OTRF events that supported rules matched during replay and writes,
under ``<root>/review/`` on the cluster only:

- ``candidates.jsonl``: one line per candidate event, with its v1 fields and the rules that matched it;
- ``labels.csv``: one row per event for the reviewer (``label``, ``rationale``, ``reviewer``).
  It is created once and never overwritten, so a reviewer's work is never lost.

Both files hold raw event values, so they are private to the user (mode 0600, directory 0700).
They must stay off the repository and out of AI-assistant sessions. ``status`` validates the
labels file and returns counts only.
"""

from __future__ import annotations

import csv
import io
import json
import os
from collections import Counter
from pathlib import Path
from typing import Any

from .positives import otrf_events, supported_rules

LABELS = ("malicious", "benign", "unknown")
LABEL_COLUMNS = ("event_id", "label", "rationale", "reviewer")
MAX_LABELS_BYTES = 5 * 1024 * 1024
MAX_RATIONALE_CHARS = 1000


class ReviewError(ValueError):
    pass


def _private_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    tmp = path.with_name(f".{path.name}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)
    os.replace(tmp, path)


def candidates(root: Path, report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """OTRF events matched by at least one rule, keyed by event id, with the matching rules."""
    pool = {p.event.event_id: p for p in otrf_events(root / "otrf")}
    rules, _ = supported_rules(root / "sigma")
    out: dict[str, dict[str, Any]] = {}
    for rule_id, entry in sorted(report["per_rule"].items()):
        for event_id in entry.get("matched_event_ids", []):
            if not event_id.startswith("otrf:"):
                continue
            if event_id not in pool:
                raise ReviewError(f"replay event {event_id} is not in the current OTRF pool; re-run replay")
            item = out.setdefault(
                event_id,
                {
                    "event_id": event_id,
                    "dataset": pool[event_id].source,
                    "fields": pool[event_id].event.data,
                    "rules": [],
                },
            )
            title = rules[rule_id].title if rule_id in rules else None
            item["rules"].append({"rule_id": rule_id, "title": title})
    return out


def write_sheet(root: Path, report: dict[str, Any]) -> dict[str, int]:
    found = candidates(root, report)
    review = root / "review"
    _private_write(
        review / "candidates.jsonl",
        "".join(json.dumps(found[k], sort_keys=True, ensure_ascii=False) + "\n" for k in sorted(found)),
    )
    labels = review / "labels.csv"
    created = 0
    if not labels.exists():
        buf = io.StringIO()
        writer = csv.writer(buf, lineterminator="\n")
        writer.writerow(LABEL_COLUMNS)
        writer.writerows([k, "", "", ""] for k in sorted(found))
        _private_write(labels, buf.getvalue())
        created = 1
    return {
        "candidate_events": len(found),
        "rules": len({r["rule_id"] for c in found.values() for r in c["rules"]}),
        "datasets": len({c["dataset"] for c in found.values()}),
        "labels_file_created": created,
    }


def read_labels(path: Path, known: set[str]) -> tuple[dict[str, str], list[str]]:
    """Validated ``event_id -> label`` for reviewed rows, plus problems (row numbers and reasons only)."""
    if path.stat().st_size > MAX_LABELS_BYTES:
        raise ReviewError(f"labels file exceeds {MAX_LABELS_BYTES} bytes")
    labels: dict[str, str] = {}
    problems: list[str] = []
    with path.open(encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        if tuple(reader.fieldnames or ()) != LABEL_COLUMNS:
            raise ReviewError(f"labels.csv header must be {','.join(LABEL_COLUMNS)}")
        for n, row in enumerate(reader, start=2):
            event_id = (row.get("event_id") or "").strip()
            label = (row.get("label") or "").strip().lower()
            rationale = (row.get("rationale") or "").strip()
            reviewer = (row.get("reviewer") or "").strip()
            if event_id not in known:
                problems.append(f"row {n}: unknown event id")
            elif event_id in labels:
                problems.append(f"row {n}: duplicate event id")
            elif not label:
                continue  # not reviewed yet
            elif label not in LABELS:
                problems.append(f"row {n}: label must be one of {', '.join(LABELS)}")
            elif not reviewer:
                problems.append(f"row {n}: reviewer is required")
            elif label != "unknown" and not rationale:
                problems.append(f"row {n}: rationale is required for {label}")
            elif len(rationale) > MAX_RATIONALE_CHARS:
                problems.append(f"row {n}: rationale exceeds {MAX_RATIONALE_CHARS} characters")
            else:
                labels[event_id] = label
    return labels, problems


def status(root: Path, report: dict[str, Any]) -> dict[str, object]:
    """Review progress and the roots that reviewed labels would yield; counts and rule ids only."""
    found = candidates(root, report)
    labels, problems = read_labels(root / "review" / "labels.csv", set(found))
    malicious = {e for e, label in labels.items() if label == "malicious"}
    per_rule = report["per_rule"]
    verified: Counter[str] = Counter()
    for rule_id, entry in per_rule.items():
        verified[rule_id] = int(entry["own_regression_matched"]) + sum(
            e in malicious for e in entry["matched_event_ids"]
        )
    return {
        "schema_version": 1,
        "candidate_events": len(found),
        "reviewed": len(labels),
        "unreviewed": len(found) - len(labels),
        "labels": dict(sorted(Counter(labels.values()).items())),
        "problems": problems,
        "roots": {
            "with_1plus_verified_positive": sum(n >= 1 for n in verified.values()),
            "with_2plus_verified_positives": sum(n >= 2 for n in verified.values()),
        },
    }
