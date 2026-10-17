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
import fcntl
import io
import json
import os
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from aegissec.core.errors import Rejected

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


def label_problem(label: str, rationale: str, reviewer: str) -> str | None:
    if label not in LABELS:
        return f"label must be one of {', '.join(LABELS)}"
    if not reviewer:
        return "reviewer is required"
    if label != "unknown" and not rationale:
        return f"rationale is required for {label}"
    if len(rationale) > MAX_RATIONALE_CHARS:
        return f"rationale exceeds {MAX_RATIONALE_CHARS} characters"
    if any(c in rationale + reviewer for c in "\r\n"):
        return "rationale and reviewer must be one line"
    return None


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
            elif problem := label_problem(label, rationale, reviewer):
                problems.append(f"row {n}: {problem}")
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
        "ai_assisted": _ai_assisted(root / "review" / "labels.csv", set(labels)),
        "problems": problems,
        "roots": {
            "with_1plus_verified_positive": sum(n >= 1 for n in verified.values()),
            "with_2plus_verified_positives": sum(n >= 2 for n in verified.values()),
        },
    }


# ---------------------------------------------------------------- interactive labelling (run by the reviewer)


def _load_sheet(root: Path) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    review = root / "review"
    sheet = [
        json.loads(line) for line in (review / "candidates.jsonl").read_text(encoding="utf-8").splitlines() if line
    ]
    with (review / "labels.csv").open(encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        if tuple(reader.fieldnames or ()) != LABEL_COLUMNS:
            raise ReviewError(f"labels.csv header must be {','.join(LABEL_COLUMNS)}")
        rows = [dict(r) for r in reader]
    return sheet, rows


def dataset_info(otrf_root: Path) -> dict[str, dict[str, Any]]:
    """OTRF metadata (title, description, ATT&CK techniques) keyed by archive path, for the reviewer."""
    from .qc import MAX_METADATA_BYTES, OTRF_WINDOWS, _read_yaml

    out: dict[str, dict[str, Any]] = {}
    for path in sorted((otrf_root / "datasets/atomic/_metadata").glob("SDWIN-*.yaml")):
        try:
            doc = _read_yaml(path, MAX_METADATA_BYTES)
        except Rejected:
            continue  # metadata is advisory for the reviewer; QC reports unreadable files
        if not isinstance(doc, dict):
            continue
        techniques = sorted(
            str(m["technique"]) + (f".{m['sub-technique']}" if m.get("sub-technique") else "")
            for m in doc.get("attack_mappings") or []
            if isinstance(m, dict) and m.get("technique")
        )
        info = {
            "id": path.stem,
            "title": doc.get("title"),
            "description": doc.get("description"),
            "techniques": techniques,
        }
        for item in doc.get("files") or []:
            link = item.get("link") if isinstance(item, dict) else None
            if isinstance(link, str) and OTRF_WINDOWS + "/" in link:
                out[link.split(OTRF_WINDOWS + "/", 1)[1].removesuffix(".zip")] = info
    return out


def next_candidate(root: Path) -> tuple[dict[str, Any] | None, int]:
    """The first unlabelled candidate (with its dataset metadata) and how many remain."""
    sheet, rows = _load_sheet(root)
    labelled = {r["event_id"] for r in rows if (r.get("label") or "").strip()}
    todo = [c for c in sheet if c["event_id"] not in labelled]
    if not todo:
        return None, 0
    item = dict(todo[0])
    item["dataset_info"] = dataset_info(root / "otrf").get(item["dataset"])
    return item, len(todo)


def format_candidate(item: dict[str, Any], remaining: int) -> str:
    info = item.get("dataset_info") or {}
    lines = [
        f"{remaining} left to label",
        f"event    {item['event_id']}",
        f"dataset  {item['dataset']}"
        + (f"  ({info.get('id')}: {info.get('title')})" if info else "  (no OTRF metadata)"),
    ]
    if info.get("techniques"):
        lines.append(f"ATT&CK   {', '.join(info['techniques'])}")
    if info.get("description"):
        lines.append(f"scenario {' '.join(str(info['description']).split())}")
    lines.append("matched by:")
    lines += [f"  - {r['title']} ({r['rule_id']})" for r in item["rules"]]
    lines.append("fields:")
    lines += [f"  {k}: {v}" for k, v in sorted(item["fields"].items())]
    return "\n".join(lines)


def _set_label(root: Path, event_id: str, label: str, rationale: str, reviewer: str) -> None:
    """Record one decision in labels.csv, keeping every other row as it was."""
    label, rationale, reviewer = label.strip().lower(), rationale.strip(), reviewer.strip()
    if problem := label_problem(label, rationale, reviewer):
        raise ReviewError(problem)
    _, rows = _load_sheet(root)
    hits = [r for r in rows if r["event_id"] == event_id]
    if len(hits) != 1:
        raise ReviewError(f"{event_id} is not exactly one row of labels.csv")
    hits[0].update(label=label, rationale=rationale, reviewer=reviewer)
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=LABEL_COLUMNS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    _private_write(root / "review" / "labels.csv", buf.getvalue())


AI_REVIEWER_PREFIX = "ai-"


def _import_labels(root: Path, rows: list[dict[str, Any]]) -> dict[str, int]:
    """Bulk-record ``event_id, label, rationale, reviewer`` rows. Every row is validated first; any
    invalid row aborts the whole import. A label a human already set is never overwritten."""
    _, current = _load_sheet(root)
    by_id = {r["event_id"]: r for r in current}
    problems = []
    for n, row in enumerate(rows, 1):
        if row.get("event_id") not in by_id:
            problems.append(f"row {n}: unknown event id")
        elif problem := label_problem(_text(row, "label").lower(), _text(row, "rationale"), _text(row, "reviewer")):
            problems.append(f"row {n}: {problem}")
    if problems:
        raise ReviewError("; ".join(problems[:10]))
    counts = {"imported": 0, "kept_existing_human_label": 0}
    for row in rows:
        existing = by_id[row["event_id"]]
        human = (existing.get("label") or "").strip() and not (existing.get("reviewer") or "").startswith(
            AI_REVIEWER_PREFIX
        )
        if human:
            counts["kept_existing_human_label"] += 1
            continue
        existing.update(
            label=_text(row, "label").lower(), rationale=_text(row, "rationale"), reviewer=_text(row, "reviewer")
        )
        counts["imported"] += 1
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=LABEL_COLUMNS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(current)
    _private_write(root / "review" / "labels.csv", buf.getvalue())
    return counts


def _ai_assisted(path: Path, reviewed: set[str]) -> int:
    """How many reviewed rows came from an AI reviewer (reported apart from human labels)."""
    with path.open(encoding="utf-8", newline="") as fh:
        return sum(
            1
            for r in csv.DictReader(fh)
            if r.get("event_id") in reviewed and (r.get("reviewer") or "").startswith(AI_REVIEWER_PREFIX)
        )


def _text(row: dict[str, Any], key: str) -> str:
    """A field as stripped text; missing or null values become empty strings."""
    value = row.get(key)
    return "" if value is None else str(value).strip()


@contextmanager
def _labels_lock(root: Path) -> Iterator[None]:
    """Serialize read-modify-write updates of labels.csv between concurrent reviewers."""
    lock = root / "review" / ".labels.lock"
    lock.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with lock.open("a") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fh, fcntl.LOCK_UN)


def set_label(root: Path, event_id: str, label: str, rationale: str, reviewer: str) -> None:
    """Record one decision in labels.csv, keeping every other row as it was."""
    with _labels_lock(root):
        _set_label(root, event_id, label, rationale, reviewer)


def import_labels(root: Path, rows: list[dict[str, Any]]) -> dict[str, int]:
    """Bulk-record labels atomically; never overwrites a human label (see ``_import_labels``)."""
    with _labels_lock(root):
        return _import_labels(root, rows)
