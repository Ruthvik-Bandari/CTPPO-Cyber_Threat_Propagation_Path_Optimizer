"""Natural maintenance faults mined from SigmaHQ's own history (plan section 11, provenance ``natural``).

Each commit that modified a Windows process_creation rule is a maintenance event. The version
before the commit is the *impaired* rule, and the version after it is the maintainers' *fix*.
Stage 1 (``mine``) walks the history up to the pinned commit and keeps pairs where both versions
fall within the supported subset and the detection logic changed. It then classifies each change
with an AST diff, not a text diff:

- ``condition``: the condition was edited;
- ``values_added`` / ``values_removed``: a predicate's value list was extended or narrowed;
- ``modifier``: a predicate's modifier or ``|all`` changed;
- ``field``: a selection now tests a different field;
- ``selection_added`` / ``selection_removed``: a selection was added or removed.

Each pair is also scored with an approximate AST edit count, and ``within_contract`` says whether
the fix fits the repair contract: at most 3 edits, no removed selection, and at most 8 values per
changed predicate.

Stage 2 (``build``) verifies each pair on the pinned engine. A pair becomes a case only when the fix
detects a verified positive that the impaired version misses. Fixes that only remove matches
(false-positive fixes) cannot be verified without reviewed benign events, so they are counted and
not guessed at. A case inherits its root's split from the frozen manifest, and reserve roots never
enter the benchmark.

The rule texts come from a public repository, so the mining output is shareable. Case folders hold
event values and stay private on the cluster.
"""

from __future__ import annotations

import subprocess
from collections import Counter
from collections.abc import Iterator
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from aegissec.core.errors import Rejected
from aegissec.detect.candidate import condition_edits
from aegissec.detect.engine import Elasticsearch
from aegissec.detect.fixtures import Event
from aegissec.detect.rule import Rule, parse_rule, render_condition

from .positives import PoolEvent, otrf_events, sigma_events
from .qc import SIGMA_RULES
from .variants import HEALTHY, NEGATIVES_PER_ROOT, Variant, _matched, _rank, fixtures, write_case

GIT_TIMEOUT_S = 600
MAX_RULE_BYTES = 100 * 1024
_SEP = "\x1f"


@dataclass(frozen=True)
class Change:
    commit: str
    date: str
    subject: str
    path: str
    rule_id: str
    kinds: tuple[str, ...]
    edits: int
    within_contract: bool
    before: str
    after: str


def _git(git_dir: Path, *args: str, stdin: bytes | None = None) -> bytes:
    return subprocess.run(  # noqa: S603 - fixed argument list, no shell
        ["git", f"--git-dir={git_dir}", *args],  # noqa: S607 - git from PATH
        input=stdin,
        capture_output=True,
        timeout=GIT_TIMEOUT_S,
        check=True,
    ).stdout


def modifications(git_dir: Path, pinned: str) -> Iterator[tuple[str, str, str, str, str]]:
    """``(commit, date, subject, old_path, new_path)`` for every modified or renamed rule file."""
    out = _git(
        git_dir,
        "log",
        "--no-merges",
        f"--format=@@{_SEP}%H{_SEP}%cI{_SEP}%s",
        "--name-status",
        "-M",
        "--diff-filter=MR",
        pinned,
        "--",
        SIGMA_RULES,
    ).decode("utf-8", errors="replace")
    commit = date = subject = ""
    for line in out.splitlines():
        if line.startswith(f"@@{_SEP}"):
            _, commit, date, subject = line.split(_SEP, 3)
            continue
        parts = line.split("\t")
        if not parts[0] or not commit:
            continue
        old, new = (parts[1], parts[2]) if parts[0].startswith("R") and len(parts) == 3 else (parts[-1], parts[-1])
        if new.endswith(".yml") and new.startswith(SIGMA_RULES + "/"):
            yield commit, date, subject, old, new


def _blobs(git_dir: Path, specs: list[str]) -> list[bytes | None]:
    """Read many ``rev:path`` objects with one ``git cat-file --batch``; None when missing or too large."""
    raw = _git(git_dir, "cat-file", "--batch", stdin=("\n".join(specs) + "\n").encode())
    out: list[bytes | None] = []
    pos = 0
    for _ in specs:
        end = raw.index(b"\n", pos)
        header = raw[pos:end].split()
        pos = end + 1
        if len(header) < 3 or header[1] != b"blob":
            out.append(None)
            continue
        size = int(header[2])
        out.append(raw[pos : pos + size] if size <= MAX_RULE_BYTES else None)
        pos += size + 1
    return out


def _predicates(rule: Rule) -> dict[tuple[str, int, str], tuple[str, bool, frozenset[str]]]:
    """(selection, branch, field) -> (modifier, match_all, values) for a structural diff."""
    out: dict[tuple[str, int, str], tuple[str, bool, frozenset[str]]] = {}
    for name, sel in rule.selections.items():
        for b, branch in enumerate(sel.branches):
            for p in branch:
                out[(name, b, p.field)] = (p.modifier, p.match_all, frozenset(p.values))
    return out


def classify(before: Rule, after: Rule) -> tuple[tuple[str, ...], int, bool]:
    """Change kinds, approximate AST edits, and whether the fix fits the repair contract."""
    kinds: set[str] = set()
    edits = 0
    added = after.selections.keys() - before.selections.keys()
    removed = before.selections.keys() - after.selections.keys()
    if added:
        kinds.add("selection_added")
        edits += sum(1 + len(after.selections[n].predicates) for n in added)
    if removed:
        kinds.add("selection_removed")
    if render_condition(before.condition) != render_condition(after.condition):
        kinds.add("condition")
        edits += 0 if (added or removed) else condition_edits(before.condition, after.condition)
    old, new = _predicates(before), _predicates(after)
    big_values = False
    for key in old.keys() & new.keys():
        (m1, a1, v1), (m2, a2, v2) = old[key], new[key]
        if (m1, a1) != (m2, a2):
            kinds.add("modifier")
            edits += 1
        if v1 != v2:
            kinds.add("values_added" if v2 > v1 else "values_removed" if v2 < v1 else "values_changed")
            edits += 1
            big_values |= len(v2) > 8
    shared = before.selections.keys() & after.selections.keys()
    moved = {k[:2] for k in old.keys() ^ new.keys() if k[0] in shared}
    if moved:
        kinds.add("field")
        edits += len(moved)
    within = bool(kinds) and edits <= 3 and not removed and not big_values
    return tuple(sorted(kinds)), edits, within


def mine(git_dir: Path, pinned: str, supported_ids: set[str]) -> tuple[list[Change], Counter[str]]:
    """Every detection-changing maintenance pair for a supported rule, plus counts of what was skipped."""
    mods = list(modifications(git_dir, pinned))
    skipped: Counter[str] = Counter()
    specs = [s for c, _, _, old, new in mods for s in (f"{c}^:{old}", f"{c}:{new}")]
    blobs = _blobs(git_dir, specs) if specs else []
    changes: list[Change] = []
    for i, (commit, date, subject, _, new) in enumerate(mods):
        before_raw, after_raw = blobs[2 * i], blobs[2 * i + 1]
        if before_raw is None or after_raw is None:
            skipped["missing_or_oversized_blob"] += 1
            continue
        try:
            before = parse_rule(before_raw.decode("utf-8"))
            after = parse_rule(after_raw.decode("utf-8"))
        except (Rejected, UnicodeDecodeError):
            skipped["outside_supported_subset"] += 1
            continue
        rule_id = after.rule_id or ""
        if rule_id not in supported_ids:
            skipped["rule_not_supported_at_pin"] += 1
            continue
        if before.selections == after.selections and before.condition == after.condition:
            skipped["metadata_only"] += 1
            continue
        kinds, edits, within = classify(before, after)
        changes.append(
            Change(commit, date, subject, new, rule_id, kinds, edits, within, before.to_yaml(), after.to_yaml())
        )
    return changes, skipped


def summarize_mining(changes: list[Change], skipped: Counter[str], pinned: str) -> dict[str, Any]:
    kinds: Counter[str] = Counter(k for c in changes for k in c.kinds)
    return {
        "schema_version": 1,
        "pinned_commit": pinned,
        "detection_changes": len(changes),
        "rules": len({c.rule_id for c in changes}),
        "within_contract": sum(c.within_contract for c in changes),
        "kinds": dict(sorted(kinds.items())),
        "edits": dict(sorted(Counter(min(c.edits, 6) for c in changes).items())),
        "skipped": dict(sorted(skipped.items())),
    }


def to_record(change: Change) -> dict[str, Any]:
    return asdict(change)


def build(
    root: Path,
    changes: list[dict[str, Any]],
    manifest: dict[str, Any],
    report: dict[str, Any],
    *,
    benign: set[str],
    es: Elasticsearch,
    seed: str,
) -> dict[str, Any]:
    """Verify mined pairs on the engine and write natural cases for roots in the split."""
    split_of = {r["id"]: (s, r) for s, groups in manifest["splits"].items() for g in groups for r in g["rules"]}
    pool = {p.event.event_id: p for p in [*sigma_events(root / "sigma"), *otrf_events(root / "otrf")]}
    otrf_ids = sorted(k for k, p in pool.items() if p.pool == "otrf")
    out = root / "benchmark" / "cases"
    result: Counter[str] = Counter()
    kinds: Counter[str] = Counter()
    per_split: Counter[str] = Counter()
    for change in changes:
        placed = split_of.get(change["rule_id"])
        if placed is None or placed[0] == "reserve":
            result["root_not_in_split"] += 1
            continue
        split, entry = placed
        before, after = parse_rule(change["before"]), parse_rule(change["after"])
        positives: list[PoolEvent] = [pool[e] for e in entry["positive_event_ids"] if e in pool]
        matched = set(report["per_rule"].get(change["rule_id"], {}).get("matched_event_ids", []))
        background = sorted((e for e in otrf_ids if e not in matched), key=lambda e: _rank(seed, change["rule_id"] + e))
        negatives = [pool[e] for e in sorted(matched & benign)] + [pool[e] for e in background[:NEGATIVES_PER_ROOT]]
        events = fixtures(change["rule_id"], positives, negatives, benign)
        verdict, kept = _verify(es, before, after, events)
        result[verdict] += 1
        if kept is None:
            continue
        variant = Variant(
            "natural",
            before,
            HEALTHY,
            tuple(kept),
            f"SigmaHQ {change['commit'][:10]} ({change['date'][:10]}): {change['subject'][:120]}",
            {"outcome": "repaired", "family": "logic"},
        )
        case_id = f"{change['rule_id']}-natural-{change['commit'][:10]}"
        write_case(out, change["rule_id"], split, variant, after, case_id=case_id, provenance="natural")
        kinds.update(change["kinds"])
        per_split[split] += 1
    return {
        "schema_version": 1,
        "verification": dict(sorted(result.items())),
        "cases_by_split": dict(sorted(per_split.items())),
        "case_change_kinds": dict(sorted(kinds.items())),
    }


def _verify(es: Elasticsearch, before: Rule, after: Rule, events: list[Event]) -> tuple[str, list[Event] | None]:
    """A pair is a case only if the fix detects a verified positive the impaired version misses.
    Positives the fix itself misses are dropped (the pinned rule may postdate the fix)."""
    malicious = {e.event_id for e in events if e.label == "malicious"}
    if not malicious:
        return "no_verified_positives", None
    try:
        with es.replay_index(events) as index:
            fixed = _matched(es, index, after, HEALTHY)
            broken = _matched(es, index, before, HEALTHY)
    except Rejected as exc:
        return f"engine:{exc.reason}", None
    detected = malicious & fixed
    if not detected:
        return "fix_detects_no_positive", None
    if detected <= broken:
        return "fp_only_or_unobservable" if broken != fixed else "no_behavior_change", None
    keep = [e for e in events if e.label != "malicious" or e.event_id in detected]
    return "verified", keep
