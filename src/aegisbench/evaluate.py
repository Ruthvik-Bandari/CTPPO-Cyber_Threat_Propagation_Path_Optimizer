"""Benchmark evaluation of a repair system over the generated cases (plan section 13).

Each case runs through the system on the pinned engine. Results are scored against the case's
expected outcome:

- ``success``:
  - ``repaired`` cases count only when the repair passed independent validation, so
    provisional repairs are not successes, and a mapping case must be repaired by a mapping patch;
  - ``insufficient_evidence`` and ``unchanged`` cases count when that exact outcome is returned.
- ``wrong_change``: the system changed something it should not have. That is any ``repaired``
  outcome on a healthy or missing-telemetry case, or a repair with the wrong patch kind.
- ``abstained``: the system returned no repair. Abstentions and failures stay in the denominator.

Confidence intervals are percentile bootstraps that resample roots, not cases, because the
variants of one root are correlated. The locked test split is evaluated only on request
(``locked=True``), after a system is chosen.

Results hold case ids, root ids, outcomes and counts, never event values.
"""

from __future__ import annotations

import random
from collections import defaultdict
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

from aegissec.core.errors import Rejected
from aegissec.core.safe_load import load_yaml
from aegissec.detect.engine import Elasticsearch
from aegissec.detect.workflow import Inputs
from aegissec.detect.workflow import run as b0_run

System = Callable[[Inputs, Elasticsearch], dict[str, Any]]
SYSTEMS: dict[str, System] = {"b0": b0_run}
BOOTSTRAP_REPS = 2000
OPEN_SPLITS = ("train", "development")


def load_case(case_dir: Path) -> tuple[dict[str, Any], Inputs]:
    manifest = load_yaml((case_dir / "case.yml").read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise ValueError(f"{case_dir.name}: malformed case.yml")

    def text(name: str) -> str | None:
        path = case_dir / name
        return path.read_text(encoding="utf-8") if path.is_file() else None

    validation = case_dir / "validation.jsonl"
    return manifest, Inputs(
        rule_text=(case_dir / "rule.yml").read_text(encoding="utf-8"),
        mapping_text=(case_dir / "mapping.yml").read_text(encoding="utf-8"),
        dev_path=case_dir / "development.jsonl",
        validation_path=validation if validation.is_file() else None,
        healthy_rule_text=text("healthy_rule.yml"),
        healthy_mapping_text=text("healthy_mapping.yml"),
    )


def score(manifest: dict[str, Any], report: dict[str, Any] | None, error: str | None = None) -> dict[str, Any]:
    expected = manifest["expected"]
    outcome = report["outcome"] if report else "error"
    provisional = bool(report and report.get("provisional"))
    patch_kind = (report or {}).get("artifact", {}).get("kind") if outcome == "repaired" else None
    want = expected["outcome"]
    if want == "repaired":
        right_kind = "patch_kind" not in expected or patch_kind == expected["patch_kind"]
        success = outcome == "repaired" and not provisional and right_kind
        wrong = outcome == "repaired" and not right_kind
    else:
        success = outcome == want
        wrong = outcome == "repaired"
    return {
        "case_id": manifest["case_id"],
        "root_id": manifest["root_id"],
        "split": manifest["split"],
        "kind": manifest["fault"]["kind"],
        "expected": want,
        "outcome": outcome,
        "provisional": provisional,
        "patch_kind": patch_kind,
        "has_validation": bool(manifest.get("validation")),
        "success": success,
        "wrong_change": wrong,
        "abstained": outcome == "abstained",
        "error": error,
    }


def run_cases(cases_root: Path, system: System, es: Elasticsearch, *, locked: bool = False) -> list[dict[str, Any]]:
    splits = (*OPEN_SPLITS, "test") if locked else OPEN_SPLITS
    rows = []
    for split in splits:
        for case_dir in sorted(p for p in (cases_root / split).glob("*") if (p / "case.yml").is_file()):
            manifest, inputs = load_case(case_dir)
            if manifest.get("split") != split:
                raise ValueError(
                    f"{case_dir.name}: case.yml says split {manifest.get('split')!r}, folder says {split!r}"
                )
            try:
                rows.append(score(manifest, system(inputs, es)))
            except Rejected as exc:  # an invalid case or engine failure is an error, never a pass
                rows.append(score(manifest, None, f"{exc.reason}: {exc.detail}"[:200]))
    return rows


def _rate(rows: list[dict[str, Any]], key: str) -> float | None:
    return sum(bool(r[key]) for r in rows) / len(rows) if rows else None


def bootstrap(rows: list[dict[str, Any]], key: str, seed: int = 0, reps: int = BOOTSTRAP_REPS) -> list[float] | None:
    """95% percentile interval of ``key``'s rate, resampling roots with replacement."""
    by_root: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        by_root[r["root_id"]].append(r)
    roots = sorted(by_root)
    if len(roots) < 2:
        return None
    rng = random.Random(seed)  # noqa: S311 - statistical resampling, not security
    stats = []
    for _ in range(reps):
        sample = [r for root in rng.choices(roots, k=len(roots)) for r in by_root[root]]
        stats.append(sum(bool(r[key]) for r in sample) / len(sample))
    stats.sort()
    return [round(stats[int(0.025 * reps)], 4), round(stats[int(0.975 * reps) - 1], 4)]


def summarize(rows: Iterable[dict[str, Any]], seed: int = 0) -> dict[str, Any]:
    rows = list(rows)

    def block(subset: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "cases": len(subset),
            "roots": len({r["root_id"] for r in subset}),
            "success_rate": _rate(subset, "success"),
            "success_ci95": bootstrap(subset, "success", seed),
            "wrong_change_rate": _rate(subset, "wrong_change"),
            "abstention_rate": _rate(subset, "abstained"),
            "provisional_repairs": sum(r["provisional"] for r in subset),
            "errors": sum(r["error"] is not None for r in subset),
            "outcomes": dict(sorted(_count(r["outcome"] for r in subset).items())),
        }

    return {
        "overall": block(rows),
        "by_split": {s: block([r for r in rows if r["split"] == s]) for s in sorted({r["split"] for r in rows})},
        "by_kind": {k: block([r for r in rows if r["kind"] == k]) for k in sorted({r["kind"] for r in rows})},
        "with_validation_suite": block([r for r in rows if r["has_validation"]]),
    }


def _count(values: Iterable[str]) -> dict[str, int]:
    out: dict[str, int] = defaultdict(int)
    for v in values:
        out[v] += 1
    return dict(out)
