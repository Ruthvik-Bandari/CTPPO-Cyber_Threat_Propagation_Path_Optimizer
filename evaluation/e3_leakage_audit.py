"""
E3 — ML leakage / circularity audit (Phase 5)
=============================================

A reusable, dependency-free **leakage checker** plus a runnable audit of the severity classifier's
train/test split. The full written audit of every ML component (splits + circularity risks +
mitigations) is in `docs/RESEARCH/E3_ML_LEAKAGE_AUDIT.md`; this module provides the *measurement*
for the one component where text-level leakage is a real risk — the severity classifier — and a
guard that can be reused.

The checker detects two kinds of train/test contamination for text datasets:
- **exact** overlap: an identical description string appears in both splits (the classifier dedups
  by exact text before splitting, so this should be 0 — the guard confirms it), and
- **near-duplicate** overlap: a test description whose token-Jaccard similarity to some train
  description is ≥ a threshold (boilerplate CVE text that exact-dedup misses — the residual risk).

Author: CTPPO
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Dict, List, Set

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_WORD = re.compile(r"[a-z0-9]+")


def _tokens(text: str) -> Set[str]:
    return set(_WORD.findall(text.lower()))


def _jaccard(a: Set[str], b: Set[str]) -> float:
    if not a and not b:
        return 1.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


def split_text_overlap(train_texts: List[str], test_texts: List[str],
                       near_threshold: float = 0.9) -> Dict[str, float]:
    """Measure exact + near-duplicate contamination of ``test_texts`` against ``train_texts``."""
    train_set = set(train_texts)
    train_tok = [_tokens(t) for t in train_texts]
    exact = sum(1 for t in test_texts if t in train_set)
    near = 0
    for t in test_texts:
        if t in train_set:
            continue
        tt = _tokens(t)
        if any(_jaccard(tt, tr) >= near_threshold for tr in train_tok):
            near += 1
    n = len(test_texts)
    return {
        "n_train": len(train_texts),
        "n_test": n,
        "exact_overlap": exact,
        "near_dup_overlap": near,
        "exact_frac": exact / n if n else 0.0,
        "near_dup_frac": near / n if n else 0.0,
        "near_threshold": near_threshold,
    }


def audit_severity_split(per_class: int = 60, seed: int = 0) -> Dict:
    """Fetch the real severity dataset, reproduce the stratified split, and measure leakage.

    Returns the overlap report, or {'available': False, ...} if the dataset can't be fetched
    offline (the methodology is then documented in the audit doc from the code).
    """
    try:
        from ml.train_severity import fetch_dataset, _stratified_split
        data = fetch_dataset(per_class)
        if not data:
            return {"available": False, "reason": "empty dataset (offline / no cache)"}
        train, va, te = _stratified_split(data, seed=seed)
        report = split_text_overlap([d[0] for d in train], [d[0] for d in te])
        report["available"] = True
        report["n_total"] = len(data)
        report["n_val"] = len(va)
        return report
    except Exception as e:                       # network/dep missing — documented, not fabricated
        return {"available": False, "reason": f"{type(e).__name__}: {e}"}


if __name__ == "__main__":
    # 1) Controlled demonstration that the checker catches exact + near-dup contamination.
    train = ["A buffer overflow in foo allows remote code execution",
             "SQL injection in the login form permits authentication bypass"]
    test_clean = ["An out-of-bounds read in bar leaks kernel memory"]
    test_dirty = ["A buffer overflow in foo allows remote code execution",      # exact dup
                  "A buffer overflow in foo allows remote code execution now"]   # near dup
    print("clean split:", split_text_overlap(train, test_clean))
    print("dirty split:", split_text_overlap(train, test_dirty))

    # 2) Real audit of the severity classifier's stratified split (if fetchable offline).
    print("\nseverity split audit:", audit_severity_split())
