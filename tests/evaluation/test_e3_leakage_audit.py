"""Tests for Phase 5 / E3 — the train/test leakage checker.

Fast, offline, deterministic (pure function on controlled inputs). The real-dataset audit
(0 exact / 0 near-dup overlap on 240 CVEs) is reported in the doc; here we verify the checker
detects exact + near-duplicate contamination and reports clean splits as clean.
"""

from evaluation.e3_leakage_audit import split_text_overlap


def test_clean_split_has_no_overlap():
    train = ["a buffer overflow in foo allows rce", "sql injection bypasses auth in the login form"]
    test = ["an out of bounds read in bar leaks kernel memory"]
    r = split_text_overlap(train, test)
    assert r["exact_overlap"] == 0 and r["near_dup_overlap"] == 0


def test_detects_exact_duplicate():
    train = ["a buffer overflow in foo allows rce"]
    test = ["a buffer overflow in foo allows rce"]
    r = split_text_overlap(train, test)
    assert r["exact_overlap"] == 1
    assert r["exact_frac"] == 1.0


def test_detects_near_duplicate_but_not_exact():
    train = ["a buffer overflow in foo allows remote code execution"]
    test = ["a buffer overflow in foo allows remote code execution now"]   # 9/10 token Jaccard
    r = split_text_overlap(train, test, near_threshold=0.8)
    assert r["exact_overlap"] == 0
    assert r["near_dup_overlap"] == 1


def test_near_threshold_is_respected():
    train = ["alpha beta gamma delta epsilon"]
    test = ["alpha beta gamma zeta eta"]                                   # 3/7 Jaccard ≈ 0.43
    assert split_text_overlap(train, test, near_threshold=0.9)["near_dup_overlap"] == 0
    assert split_text_overlap(train, test, near_threshold=0.4)["near_dup_overlap"] == 1
