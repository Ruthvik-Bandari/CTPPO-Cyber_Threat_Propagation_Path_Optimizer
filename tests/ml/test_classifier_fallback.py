"""Tests for Phase 5 / E1 — the CVE severity classifier's justified fallback role.

Fast. Covers the pure `severity_to_impact` mapping (the classifier's one engine-adjacent role:
a coarse impact fallback for no-CVSS CVEs). The model itself (DistilBERT, 0.729 macro-F1) is
exercised by the API and trainer; here we only test the pure label→impact mapping.
"""

from ml.cve_classifier import severity_to_impact, SEVERITY_CLASSES


def test_severity_impact_monotonic():
    impacts = [severity_to_impact(s) for s in SEVERITY_CLASSES]   # CRITICAL..LOW
    assert impacts == sorted(impacts, reverse=True)               # strictly decreasing severity → impact
    assert severity_to_impact("CRITICAL") == 9.5
    assert severity_to_impact("LOW") == 2.5


def test_severity_impact_handles_enum_prefix_and_case():
    assert severity_to_impact("Severity.HIGH") == 7.5
    assert severity_to_impact("high") == 7.5


def test_severity_impact_unknown_returns_default():
    assert severity_to_impact("UNRATED") == 5.0
    assert severity_to_impact("", default=1.0) == 1.0
