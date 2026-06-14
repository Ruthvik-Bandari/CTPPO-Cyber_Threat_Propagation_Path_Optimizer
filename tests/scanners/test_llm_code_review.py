"""
Offline tests for the LLM code reviewer's finding-mapping logic.

These do NOT call the Anthropic API — they exercise ``findings_from_payload``
(the pure conversion from model JSON to VulnerabilityFinding) and the schema.
Run: python -m pytest tests/scanners/test_llm_code_review.py  (or run directly).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scanners.llm_code_review import findings_from_payload, FINDINGS_SCHEMA  # noqa: E402
from scanners.models import Severity, ScannerType, VulnerabilityCategory  # noqa: E402


def test_maps_core_fields():
    payload = {"findings": [{
        "title": "SQL Injection in login handler",
        "severity": "CRITICAL", "cwe": "CWE-89", "line": 42,
        "description": "User input concatenated directly into a SQL query.",
        "recommendation": "Use parameterized queries.", "confidence": "High",
    }]}
    out = findings_from_payload(payload, "api/login.py")
    assert len(out) == 1
    f = out[0]
    assert f.severity == Severity.CRITICAL
    assert f.scanner == ScannerType.LLM
    assert f.cwe_ids == ["CWE-89"]
    assert f.owasp_category == VulnerabilityCategory.A03_INJECTION   # "injection" keyword
    assert "login.py:42" in f.evidence
    assert f.solution == "Use parameterized queries."
    assert f.metadata["source"] == "llm_code_review"
    assert f.metadata["line"] == 42
    assert "llm-review" in f.tags


def test_unknown_severity_falls_back_to_info():
    out = findings_from_payload({"findings": [{"title": "x", "severity": "WAT"}]}, "f.py")
    assert out[0].severity == Severity.INFO


def test_empty_or_titleless_skipped():
    assert findings_from_payload({"findings": []}, "x.py") == []
    assert findings_from_payload({"findings": [{"title": "  "}]}, "x.py") == []
    assert findings_from_payload({}, "x.py") == []          # no 'findings' key -> no crash


def test_schema_is_strict():
    assert FINDINGS_SCHEMA["additionalProperties"] is False
    item = FINDINGS_SCHEMA["properties"]["findings"]["items"]
    assert item["additionalProperties"] is False
    assert set(item["required"]) >= {"title", "severity", "cwe", "line"}
    assert "CRITICAL" in item["properties"]["severity"]["enum"]


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"PASS  {fn.__name__}")
    print(f"\n{len(fns)} tests passed.")
