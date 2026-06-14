"""
LLM-Based Code Security Reviewer
================================

Emulates Claude Code's `/security-review`: uses Claude (Anthropic SDK) to read
source files and find security vulnerabilities through semantic understanding —
the kind of issues signature scanners (nmap/ZAP/CVE matching) miss. Findings are
emitted as ``VulnerabilityFinding`` objects so they flow into the attack graph
alongside every other scanner's output.

This is an *authorized defensive* tool: review your own / permitted code.

Two roles in the project (see docs/RESEARCH/03_LLM_CODE_REVIEW_SPEC.md):
1. Scan-time reviewer — findings feed the attack graph + cost model.
2. Teacher for distillation — its labels can bootstrap training of CTPPO's own
   (cheaper) model. Caveat: LLM labels are noisy; treat as weak supervision.

Requirements: ``pip install anthropic`` and ``ANTHROPIC_API_KEY`` in the env.
Degrades gracefully: if the SDK or key is missing, ``review_*`` returns ``[]``
and logs a warning — it never fabricates findings.

Author: CTPPO
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanners.models import (
    VulnerabilityFinding, Severity, ScannerType,
    classify_owasp_category, get_mitre_techniques,
)

logger = logging.getLogger(__name__)

# Per the claude-api skill: default to Opus 4.8 unless the caller names another.
DEFAULT_MODEL = "claude-opus-4-8"

SYSTEM_PROMPT = """You are a precise application-security code reviewer performing an \
authorized review. Find concrete, exploitable vulnerabilities in the code you are given: \
injection (SQL/command/template), broken authn/authz, secrets in code, SSRF, path \
traversal, insecure deserialization, weak crypto, unsafe file handling, and similar.

Rules:
- Report only issues you can point to in the code. Do NOT invent problems or pad the list.
- It is correct to return an empty findings list for clean code.
- Set `confidence` honestly (High only when the code clearly shows the flaw).
- Give the 1-based `line` of the most relevant line, a CWE id when applicable \
(e.g. "CWE-89"), and a concrete `recommendation`.
- Severity reflects real-world impact if exploited (CRITICAL/HIGH/MEDIUM/LOW/INFO)."""

# Structured-output schema (output_config.format). additionalProperties:false required.
FINDINGS_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "severity": {"type": "string",
                                 "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
                    "cwe": {"type": "string"},
                    "line": {"type": "integer"},
                    "description": {"type": "string"},
                    "recommendation": {"type": "string"},
                    "confidence": {"type": "string", "enum": ["High", "Medium", "Low"]},
                },
                "required": ["title", "severity", "cwe", "line",
                             "description", "recommendation", "confidence"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["findings"],
    "additionalProperties": False,
}

_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW, "INFO": Severity.INFO,
}


def findings_from_payload(
    payload: Dict[str, Any], source_file: str, model: str = DEFAULT_MODEL
) -> List[VulnerabilityFinding]:
    """Convert the model's JSON payload into VulnerabilityFinding objects.

    Pure function (no network) — the unit-testable core of the reviewer.
    """
    findings: List[VulnerabilityFinding] = []
    for item in payload.get("findings", []):
        title = (item.get("title") or "").strip()
        if not title:
            continue
        desc = (item.get("description") or "").strip()
        cwe = (item.get("cwe") or "").strip()
        findings.append(VulnerabilityFinding(
            title=title,
            description=desc,
            severity=_SEVERITY_MAP.get((item.get("severity") or "").upper(), Severity.INFO),
            confidence=item.get("confidence", "Medium"),
            scanner=ScannerType.LLM,
            scanner_rule_id=f"llm:{cwe}" if cwe else "llm",
            target_host=source_file,
            cwe_ids=[cwe] if cwe else [],
            owasp_category=classify_owasp_category(title, desc),
            mitre_attack_ids=get_mitre_techniques(title, desc),
            solution=(item.get("recommendation") or "").strip(),
            evidence=f"{source_file}:{item.get('line')}" if item.get("line") else "",
            tags={"llm-review"},
            metadata={"source": "llm_code_review", "model": model,
                      "line": item.get("line"), "llm_confidence": item.get("confidence")},
        ))
    return findings


class LLMCodeReviewer:
    """Reviews source files for security vulnerabilities using Claude.

    Args:
        model: Claude model id (defaults to Opus 4.8).
        max_file_chars: skip / truncate files larger than this (keeps requests bounded).
        client: an ``anthropic.Anthropic`` instance (injected for testing); if None,
            one is constructed lazily and reads ``ANTHROPIC_API_KEY`` from the env.
    """

    def __init__(self, model: str = DEFAULT_MODEL, max_file_chars: int = 60_000,
                 client: Optional[Any] = None) -> None:
        self.model = model
        self.max_file_chars = max_file_chars
        self._client = client
        self._unavailable_reason: Optional[str] = None
        if client is None:
            try:
                import anthropic  # noqa: F401
                self._client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY
            except ImportError:
                self._unavailable_reason = "anthropic SDK not installed (pip install anthropic)"
            except Exception as exc:  # e.g. missing API key
                self._unavailable_reason = f"Anthropic client init failed: {exc}"

    @property
    def available(self) -> bool:
        return self._client is not None

    def review_file(self, path: str | Path) -> List[VulnerabilityFinding]:
        """Review one source file. Returns [] (with a warning) if unavailable/error."""
        if not self.available:
            logger.warning("llm_code_review unavailable: %s", self._unavailable_reason)
            return []
        p = Path(path)
        try:
            code = p.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.warning("llm_code_review: cannot read %s: %s", p, exc)
            return []
        if len(code) > self.max_file_chars:
            code = code[: self.max_file_chars]  # bound the request; review the head
            logger.info("llm_code_review: truncated %s to %d chars", p, self.max_file_chars)

        try:
            resp = self._client.messages.create(
                model=self.model,
                max_tokens=16_000,
                thinking={"type": "adaptive"},
                system=SYSTEM_PROMPT,
                output_config={"format": {"type": "json_schema", "schema": FINDINGS_SCHEMA}},
                messages=[{"role": "user",
                           "content": f"File: {p}\n\n```\n{code}\n```"}],
            )
        except Exception as exc:
            logger.warning("llm_code_review: API call failed for %s: %s", p, exc)
            return []

        if getattr(resp, "stop_reason", None) == "refusal":
            logger.warning("llm_code_review: model refused review of %s", p)
            return []
        text = next((b.text for b in resp.content if getattr(b, "type", None) == "text"), "")
        try:
            payload = json.loads(text)
        except (json.JSONDecodeError, TypeError) as exc:
            logger.warning("llm_code_review: could not parse output for %s: %s", p, exc)
            return []
        return findings_from_payload(payload, str(p), self.model)

    def review_paths(self, paths: List[str | Path]) -> List[VulnerabilityFinding]:
        """Review multiple files; concatenates findings."""
        out: List[VulnerabilityFinding] = []
        for path in paths:
            out.extend(self.review_file(path))
        return out


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    reviewer = LLMCodeReviewer()
    print("available:", reviewer.available, "-", reviewer._unavailable_reason or "ok")
    if reviewer.available and len(sys.argv) > 1:
        for f in reviewer.review_paths(sys.argv[1:]):
            print(f"[{f.severity.name}] {f.title} ({f.cwe_ids}) -> {f.solution[:80]}")
