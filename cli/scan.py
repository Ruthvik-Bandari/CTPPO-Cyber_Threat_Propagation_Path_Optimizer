"""
Local repo scanning for the CLI (Phase B / B5b)
===============================================

Walks a local repository path to collect file metadata and the list of code files, then
optionally runs the model-assisted code reviewer (``scanners/llm_code_review.py``). The
reviewer needs ``anthropic`` + ``ANTHROPIC_API_KEY``; when unavailable the scan degrades
honestly to a file-metadata-only submission (clearly reported, never faked).

NOTE: remote Git clone + SSH verification are not implemented yet — ``scan`` operates on a
local path. Those are a B5b follow-up (the design's CI/CD Git integration).
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import List, Tuple

CODE_EXTS = {
    ".py", ".ts", ".tsx", ".js", ".jsx", ".go", ".rs", ".java", ".cpp", ".c",
    ".rb", ".php", ".cs", ".kt", ".swift", ".scala", ".h", ".hpp",
}
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build",
              ".mypy_cache", ".pytest_cache", "graphify-out"}


def collect_repo_files(root, max_code_files: int = 200) -> Tuple[List[dict], List[Path]]:
    """Return (file_metadata, code_paths) for a repo path. Skips common junk dirs."""
    root = Path(root)
    metas: List[dict] = []
    code_paths: List[Path] = []
    for path in sorted(root.rglob("*")):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if not path.is_file():
            continue
        ext = path.suffix.lower()
        try:
            size = path.stat().st_size
        except OSError:
            size = 0
        metas.append({
            "name": str(path.relative_to(root)),
            "size": size,
            "content_type": ext.lstrip("."),
        })
        if ext in CODE_EXTS and len(code_paths) < max_code_files:
            code_paths.append(path)
    return metas, code_paths


def run_review(code_paths: List[Path]) -> Tuple[List[dict], bool, str]:
    """Run the LLM code reviewer if available. Returns (findings, available, reason)."""
    if not code_paths:
        return [], False, "no code files to review"
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from scanners.llm_code_review import LLMCodeReviewer
    except Exception as e:                       # reviewer/deps not importable
        return [], False, f"reviewer unavailable ({e})"
    reviewer = LLMCodeReviewer()
    if not reviewer.available:
        return [], False, reviewer._unavailable_reason or "reviewer unavailable"
    findings = reviewer.review_paths([str(p) for p in code_paths])
    out = [{
        "title": f.title,
        "severity": getattr(f.severity, "name", str(f.severity)),
        "cwe_ids": list(f.cwe_ids),
        "solution": f.solution,
    } for f in findings]
    return out, True, "ok"
