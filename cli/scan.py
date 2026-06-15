"""
Local repo scanning for the CLI (Phase B / B5b)
===============================================

Walks a local repository path to collect file metadata and the list of code files, then
optionally runs the model-assisted code reviewer (``scanners/llm_code_review.py``). The
reviewer needs ``anthropic`` + ``ANTHROPIC_API_KEY``; when unavailable the scan degrades
honestly to a file-metadata-only submission (clearly reported, never faked).

Remote Git: ``scan`` accepts a remote repo URL (https/ssh/git) — it verifies access with
``git ls-remote`` (which also exercises SSH-key auth for ssh:// and git@ URLs), shallow-clones
it to a temp dir, records the resolved commit, then scans the working tree. The system ``git``
is used, so any credentials/SSH agent the user already has apply.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import List, Optional, Tuple

CODE_EXTS = {
    ".py", ".ts", ".tsx", ".js", ".jsx", ".go", ".rs", ".java", ".cpp", ".c",
    ".rb", ".php", ".cs", ".kt", ".swift", ".scala", ".h", ".hpp",
}
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build",
              ".mypy_cache", ".pytest_cache", "graphify-out"}


_REMOTE_RE = re.compile(r"^(https?://|git@|ssh://|git://)")


def is_remote_repo(target: str) -> bool:
    """True if ``target`` looks like a remote Git URL rather than a local path."""
    return bool(_REMOTE_RE.match(target)) or target.endswith(".git")


def clone_and_verify(repo_url: str, ref: Optional[str] = None) -> Tuple[Path, dict]:
    """Verify access to a remote repo, shallow-clone it, and return (local_path, git_info).

    Raises RuntimeError on any failure. Uses the system ``git`` so existing credentials /
    SSH-agent keys apply (this is the "SSH login + Git verification" of the design).
    """
    if not shutil.which("git"):
        raise RuntimeError("git is not installed on this machine")

    # ls-remote both verifies the URL is reachable and that auth/identity works (esp. SSH).
    try:
        ls = subprocess.run(["git", "ls-remote", repo_url], capture_output=True, text=True, timeout=60)
    except (subprocess.TimeoutExpired, OSError) as e:
        raise RuntimeError(f"git ls-remote failed: {e}")
    if ls.returncode != 0:
        raise RuntimeError(f"cannot access {repo_url}: {ls.stderr.strip() or 'access denied'}")

    tmp = Path(tempfile.mkdtemp(prefix="ctppo_clone_"))
    cmd = ["git", "clone", "--depth", "1"]
    if ref:
        cmd += ["--branch", ref]
    cmd += [repo_url, str(tmp)]
    try:
        cl = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except (subprocess.TimeoutExpired, OSError) as e:
        shutil.rmtree(tmp, ignore_errors=True)
        raise RuntimeError(f"git clone failed: {e}")
    if cl.returncode != 0:
        shutil.rmtree(tmp, ignore_errors=True)
        raise RuntimeError(f"git clone failed: {cl.stderr.strip()}")

    commit = subprocess.run(["git", "-C", str(tmp), "rev-parse", "HEAD"], capture_output=True, text=True)
    git_info = {
        "remote_git": repo_url,
        "verified": True,
        "ref": ref,
        "commit": commit.stdout.strip() if commit.returncode == 0 else None,
    }
    return tmp, git_info


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
