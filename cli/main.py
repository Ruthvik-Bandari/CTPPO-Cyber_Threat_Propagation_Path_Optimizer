"""
CTPPO CLI entry point (open-source, local-first, no-auth)
=========================================================

Commands:
  ctppo-cli scan PATH|URL [--name N] [--prompt P] [--ref R] [--api-url URL]
      scan a local repo or remote git URL; submit it as an instance to the local API
"""

from __future__ import annotations

import argparse
import sys
from typing import Optional

import shutil

from cli.client import CtppoClient, CtppoError
from cli.config import DEFAULT_API_URL, resolve_api_url
from cli.scan import clone_and_verify, collect_repo_files, is_remote_repo, run_review


def cmd_scan(args) -> None:
    client = CtppoClient(resolve_api_url(args.api_url))

    # Remote repo URL? Verify access (incl. SSH-key auth), shallow-clone, then scan the tree.
    scan_path = args.path
    cleanup_dir = None
    git_info: dict = {"remote_git": None}
    if is_remote_repo(args.path):
        print(f"Verifying + cloning {args.path} …")
        try:
            cloned, git_info = clone_and_verify(args.path, args.ref)
        except RuntimeError as e:
            raise CtppoError(str(e))
        scan_path = cloned
        cleanup_dir = cloned
        print(f"Cloned at {git_info.get('commit', '?')[:12] if git_info.get('commit') else '?'}")

    try:
        metas, code_paths = collect_repo_files(scan_path)
        print(f"Scanning {args.path}: {len(metas)} file(s), {len(code_paths)} code file(s)")
        findings, available, reason = run_review(code_paths)
        if available:
            print(f"Model-assisted code review: {len(findings)} finding(s)")
        else:
            print(f"Code review skipped ({reason}); submitting file-metadata scan only.")
        target_spec = {
            "repo_path": str(args.path),
            "review_findings": findings,
            "reviewer_available": available,
            **git_info,
        }
        instance = client.create_instance(
            name=args.name or f"scan: {args.path}",
            prompt=args.prompt or "",
            files=metas,
            target_spec=target_spec,
        )
        print(f"Created instance {instance['id']} ({len(instance['files'])} files recorded).")
    finally:
        if cleanup_dir is not None:
            shutil.rmtree(cleanup_dir, ignore_errors=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ctppo-cli", description="CTPPO local-first CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="scan a local path or remote git URL; submit as an instance")
    p_scan.add_argument("path", help="local repo path or remote git URL (https/ssh/git)")
    p_scan.add_argument("--name", default=None)
    p_scan.add_argument("--prompt", default=None)
    p_scan.add_argument("--ref", default=None, help="branch/tag to clone (remote URLs only)")
    p_scan.add_argument("--api-url", default="", help=f"CTPPO API base URL (default {DEFAULT_API_URL})")
    p_scan.set_defaults(func=cmd_scan)

    return parser


def main(argv: Optional[list] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        args.func(args)
        return 0
    except CtppoError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
