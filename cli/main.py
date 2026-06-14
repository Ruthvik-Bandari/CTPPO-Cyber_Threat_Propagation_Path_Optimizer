"""
CTPPO CLI entry point (Phase B / B5b)
=====================================

Commands:
  ctppo-cli configure --api-key KEY [--api-url URL]   store credentials
  ctppo-cli login                                     validate the key; show identity + sub
  ctppo-cli whoami                                    alias for login
  ctppo-cli scan PATH [--name N] [--prompt P]         scan a local repo, submit as an instance
"""

from __future__ import annotations

import argparse
import sys
from typing import Optional

from cli.client import CtppoClient, CtppoError
from cli.config import DEFAULT_API_URL, load_config, save_config
from cli.scan import collect_repo_files, run_review


def _client() -> CtppoClient:
    cfg = load_config()
    return CtppoClient(cfg.get("api_url", DEFAULT_API_URL), cfg.get("api_key", ""))


def cmd_configure(args) -> None:
    path = save_config(args.api_key, args.api_url)
    print(f"Saved CTPPO config to {path}")


def cmd_login(args) -> None:
    client = _client()
    user = client.whoami()
    sub = client.subscription_status()
    print(f"Logged in as {user['email']} (role: {user.get('role')})")
    status = sub.get("status", "unknown")
    days = sub.get("days_remaining")
    print(f"Subscription: {status}" + (f" ({days} days left)" if days is not None else ""))


def cmd_scan(args) -> None:
    client = _client()
    metas, code_paths = collect_repo_files(args.path)
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
        # remote Git clone + SSH verification: not yet implemented (B5b follow-up).
        "remote_git": "not_implemented",
    }
    instance = client.create_instance(
        name=args.name or f"scan: {args.path}",
        prompt=args.prompt or "",
        files=metas,
        target_spec=target_spec,
    )
    print(f"Created instance {instance['id']} ({len(instance['files'])} files recorded).")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ctppo-cli", description="CTPPO subscription-tied CLI client")
    sub = parser.add_subparsers(dest="command", required=True)

    p_cfg = sub.add_parser("configure", help="store the API key + API URL")
    p_cfg.add_argument("--api-key", required=True)
    p_cfg.add_argument("--api-url", default=DEFAULT_API_URL)
    p_cfg.set_defaults(func=cmd_configure)

    for name in ("login", "whoami"):
        p = sub.add_parser(name, help="validate the API key; show identity + subscription")
        p.set_defaults(func=cmd_login)

    p_scan = sub.add_parser("scan", help="scan a local repo path and submit it as an instance")
    p_scan.add_argument("path")
    p_scan.add_argument("--name", default=None)
    p_scan.add_argument("--prompt", default=None)
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
