"""``python -m aegisbench {acquire,qc,replay,review-sheet,review-status,split} --root DIR [--source NAME ...] [--es-url URL]``.

``acquire`` writes ``<root>/<source>/`` checkouts and ``<root>/manifests/<source>.json``.
``qc`` re-verifies each manifest against disk, then writes ``<root>/reports/qc-<source>.json``.
``replay`` runs every supported Sigma rule on the pinned engine and writes ``reports/replay-positives.json``.
``review-sheet`` writes the private OTRF candidate review files; ``review-status`` validates labels (counts only).
``split`` previews the root-grouped split (``reports/split-preview.json``); ``--freeze`` writes
``benchmark/split-manifest.json`` once.
Exit status is 1 if any source fails, so a Slurm job fails visibly. ``acquire`` uses only the
standard library, so it runs on the cluster transfer node without the project environment.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from .acquire import AcquisitionError, checkout, manifest
from .sources import SOURCES, by_name


def _write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, path)


def _replay(root: Path, es_url: str) -> int:
    from aegissec.core.errors import Rejected
    from aegissec.detect.engine import Elasticsearch

    from .positives import run

    es = Elasticsearch(es_url, timeout=120.0)
    try:
        report = run(root, es)
    except Rejected as exc:
        print(f"replay: FAILED {exc.reason}: {exc.detail}", file=sys.stderr)
        return 1
    finally:
        es.close()
    _write_json(root / "reports" / "replay-positives.json", report)
    print(f"replay: {report['rules_replayed']} rules; fidelity {report['fidelity']}; summary {report['summary']}")
    return 1 if report["engine_errors"] else 0


SPLIT_SEED = "aegis-bench-v1"


def _split(root: Path, seed: str, frozen: bool) -> int:
    from .review import ReviewError, candidates, read_labels
    from .split import SplitError, build, freeze

    try:
        report = json.loads((root / "reports" / "replay-positives.json").read_text())
        malicious: set[str] = set()
        labels_path = root / "review" / "labels.csv"
        if labels_path.exists():
            labels, problems = read_labels(labels_path, set(candidates(root, report)))
            if problems:
                raise ReviewError(f"{len(problems)} invalid label rows; run review-status")
            malicious = {e for e, label in labels.items() if label == "malicious"}
        manifest = build(root / "sigma", report, malicious, seed)
        if frozen:
            digest = freeze(manifest, root / "sigma", root / "benchmark" / "split-manifest.json")
            print(f"split: frozen, sha256 {digest}")
        else:
            _write_json(root / "reports" / "split-preview.json", manifest)
    except (ReviewError, SplitError, OSError, ValueError) as exc:
        print(f"split: FAILED {exc}", file=sys.stderr)
        return 1
    print(
        f"split: {manifest['eligible_roots']} eligible roots, largest group {manifest['largest_group']}, {manifest['summary']}"
    )
    return 0


def _review(root: Path, command: str) -> int:
    from .review import ReviewError, status, write_sheet

    try:
        report = json.loads((root / "reports" / "replay-positives.json").read_text())
        if command == "review-sheet":
            print(f"review-sheet: {write_sheet(root, report)} (raw values in {root / 'review'}, private to you)")
            return 0
        result = status(root, report)
    except (ReviewError, OSError, ValueError) as exc:
        print(f"{command}: FAILED {exc}", file=sys.stderr)
        return 1
    _write_json(root / "reports" / "review-status.json", result)
    print(f"review-status: {result}")
    return 1 if result["problems"] else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aegisbench")
    parser.add_argument("command", choices=["acquire", "qc", "replay", "review-sheet", "review-status", "split"])
    parser.add_argument("--root", type=Path, required=True, help="data root outside the repository")
    parser.add_argument("--source", action="append", choices=[s.name for s in SOURCES])
    parser.add_argument("--es-url", default="http://127.0.0.1:9200", help="pinned Elasticsearch for replay")
    parser.add_argument("--freeze", action="store_true", help="split: write the frozen manifest (never overwritten)")
    parser.add_argument("--seed", default=SPLIT_SEED, help="split: assignment seed")
    args = parser.parse_args(argv)
    root: Path = args.root.resolve()
    repo = Path(__file__).resolve().parents[2]
    if (repo / ".git").exists() and root.is_relative_to(repo):
        parser.error("--root must be outside the repository working tree")
    selected = [by_name(n) for n in args.source] if args.source else list(SOURCES)
    if args.command == "replay":
        return _replay(root, args.es_url)
    if args.command in ("review-sheet", "review-status"):
        return _review(root, args.command)
    if args.command == "split":
        return _split(root, args.seed, args.freeze)

    failed = False
    for source in selected:
        dest = root / source.name
        try:
            if args.command == "acquire":
                checkout(source, dest)
                record = manifest(source, dest)
                _write_json(root / "manifests" / f"{source.name}.json", record)
                print(f"{source.name}: {record['file_count']} files, content {str(record['content_sha256'])[:12]}")
            else:
                from .qc import QC  # needs the project environment; acquire needs only the stdlib

                recorded = json.loads((root / "manifests" / f"{source.name}.json").read_text())
                current = manifest(source, dest)
                if current["files"] != recorded["files"]:
                    raise AcquisitionError(f"{source.name}: files changed since acquisition")
                report = {
                    "schema_version": 1,
                    "source": source.name,
                    "commit": source.commit,
                    "content_sha256": current["content_sha256"],
                    "checks": QC[source.name](dest),
                }
                _write_json(root / "reports" / f"qc-{source.name}.json", report)
                print(f"{source.name}: QC report written")
        except (AcquisitionError, OSError, ValueError) as exc:
            failed = True
            print(f"{source.name}: FAILED {exc}", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
