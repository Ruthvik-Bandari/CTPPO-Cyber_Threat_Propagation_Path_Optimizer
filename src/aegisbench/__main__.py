"""``python -m aegisbench {acquire,qc,replay,review-sheet,review-status,split,variants,evaluate} --root DIR [--source NAME ...] [--es-url URL]``.

``acquire`` writes ``<root>/<source>/`` checkouts and ``<root>/manifests/<source>.json``.
``qc`` re-verifies each manifest against disk, then writes ``<root>/reports/qc-<source>.json``.
``replay`` runs every supported Sigma rule on the pinned engine and writes ``reports/replay-positives.json``.
``review-sheet`` writes the private OTRF candidate review files; ``review-status`` validates labels (counts only).
``split`` previews the root-grouped split (``reports/split-preview.json``); ``--freeze`` writes
``benchmark/split-manifest.json`` once. ``variants`` writes impairment cases (private) and
``reports/variants.json``. ``evaluate`` scores a repair system on the cases (train and development;
``--locked`` adds the test split) into ``reports/eval-<system>.json``.
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


def _reviewed(root: Path, report: dict[str, object]) -> dict[str, str]:
    """Validated labels, or {} before review; invalid rows stop the run."""
    from .review import ReviewError, candidates, read_labels

    path = root / "review" / "labels.csv"
    if not path.exists():
        return {}
    labels, problems = read_labels(path, set(candidates(root, report)))
    if problems:
        raise ReviewError(f"{len(problems)} invalid label rows; run review-status")
    return labels


def _evaluate(root: Path, system_name: str, es_url: str, *, locked: bool) -> int:
    from aegissec.core.errors import Rejected
    from aegissec.detect.engine import Elasticsearch

    from .evaluate import SYSTEMS, run_cases, summarize

    if system_name not in SYSTEMS:
        print(f"evaluate: unknown system {system_name!r}; choose from {sorted(SYSTEMS)}", file=sys.stderr)
        return 2
    es = Elasticsearch(es_url, timeout=120.0)
    try:
        es.require_pinned()
        rows = run_cases(root / "benchmark" / "cases", SYSTEMS[system_name], es, locked=locked)
    except (Rejected, OSError, ValueError) as exc:
        print(f"evaluate: FAILED {exc}", file=sys.stderr)
        return 1
    finally:
        es.close()
    suffix = "-locked" if locked else ""
    summary = summarize(rows)
    result = {"schema_version": 1, "system": system_name, "locked_test_included": locked, "summary": summary}
    _write_json(root / "reports" / f"eval-{system_name}{suffix}.json", {**result, "cases": rows})
    print(f"evaluate: {json.dumps(summary['overall'])}")
    return 0


def _variants(root: Path, manifest_path: Path | None, es_url: str, seed: str) -> int:
    import shutil

    from aegissec.core.errors import Rejected
    from aegissec.detect.engine import Elasticsearch

    from .review import ReviewError
    from .variants import build

    frozen = root / "benchmark" / "split-manifest.json"
    path = manifest_path or frozen
    es = Elasticsearch(es_url, timeout=120.0)
    try:
        es.require_pinned()
        manifest = json.loads(path.read_text())
        report = json.loads((root / "reports" / "replay-positives.json").read_text())
        benign = {e for e, label in _reviewed(root, report).items() if label == "benign"}
        shutil.rmtree(root / "benchmark" / "cases", ignore_errors=True)  # regenerate deterministically
        result = build(root, manifest, report, benign=benign, es=es, seed=seed)
    except (Rejected, ReviewError, OSError, ValueError) as exc:
        print(f"variants: FAILED {exc}", file=sys.stderr)
        return 1
    finally:
        es.close()
    result["manifest"] = path.name
    result["from_frozen_split"] = path.resolve() == frozen.resolve()
    _write_json(root / "reports" / "variants.json", result)
    print(f"variants: {result}")
    return 0


def _split(root: Path, seed: str, frozen: bool) -> int:
    from .review import ReviewError
    from .split import SplitError, build, freeze

    try:
        report = json.loads((root / "reports" / "replay-positives.json").read_text())
        malicious = {e for e, label in _reviewed(root, report).items() if label == "malicious"}
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


def _label(root: Path, args: argparse.Namespace) -> int:
    """Interactive labelling. Prints raw event values: for the reviewer's own terminal only."""
    from .review import ReviewError, format_candidate, next_candidate, set_label

    try:
        if args.command == "review-label":
            if not (args.event and args.label):
                raise ReviewError("review-label needs --event and --label")
            set_label(root, args.event, args.label, args.rationale, args.reviewer)
        item, remaining = next_candidate(root)
    except (ReviewError, OSError, ValueError) as exc:
        print(f"{args.command}: FAILED {exc}", file=sys.stderr)
        return 1
    print(format_candidate(item, remaining) if item else "Every candidate is labelled.")
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
    parser.add_argument(
        "command",
        choices=[
            "acquire",
            "qc",
            "replay",
            "review-sheet",
            "review-status",
            "review-next",
            "review-label",
            "split",
            "variants",
            "evaluate",
        ],
    )
    parser.add_argument("--root", type=Path, required=True, help="data root outside the repository")
    parser.add_argument("--source", action="append", choices=[s.name for s in SOURCES])
    parser.add_argument("--es-url", default="http://127.0.0.1:9200", help="pinned Elasticsearch for replay")
    parser.add_argument("--freeze", action="store_true", help="split: write the frozen manifest (never overwritten)")
    parser.add_argument("--seed", default=SPLIT_SEED, help="split: assignment seed")
    parser.add_argument("--manifest", type=Path, help="variants: split manifest (default: the frozen one)")
    parser.add_argument("--system", default="b0", help="evaluate: repair system")
    parser.add_argument("--locked", action="store_true", help="evaluate: include the locked test split")
    parser.add_argument("--event", help="review-label: event id")
    parser.add_argument("--label", choices=["malicious", "benign", "unknown"], help="review-label: decision")
    parser.add_argument("--rationale", default="", help="review-label: what decided it (one line)")
    parser.add_argument("--reviewer", default=os.environ.get("AEGIS_REVIEWER", ""), help="review-label: initials")
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
    if args.command in ("review-next", "review-label"):
        return _label(root, args)
    if args.command == "split":
        return _split(root, args.seed, args.freeze)
    if args.command == "evaluate":
        return _evaluate(root, args.system, args.es_url, locked=args.locked)
    if args.command == "variants":
        return _variants(root, args.manifest, args.es_url, args.seed)

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
