"""``python -m aegisbench {acquire,qc} --root DIR [--source NAME ...]``.

``acquire`` writes ``<root>/<source>/`` checkouts and ``<root>/manifests/<source>.json``.
``qc`` re-verifies each manifest against disk, then writes ``<root>/reports/qc-<source>.json``.
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aegisbench")
    parser.add_argument("command", choices=["acquire", "qc"])
    parser.add_argument("--root", type=Path, required=True, help="data root outside the repository")
    parser.add_argument("--source", action="append", choices=[s.name for s in SOURCES])
    args = parser.parse_args(argv)
    root: Path = args.root.resolve()
    repo = Path(__file__).resolve().parents[2]
    if (repo / ".git").exists() and root.is_relative_to(repo):
        parser.error("--root must be outside the repository working tree")
    selected = [by_name(n) for n in args.source] if args.source else list(SOURCES)

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
