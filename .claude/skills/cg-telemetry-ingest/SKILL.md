---
name: cg-telemetry-ingest
description: Build or change the safe JSONL telemetry importer, schema profiler and fixture provenance checks for Sysmon EventID 1 and the ECS-mapped process creation variant. Use when adding a supported telemetry source, fixture loader, or field coverage profiling. Do not use for Sigma rule semantics (cg-sigma-adapter) or for fetching data from remote systems (cg-connector).
---

# Telemetry ingest and schema profiling

Plan refs: sections 4 (FR01, FR02, budgets), 5, 7 (DatasetVersion, SchemaProfile), 9 (diagnosis sequence), 11, 16.

## Expected inputs

- A synthetic or sanitized JSONL fixture set under the repo (never `data/raw/` or `data/locked/`).
- Target schema: Sysmon EID1 style (`Image`, `CommandLine`, `ParentImage`, `User`, ...) or ECS (`process.executable`, `process.command_line`, `process.parent.executable`, ...).
- Label manifest: per-event malicious / benign / unknown, scenario ID, reviewer rationale.

## Steps

1. Stream-parse JSONL with bounded line length, nesting depth and total size (250 MB per job). Reject oversized input with an explicit 413-equivalent reason code.
2. Assign stable event IDs; compute SHA-256 of each file and record them in the DatasetVersion manifest with license and source revision.
3. Validate the label manifest: every event ID resolves, labels are one of the three values, unknown is kept separate and never coerced.
4. Profile each field: presence count, null count, type set, cardinality. Distinguish "field absent" from "field present with no matching value" (needed for the missing-telemetry demonstration).
5. Compare required rule fields to observed fields and emit required / observed / missing with counts.
6. Treat every string as data: no evaluation, no template expansion, no path resolution from event content.
7. Add tests: malformed line, deep nesting, oversized file, duplicate IDs, Unicode, arrays, mixed types, a prompt-injection string inside `CommandLine`.

## Output evidence

- DatasetVersion manifest with hashes, schema profile JSON, test names and command output.
- Documented ceilings and measured ingest time on the recorded machine, if measured.

## Failure conditions (stop and report)

- Input would come from raw or locked locations, or from a live system.
- Labels are missing or ambiguous and the task asks to infer them.
- Fixtures contain credentials or unsanitized institutional telemetry.
