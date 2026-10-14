---
name: cg-plan-slice
description: Turn one backlog ticket (CG001-CG016) into a single-session implementation slice with changed paths, contracts, failure behavior, commands and acceptance evidence. Use before any substantive code change. Do not use to plan multiple tickets at once, to plan the whole platform, or for trivial typo fixes.
---

# Plan one implementation slice

Plan refs: sections 17 (definition of done), 18, 19 (backlog and task sizing), 22.

## Expected inputs

- A ticket ID and short goal, e.g. `CG005 safe Sigma parser`.
- `docs/handoff.md` and the ticket's dependencies from the section 19 table.

## Steps

1. Confirm dependencies are complete per `docs/handoff.md`. If a dependency is open, plan that instead or stop.
2. Bound the slice to one or two focused sessions. If it is larger, split it and plan only the first part.
3. List exact paths to create or modify. Exclude unrelated directories. If more than one language changes, require an ADR in `docs/adr/` first.
4. Define input contracts (schema version, size ceilings: 100 KB rule, 250 MB telemetry job) and output contracts (domain outcome: repaired, unchanged, abstained, unsupported, insufficient_evidence).
5. Enumerate failure states and their reason codes. Each must be an explicit non-success, never a silent empty result.
6. Name the tests: unit, contract and, where semantics matter, real-engine replay against the pinned Elasticsearch. Synthetic fixtures only.
7. List the exact commands that will prove completion, taken from real files.
8. Write acceptance criteria matching the section 17 definition of done.

## Output evidence

- A plan block: ticket, scope, out of scope, paths, contracts, failure states, tests, commands, acceptance criteria, risks.
- Explicit list of assumptions the user must confirm.

## Failure conditions (stop and report)

- The request spans several tickets or "build the platform".
- Acceptance would rely on model output or conversion success instead of replay.
- The slice needs locked test data, raw telemetry or credentials.
