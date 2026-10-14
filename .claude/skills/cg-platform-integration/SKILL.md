---
name: cg-platform-integration
description: Connect the Python analysis core to the Spring Boot backend, leased worker, CLI and Next.js review UI - jobs, outbox, claim/heartbeat/complete, review page and exact-hash approval export (CG009, CG010, CG011). Use when wiring analysis results into cases and the analyst workflow. Do not use for changing rule semantics, replay internals or ML training.
---

# Backend, worker, CLI and UI integration

Plan refs: sections 4 (FR05-FR10), 5 (analyst workflow), 6, 7, 8 (routes, job behavior), 17.

## Expected inputs

- The contracts from cg-schema-contract and core functions in `analysis/`.
- Target route(s) from the section 8 table and affected UI pages.

## Steps

1. Backend creates a job and outbox entry in one transaction with an idempotency key. It owns all state transitions.
2. Worker claims via `/internal/v1/jobs/*` with a scoped service identity, heartbeats every 15 s on a 90 s lease, writes each attempt to its own temp dir, and completes with compare-and-set on the lease. 10 minute wall cap; cooperative cancel between index, inference and replay.
3. Retry transient infrastructure failures at most twice with backoff; never retry invalid rules or missing required fields.
4. Artifacts: write temp, SHA-256, atomic finalize, then acknowledge. Successful jobs store only content references.
5. CLI calls the same core and emits JSON with machine-readable exit states matching domain outcomes.
6. Every new route has ANALYST/ADMIN or project-reader checks plus cross-user and role denial tests.
7. Review page shows original rule, diff, replay matches, abstention reason and evidence refs. Approval binds proposal hash and validation run ID; a stale run cannot be approved and later edits invalidate export.
8. Linking a repair run to an incident must not change incident severity or riskScore. Existing incident tests still pass.
9. For UI work, follow `frontend/AGENTS.md` and `.claude/rules/ui.md`.

## Output evidence

- Route list with auth tests, lease and idempotency tests, CLI JSON sample from synthetic fixtures, command output for backend, frontend and analysis checks.

## Failure conditions (stop and report)

- The worker would hold business authorization or database credentials beyond its scoped API.
- Model failure would block static diagnosis, original replay or evidence inspection.
- Incident lifecycle or authorization regressions appear.
