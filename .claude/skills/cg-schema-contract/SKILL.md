---
name: cg-schema-contract
description: Define or change versioned contracts and domain records (RuleVersion, SchemaProfile, DatasetVersion, FailureCase, RepairProposal, ValidationRun, Approval, Job/Outbox, ConnectorConfig), OpenAPI DTOs, Pydantic envelopes and migrations. Use when changing an API route, job envelope or persisted entity. Do not use for UI-only styling or for telemetry field mappings (use cg-telemetry-ingest or cg-sigma-adapter).
---

# Versioned schema and contract changes

Plan refs: sections 7, 8, 3 (ddl-auto and riskScore findings), 16.

## Expected inputs

- The entity or route being changed and the ticket ID.
- Current OpenAPI, Java DTOs, Pydantic models and migration directory.

## Steps

1. State the invariant for each touched entity from the section 7 table (e.g. RuleVersion content is immutable; Approval binds proposal hash and validation id).
2. Bump an explicit `schema_version` on any changed envelope. Keep existing incident APIs backward compatible.
3. Keep score fields distinct: `analyst_severity`, `reporter_risk_score`, `model_rank_score`, replay metrics. Never reuse the legacy `riskScore` column for model output.
4. For persistence, add a versioned migration (not `ddl-auto=update`) and a forward migration test. Non-test profiles should use schema validation.
5. Mirror the contract on both sides: Java DTO + OpenAPI, and Pydantic model in `analysis/`. Add a contract test that round-trips a fixture envelope through both.
6. Job states are only queued, running, succeeded, failed, canceled, expired. Domain outcomes are separate fields. Completion uses compare-and-set on lease ID.
7. Status codes: 202 + job URL, 400, 401/403, 409 stale version, 413 size limit. No stack traces in responses.
8. ConnectorConfig stores a credential reference only.

## Output evidence

- Diff of contract files, migration file names, contract test names and their command output.
- A compatibility note for existing incident routes.

## Failure conditions (stop and report)

- A change would mutate stored RuleVersion content or historical riskScore meaning.
- A field would carry credentials or raw event payloads into evidence.
- Java and Python contracts cannot be kept in sync within the slice.
