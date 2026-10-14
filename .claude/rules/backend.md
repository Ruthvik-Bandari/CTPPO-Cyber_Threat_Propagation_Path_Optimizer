---
paths:
  - "backend/**"
---

# Spring Boot backend

- Verify with `cd backend && ./mvnw -B test`.
- Every new `/api/v1/*` route enforces ANALYST/ADMIN or project-reader checks and gets cross-user and role denial tests. `/internal/v1/jobs/*` accepts only a scoped service identity.
- The backend owns job state transitions: job + outbox in one transaction, idempotency keys, compare-and-set completion on the current lease.
- Add versioned migrations; do not rely on `ddl-auto=update` for new tables. Non-test profiles move toward schema validation.
- RuleVersion content is immutable. Approval binds proposal hash and validation run ID; reject stale runs with 409.
- Keep `riskScore` meaning unchanged (reporter-supplied). New score fields are distinct columns.
- Linking a repair run to an incident must not change its severity.
- Return 202/400/401/403/409/413 per the plan; never leak stack traces.
- Preserve incident lifecycle and authorization regression tests.
