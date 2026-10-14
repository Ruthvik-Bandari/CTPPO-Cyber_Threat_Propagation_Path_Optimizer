---
paths:
  - "frontend/**"
---

# Analyst UI (Next.js)

- Read `frontend/AGENTS.md` first: this Next.js version has breaking changes; consult `node_modules/next/dist/docs/` before using framework APIs.
- Verify with `cd frontend && npm run lint && npm run typecheck && npm run build`.
- Display analyst severity, reporter risk score, model ranking score and replay metrics as separately labeled values. Never show a ranking score as confidence or probability.
- Show abstained, unsupported, insufficient_evidence and engine-error states explicitly; do not render them as "no matches".
- Render rule text, log fields and model explanations as plain text (no `dangerouslySetInnerHTML`); they are untrusted.
- The approve action submits the exact proposal hash and validation run ID shown on screen; disable it when the run is stale.
- The browser talks only to the application origin; no direct calls to Elasticsearch, the worker or the model service.
- Keep existing incident pages working.
