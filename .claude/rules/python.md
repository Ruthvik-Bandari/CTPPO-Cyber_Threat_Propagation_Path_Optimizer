---
paths:
  - "analysis/**/*.py"
---

# Python analysis core

- Run tests with `cd analysis && uv run pytest`. Add dependencies through `uv` so `uv.lock` stays authoritative.
- The core is shared by CLI, FastAPI and worker. Keep adapters thin; no business authorization here.
- Load YAML with a safe loader only. Bound file size, line length and nesting. Never `pickle`, `eval` or `exec` imported content.
- Validate envelopes with Pydantic and an explicit `schema_version`.
- Do not implement a Python matcher as a stand-in for Elasticsearch. Matching claims come from replay on the pinned engine.
- Return explicit domain outcomes (`repaired`, `unchanged`, `abstained`, `unsupported`, `insufficient_evidence`) with reason codes; never an empty result for an error.
- Hash artifacts with SHA-256, write to a temp path, then atomically rename.
- Tests use synthetic fixtures in the repo. Never read `data/raw/` or `data/locked/`.
- Logs carry job, attempt and artifact IDs, not raw event payloads or credentials.
