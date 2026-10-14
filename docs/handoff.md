# Session handoff

Maintained per session: overwrite these sections at the end of every Claude Code session (see `docs/claude/workflow.md`). Detailed history lives in git.

## Current git SHA

`8798c9743e052a3b6bd45cfbec0916e2105153a4` on `main`, equal to `origin/main` (2026-10-14).

The working tree is not clean. Uncommitted changes:

- documentation set: `docs/modules/`, `docs/api.md`, `docs/security-model.md`, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`, `CITATION.cff`, `CLAUDE.md`, this file;
- `.claude/` rule and skill updates, `scripts/check_claude_pack.py` and `docs/claude/gitignore_additions.txt`;
- `.github/workflows/ci.yml` (runners pinned to `ubuntu-24.04`, changed in the main session).

## Completed

- Aegis-Sec 0.1.0 package (`0b76c16`):
  - `src/aegissec/{core,detect,forensics,webcheck,bitcoin,server}` and the `aegis-sec` CLI;
  - detection repair B0 with 11 synthetic cases, each reaching its expected outcome on the pinned engine.
- Dashboard (`8798c97`): React + Vite source in `frontend/`, bundled into the wheel, screenshots in `docs/screenshots/`. The interactive Swagger page was removed so the tool works offline under the CSP; the API schema is served only at `GET /api/openapi.json`.
- Documentation set for 0.1.0 (uncommitted, listed above). It is written against the source.
- The Claude pack now points at the Aegis-Sec layout:
  - rules: `python.md` covers `src/aegissec/**/*.py`, `backend.md` covers the FastAPI server, `ui.md` covers the React dashboard;
  - skills: `cg-repo-audit`, `cg-schema-contract`, `cg-platform-integration`.

## Commands actually run

| Command | Result |
| --- | --- |
| `uv run pytest` | 477 passed (pinned engine up at 127.0.0.1:9200), on `8798c97` |
| `uv run ruff check src tests scripts` | All checks passed |
| `uv run ruff format --check src tests scripts` | 78 files already formatted |
| `uv run mypy` | Success: no issues found in 49 source files |
| `uv run aegis-sec detect demo c01-mapping-drift-commandline` | outcome `repaired`, exit 0 (output in `docs/modules/detect.md`) |
| `detect demo` on c00, c03, c10 / c05 / c09 | exit 0 / 10 / 11 |
| `python3 scripts/check_claude_pack.py` | 177/177 checks passed |
| `python3 .claude/hooks/test_protect_paths.py` | 12 tests OK |
| CI run 38535907603 on `8798c97` | success, all 6 jobs |

## Failed or skipped checks

- None outstanding. The dashboard was built and its gates run locally, and CI built it on `8798c97`.

## Artifact IDs

- Evidence from the c01 demo, written to a scratch directory and not kept: `4162c86b52d18c279dbacc59158b725bfafe1657b4d0564c419ae988b92f2c9b`.

## Next action

1. Start the research track. Build the frozen, root-grouped benchmark (plan section 11), then run B1 (retrieval) and B2 (an unmodified open model) locally.
2. Schedule M1 (LoRA/QLoRA) on university HPC (plan section 14), after a smoke job records CUDA, driver and GPU-memory facts. This waits on the owner's HPC access.
3. Optional hardening: have the mempool.space client connect to the validated IP, as webcheck does (`docs/security-model.md`, known limitations).
