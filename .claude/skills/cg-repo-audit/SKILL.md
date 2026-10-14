---
name: cg-repo-audit
description: Audit this CyberGuard fork against the upstream baseline commit and inventory commands, locks, auth tests, evidence storage and migrations. Use when starting a session on a fresh checkout, after an upstream merge, or when CG001 needs refreshing. Do not use to implement features or fix findings; it produces findings only.
---

# CyberGuard repository audit

Read-only inspection that separates observed facts from assumptions. Plan refs: sections 3, 17, 19 (CG001), 20.

## Expected inputs

- The current checkout and `git log` / `git remote -v`.
- Upstream baseline: `tanishka-bandari/cyberguard` at `9d00c744420d4681fc199f053f29b0863e31a910`.
- `docs/handoff.md` (previous session state), if present.

## Steps

1. Record current branch, HEAD SHA and whether the baseline commit is an ancestor (`git merge-base --is-ancestor`). If not, say so; do not guess.
2. Confirm `LICENSE` is the upstream MIT text and that attribution to the upstream author is retained in README or a fork manifest.
3. Inventory build and test entry points by reading files, not by assuming: `backend/pom.xml` and `mvnw`, `frontend/package.json` scripts, `analysis/pyproject.toml` and `uv.lock`, `.github/workflows/*`. List each command with its source file.
4. Check dependency locks: `frontend/package-lock.json`, `analysis/uv.lock`, Maven wrapper version. Note anything unpinned (floating Docker tags, `latest` images, unpinned Elasticsearch).
5. Locate authorization and incident lifecycle tests in `backend/src/test`. Note which roles (USER, ANALYST, ADMIN) and denial cases are covered.
6. Inspect persistence: `spring.jpa.hibernate.ddl-auto` value, presence of Flyway/Liquibase migrations, and how `riskScore` is stored (plan section 3: reporter-supplied, not a model prediction).
7. Inspect evidence and file storage paths, upload limits and whether hashes are computed.
8. Run only commands the user permits; record exact command and exit status. Commands not run are listed as not run.

## Output evidence

- A findings table: item, observation, source file:line, fact or assumption.
- Command inventory with status: ran-passed, ran-failed, not-run (reason).
- Gaps mapped to tickets CG001-CG003 and the risks they create.

## Failure conditions (stop and report)

- Baseline commit cannot be found or the license/attribution has been removed.
- The audit would require reading `.env`, keys, `data/raw/` or `data/locked/`.
- A command needs network access or credentials the session was not given.
