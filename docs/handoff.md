# Session handoff

Maintained per session: overwrite these sections at the end of every Claude Code session (see `docs/claude/workflow.md`). Detailed history lives in git.

## Current git SHA

The tip of `main`, pushed to `origin/main` after every change (2026-10-14). The working tree is clean after the commit that adds this file.

## Completed

- Aegis-Sec 0.1.0 package, dashboard and documentation (`0b76c16`, `8798c97`, `911b87a`).
- HPC access to Northeastern Explorer:
  - the `explorer` (login) and `explorer-xfer` (transfer node) SSH aliases use key login;
  - the repo is cloned at `~/aegis-sec`, and the environment is built on the login node with `hpc/setup_env.sh`.
- The GPU smoke job ran: Tesla V100-SXM2-32GB, driver 545.23.08, `cuda/12.8.0` and `python/3.13.5` modules.
- The research package `src/aegisbench/` (not in the wheel) does three things:
  - fetches SigmaHQ r2026-07-01, OTRF Security-Datasets and Atomic Red Team at pinned commits;
  - writes license and SHA-256 manifests;
  - writes aggregate QC reports.
- QC ran clean. The results are in `docs/data/qc/` (README plus JSON).
- Fixed a shipped bug: dated Sigma rules (all real SigmaHQ rules) were rejected with `yaml_tag_not_allowed`. Timestamps now load as text.
- Documents: `docs/data/sources.md` (license record), `docs/data/policy.md` (data and model guardrails), `docs/data/compliance.md` (approvals checklist), `docs/hpc.md` (runbook and choosing GPUs by task).

## Commands actually run

| Command | Result |
| --- | --- |
| `uv run pytest` | 494 passed (engine up) |
| `uv run pytest -m engine` | 23 passed |
| `uv run ruff check src tests scripts`, `ruff format --check`, `mypy` | clean (54 source files) |
| `ssh explorer-xfer 'cd ~/aegis-sec && bash -l hpc/acquire.sh'` | 3 sources acquired: 1,567, 269 and 1,321 files |
| `sbatch hpc/qc.sbatch` (job 11085056) | COMPLETED; 0 problems in Sigma and OTRF |

## Facts learned about the cluster

- Compute nodes have no internet. The transfer node `xfer.discovery.neu.edu` does, but it runs CentOS 7 (glibc 2.17, git 1.8, with module `git/2.19.0`). Never build the project environment there.
- Batch scripts need `#!/bin/bash -l` for `module`.
- `/scratch` is purged on the first Tuesday of each month.
- Slurm accounts visible to the user: `aai6610.202610` and `j.liebowitz`. The owner still has to confirm which one to charge.

## Failed or skipped checks

- The first combined acquire+QC job hung (compute nodes have no internet) and was cancelled. The work was split into a transfer-node acquire step and a Slurm QC job.

## Next action

1. Owner decision: how to reach about 60 benchmark roots (see `docs/data/qc/README.md`). Either widen the v1 subset (list-of-maps, `contains|all`, `1 of`/`all of`; needs an ADR), or find positives for the 192 supported rules by replaying OTRF EID 1 events on the pinned engine. Or both.
2. Build the root-grouped split manifest (36/12/12), freeze its hashes, then generate impairment variants and replay labels.
3. B1 and B2 on `gpu-short` V100, then M1 on A100 after the measured gap (plan sections 12 to 14).
4. Owner items in `docs/data/compliance.md`: Slurm account, `/work` storage, and IRB review for practitioner trials.
