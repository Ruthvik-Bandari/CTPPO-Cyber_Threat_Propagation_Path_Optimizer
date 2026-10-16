# Session handoff

Maintained per session: overwrite these sections at the end of every Claude Code session (see `docs/claude/workflow.md`). Detailed history lives in git.

## Current git SHA

The tip of `main`, pushed to `origin/main` after every change (2026-10-15). The working tree is clean after the commit that adds this file.

## Completed

- Aegis-Sec 0.1.0 package, dashboard and documentation (`0b76c16`, `8798c97`, `911b87a`).
- HPC access to Northeastern Explorer:
  - SSH aliases `explorer` (login), `explorer-01` (fallback login node) and `explorer-xfer` (transfer node);
  - the repo is at `~/aegis-sec`;
  - jobs charge `aai6610.202610`.
- `src/aegisbench/` (not in the wheel) also has `review-sheet`/`review-next`/`review-label`/`review-status`, `split` (preview, `--freeze`) and `variants` (verified impairment cases). It does three core things:
  - `acquire` fetches the pinned sources;
  - `qc` writes aggregate checks;
  - `replay` runs every supported rule on the pinned Elasticsearch against SigmaHQ regression and OTRF events.
- ADR 0002 widened the Sigma subset to lists of field maps, `|all`, and `1 of` / `all of`. 997 of 1,182 SigmaHQ rules are now supported (up from 192).
- Replay (job 11105959):
  - 0 engine errors;
  - fidelity 83/83 against SigmaHQ's declared match counts;
  - 176 rules with at least one positive and 43 with two or more.
  - Details are in `docs/data/qc/README.md`.
- Webcheck:
  - CSP strength, HSTS details and cookie prefix checks;
  - offline conformance pages;
  - `scripts/webcheck_conformance.py`, with 8/8 badssl.com endpoints as expected.
- Fixed bugs:
  - dated Sigma rules were rejected;
  - the engine client sent loopback traffic through `HTTP_PROXY`;
  - QC collapsed same-named OTRF archives (155 counted as 118);
  - two review findings on the subset widening (edit counting, underscore patterns).

## Commands actually run

| Command | Result |
| --- | --- |
| `uv run pytest` | 551 passed (engine up) |
| `uv run ruff check`, `ruff format --check`, `mypy` | clean (55 source files) |
| `uv run python scripts/webcheck_conformance.py` | 8/8 endpoints as expected |
| `ssh explorer-xfer 'cd ~/aegis-sec && bash -l hpc/fetch_engine.sh'` | Elasticsearch 8.19.3 tarball, SHA-512 verified |
| `sbatch hpc/qc.sbatch` (job 11105891) | COMPLETED, 0 problems |
| `sbatch hpc/replay.sbatch` (job 11105959) | COMPLETED, 997 rules, 0 engine errors |

## Facts learned about the cluster

- Compute nodes have no internet, and the nodes set `http(s)_proxy` without `NO_PROXY`. Loopback traffic must bypass the proxy.
- The transfer node has internet and the same `/home` and `/scratch`. It runs CentOS 7 with no Apptainer, so never build the environment there. Slurm is not available on it.
- The login node `explorer-02` (129.10.0.146) timed out on 2026-10-15. `explorer-01` (129.10.0.145) worked.
- There is no Docker. Jobs run Elasticsearch from the official tarball. Its bundled S3 plugin probes cloud metadata unless `AWS_REGION` is set.
- `/scratch` is purged on the first Tuesday of each month.

## Failed or skipped checks

- Replay job 11105413: the health check went through the proxy. Fixed.
- Replay job 11105791: duplicate OTRF event ids were caught by the engine count check. Fixed.

## Next action

1. **Owner:** label the 175 OTRF candidates (`docs/data/review.md`). That is what unlocks validated success: 81 of 88 repairs are provisional today. It also lets more of the 1,156 unobservable natural fixes be verified.
2. Rerun the chain on the cluster: `natural.sbatch`, then `review_split.sbatch`, then freeze the split, then `variants.sbatch`, then `evaluate.sbatch b0` and `b1`.
3. B2: verify the scratch GPU environment inside a job, since the login node kills torch imports. Then run `hpc/b2.sbatch`. M1 (`sft.sbatch`, then `m1.sbatch --max-steps 5`, then a full run) only if B2 shows a gap on natural cases.
4. Locked test evaluation once (`--locked`), then the model and dataset cards.
5. Owner items in `docs/data/compliance.md`: `/work` storage, and IRB review for practitioner trials.

Latest results are in `docs/data/qc/README.md`:

- B0 = B1 = 0.520 validated success.
- Outcome match is 0.977.
- On natural cases, success is 0.20. B0 weakened 2 rules; B1 abstained instead.
