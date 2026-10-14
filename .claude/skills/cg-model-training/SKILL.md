---
name: cg-model-training
description: Prepare a reviewed training run plan and artifacts for M1 (LoRA/QLoRA SFT), M2 (execution-feature ranker) or M3 (DPO) on university H200/A100 nodes. Explicit invocation only, after CG012 split freeze. Do not use for baselines, evaluation, or to submit a scheduler job without the user explicitly requesting submission in this session.
disable-model-invocation: true
---

# Model training run preparation

Plan refs: sections 11, 12 (stages and training examples), 14 (HPC, inference contract), 16 (supply chain, leakage), 18 (scope gates).

## Expected inputs

- Frozen split manifest hash and the leakage check result from cg-benchmark-design.
- Candidate base model repository, exact revision, license and tokenizer.
- Training-partition examples (and development data for model selection only).
- Allocation details the user supplies: partition names, GPU hours, scratch paths.

## Steps

1. Verify the split manifest hash matches the frozen value and rerun the root-overlap check. Stop on mismatch.
2. Confirm every training source license permits training; record it.
3. Pin environment (lock file hash, CUDA, driver, PyTorch, precision) and model revision. Never load remote executable model code or unreviewed checkpoints; no pickle from untrusted sources.
4. Build examples from the training partition only: failing rule, schema summary, replay findings, retrieved training examples to bounded patch or abstention. Include rejected candidates and their error types.
5. Draft a scheduler script with explicit CPUs, RAM, GPUs, wall time and scratch; start with a smoke job that records hardware and peak memory.
6. Log seed, effective batch size, gradient accumulation, sequence limit (pilot 2k-4k, inspect truncation), optimizer, checkpoint steps.
7. A ranker may use AST edit distance, schema validity and dev replay features only. It never sees locked test outcomes.
8. Prepare, but do not submit, the job. Submission requires an explicit request in this session.

## Output evidence

- Run plan, manifest (hashes, revision, seed, hardware), scheduler script, smoke results if run, and failed job logs.

## Failure conditions (stop and report)

- Split hashes do not match, or any locked test input is reachable.
- Reviewed training data is insufficient (section 18 week 10 gate): recommend delay.
- Model license or revision cannot be pinned.
