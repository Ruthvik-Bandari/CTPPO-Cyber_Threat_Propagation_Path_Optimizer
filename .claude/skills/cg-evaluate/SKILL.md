---
name: cg-evaluate
description: Run or report a frozen comparison of B0, B1, B2, M1 and M1+ranker on identical cases with honest denominators, grouped bootstrap intervals and failure disclosure. Explicit invocation only. Do not use for development tuning, for editing labels or splits, or to view raw locked inputs; locked evaluation returns aggregate reports only.
disable-model-invocation: true
---

# Frozen evaluation and honest metrics

Plan refs: sections 10 (report content), 11, 13 (metrics, comparison, gates), 16 (benchmark leakage), 24 (claim discipline).

## Expected inputs

- Frozen artifacts: split manifest hash, suite hash, engine image digest, model revisions and prompt hashes for each method.
- For locked test: an aggregate report produced by the separate evaluator identity outside this tree.
- The pre-registered metric definitions and any disclosed target changes.

## Steps

1. Verify every input hash against the frozen record. Any mismatch stops the evaluation.
2. Confirm all methods share the same cases, candidate budget (4) and evidence budget.
3. Compute validated repair success with abstentions and failures in the denominator; preservation rate; benign match rate and FP per 10,000 benign; diagnosis accuracy; abstention quality; operational cost.
4. Engine errors are failed or unavailable runs, never negative predictions.
5. Use paired case comparisons and bootstrap intervals clustered by root or rule family. Do not treat events from one scenario as independent.
6. Report per fault provenance stratum (natural, lab, synthetic) and include healthy rules that must remain unchanged.
7. If M1 does not credibly beat B2, say so and recommend the stronger baseline.
8. List all cases, exclusions and failed runs.

## Output evidence

- Results table per method with denominators and intervals, list of exclusions and failed runs, hashes of every input.

## Failure conditions (stop and report)

- Any request to relabel, drop or re-split locked cases, or to tune on locked results.
- Locked raw inputs would enter the working tree or the prompt.
- Hashes do not match the frozen record.
