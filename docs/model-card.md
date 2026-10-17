# Model card: M1 detection-repair adapter (research, not released)

**Status: research result, not shipped.** Under plan section 13, adaptation ships only if it credibly beats the strongest baseline, and M1 does not (see Results). The shipped `aegis-sec detect` uses the deterministic generator; B1 retrieval is the recommended research baseline.

## Model

| | |
| --- | --- |
| Base model | [Qwen/Qwen2.5-Coder-7B-Instruct](https://huggingface.co/Qwen/Qwen2.5-Coder-7B-Instruct), revision `c03e6d358207e414f1eca0bb1891e29f1db0e242`, Apache-2.0 |
| Adapter | LoRA on `q,k,v,o,gate,up,down` projections; r 16, alpha 32, dropout 0.05 |
| Training | Supervised fine-tuning on completions only; AdamW with learning rate 2e-4 and a cosine schedule (5% warmup); effective batch 8; 3 epochs; bf16; context 4,096 with no truncation observed |
| Hardware | One A100-SXM4-80GB. Peak memory 18.9 GB, about 2,100 tokens per second, 4.5 minutes per seed |
| Seeds | 1, 2, 3 (see Results) |
| Code | `src/aegisbench/m1.py` (training), `src/aegisbench/sft.py` (data), `src/aegisbench/hf.py` (inference) |
| Run records | `reports/m1-seed*-training.json`, which hold the configuration, loss history, memory, throughput, base revision and data SHA-256 |

## Intended use

The adapter proposes **candidate repairs** for a broken Sigma rule, as structured JSON patches under the candidate contract: at most 3 AST edits and at most 4 candidates, and it never drops a selection. Its input is the rule, the field mapping, field coverage, the deterministic diagnosis and replay counts.

Every proposal is then screened, frozen and validated on the pinned Elasticsearch by the same workflow used for B0. The model's output is never applied without that validation.

**Not intended for:**
- applying rule changes automatically;
- free-text security advice;
- any task outside the candidate contract.

The model has no tools and no network access. It loads with `trust_remote_code=False` from a local, revision-pinned snapshot.

## Training data

126 train and 43 development examples come from the benchmark's train and development splits, never test; see the [dataset card](data/dataset-card.md). Each example pairs the exact B2 prompt with the reference repair recovered from the healthy rule. Missing-telemetry and healthy cases have the target `{"candidates": []}`. Six natural fixes that cannot be written within the contract were skipped. The prompts hold no event values.

## Results

These are paired results on 175 train and development cases from 51 roots, before the locked test split. The intervals come from a root-resampling bootstrap.

| System | Validated success | Outcome match | Weakened rules | Abstained | Δ vs B0 |
| --- | --- | --- | --- | --- | --- |
| B0, deterministic | 0.560 | 0.949 | 6 | 1% | — |
| B1, retrieval | 0.560 | 0.943 | 0 | 5% | ±0 |
| B2, unmodified model | 0.509 | 0.760 | 0 | 23% | −0.051 (−0.084 to −0.023) |
| M1 seed 1 | 0.549 | 0.920 | 0 | 7% | −0.011 (−0.028 to +0.000) |

<!-- SEEDS: three-seed summary added when seeds 2 and 3 finish -->

- **M1 vs B2:** +0.040 (95% CI +0.017 to +0.072). M1 won 7 cases and lost none, with zero malformed outputs. Fine-tuning clearly teaches the output contract and the logic repairs.
- **M1 vs B0:** statistically indistinguishable. M1 never weakened a rule, while B0 did so 6 times.
- **Natural faults (11 cases):** no system is above 0.09 validated success, and M1 scores 0.00.

## Limitations and risks

- **The benchmark is small and partly synthetic.** Its logic faults mirror B0's own search space, which favors B0. Natural faults are few. Results are exploratory.
- **The labels are AI-assisted,** and the human check is pending. The split is a preview and not yet frozen.
- **A model proposal can be wrong or weaken a rule.** The validation policy is the guard, and it needs reviewed benign events to detect weakening. Provisional repairs (no validation suite) are less trustworthy.
- **Prompt injection.** Rule text is passed to the model, and a malicious rule could try to steer it. The model has no tools, and every output passes the candidate contract and engine validation, so the worst case is a rejected or abstained repair.

## Reproduce

Follow [`docs/research.md`](research.md), steps 9 to 11. The commands are:

- `hpc/sft.sbatch`;
- `hpc/m1.sbatch --max-steps 5`, then `hpc/m1.sbatch --train-seed N`;
- `hpc/m1_eval.sbatch m1-seedN`;
- `compare --systems b0 b1 b2 m1-seed1 m1-seed2 m1-seed3`.
