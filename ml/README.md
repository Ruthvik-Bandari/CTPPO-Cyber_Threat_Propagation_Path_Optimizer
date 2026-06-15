# CTPPO — ML components

The engine's ML is intentionally small and honest. Two pieces, both **optional** to the core
exact NAMOA\* search. Canonical numbers live in `docs/RESEARCH/METRICS.md`.

## 1. Severity classifier (text-only) — `cve_classifier.py`
DistilBERT over the CVE **description** → {CRITICAL, HIGH, MEDIUM, LOW}. It deliberately does
**not** take the CVSS score/vector as input — that would be circular (the label is a threshold on
that score). Honest held-out **macro-F1 = 0.729** (majority baseline 0.102). See
`docs/RESEARCH/A4_SEVERITY_CLASSIFIER.md`. Train with `ml/train_severity.py`.

## 2. GNN exploitability refiner — `ml/gnn/` + `evaluation/pignn_path_recovery.py`
A small GCN that refines per-edge success probability from graph structure, blended with the
rule-based EPSS/KEV/CVSS cost.
- Real PIGNN Active-Directory dataset: **0.956 ROC-AUC** for attack-path structure (vs 0.883
  without message passing).
- On our own synthetic graphs it only **matches** EPSS ranking on per-node AUC (honest mixed
  result). See `A3_PIGNN_VALIDATION.md` / `A3_GNN_ABLATION.md`.

## Removed legacy prototype
An earlier prototype (`ctppo_ml.py` `CTPPOPipeline` + a DuelingDQN defender + an nltk-based
`data_preprocessor`) has been **removed** — it was never used by the engine or API. The shipping
system uses **exact NAMOA\* search (no RL)** plus the two components above. Earlier "GNN 97.6%
accuracy on 276K CVEs" / "RL 5000 episodes" claims referred to that prototype — see
`docs/RESEARCH/METRICS.md` §4.
