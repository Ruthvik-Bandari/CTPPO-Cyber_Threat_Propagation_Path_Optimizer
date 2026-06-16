# E2 — The GNN's role: exploratory, with one measured (topology) lift

**Phase 5 (modeling scope), deliverable E2.** Roadmap: `05_OSS_REALTIME_PLAN.md` §Phase-5.
**Status: DONE (2026-06-15).** Decision + a new engine-level experiment.

## The question

The critique asked us to position the GNN honestly: **exploratory** or **a measured lift**? A3
already measured it at the per-node level; E2 settles the positioning and adds the one measurement
A3 didn't do — the **engine-level decision** test, which is the test CTPPO actually cares about.

## What was already measured (A3)

| Setting | Result | Source |
|---|---|---|
| GNN vs EPSS on CTPPO's own synthetic graphs (per-node exploitability AUC) | **only matches** EPSS ranking; improves calibration (RMSE), no AUC lift; wins only at high lateral coupling | `A3_GNN_ABLATION.md` |
| GNN on the **real PIGNN AD dataset** (attack-path-node membership) | message passing **0.956 ROC-AUC** vs **0.883** topology-blind MLP → **+0.073 from topology** | `A3_PIGNN_VALIDATION.md` |

So per-node, the GNN does **not** beat EPSS (EPSS is already a strong per-CVE ranker). Its one
measured lift is **structural**: when the signal is topological, message passing adds real AUC.

## New (E2): the engine-level decision test

`evaluation/e2_gnn_engine_lift.py` wires the **trained A3 checkpoint**
(`models/exploitability_gnn.pt`) into the engine via `refine_graph_costs` and asks: does it change
the **Pareto-critical top fix** — the actual prioritization decision — vs the rule baseline? (The
working principle: *the decisive test is the multi-objective path decision, not per-node AUC.*)

**Measured (60 real-CVE neutral nets, real EPSS/KEV, 2026-06-15):**

| Quantity | Result |
|---|---:|
| Pareto top-fix **changed** by GNN refinement | **0 / 60 = 0.0%** |
| per-edge success-probability movement | mean **0.032**, max **0.347** |
| mean Pareto front size (rule → GNN) | 1.22 → 1.20 |

The GNN **does** move success-probability magnitude (up to 0.347 on an edge), but it changes the
**engine-level decision in 0% of nets**. This is exactly the **B1–B8 pattern restated for the GNN**:
a refinement moves reachability *magnitude* but not the prioritization *decision*, because the
data-grounded structure (EPSS/KEV + which edge is the bottleneck/choke point) drives which fix wins
— and the GNN was trained to *match* EPSS, so it can't override the structure it agrees with.

## The decision: position as EXPLORATORY (default-off), with the honest topology caveat

- **Exploratory as an EPSS replacement / engine refiner.** It matches EPSS per-node (A3) and changes
  zero top-fix decisions when wired into the engine (E2). It is correctly an **optional, default-off**
  refiner (`refine_graph_costs`, `ctppo demo --gnn`); the shipping engine is exact NAMOA\* over
  data-grounded costs, **no GNN in the critical path**. It is **not** a headline result and is not
  framed as one (METRICS §2 already says "only matches EPSS ranking — honest mixed result").
- **One measured lift, honestly scoped:** topology. On the real PIGNN AD task, message passing adds
  **+0.07 ROC-AUC** over a topology-blind MLP — a genuine, measured contribution, but on the
  *structural* attack-path-membership task, not on CTPPO's per-CVE cost refinement. That is where the
  GNN's value is real, and where future work (richer topological features, the C1/C2 identity/cloud
  graphs) could extend it.

So: **keep the GNN as an exploratory, optional, default-off component**, with the PIGNN topology
result as its one honest measured win — not as a claim that it improves CTPPO's recommendations.

## Files

`evaluation/e2_gnn_engine_lift.py` (the engine-level decision experiment),
`tests/evaluation/test_e2_gnn_engine_lift.py` (1 slow test). Decision recorded here + METRICS §2.
Next in Phase 5: E3 (leakage / circularity audit + documented splits).
