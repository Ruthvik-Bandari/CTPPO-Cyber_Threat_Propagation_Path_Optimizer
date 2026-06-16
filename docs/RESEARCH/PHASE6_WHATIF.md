# Phase 6 — What-if remediation simulator (surfaces the D4 exact-incremental engine)

**Phase 6 (realtime product UX), deliverable 1.** Roadmap: `05_OSS_REALTIME_PLAN.md` §Phase-6.
**Status: DONE (2026-06-15).** Sources: `evaluation/d4_incremental.py` (engine), `api/server_secure.py`
(`/api/attack-paths/whatif`), `frontend/.../WhatIfPanel.tsx` (UX).

## What this delivers

D4 (Phase 2) proved an **exact incremental what-if**: patching a CVE that lies on **no** Pareto path
leaves the front unchanged, so its recompute can be skipped — verified to match full recompute 100%.
That engine was only reachable from the evaluation harness. Phase 6 surfaces it as a product feature.

- **Reusable core** — `evaluation/d4_incremental.py::whatif_front(graph, edge_map, patched_cves,
  recompute_fn)`. Runs the baseline front, applies the D4 skip rule (if no patched CVE's edge is on
  the baseline front → return baseline, `skipped=True`, no re-search), else calls `recompute_fn`.
- **API** — `POST /api/attack-paths/whatif` (a network + `patch_cves`) → the after-patch Pareto front
  plus a `whatif` block: `skipped_recompute`, `before/after_reachability`, `reachability_reduction`,
  `before/after_num_paths`. When the patch is off-front it returns the **provably-unchanged** answer
  without re-searching.
- **Frontend** — `WhatIfPanel` on the attack-paths page (custom-network flow): select CVE(s) to
  patch → see before/after reachability, the reduction, and the path-count change; an off-front
  patch shows the honest "front provably unchanged" note. Typecheck + production build green.

## Measured (test `tests/api/test_whatif_api.py`)

On a small entry→web→crown chain with an off-path dead-end CVE:

| Patch | Result |
|---|---|
| `CVE-OFFPATH` (on no optimal path) | `skipped_recompute=True`, `reachability_reduction=0.0`, path count unchanged — **D4 skip** (front provably unchanged, no re-search) |
| `CVE-CHAIN-2` (the only edge into the crown) | `skipped_recompute=False`, recompute runs, `after_reachability < before_reachability`, `reachability_reduction > 0` |
| no patch | baseline front returned unchanged |

So the product feature behaves exactly as the D4 theorem requires: off-front patches are instant,
provably-correct no-ops; on-front patches recompute the exact front and report the reachability the
fix removes — the operator's "what do I actually gain by patching this?" question, answered exactly.

## Honest scope

The reachability figure is the best-path success probability (a point estimate); the **uncertainty
bands** that turn it into a *range* are the next Phase-6 deliverable. The what-if is exact for the
*modeled* graph — it inherits the same data-grounded-vs-heuristic split the C4 grader exposes (a
patch on a heuristic credential/cloud/misconfig edge moves a heuristic reachability).

## Files

`evaluation/d4_incremental.py` (`whatif_front`), `api/server_secure.py`
(`/api/attack-paths/whatif`, `WhatIfRequest`, `_graph_and_edgemap_from_request`, `_best_success`),
`frontend/src/components/attack/WhatIfPanel.tsx` + `dashboard.attack-paths.tsx` wiring +
`frontend/src/api/client.ts` (`attackPathApi.whatif`), `tests/api/test_whatif_api.py` (3 tests).
Next in Phase 6: per-path uncertainty bands; SIEM/EDR/ticketing hooks.
