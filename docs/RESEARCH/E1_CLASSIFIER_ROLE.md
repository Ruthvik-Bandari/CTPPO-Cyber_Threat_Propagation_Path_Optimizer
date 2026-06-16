# E1 — The CVE severity classifier's role: KEEP, narrowly justified

**Phase 5 (modeling scope), deliverable E1.** Roadmap: `05_OSS_REALTIME_PLAN.md` §Phase-5.
**Status: DONE (2026-06-15).** Decision + honest scoping.

## The question

The critique flagged the CVE severity classifier as **decorative** — *not used by the engine /
Pareto path*. E1 asks us to **cut it or justify it**, honestly.

## The finding (confirmed by the import graph)

`ml/cve_classifier.py` (text-only DistilBERT, description → CVSS severity band, **0.729 held-out
macro-F1** vs 0.10 majority — see `A4_SEVERITY_CLASSIFIER.md`) is imported by **only**:

- `api/server_secure.py` — the `/api/classify` analyst endpoint, and
- `ml/train_severity.py` — its own trainer.

It is **not** imported by `core/`, `algorithms/`, `scanners/`, or `evaluation/`. So the critique is
correct: **the classifier is not in the NAMOA\* / Pareto critical path.** The engine ranks paths
and fixes from **EPSS** (exploit probability), **KEV** (exploited-in-the-wild), and the **CVSS
vector** (exploitability + impact sub-scores) — never from a predicted severity band. Cutting it
would not change a single Pareto path or recommended fix.

## The decision: KEEP, with a narrow honest justification (not "decorative")

We keep it, justified on two grounds, and we state plainly what it is **not**:

1. **A standalone analyst-triage tool** (`/api/classify`). Given a vulnerability *description* and
   nothing else, it returns a severity read with calibrated confidence. The honest value is the
   **measured 0.729 macro-F1** (not the retired "97.6%" — that was the circular CVSS-fed setup,
   see METRICS §2/§4). This is a legitimate, self-contained utility.

2. **A coarse impact *fallback* for no-CVSS CVEs.** Real ingestion produces CVEs with a description
   but **no CVSS**: 3b's **Qualys / OpenVAS / nmap** importers emit *no CVSS vector at all* (EPSS/KEV
   still key on the CVE id, but the impact sub-score has nothing to ground it), and 3a measured
   **~7.7% of freshly-modified NVD CVEs** (25 / 323 on 2026-06-15) had no CVSS vector yet. For those,
   a predicted severity band → a coarse impact estimate is **better than a blind default**. E1 adds
   the concrete hook: `severity_to_impact()` (CVSS v3.1 band midpoints: CRITICAL 9.5 / HIGH 7.5 /
   MEDIUM 5.0 / LOW 2.5).

   *Honest coverage note:* the local NVD cache snapshot right now happens to be **100% CVSS-covered**
   (it holds older, well-scored CVEs), so the gap can't be re-measured from it today — the real
   evidence of the gap is the 3a/3b measurements above, not this snapshot.

**What it is explicitly NOT:** it does **not** decide which path or fix wins — EPSS/KEV/CVSS-vector
and graph structure do that. Severity is a *coarse aggregate* (a band on the base score), so even as
a fallback it is a **weak impact proxy** and the caller must flag it heuristic
(`data_grounded=False`). To keep this honest and avoid coupling the engine to a 266 MB DistilBERT,
the fallback lives at the **enrichment layer** (`severity_to_impact` is a pure, torch-free mapping);
`core/cost_model.build_edge_cost` is **unchanged** and never imports the model. The fallback is
available to an ingestion caller that already has the model loaded, not wired into the hot path.

## Why not cut it

Cutting would remove a working, honestly-measured analyst tool and the only available impact signal
for the genuine no-CVSS case (3b scanners). The cost of keeping it is bounded: it is isolated behind
one endpoint + one pure mapping, with zero engine coupling. So **keep + justify** beats **cut**.

## Files

`ml/cve_classifier.py` (`severity_to_impact`, the justified fallback hook),
`tests/ml/test_classifier_fallback.py` (3 tests). Decision recorded here and in METRICS §2.
Next in Phase 5: E2 (GNN role) and E3 (leakage audit).
