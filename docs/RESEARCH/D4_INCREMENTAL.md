# D4 — Incremental re-analysis (what-if patch)

**Updated:** 2026-06-15 · Reproduce: `python3 evaluation/d4_incremental.py`.

## Question
The operational query is "what if I patch CVE X?" — recompute the attack-path front after removing
X. Re-running the full search for every candidate is wasteful. Can we recompute incrementally?

## The exact skip rule
**Patching a CVE whose edge lies on no current Pareto-optimal path leaves the front unchanged.**
Removing an edge only removes paths (never lowers any other path's cost); if no Pareto path uses
the edge, every Pareto path survives with its cost intact and stays non-dominated. ⇒ **skip the
recompute for off-front CVEs.** (Detection is done at the host-pair level, so it is robust to
parallel edges: a CVE is skippable only if no Pareto path traverses its (source, target) pair.)

Since CTPPO fronts are small (D1–D3), many candidate patches are off-front and need no search.

## Result (60 Phase-C networks, every candidate CVE patched)
| Metric | Value |
|---|--:|
| Candidate patches (CVEs) | 443 |
| Off-front (skipped, no search) | ~38% |
| **Incremental == full recompute** | **100%** (overall and skipped-only) |
| Batch what-if speed-up | ~1.7× |

The incremental result matches a from-scratch full recompute **exactly**, confirming the skip rule,
while running ~1.7× faster across a batch of candidate patches (more skips ⇒ more speed-up; the
gain scales with how off-front the candidates are).

## Honest note — D4 surfaced (and we fixed) a NAMOA\* completeness bug
While verifying D4, the skipped-patch match rate came out at **98.4%, not 100%**. The skip rule is
exact, so the gap pointed at the engine. Root cause: **`AttackGraph` was not handling parallel
edges** — two CVEs on the same host pair were indexed as one in `adjacency`, so `get_outgoing_edges`
(and thus NAMOA\*) could not traverse the second edge, **silently dropping every path that used
it** and returning an *incomplete* Pareto front. Removing an "off-front" edge then sometimes
surfaced a path the incomplete base run had missed → the 1.6% mismatch.

Fixed in `core/attack_graph.py` (parallel-safe out/in edge-id lists for traversal; see
`tests/algorithms/test_namoa_completeness.py`). After the fix, NAMOA\* returns the **complete**
Pareto front (verified == brute-force on 80/80 random graphs), and D4's incremental result matches
full recompute **100%**. This restores the project's "exact / complete multi-objective Pareto"
claim — and is the more important outcome of D4 than the speed-up. The Phase-C headline numbers
shifted by < 1 pp under the fix (now computed on complete fronts); see METRICS §1.

## Verdict
Incremental what-if is **exactly equivalent** to full recompute (off-front patches are provably
no-ops), giving a ~1.7× batch speed-up that grows with the off-front fraction — and it feeds the
Phase-6 what-if remediation simulator. Its verification also caught and fixed a real
front-completeness bug in the engine.
