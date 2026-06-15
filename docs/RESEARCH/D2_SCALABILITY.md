# D2 — Runtime vs graph size + tractability ceiling

**Updated:** 2026-06-15 · Reproduce: `python3 evaluation/d2_scalability.py`.

## Question
How does exact NAMOA\* scale with graph size, and where is the practical ceiling?

## Result (1) — realistic scaling is gentle (near-linear)
Seeded data-grounded multi-host networks with **bounded out-degree** (a realistic sparse topology,
not a clique), real EPSS/KEV/CVSS edges, median of 3 reps:

| hosts | nodes | edges | median runtime | mean front | mean labels |
|--:|--:|--:|--:|--:|--:|
| 10 | 32 | 43 | 3.2 ms | 1.0 | 15 |
| 20 | 62 | 89 | 4.6 ms | 3.0 | 50 |
| 40 | 122 | 185 | 5.9 ms | 2.7 | 70 |
| 80 | 242 | 387 | 10.5 ms | 4.3 | 158 |
| 160 | 482 | 788 | 21.0 ms | 5.3 | 365 |
| 320 | 962 | 1581 | 26.8 ms | 4.0 | 392 |

Exact search handles a **~1000-node** network in **~27 ms**, scaling roughly linearly (labels ≈
linear in nodes). The reason is the D1 finding: on realistic topologies the **Pareto front stays
small** (1–5 paths), so the label-setting search does not blow up.

## Result (2) — worst-case ceiling is set by front size, not node count
The Pareto-hard family (D1's construction; a 2-wide layered DAG engineered for front explosion).
The front grows super-linearly (up to ~2^k, sub-exponential here only because the success-surprisal
floor caps the number of distinct levels), and runtime explodes:

| k | nodes | exact front | labels | runtime |
|--:|--:|--:|--:|--:|
| 5 | 12 | 32 | 95 | 34 ms |
| 7 | 16 | 103 | 350 | 297 ms |
| 8 | 18 | 168 | 621 | 808 ms |
| 9 | 20 | 245 | 1034 | 1.9 s |
| 10 | 22 | 322 | 1601 | 3.9 s |
| 11 | 24 | 399 | 2322 | 7.0 s |

**Published tractability ceiling:** exact NAMOA\* exceeds a 5 s budget at **k = 11 — a graph of just
24 nodes** but a ~400-path Pareto front. The ceiling is governed by the **Pareto-front size (depth
of competing tradeoffs), not the node/edge count**: a 962-node realistic network (27 ms) is far
more tractable than a 24-node adversarial one (7 s).

## Result (3) — ε-Pareto (D1) extends the ceiling
At the same worst-case depth k = 10 (exact = 3.9 s):

| ε | front | labels | runtime |
|--:|--:|--:|--:|
| 0.00 (exact) | 322 | 1601 | 3854 ms |
| 0.10 | 8 | 233 | 43 ms |
| 0.50 | 4 | 86 | 10 ms |

ε = 0.1 gives a **~90× speed-up** by collapsing the front, pushing the ceiling well past where
exact stops being practical (with the (1+ε)^d error characterisation from D1).

## Verdict
Exact NAMOA\* is **tractable for realistic CTPPO networks at least to ~1000 nodes in tens of
milliseconds** (near-linear; small fronts). The hard ceiling is **front-size driven**: adversarial
Pareto-front explosion makes even a ~24-node graph take seconds. The D1 ε-Pareto fallback is the
mitigation — it restores millisecond runtimes at the cost of a bounded, measured approximation. D3
(lateral-edge density) is the realistic mechanism that could push toward this worst case, and is
where the fallback earns its keep.
