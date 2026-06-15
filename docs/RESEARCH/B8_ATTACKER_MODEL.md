# B8 — Attacker-model sensitivity

**Updated:** 2026-06-15 · Reproduce: `python3 evaluation/b8_attacker_model.py`.

## Question
CTPPO's Pareto front assumes a **rational 3-objective attacker** trading off time, success
probability, and (stealth) business impact. Real attackers may instead optimise a *single*
objective — fastest, most-likely-to-succeed, or stealthiest — or weight the three differently.
**Does the recommended remediation change under those attacker models?**

## Method
NAMOA\* returns the **complete** Pareto front (exact; recall = 1.00 in A3), so every
single-objective optimum and every positive-weight scalar optimum already lies on it. For each
attacker model (the 3 single-objective extremes plus 7 weighted scalarizations) we pick its
optimal path from the front — objectives min-max-normalised per front so 0 = best-for-attacker
(fastest / **highest** success / lowest impact) — then ask whether the **3-objective recommended
fix** (`pareto_top_fix`, the CVE on the most Pareto paths) still lies on that attacker's chosen
path, i.e. whether fixing it still breaks the attack.

- **Part 1 — Construct** (prove the attacker model is *live*): a network with two **disjoint**
  routes (no shared choke point) whose per-objective optima diverge.
- **Part 2 — Decision sweep**: 60 seeded data-grounded networks; how often attacker-optimal paths
  diverge and how often the 3-objective recommendation still covers each attacker's path.

## Result — Part 1: the attacker model is live (boundary case)
Two disjoint routes — A (fast / high-success / high-impact) and B (slow / low-success / low-impact)
— to a shared goal:

| Property | Value |
|---|---|
| Pareto front size | 2 |
| Distinct attacker-optimal paths | **2** (model is live) |
| 3-objective recommended fix | `CVE-2014-0160` (on route A) |
| Recommendation covers **every** attacker model | **False** |
| Models **missed** | `min_impact`, `stealth_biased` (they take route B) |

When the two attack routes share **no** CVE, the single recommended fix sits on route A and a
**stealth (min-impact) attacker on route B is missed.** So the attacker model genuinely can change
which fix is needed — a single recommendation is not always sufficient.

## Result — Part 2: on data-grounded networks the recommendation is robust
60 seeded multi-host networks:

| Metric | Result |
|---|---:|
| Nets where attacker-optimal paths diverge | 18.3% |
| Mean distinct attacker paths / net | 1.20 (mean front size 1.20) |
| **Overall recommendation coverage** (R on the attacker's optimal path) | **100.0%** |
| Per-model coverage (all 10 models) | 100.0% each |

Even though attacker-optimal paths diverge in ~18% of nets, the 3-objective recommended fix covers
**100%** of (net, attacker-model) pairs. The reason is structural: `pareto_top_fix` returns a
**choke point** — the CVE lying on the most Pareto paths — which on realistic networks is on a
shared entry/early segment that *every* attacker must traverse regardless of how they weight their
objectives. The remediation is therefore robust to the attacker-model assumption on these networks.

## Verdict
**B8 is nuanced like B7.** The attacker model is *live* — single-objective attackers do take
different routes, and on a **disjoint-route** topology the one recommended fix misses the stealth
attacker. But because the recommendation is a **choke point**, on data-grounded networks (which
share an entry segment) it covers **100%** of attacker models. So the 3-objective Pareto framing's
recommendation is robust to attacker-model misspecification *except* when attack routes are fully
disjoint — exactly the case where a single fix is provably insufficient and **per-objective or
multi-fix remediation** is required (the same "front genuinely branches" caveat as B7, and the
`goal coverage 0.90` per-goal-query caveat in METRICS §3).
