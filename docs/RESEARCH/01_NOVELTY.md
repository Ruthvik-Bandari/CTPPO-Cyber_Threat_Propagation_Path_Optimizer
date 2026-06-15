# Novelty Memo — CTPPO Research Direction

**Status:** Draft for review · **Date:** 2026-06-13

This memo defines the precise research contribution we are claiming, the prior work it
sits against, and the honest risks. It exists so we do not build a GNN before we know
the paper is viable.

---

## 1. Thesis (the one sentence we are trying to prove)

> Attack-path prioritization is more useful to defenders when (a) edge costs are grounded
> in real exploit-likelihood data (EPSS / CISA KEV / CVSS sub-metrics) rather than CVSS
> severity alone, and (b) paths are surfaced as a **multi-objective Pareto front**
> (attacker time vs. success probability vs. business impact) computed with NAMOA*,
> rather than as a single risk-ranked list.

Everything we build serves proving or disproving that sentence against baselines.

## 2. What already exists (related work)

| Work | What it does | Objective | Cost grounding | Optimal search |
|------|--------------|-----------|----------------|----------------|
| MulVAL (Ou et al., 2005) | Generates logical attack graphs from configs | n/a | rules | no |
| NAMOA* (Mandow & Pérez de la Cruz, 2005) | Exact multi-objective shortest paths (general) | multi | n/a | **yes** |
| SPGNN-API (arXiv 2305.19487) | GNN identifies attack paths + autonomous mitigation | **single** | CVSS severity in-path | no (neural scoring) |
| Physics-Informed GNN (MDPI, 2025) | GNN predicts attack paths; ships ~1k labeled env. graphs | single | CVSS-style | no |
| GRAIN (Comput. & Secur., 2024) | GNN+RL reconstructs multi-step attack scenarios | single | alert causality | no |
| RL-GNN fusion (Sci. Rep., 2025) | RL optimizes GNN risk prioritization (+15.7% AUROC) | single | CVSS impact | no |
| EPSS (Jacobs et al., FIRST) | ML probability a CVE is exploited in 30 days | n/a | **real exploit data** | n/a |
| **XM Cyber** (commercial APM / CTEM) | choke-point analysis: "fix the issue on the most attack paths"; identity/AD-centric | single (path count) | exploitability + identity | heuristic (not exact Pareto) |
| **BAS** (Horizon3 NodeZero, Pentera, Cymulate, SafeBreach) | autonomously *validate* exploitability by chaining real exploits/credentials | n/a (validation) | real (executes) | n/a |

**Reading of the field:**
- GNN-for-attack-path *identification* is solved and crowded (SPGNN-API, MDPI, GRAIN).
- Those works output a **single** risk/path score. None produce a Pareto front trading
  off attacker *time vs. probability vs. stealth/impact*.
- They ground costs in **CVSS severity**, not EPSS exploit-likelihood.
- None couple learned costs with a **classical exact multi-objective optimizer (NAMOA*)**.
- A large **commercial** category (XM Cyber APM/CTEM; Horizon3/Pentera/Cymulate/SafeBreach BAS)
  already prioritizes by attack paths — XM Cyber's pitch is literally "fix the vuln on the most
  paths" (choke-point analysis). So **choke-point prioritization is prior art, not our novelty**;
  and BAS tools *validate* exploitability by execution while CTPPO *estimates* probability — we
  are a **model, not a validator**.

## 3. The gap we claim (precise)

The intersection is open:

1. **Multi-objective Pareto attack paths** (time / success-prob / impact) via NAMOA* on
   real network attack graphs — not single-objective scoring.
2. **EPSS/KEV-grounded edge costs** — exploit *likelihood from real-world data*, not CVSS
   severity as a stand-in for likelihood.
3. **GNN refines the data-grounded prior** using graph context, and we measure whether the
   GNN actually beats the rule-based prior (ablation), instead of asserting a GNN exists.

The defensible novelty is the **combination (1)+(2)+(3) with an honest ablation**, not any
single piece — and explicitly **not** choke-point prioritization itself (XM Cyber's commercial
APM already does "fix the vuln on the most paths"). What is unoccupied: an *exact multi-objective
Pareto front* (effort vs probability vs impact trade-offs, not a single path count) over
**EPSS/KEV-grounded** costs with an **openly-reproducible** honest learned-refiner ablation. If a reviewer asks "why not just EPSS-rank the CVEs?", the answer is the
Pareto front exposes trade-offs a scalar ranking hides (e.g., a slow-but-certain path vs. a
fast-but-noisy one) — and we must *show* that this matters empirically.

## 4. Honest risks (ranked)

1. **Time-to-exploit has weak empirical grounding.** No public dataset gives exploit time
   in hours. Mitigation: treat it as a *relative/ordinal* cost derived from CVSS
   exploitability + KEV tooling availability, and say so plainly. Do not report fake hours.
2. **Novelty is narrow.** If the Pareto framing doesn't change decisions vs. EPSS-ranking
   in evaluation, the contribution collapses to "we used EPSS." The eval must test exactly
   this.
3. **GNN may not beat the rule-based prior.** That's fine and still publishable as a
   negative/ablation result — but only if we frame it as a measured comparison from the
   start, never as an assumed win.
4. **Eval data realism.** Public labeled attack-path datasets are largely synthetic. We
   triangulate: (a) published datasets, (b) our own emulated multi-host testbed, (c)
   baselines on both. Generalization claims must be scoped to what the data supports.

## 5. Go / No-Go

**Go**, with the contribution scoped to "EPSS-grounded multi-objective Pareto attack-path
prioritization, with a GNN-vs-rule-based ablation." Realistic venue: MS thesis chapter,
arXiv preprint, or a security/ML workshop (AISec, MLSec). Not top-tier unless the
evaluation is exceptional.

**Kill criteria** (revisit if any hold): a search turns up an existing EPSS-grounded
multi-objective Pareto attack-path paper; or the evaluation shows the Pareto front never
changes a remediation decision vs. EPSS-ranking.

## 6. Sources

- NAMOA*: Mandow & Pérez de la Cruz, "A New Approach to Multiobjective A* Search" (IJCAI 2005).
- SPGNN-API: <https://arxiv.org/abs/2305.19487>
- Physics-Informed GNN for Attack Path Prediction: <https://www.mdpi.com/2624-800X/5/2/15>
- GRAIN (GNN+RL attack reconstruction): <https://www.sciencedirect.com/science/article/abs/pii/S0167404824004851>
- RL-GNN fusion: <https://www.nature.com/articles/s41598-025-25200-3>
- EPSS: <https://arxiv.org/abs/1908.04856> · <https://dl.acm.org/doi/10.1145/3436242> · <https://www.first.org/epss/>
- CISA KEV catalog: <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>
- XM Cyber (attack-path management / choke-points): <https://www.xmcyber.com/>
- Horizon3 NodeZero (autonomous pentest / BAS): <https://www.horizon3.ai/>
- Breach-and-attack-simulation category: Cymulate · Pentera · SafeBreach.
