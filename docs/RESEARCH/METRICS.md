# CTPPO — Metrics of Record (canonical)

**Updated:** 2026-06-15. Single source of truth for CTPPO's measured results. If any other
file (README, résumé, slides, an old summary) disagrees, **this file and `OVERVIEW.md` win.**
Every number is a measurement from a named harness — nothing projected or rounded up.

## 1. Core thesis — does multi-objective Pareto beat CVSS ranking?
Source: `evaluation/phase_c_eval.py` → `docs/RESEARCH/C_EVALUATION.md`.

> **Scope caveat (read first).** A *mechanism* result on **300 synthetic networks deliberately
> seeded** with high-CVSS off-path dead ends — the exact case CVSS ranking gets wrong.
> **Update (2026-06-15):** the two checks this caveat said were "required before generalizing" are
> now done. **A2 neutral base-rate (§8):** re-running the comparison on an *un-stacked* generator
> (no off-path CVSS bias, real EPSS/KEV) leaves the Pareto advantage essentially unchanged
> (~85% vs ~33–37% for CVSS/EPSS/risk/MulVAL-style on *both* distributions) — the advantage is
> path/choke-point awareness, **not** a stacking artifact. **A1 live testbed (§7, 3c):** on real
> running services the predicted Pareto path == the live-exploitable path (recall/soundness 1.00).
> Still synthetic-topology + synthetic-per-edge-CVSS here; real-topology generalization remains the
> testbed's and future external datasets' job. See §8 for the honest caveats.

| Metric (300 seeded synthetic nets) | CVSS fix | Pareto fix | Oracle |
|---|---:|---:|---:|
| Oracle reachability-reduction recovered | 24.0% | **84.1%** | 100% |
| — 95% CI (A5, n=293) | [19.5, 28.8]% | **[80.0, 87.9]%** | — |
| Mean reachability reduction | 0.021 | 0.083 | 0.094 |

- Top-fix divergence (CVSS-top ≠ Pareto-top): **92.0%** (95% CI [88.4, 94.6], n=300).
- Pareto fix ≥ CVSS fix: **94.0%** [90.7, 96.2] of nets; strictly better: **73.0%** [67.7, 77.7].
- **Statistical rigor (A5):** the CVSS and Pareto recovery CIs **do not overlap**, so the gap is
  robust, not a point-estimate artifact. Networks: nodes 5.5 mean [4–7], edges 7.8 [3–12]; seeds
  0..299. Bootstrap CIs for means, Wilson for proportions. See `A5_STATISTICAL_RIGOR.md`.
- **Completeness correction (2026-06-15):** these numbers were recomputed after fixing a NAMOA\*
  Pareto-front *completeness* bug (`AttackGraph` dropped parallel edges — two CVEs on one host
  link — from traversal, so some paths were unreachable; D2/D4 §6). The fix shifted every figure
  here by **< 1 pp** (e.g. Pareto recovery 84.6→84.1%, divergence 92.3→92.0%) — the thesis is
  unchanged, now computed on the **complete** front. NAMOA\* output is verified == brute-force on
  80/80 random graphs (`tests/algorithms/test_namoa_completeness.py`).

## 2. ML components (honest, current)
| Component | Measured result | Source |
|---|---|---|
| Severity classifier (DistilBERT, text-only) | **0.729 held-out macro-F1** vs 0.102 majority baseline | `A4_SEVERITY_CLASSIFIER.md` |
| GNN exploitability refiner — real PIGNN AD dataset | **0.956 ROC-AUC** for attack-path structure (vs 0.883 without message passing) | `A3_PIGNN_VALIDATION.md` |
| GNN — own synthetic graphs | only **matches** EPSS ranking on per-node AUC (improves calibration) — honest mixed result | `A3_GNN_ABLATION.md` |

The severity classifier is text-only on purpose: feeding the CVSS score/vector would be circular
(the label is a threshold on that score → a fake ~100% F1).

## 3. Soundness AND recall (A3 — measured 2026-06-15)
On the emulated ground-truth testbed (`evaluation/emulated_testbed.py`, 5 topologies; each path's
cost vector recomputed **independently** of the engine):

| Property | Result | Notes |
|---|---|---|
| Soundness (precision) — every returned path is real & exploitable | **1.00** | exact optimizer returns no phantom paths |
| **Pareto recall** — front contains the truly non-dominated paths | **1.00** | empirical completeness of the front |
| **Attacker recall** — front contains each per-objective optimum (max success / min effort / min impact) | **1.00** | the route an attacker optimizing any single objective would take is present |
| Goal coverage — front reaches every reachable crown jewel | **0.90** | honest gap: the single *global* Pareto front omits a globally-dominated crown jewel's path (`two_crown_jewels`); mitigation = per-goal queries |

Still NOT measured: neutral base-rate on an un-stacked distribution (Phase 4 / A2); generalization
on real exploitable infra — container/VM (Phase 3 / A1). Recall on the real PIGNN dataset is
partial (node-on-path F1 0.45 — see `C2_PATH_RECOVERY.md`).

**Completeness now verified beyond the hand-built testbed (2026-06-15).** The recall=1.00 above was
measured on 5 emulated topologies (no parallel edges). A Phase-2/D4 audit then found NAMOA\*
returning *incomplete* fronts on graphs with **parallel edges** (two CVEs on one host link), which
`AttackGraph` had silently collapsed in its traversal index. After the fix (parallel-safe edge
lists, `core/attack_graph.py`), NAMOA\*'s front is verified **== the brute-force true Pareto front
on 80/80 random graphs** (`tests/algorithms/test_namoa_completeness.py`) — restoring the "exact /
complete" claim on the harder, parallel-edge case too.

## 4. Reconciliation — "97.6% on 276K CVEs" and "RL" (H1/H2)
Older artifacts (an early `ml/README.md` table, legacy summaries, possibly a résumé line)
referenced **"GNN 97.6% accuracy on 276K clean CVEs"**, **"RL (5000 episodes)"**, and a
**reinforcement-learning defender**. Those describe an **earlier prototype** (`ml/ctppo_ml.py`'s
`CTPPOPipeline` + a DuelingDQN defender + an nltk-based `data_preprocessor`) that has since been
**removed from the repo** — it was never used by the engine or API. The shipping system is:

- **Exact multi-objective search (NAMOA\*) — no RL.** (`algorithms/namoa_star.py`)
- **Text-only DistilBERT severity classifier — 0.729 macro-F1, not 97.6%** (the 97.6% came from
  the circular setup above). (`ml/cve_classifier.py`)
- **An optional GNN exploitability refiner** with the honest mixed result in §2.

One-liner for interviews: *"CTPPO is exact NAMOA\* multi-objective search over a data-grounded
attack graph — no RL. The earlier RL / ~97.6% figures were a separate prototype I retired; the
honest current numbers are 0.729 macro-F1 and the Pareto-vs-CVSS mechanism result above."*

The third-party **"RL-GNN fusion"** / **"GRAIN"** entries in `01_NOVELTY.md` and `PAPER_DRAFT.md`
are **related-work citations of other people's papers**, not CTPPO components — they stay.

## 5. Cost-model sensitivity (Phase 1, in progress)
| Assumption tested | Finding | Source |
|---|---|---|
| **B3** — lateral-movement prior (heuristic, ungrounded topology) | Pareto-critical top fix is **invariant in 91.7%** of 60 seeded multi-host networks across a flat→strong-segmentation prior grid; the prior flips the fix in **≤8.3%**. Data-grounded vuln edges dominate the ranking; the heuristic's influence is **bounded but non-zero**. | `B3_LATERAL_SENSITIVITY.md` |
| **B2** — path-prob edge independence (∏ pᵢ) | Magnitude is **very** sensitive: independence under-estimates correlated multi-hop success by **4×–1440× (grows with hops)** → reachability magnitude isn't a trustworthy point estimate. But the **path ranking is unchanged (100%)** on these EPSS-grounded nets (a path's lowest-prob edge dominates both ∏ and min → concordant), so **ranking-based remediation is robust even though the magnitude is not**. (ρ=1 = upper bound.) | `B2_EDGE_INDEPENDENCE.md` |

| **B1** — EPSS marginal vs conditional | Conditioning raises reachability magnitude **1.7×–3.5×** but leaves the **ranking 100% unchanged**: uniform conditioning is provably order-invariant ((∏p)^γ), and KEV-weighted conditioning raises already-high KEV edges, not the low non-KEV bottleneck that decides the winner. Marginal-vs-conditional is a magnitude issue, not a prioritization one (on these nets). | `B1_EPSS_CONDITIONAL.md` |

| **B4** — time-to-exploit proxy | **Construct validity PASSES** (time monotone in CVSS Attack-Vector N<A<L<P & Complexity L<H; KEV 2.0× speed-up). **External validity INCONCLUSIVE** — the only available real sample (97 NVD-cache CVEs) is narrow/low-EPSS with zero KEV (`Spearman=+0.02`). Construct-valid but **not externally grounded**; needs Metasploit/ExploitDB + KEV-dates (Phase 3). *(The one Phase-1 item that isn't clean.)* | `B4_B5_TIME_CRITICALITY.md` |
| **B5** — asset criticality (user-supplied, scales impact) | Pareto-critical top fix is **≥93% unchanged** even when criticality is uniform / shuffled / **inverted** (60 multi-host nets). Mis-set criticality distorts impact *magnitude* but rarely the prioritization decision. | `B4_B5_TIME_CRITICALITY.md` |
| **B6** — success-probability heuristic multipliers (AC exec factors, KEV exist-floor, EPSS-missing prior) | Each knob is **live** (per-edge `P(success)` swings up to **0.56** AC, **0.88** KEV-floor-when-it-binds, **0.45** missing-prior), yet the Pareto-critical top fix is **invariant in 93.3%** of 60 mixed-pool nets across **9 multiplier settings** — even though best-path success **magnitude moves a lot** (median up to ~8.8×, max ~119× under combined extremes): magnitude not decision, the B1–B6 pattern. Honest data-coverage note (shared with B4): the **KEV floor is inert at its default 0.90** on real KEV CVEs (all have EPSS≈0.94 > floor) — `floor_off` is byte-identical to baseline; the floor's sharp effect is only seen in the synthetic KEV+missing-EPSS construct. | `B6_SUCCESS_MULTIPLIERS.md` |
| **B7** — cost-combination semantics (time=sum, success=∏, impact=max) | **Impact max-vs-sum:** the knob is *live* (a constructed short-high-crit vs long-low-crit net reshapes the front), yet the top fix is **invariant in 100%** of 60 data-grounded nets (fronts are usually a single dominant route; sum changes the front in only ~7%). **Success ∏-vs-noisy-OR:** the **exception** — noisy-OR rewards path length (`Spearman(success,len)=+0.91` vs ∏'s **−0.86**; an inversion: short `[0.8]` ∏=0.80 vs long `[0.5×4]` ∏=0.06 but noisy-OR 0.94), i.e. the `da8656e` longer-path pathology. The success-combination is **load-bearing**, so ∏ is correctly a fixed semantic, not a tunable knob. | `B7_COMBINATION_SEMANTICS.md` |
| **B8** — attacker model (3-objective Pareto vs single-objective / weighted) | The attacker model is *live* — on a **disjoint-route** construct the single-objective attackers split and the one recommended fix **misses the stealth (min-impact) attacker**. But over 60 data-grounded nets, although attacker-optimal paths diverge in **18.3%**, the 3-objective recommended fix covers **100%** of (net, attacker-model) pairs across **10 attacker models** — because `pareto_top_fix` returns a **choke point** (CVE on the most paths) that every attacker must cross. Robust to the attacker model **except** when routes are fully disjoint (→ per-objective / multi-fix remediation needed, the B7 / `goal-coverage 0.90` caveat). | `B8_ATTACKER_MODEL.md` |

**Phase-1 cost-model pattern (B1–B8):** every *heuristic* modeling assumption stress-tested moves the
reachability *magnitude* (often a lot) but **not the prioritization decision** (≥91% stable) — the
data-grounded structure drives which fix is recommended. Report multi-hop reachability as a **range**,
not a point estimate. **One structural exception (B7):** the success-combination semantics (∏ vs
noisy-OR) IS decision-relevant — noisy-OR rewards path length — so the engine correctly fixes it to ∏
rather than exposing it. **B8 boundary:** the recommended fix is attacker-model-robust because it is a
choke point, *except* on fully-disjoint attack routes (single fix insufficient). Open grounding items:
**B4** (time proxy: construct-valid, not externally grounded) and B6's related KEV-floor coverage gap.

**A5 — statistical rigor (closes Phase 1):** every headline above (Phase-C 92.0% / 24.0% / 84.1%
and the B3/B5/B6/B7/B8 invariance + B4 Spearman) now carries n, seeds, graph node/edge counts and a
95% CI (bootstrap for means, Wilson for proportions). Invariance/coverage lower bounds are all
≥ 81.9% (n=60+); B4's Spearman CI **[−0.2, +0.2]** straddles zero (externally inconclusive, the lone
open grounding item). Full table in `A5_STATISTICAL_RIGOR.md`. **Phase 1 (core-math soundness) is complete.**

## 6. Scalability (Phase 2, in progress)
| Item | Finding | Source |
|---|---|---|
| **D1** — ε-Pareto bounded-approximation fallback (exact stays default, ε=0) | On a constructed Pareto-hard instance (16 nodes, 103-path exact front) ε-mode shrinks the front **103→2**, labels expanded **350→35**, runtime **298→4 ms**. **Honest bound correction:** per-label ε-dominance **compounds over path depth d**, so the naive (1+ε) bound is **violated** (ε=0.05→factor 1.348); the correct end-to-end bound is **(1+ε)^d** (holds for tested ε≥0.05; observed factor ≤1.95 even at ε=1.0). A depth-scaling recipe ε_step=(1+target)^(1/d)−1 targets a true end-to-end factor (met for moderate targets; very tight targets sensitive to near-zero success-surprisal). On realistic CTPPO nets the exact front is already small (~1.2 paths) so ε mainly bounds the worst case + trims labels. | `D1_EPSILON_PARETO.md` |
| **D2** — runtime vs graph size + tractability ceiling | **Realistic** sparse multi-host nets scale **near-linearly**: ~1000 nodes (962n/1581e) in **~27 ms**, fronts stay 1–5. **Worst case** (Pareto-hard family) is **front-size driven, not node count**: exact exceeds a 5 s budget at **k=11 — only 24 nodes** but a ~400-path front. **ε extends the ceiling**: at k=10 (exact 3.9 s) ε=0.1 → 43 ms (~90× faster). Published ceiling: exact is fine for realistic topologies to ≥1000 nodes; adversarial front explosion needs the D1 ε fallback. | `D2_SCALABILITY.md` |
| **D3** — lateral-edge density handling | On data-grounded nets, dense reachability is an **edge-count explosion O(H²), NOT a search explosion**: at full mesh edges grow **67→3322** (H=10→80) but the **Pareto front stays ≈1** (one route dominates) — a real front explosion needs D2's adversarial costs, not mere density. Handling = `max_lateral_per_host=K` budget (default off) bounding edges to **O(H·K)** (budgeted 52→472). **Honest decision cost:** unlike B3's reweighting, dropping edges removes paths → **K≥3 keeps the top fix in ~80%**, aggressive **K=2 changes it ~45%** (use a generous K). | `D3_LATERAL_DENSITY.md` |

| **D4** — incremental re-analysis (what-if patch) | Exact skip rule: patching a CVE on **no** Pareto path leaves the front unchanged → skip its recompute. Over 60 Phase-C nets (443 candidate patches), **~38% skip**, incremental **== full recompute 100%**, **~1.7× batch speed-up**. D4's verification **surfaced and fixed a NAMOA\* completeness bug** (parallel edges dropped from traversal → incomplete fronts; pre-fix skip-match was 98.4%). Post-fix: complete fronts (verified == brute-force 80/80) and exact incremental what-if. | `D4_INCREMENTAL.md` |

**Phase 2 (scalability) complete: D1–D4.** Net engine change: an opt-in ε-Pareto fallback (D1) and
a `max_lateral_per_host` budget (D3), both default-off; a published tractability ceiling (D2,
front-size-driven); exact incremental what-if (D4); and a **NAMOA\* completeness fix** (parallel
edges) that D4 surfaced — restoring "exact / complete" and shifting Phase-C headlines by < 1 pp.

## 7. Realtime ingestion (Phase 3, in progress)
| Source / item | Finding | Source |
|---|---|---|
| **3a** — threat-feed auto-refresh + provenance + staleness | A single refresh job for all three grounding sources, each cached feed now carries provenance (url, `fetched_at`, source-reported `source_as_of` + version, `record_count`, sha256, bytes) and a staleness view (age vs 24 h TTL → fresh/stale/unknown). **Live refresh 2026-06-15:** EPSS **340,247** scores (v2026.06.15, score_date 2026-06-15), CISA KEV **1,621** CVEs (catalogVersion 2026.06.15), NVD recent-changes window (last 1 day) **323** CVEs modified (`totalResults`=323, fetched 323/323, **298/323** with a CVSS vector). Staleness verified end-to-end: the prior Jun-14 cache read **36.2 h old → `stale`** (>24 h TTL) before auto-refresh, then `fresh`. NVD is honestly a *recent-changes slice* (incremental sync), **not** a full ~358 k mirror. `GET /api/threat-data/status` + `ctppo threat-data` + `scripts/refresh-threat-feeds.sh` expose it. | `3a_THREAT_FEEDS.md` |
| **3b** — scanner import (Nessus/Qualys/OpenVAS/nmap) | An adapter parses each scanner's output file → canonical `NetworkSpec`/`build_network` → `AttackGraph` → NAMOA\* (closes the **G1** repo-scan→graph gap). **Measured end-to-end on all 4 formats** (schema-accurate fixtures, real KEV CVEs, 3a-refreshed feeds): each yields a valid attacker→goal Pareto path (2 hosts / 8 nodes / 7 edges / 1 path each). **8/8 CVEs are EPSS+KEV-grounded across formats** — *including Qualys/OpenVAS/nmap which emit no CVSS vector*, because EPSS/KEV key on CVE id; the CVSS vector (present in Nessus 2/2) only grounds the time/impact sub-scores (else base-score fallback). **Honest caveat:** scanner output gives data-grounded *host vulnerabilities* but **no topology** — reachability/zones/entry/goal are INFERRED heuristics (subnet grouping, well-known ports, highest-CVSS goal), flagged `topology_inferred` and overridable, the same bounded-heuristic situation as B3. `ctppo import-scan` + `POST /api/scan/import`. | `3b_SCANNER_IMPORT.md` |
| **3c** — LIVE container/VM testbed (centerpiece, A1) | The full loop on **real running services**: docker-compose vulnerable Apache (httpd 2.4.49 / 2.4.50, both KEV) on a segmented network → **live `nmap -sV`** → version→CVE → graph → NAMOA\* → compare predicted vs ground-truth path. **Live run 2026-06-15:** nmap fingerprinted both versions → CVE-2021-41773 / CVE-2021-42013, **EPSS 0.99992 / 0.99964, both KEV**; **both CVEs verified LIVE-exploited** (path-traversal PoC leaking `/etc/passwd`, `root:x:0:0:…`); NAMOA\*'s predicted Pareto path = the ground-truth exploitable path Internet→web→app, **recall 1.00, soundness 1.00**. Ground truth anchored by construction (pinned versions ⇒ known CVEs + known segmentation) AND by live exploitation. Honest limits: 2 hosts/2 CVEs, version→CVE is an explicit table, lateral pivot is by-construction (entry exploit is live-verified). | `3c_LIVE_TESTBED.md` |

These are **ingestion + a live recovery/soundness validation**, not a base-rate claim — the engine
and the Phase-1/2 results above are unchanged. **Phase 3 (realtime ingestion) is complete: 3a
feeds · 3b scanner import · 3c live testbed.** Still open (deferred): B4 external grounding (Phase
3/Metasploit).

## 8. Continuous-improvement loop (Phase 4, in progress)
| Item | Finding | Source |
|---|---|---|
| **A2 + A4** — neutral base-rate & stronger baselines | Re-ran the Phase-C oracle-recovery comparison with **real-CVE-sampled** nets (real EPSS/KEV) and **4 baselines** (CVSS, EPSS, risk = EPSS×CVSS, MulVAL-style reachability-filtered) on a **stacked** and an **un-stacked (neutral)** generator. **Pareto recovers ~84.7% of oracle reduction on BOTH** (stacked [79.2,89.7], neutral [79.1,89.6]) vs **~33–37% for every baseline**; Pareto ≥ each baseline ~88–91%, strictly > ~67–71%. **The advantage is NOT a stacking artifact** — un-stacking the CVSS distribution barely moves it, because the edge is path/choke-point awareness (even the reachability-aware MulVAL-style baseline only gets ~34%: reachability-filtering then CVSS-ranking still misses the success-probability bottleneck). **Honest caveats:** the metric (reachability reduction) is aligned with what Pareto optimizes (oracle is method-independent, so 85% recovery is still meaningful); CVSS is synthetic-per-edge while EPSS/KEV are real; one synthetic topology family (real-topology = 3c testbed + future external data). | `A2_A4_BASELINES.md` |

This **updates the Phase-C "distribution built to win" framing**: the base-rate (A2) shows the
Pareto advantage survives un-stacking. Phase-C's 84.1%/24.0% remains the canonical synthetic-id
thesis number (no EPSS, 1 baseline); §8 is the EPSS-grounded, multi-baseline, base-rate-aware study.
Remaining Phase 4: the `continuous_eval.py` regression harness + a scheduled agent.
