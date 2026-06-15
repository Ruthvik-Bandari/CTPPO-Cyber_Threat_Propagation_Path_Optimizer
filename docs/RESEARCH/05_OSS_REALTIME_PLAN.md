# 05 — OSS + Realtime Plan (roadmap of record)

**Created:** 2026-06-15 · Supersedes the platform-build roadmap in `04_ROADMAP_HANDOFF.md`
for forward work. Origin: a detailed external critique of `OVERVIEW.md` (sections A–I).

## North star

A reproducible, **open-source**, **math-honest** attack-path engine that ingests **realtime
data** and **continuously re-proves its own value** — with a **live container/VM testbed** as the
centerpiece, not a footnote.

The critique in one line: *the engineering is real; the scientific claim is currently a mechanism
demo on a distribution built to win.* This plan converts mechanism → generalization, and
**removes** platform scaffolding rather than adding to it.

## Locked decisions

- **Realtime data = three sources:** live container/VM testbed (centerpiece) + auto-refreshing
  EPSS/KEV/NVD feeds + scanner import (nmap/Nessus/Qualys/OpenVAS).
- **The loop = both:** a continuous-eval harness in the repo (CI/cron) **and** a scheduled Claude
  agent that drives it, acts on regressions, and reports.
- **OSS = local-first:** strip auth, subscription, RBAC/orgs, API keys — runs with no login.
- **License:** Apache-2.0 (patent grant matters for a security tool).

---

## Phases (each has a verifiable exit criterion)

### Phase 0 — OSS conversion + honesty reconciliation
*Low-risk, high-trust, unblocks everything. This IS the critique's "freeze platform scaffolding" (G3) — we remove, not add.*
- Strip to local-first: remove subscription / orgs+RBAC / API-keys / session-gating; no-login single local user.
- Add LICENSE (Apache-2.0), CONTRIBUTING, reproducibility quick-start.
- Reconcile metrics (H1/H2/H3): one canonical metrics table; purge "97.6% / 276K CVEs" and any "RL" framing; move the adversarial-seeding caveat to the top of paper/abstract.
- Reposition novelty (F1–F4): related-work table gains commercial APM/BAS/CTEM row (XM Cyber, Cymulate, Pentera, SafeBreach, Horizon3); claim the *integration*, not NAMOA\* / MO-attack-graphs per se; foreground honest-ablation as a contribution.
- **Exit:** app runs with zero login; no subscription/RBAC deps in any route; tests green; one metrics doc of record.

### Phase 1 — Core math soundness
*The cost model's value is bounded by its least-grounded part — the topology.*
- B3 ground the lateral-movement prior (ATT&CK/credential signals) + sensitivity sweep.
- B2 edge-independence correlation-sensitivity test (+ shared-factor option).
- B1 EPSS conditional-vs-base-rate conditioning / sensitivity.
- B4 validate time-to-exploit vs Metasploit/ExploitDB + KEV add-dates; B5 asset-criticality sensitivity.
- A3 **recall/coverage** metric (does the front contain the attacker's real path?), not just soundness.
- A5 report node/edge counts, seeds, CIs, variance.
- **B6** success-probability heuristic multipliers (AC execution 0.90/0.50, KEV exist-floor 0.90, EPSS-missing prior 0.05) sensitivity.
- **B7** cost-combination semantics (impact = max vs sum; success ∏ vs noisy-OR; time = sum) sensitivity.
- **B8** attacker-model sensitivity (rational 3-objective Pareto vs single-objective / weighted preferences).
- **Status (2026-06-15):** A3 ✅ · B3 ✅ (top fix invariant 91.7%) · B2 ✅ (magnitude 4×–1440×, ranking robust) · B1 ✅ · B4/B5 ✅ (B4 externally inconclusive — open grounding item) · B6 ✅ (top fix invariant 93.3% across 9 multiplier settings; KEV floor inert at default on high-EPSS real KEV) · B7 ✅ (impact max-vs-sum: knob live but top fix 100% invariant; success ∏-vs-noisy-OR is the load-bearing exception — noisy-OR rewards path length, validating the da8656e fix) · B8 ✅ (attacker model live on disjoint routes — one fix misses the stealth attacker — but 100% recommendation coverage across 10 attacker models on data-grounded nets because the top fix is a choke point) · **A5 ✅ (CLOSES PHASE 1)** — every headline (Phase-C 92.3%/25.0%/84.6% + B3/B5/B6/B7/B8 invariance + B4 Spearman) now carries n, seeds, graph node/edge counts and a 95% CI (bootstrap for means, Wilson for proportions); CVSS vs Pareto recovery CIs **do not overlap**; B4's Spearman CI [−0.2,+0.2] straddles 0 (lone open grounding item). Pattern: *heuristic* modeling assumptions move reachability **magnitude**, not the prioritization **decision** (≥91% stable, lower bounds ≥82%); structural exceptions = success-combination (B7) and disjoint-route attacker models (B8). Full results in METRICS.md §1/§5 + A5_STATISTICAL_RIGOR.md. **PHASE 1 COMPLETE.** (Phase-C headline refined to 92.0%/24.0%/84.1% after the Phase-2 NAMOA\* completeness fix — see below; < 1 pp shift.)
- **Exit:** every modeling assumption has a documented sensitivity experiment; recall reported beside soundness.

### Phase 2 — Scalability & algorithm robustness (D)
- D1 ✅ ε-Pareto / bounded-approximation fallback (exact stays default, ε=0). On a 103-path Pareto-hard instance ε-mode cuts front 103→2, labels 350→35, runtime 298→4ms; honest bound = **(1+ε)^d** (per-label ε compounds over depth; naive (1+ε) violated), depth-scaling targets a true end-to-end factor; realistic CTPPO fronts already tiny (~1.2). `D1_EPSILON_PARETO.md`.
- D2 ✅ runtime-vs-graph-size benchmark + tractability ceiling. Realistic sparse nets near-linear (~1000 nodes in ~27ms, fronts 1–5); worst-case ceiling is FRONT-SIZE-driven not node-count (exact >5s at k=11 = 24 nodes / ~400-path front); ε=0.1 gives ~90× at k=10. `D2_SCALABILITY.md`.
- D3 ✅ lateral-edge density handling. Honest finding: dense reachability is an EDGE-COUNT explosion O(H²) (edges 67→3322 at H=10→80 full mesh) NOT a search explosion (front stays ≈1; real front explosion needs D2's adversarial costs). Handling = `max_lateral_per_host=K` budget (default off) → edges O(H·K); decision cost: K≥3 keeps top fix ~80%, K=2 changes ~45%. `D3_LATERAL_DENSITY.md`.
- D4 ✅ incremental re-analysis. Exact skip rule (patch a CVE on no Pareto path → front unchanged): ~38% of candidate patches skip, incremental == full recompute **100%**, ~1.7× batch speed-up. **D4 surfaced + we fixed a NAMOA\* completeness bug** — `AttackGraph` dropped parallel edges (two CVEs on one host link) from traversal, returning incomplete fronts; fixed with parallel-safe edge lists, verified NAMOA\* == brute-force on 80/80 random graphs. This RESTORES "exact / complete Pareto" and shifted Phase-C headlines < 1 pp. `D4_INCREMENTAL.md`, `tests/algorithms/test_namoa_completeness.py`.
- **Exit ✅:** published runtime curve (D2); ε-mode error bound (D1, (1+ε)^d); incremental recompute matches full exactly (D4). **PHASE 2 COMPLETE.**

### Phase 3 — Realtime ingestion (three sources)
- 3a ✅ live threat feeds: EPSS/KEV/NVD refresh job + provenance + staleness. One refresh job
  (`scripts/refresh-threat-feeds.sh` / `ctppo threat-data --refresh --nvd`); every cached feed
  carries provenance (url, fetched_at, source-reported as-of + version, record_count, sha256,
  bytes) and a staleness view (age vs 24 h TTL → fresh/stale/unknown), all in one
  `provenance.json` and exposed at `GET /api/threat-data/status`. NVD = recent-changes window
  (incremental sync), not a full mirror. **Live 2026-06-15:** EPSS 340,247 / KEV 1,621 / NVD
  323 modified in last day (298/323 with CVSS vector); the prior cache correctly read 36.2 h
  `stale` before auto-refresh. `3a_THREAT_FEEDS.md`, `tests/core/test_threat_feeds.py`.
- 3b ✅ scanner import: Nessus/Qualys/OpenVAS/nmap-XML → multi-host graph adapter (resolves G1).
  `scanners/scan_import.py` parses all four formats (namespace-tolerant, stdlib XML) → canonical
  `NetworkSpec`/`build_network` → NAMOA\*. **Measured 2026-06-15:** all 4 formats yield a valid
  attacker→goal Pareto path; 8/8 CVEs EPSS+KEV-grounded (even Qualys/OpenVAS/nmap, which carry no
  CVSS vector — EPSS/KEV key on CVE id). **Honest caveat:** topology (reachability/zones/entry/goal)
  is INFERRED & flagged (`topology_inferred`), not in the scan — same bounded heuristic as B3;
  overridable. `ctppo import-scan` + `POST /api/scan/import`. `3b_SCANNER_IMPORT.md`,
  `tests/scanners/` (24 tests, offline).
- 3c ✅ **live container/VM testbed (A1)**: docker-compose vulnerable Apache (httpd 2.4.49/2.4.50,
  both KEV) on a segmented network → **live nmap -sV** → version→CVE → graph → NAMOA\* → compare vs
  ground truth. **Live 2026-06-15:** fingerprints → CVE-2021-41773 / CVE-2021-42013 (EPSS 0.99992 /
  0.99964, both KEV); **both CVEs verified LIVE-exploited** (path-traversal PoC leaking /etc/passwd);
  NAMOA\*'s predicted Pareto path = the ground-truth exploitable path Internet→web→app, **recall 1.00 /
  soundness 1.00**. Ground truth anchored by construction AND live exploitation. `3c_LIVE_TESTBED.md`,
  `evaluation/live_testbed.py` (+ offline fixture mode), `tests/scanners/test_live_testbed.py`.
- **Exit ✅:** each source yields a valid end-to-end graph; testbed path is recovered (recall 1.00)
  and sound (1.00). **PHASE 3 (realtime ingestion) COMPLETE: 3a feeds · 3b scanner import · 3c live testbed.**

### Phase 4 — Continuous-improvement loop (both halves)
- ✅ Repo harness `evaluation/continuous_eval.py`: latest data (online auto-refresh) → rebuild →
  NAMOA\* + baselines → metrics → timeseries (`evaluation/history/…json`, provenance-stamped) →
  regression flags (absolute floors + drop-vs-previous; non-zero exit). **Verified 2026-06-15:**
  real run pareto_recovery 0.909 (feeds fresh), and `--inject-regression` is **caught** (flags
  *below floor 0.60*, exit 1). `scripts/continuous-eval.sh`, `PHASE4_CONTINUOUS_EVAL.md`.
  - ✅ A2 **un-stacked base-rate study** + ✅ A4 baselines (EPSS-only, risk = EPSS×CVSS, MulVAL-style
    reachability-filtered): on a neutral generator Pareto recovers ~85% of oracle reduction vs
    ~33–37% for every baseline — the advantage is **not** a stacking artifact (≈ identical to
    stacked). `A2_A4_BASELINES.md`, METRICS §8. (MulVAL = a MulVAL-*style* reachability baseline,
    not the XSB-Prolog tool; honest caveat documented.)
- ◻ Scheduled Claude agent (`/schedule`): opt-in setup documented (fires the harness, reads
  history/exit code, reports / can open an issue on regression). Cadence is a deployment choice.
- **Exit:** ✅ harness runs unattended with tracked history + catches an injected regression;
  ◻ agent fires and reports (opt-in via `/schedule`, harness ready).

### Phase 5 — Modeling scope (C/E)
- C1 identity/credential/AD (biggest gap), C3 misconfig, C2 cloud IAM, C4 BAS-lite or explicit "model-not-validator" scoping; ATT&CK technique IDs on edges.
- E1 decide classifier role (cut/justify — currently decorative), E2 GNN exploratory-or-lift, E3 leakage/circularity audit + documented splits.
- **Exit:** an AD/credential lateral path appears in a testbed scenario; ML roles documented honestly.

### Phase 6 — Realtime product UX + integrations (G/I)
- "What-if" remediation simulator (on D4); per-path uncertainty bands (propagate EPSS CIs); SIEM/EDR/ticketing hooks.
- *(G4 SOC2/compliance retired by the OSS decision.)*

---

## Critique coverage map

| Item | Phase | Item | Phase |
|---|---|---|---|
| A1 testbed | 3c | C1–C4 scope | 5 |
| A2 base-rate | 4 | D1–D4 scale | 2 |
| A3 recall | 1 | E1–E3 ML | 5 |
| A4 baselines | 4 | F1–F4 novelty | 0 |
| A5 rigor | 1 | G1 repo-scan | 3b |
| B1–B5 cost model | 1 | G2 integrations | 6 |
| H1–H3 honesty | 0 | G3 scaffolding | 0 (remove) |
| scanner import | 3b | G4 compliance | dropped (OSS) |
| identity/AD | 5 | what-if / uncertainty | 6 |

Only G4 is dropped — retired by the OSS decision.
