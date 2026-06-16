# CTPPO — The Complete Guide (single self-contained document)

**CTPPO = Cyber Threat Propagation Path Optimizer.** An open-source, local-first engine that views a
network the way an attacker does — as a graph of ways to move from a foothold to your crown jewels —
and tells you **which single fix breaks the most valuable attack paths**, with the math shown and the
data sourced. Runs on your machine: no login, no cloud, Apache-2.0.

This one file answers, in order: **what it is · how it helps · its uses · how to use it · its
features · why this project · what it is not.** Every number is a real measurement from an experiment
in this repo (`docs/RESEARCH/`); nothing is projected, and the limits are stated next to the wins.

---

## Table of contents
1. [What CTPPO is](#1-what-ctppo-is)
2. [The problem it solves (how it helps)](#2-the-problem-it-solves-how-it-helps)
3. [How it works](#3-how-it-works)
4. [Measured results (inline, nothing else to open)](#4-measured-results)
5. [Features](#5-features)
6. [Who uses it and for what (use cases)](#6-who-uses-it-and-for-what)
7. [How to use it](#7-how-to-use-it)
8. [Why this project — what makes it different](#8-why-this-project)
9. [What it is NOT (honest limitations)](#9-what-it-is-not)
10. [One-line summary](#10-one-line-summary)

---

## 1. What CTPPO is

A **multi-objective attack-path optimizer**. Give it a network (hosts, their vulnerabilities or
weaknesses, and how an attacker can move between them) and it computes — *exactly* — the full set of
optimal attacker paths to your critical assets, trading off **time-to-exploit**, **success
probability**, and **business impact**. From that it recommends the **single remediation that removes
the most reachability** to what matters.

It is a **planning / prioritization model**, grounded in live threat data (EPSS, CISA-KEV, CVSS),
using an **exact, complete** search algorithm (NAMOA\*) — **no reinforcement learning, no black box.**

---

## 2. The problem it solves (how it helps)

Security teams are buried in vulnerabilities and patch by **severity** (CVSS score): "fix the 9.8s
first." But severity ignores **context**. A critical-rated vuln on an isolated box that leads nowhere
matters less than a medium-rated one that is the *only bridge* to your database. Severity-ranking
routinely points you at the wrong fix.

CTPPO answers the question a CVSS list cannot: **"Given how an attacker actually moves through *this*
network, which fix removes the most reachability to the assets that matter?"** It surfaces the
**choke point** — the step the most optimal attack paths must cross — instead of the biggest number.

**How that helps, concretely:**
- Fewer, better-targeted patches (fix the choke point, not 200 high-CVSS dead ends).
- Trade-offs made explicit (a fast-but-loud path vs a slow-but-reliable one are *both* shown).
- Every recommendation is **auditable**: you can see which data grounds it and how confident it is.

---

## 3. How it works

1. **Build a graph** of the network: entry point → host/asset → host/asset → goal (crown jewel),
   with the vulnerabilities/weaknesses that enable each move.
2. **Cost every step with real data.** Each edge carries three objectives:
   - **Time-to-exploit** — relative effort/time (from CVSS Attack-Vector & Complexity; KEV speeds it up).
   - **Success probability** — from **EPSS** (the modeled probability a CVE is exploited in the wild)
     and **CISA KEV** (is it *known*-exploited?).
   - **Business impact** — CVSS impact sub-scores × your asset criticality.
3. **Find the optimal paths exactly** with **NAMOA\*** (a complete multi-objective shortest-path
   search). Rather than one "best" path, it returns the whole **Pareto front**: every path that is
   best on *some* trade-off. The search is verified **equal to brute-force on 80/80 random graphs**,
   so a returned path is real and the front is not missing one.
4. **Recommend the fix** that lies on the most of those optimal paths — the **choke point** — and
   show, via the what-if simulator, exactly how much reachability patching it removes.

Beyond CVEs, the same engine models **identity/Active-Directory** movement (phish → pass-the-hash →
DCSync), **cloud IAM** privilege escalation (leaked key → instance-metadata theft → AssumeRole →
admin), and **misconfigurations** (default creds, exposed services, open shares) — each with **MITRE
ATT&CK technique IDs** or **CWE IDs** on the edges so a recovered path reads as a kill chain.

---

## 4. Measured results

*(All from named experiments in `docs/RESEARCH/`; canonical copy in `METRICS.md`.)*

**Core thesis — does path-aware Pareto beat CVSS ranking?** (300 seeded networks, real EPSS)

| Metric | CVSS-top fix | **Pareto fix** | Oracle (best possible) |
|---|---:|---:|---:|
| Oracle reachability-reduction recovered | 24.0% | **84.1%** | 100% |
| 95% CI | [19.5, 28.8]% | **[80.0, 87.9]%** | — |

- The CVSS fix differs from the path-aware fix in **92%** of networks; the two recovery CIs **do not
  overlap** → the gap is robust, not a fluke.
- **Not a "rigged distribution":** re-run on a neutral (un-stacked) generator *and* a **fully-real**
  one (real EPSS + KEV + **real NVD CVSS**), Pareto still recovers **~85–87%** vs **≤46%** for the
  CVSS / EPSS / risk (EPSS×CVSS) / MulVAL-style baselines.

**Live exploit validation** — a sandboxed 2-host container testbed (vulnerable Apache 2.4.49/2.4.50):
both CVEs were *actually exploited* (path-traversal leaking `/etc/passwd`), and NAMOA\*'s predicted
Pareto path **matched the real exploitable path — recall 1.00, soundness 1.00.**

**Cost-model honesty (sensitivity studies B1–B8):** every *heuristic* assumption stress-tested moves
the reachability *magnitude* (sometimes a lot) but **not the prioritization decision** (≥91% stable);
the data-grounded graph structure drives which fix wins.

**Time-to-exploit external grounding (B4):** validated against CISA **KEV add-dates** over 155 CVEs —
Spearman(proxy, disclosure→known-exploited window) = **+0.263, 95% CI [+0.11, +0.41]** (excludes 0) →
externally corroborated (modest; confounded by CISA cataloguing lag).

**ML components (honest):**
- Severity classifier (text→severity, DistilBERT): **0.729 macro-F1** (vs 0.10 majority) — an analyst
  tool, **not** part of the path engine.
- GNN exploitability refiner: **exploratory, off by default** — it matches EPSS and changed the Pareto
  decision in **0/60** networks; its only measured lift is a topology task (**+0.07 ROC-AUC**).

**Engineering:** exact/complete NAMOA\*; **232 tests pass** (full suite); knowledge graph ~3,742 nodes.

---

## 5. Features

| Feature | What it does | Honest status |
|---|---|---|
| **Exact multi-objective Pareto engine** | NAMOA\* over (time, success, impact); full trade-off front, not one score | ✅ exact/complete, verified vs brute-force |
| **Data-grounded costs** | EPSS + CISA-KEV + CVSS per CVE, auto-refreshed with provenance & staleness | ✅ live feeds (~340k EPSS / ~1.6k KEV) |
| **Scanner import** | Reads **nmap / Nessus / Qualys / OpenVAS** output → builds the graph automatically | ✅ all 4 formats, offline |
| **Live exploit validation** | Sandboxed container testbed exploits real CVEs; predicted path matched ground truth | ✅ recall/soundness 1.00 (2 hosts) |
| **Identity / AD modeling** | Credential movement with MITRE ATT&CK on every edge | ✅ recovers AD kill chains; costs flagged heuristic |
| **Cloud IAM modeling** | AWS/Azure/GCP privilege-escalation paths | ✅ recovers cloud privesc; costs flagged heuristic |
| **Misconfiguration modeling** | Non-CVE weaknesses as CWE-tagged edges | ✅ recovers CVE-free breach chains |
| **What-if remediation simulator** | "If I patch CVE X, what changes?" — exact before/after front + reachability removed | ✅ API + UI; instant for off-path patches |
| **Per-path uncertainty bands** | Reachability as a **range**, not false precision (honest about edge correlation) | ✅ on every path |
| **Evidence grader** | Per path, how much rests on **real data** vs **heuristic priors** | ✅ "model, not validator" transparency |
| **SIEM / ticketing export** | Findings as ECS / CEF / Jira-ServiceNow ticket + webhook | ✅ formats + dispatch (bring your own endpoint) |
| **CVE severity classifier** | Description → severity (for CVEs with no CVSS yet) | ✅ 0.729 F1; analyst tool, not in the path engine |
| **GNN exploitability refiner** | Optional topology-aware re-scoring | ⚠️ exploratory, off by default |

---

## 6. Who uses it and for what

- **Vulnerability / remediation teams** — stop patching by raw severity; get the *one* fix that
  collapses the most attack paths to the assets that matter, with the trade-offs shown.
- **Red / purple teams** — see the Pareto set of routes to a goal (incl. AD and cloud-IAM kill
  chains) with ATT&CK technique IDs, then validate the top ones.
- **Detection / SOC engineers** — export recommended paths to a SIEM (ECS/CEF) or open a remediation
  ticket; wire it into a pipeline.
- **Researchers / students** — a reproducible, honest testbed for multi-objective attack-path
  analysis: exact search, real threat data, documented sensitivity studies, no hand-wavy metrics.

---

## 7. How to use it

Local-first — no login. From the repo root:

```bash
# Run the API (engine + endpoints; interactive Swagger UI at /docs)
./scripts/run-api.sh                      # http://localhost:8000/docs

# Run the web UI (build a network → Pareto front + what-if + uncertainty bands)
./scripts/run-frontend.sh                 # http://localhost:5173

# Import a real scan and get attack paths
ctppo import-scan myscan.nessus           # or .xml from nmap / Qualys / OpenVAS

# Refresh threat feeds (EPSS / KEV / NVD)
./scripts/refresh-threat-feeds.sh

# Regression watch: re-prove the engine still wins (cron-friendly)
./scripts/continuous-eval.sh
```

**Key API endpoints** (try them in the Swagger UI):
- `POST /api/attack-paths/analyze` — a network → the Pareto front + per-path uncertainty bands.
- `POST /api/attack-paths/whatif` — simulate patching CVE(s); exact before/after + reachability removed.
- `POST /api/scan/import` — upload scanner XML → attack paths.
- `POST /api/integrations/export` — push findings to SIEM/ticketing (ECS/CEF/ticket + optional webhook).

In the **UI**: *Attack paths → "Build your own"* → add nodes/vulns → Analyze → you'll see the Pareto
chart, each path's reachability **range**, and the **What-if** panel to simulate patches.

---

## 8. Why this project

Commercial tools each do *part* of this — APM/CTEM tools (e.g. XM Cyber) find choke points; BAS tools
(Cymulate, Pentera, SafeBreach, Horizon3) *fire* exploits to validate. CTPPO's contribution is the
**honest integration of three things at once**:

1. **Exact multi-objective Pareto over a data-grounded graph.** Most academic attack-graph work
   optimizes a single objective or uses ungrounded probabilities; CTPPO keeps the real trade-off set
   and sources its costs from EPSS/KEV/CVSS.
2. **Radical honesty.** The headline carries its scope caveat and confidence intervals; a companion
   **evidence grader** states exactly how much of any recommendation is data-grounded vs a heuristic
   prior; an earlier prototype's inflated "97.6% / RL" framing was retired and reconciled.
3. **Open and reproducible.** Apache-2.0, runs locally, every claim traces to a named experiment and
   a test (232 tests, full suite green).

---

## 9. What it is NOT (honest limitations)

- **A model, not a validator.** It *plans and prioritizes*; it does **not** fire exploits across your
  estate (the only live exploitation is the sandboxed 2-host testbed). Pair it with a BAS tool if you
  need empirical proof at scale.
- **Some step costs are heuristic, and labeled so.** CVE steps are EPSS/KEV/CVSS-grounded; the
  *lateral-movement*, *credential*, *cloud-IAM*, and *misconfiguration* costs are documented priors
  flagged `heuristic=True` / `data_grounded=False`. They move the reachability *magnitude*, but the
  prioritization *decision* stays stable (≥91% across all sensitivity studies) because graph structure
  drives which fix wins. The evidence grader shows this per recommendation.
- **Topology can be inferred.** When a scanner gives hosts+vulns but no network map, reachability is an
  inferred heuristic (flagged, overridable) — not ground truth.
- **B4 external grounding is corroborated but not gold-standard.** KEV add-dates are a *cataloguing*
  proxy; true exploitation-timestamp grounding (Metasploit/ExploitDB module dates) is future work.

---

## 10. One-line summary

> *CTPPO is an exact, open-source, multi-objective attack-path engine that ranks remediations by how
> much real-world reachability they remove — honestly showing the math, the data sources, and the
> uncertainty — so you fix the choke point, not just the highest number.*

*This is the single, self-contained guide. For the raw canonical metrics see `METRICS.md`; for the
full build history see `05_OSS_REALTIME_PLAN.md`.*
