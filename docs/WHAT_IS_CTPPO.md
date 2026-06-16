# What is CTPPO? — a plain-language guide

**CTPPO = Cyber Threat Propagation Path Optimizer.** An open-source, local-first engine that looks
at a network the way an attacker does — as a graph of ways to move from a foothold to your crown
jewels — and tells you **which single fix breaks the most valuable attack paths**, with the math
shown and the data sourced. It runs on your machine, no login, no cloud, Apache-2.0.

> Every number in this document is a measurement from a named experiment in `docs/RESEARCH/`
> (the canonical results live in `METRICS.md`). Nothing here is projected or rounded up, and the
> honest limitations are stated alongside the wins.

---

## 1. The problem it solves

Security teams drown in vulnerabilities and patch by **severity** (CVSS score) — "fix the 9.8s
first." But severity ignores **context**: a critical-rated vuln on an isolated box that leads
nowhere matters less than a medium-rated one that is the *only bridge* to your database. Ranking by
severity routinely tells you to fix the wrong thing.

CTPPO answers the question a CVSS list can't: **"Given how an attacker actually moves through *this*
network, which fix removes the most reachability to what matters?"**

**Measured:** on 300 seeded networks, the fix CVSS ranking picks differs from the path-aware fix
**92% of the time**, and the path-aware fix recovers **84%** of the best-possible reduction in
crown-jewel reachability versus only **24%** for CVSS-top (95% CIs non-overlapping). On a
neutral/un-stacked distribution and on a **fully-real** distribution (real EPSS + KEV + CVSS) the
advantage holds (~85–87% vs ≤46% for CVSS/EPSS/risk baselines). *(Sources: `C_EVALUATION.md`,
`A2_A4_BASELINES.md`.)*

---

## 2. How it works (in one breath)

1. **Build a graph** of the network: hosts/assets, the vulnerabilities or weaknesses on them, and
   how an attacker can move between them (entry → host → host → goal).
2. **Cost every step with real data**: each step gets three numbers — **time-to-exploit**,
   **success probability** (from **EPSS** — the chance a CVE is exploited in the wild — and **CISA
   KEV** — is it *known* exploited), and **business impact** (from CVSS impact sub-scores × your
   asset criticality).
3. **Find the optimal attacker paths exactly** with **NAMOA\*** — a complete multi-objective
   shortest-path search. Instead of one "best" path it returns the whole **Pareto front**: every
   path that is best on *some* trade-off (fast-but-loud vs slow-but-reliable, etc.).
4. **Recommend the fix** that lies on the most of those optimal paths — the **choke point**.

No reinforcement learning, no black box. The search is **exact and complete** (verified equal to
brute-force on 80/80 random graphs), so a recovered path is real and the front is not missing one.

---

## 3. Key features (and the honest status of each)

| Feature | What it does | Status |
|---|---|---|
| **Exact multi-objective Pareto engine** | NAMOA\* over (time, success, impact); returns the full trade-off front, not a single score | ✅ exact/complete, verified vs brute-force |
| **Data-grounded costs** | EPSS + CISA-KEV + CVSS per CVE, auto-refreshed with provenance & staleness | ✅ live feeds (340k EPSS / 1.6k KEV) |
| **Scanner import** | Reads **nmap / Nessus / Qualys / OpenVAS** output → builds the graph automatically | ✅ all 4 formats, offline |
| **Live exploit validation** | A sandboxed container testbed actually exploits 2 CVEs; the predicted path matched the real one | ✅ recall 1.00 / soundness 1.00 (2 hosts) |
| **Identity / AD modeling** | Credential movement (phish → pass-the-hash → DCSync) with MITRE ATT&CK on every edge | ✅ recovers AD kill chains; costs flagged heuristic |
| **Cloud IAM modeling** | AWS/Azure/GCP privilege-escalation paths (leaked key → IMDS → AssumeRole → admin) | ✅ recovers cloud privesc; costs flagged heuristic |
| **Misconfiguration modeling** | Non-CVE weaknesses (default creds, exposed services, open shares) as CWE-tagged edges | ✅ recovers CVE-free breach chains |
| **What-if remediation simulator** | "If I patch CVE X, what happens?" — exact before/after front + reachability removed | ✅ API + UI; instant for off-path patches |
| **Uncertainty bands** | Reachability reported as a **range**, not a false-precise point (honest about edge correlation) | ✅ on every path |
| **Evidence grader** | Shows, per recommended path, how much rests on **real data** vs **heuristic priors** | ✅ "model, not validator" transparency |
| **SIEM / ticketing export** | Findings as ECS / CEF / Jira-ServiceNow ticket + webhook | ✅ formats + dispatch (bring your own endpoint) |
| **CVE severity classifier** | Description → severity (for CVEs with no CVSS yet) | ✅ 0.729 macro-F1; an *analyst tool*, not in the path engine |
| **GNN exploitability refiner** | Optional topology-aware re-scoring | ⚠️ **exploratory, off by default** — matches EPSS, changes 0/60 decisions; real lift only on a topology task (+0.07 AUC) |

---

## 4. Who uses it and for what

- **Vulnerability / remediation teams** — stop patching by raw severity; get the *one* fix that
  collapses the most attack paths to the assets that matter (with the trade-offs shown).
- **Red / purple teams** — see the Pareto set of routes to a goal (incl. AD and cloud-IAM kill
  chains) with ATT&CK technique IDs, then validate the top ones.
- **Detection / SOC engineers** — export the recommended paths to your SIEM (ECS/CEF) or open a
  remediation ticket; wire it into a pipeline.
- **Researchers / students** — a reproducible, honest testbed for multi-objective attack-path
  analysis: exact search, real threat data, documented sensitivity studies, no hand-wavy metrics.

---

## 5. How to use it

Local-first — no login. From the repo root:

```bash
# 1. Run the API (engine + endpoints, Swagger UI at /docs)
./scripts/run-api.sh                      # http://localhost:8000/docs

# 2. Run the web UI (build a network, see the Pareto front + what-if + uncertainty bands)
./scripts/run-frontend.sh                 # http://localhost:5173

# 3. Import a real scan and get attack paths
ctppo import-scan myscan.nessus           # or .xml from nmap/Qualys/OpenVAS

# 4. Refresh the threat feeds (EPSS / KEV / NVD)
./scripts/refresh-threat-feeds.sh

# 5. Keep checking the engine still wins (regression harness; cron-friendly)
./scripts/continuous-eval.sh
```

Programmatically, `POST /api/attack-paths/analyze` (a network → the Pareto front + uncertainty
bands), `POST /api/attack-paths/whatif` (simulate a patch), `POST /api/integrations/export` (push
to SIEM/ticketing). The Swagger UI lets you try them all.

---

## 6. Why this project — what makes it different

Commercial tools each do *part* of this: APM/CTEM tools (XM Cyber) find choke points; BAS tools
(Cymulate, Pentera, SafeBreach, Horizon3) *fire* exploits to validate. CTPPO's contribution is the
**honest integration**:

1. **Exact multi-objective Pareto** over a **data-grounded** graph — most academic attack-graph
   work optimizes a single objective or uses ungrounded probabilities; CTPPO keeps the real
   trade-off set and sources its costs from EPSS/KEV/CVSS.
2. **Radical honesty** — the headline result carries its scope caveat, confidence intervals, and a
   companion **evidence grader** that tells you exactly how much of any recommendation is
   data-grounded vs a heuristic prior. The earlier prototype's inflated "97.6% / RL" framing was
   retired and reconciled in `METRICS.md`.
3. **Open and reproducible** — Apache-2.0, runs locally, every claim traces to a named experiment
   and a test (232 tests, full suite green).

### What it is **not** (read this)

- **A model, not a validator.** It *plans and prioritizes*; it does not fire exploits across your
  estate (the only live exploitation is the sandboxed 2-host testbed). Pair it with a BAS tool if
  you need empirical proof at scale.
- **Some costs are heuristic, and labeled so.** CVE steps are EPSS/KEV/CVSS-grounded; the
  *lateral-movement*, *credential*, *cloud-IAM*, and *misconfiguration* step costs are documented
  priors flagged `heuristic=True` / `data_grounded=False`. They move the *magnitude* of reachability,
  but across every sensitivity study the **prioritization decision stays stable** (≥91%) because the
  data-grounded graph structure drives which fix wins.
- **Topology can be inferred.** When a scanner gives hosts+vulns but no map, reachability is an
  inferred heuristic (flagged, overridable) — not ground truth.

---

## 7. One-line summary

> *CTPPO is an exact, open-source multi-objective attack-path engine that ranks remediations by how
> much real-world reachability they remove — honestly showing the math, the data sources, and the
> uncertainty — so you fix the choke point, not just the highest number.*

*See `METRICS.md` for the canonical measured results and `05_OSS_REALTIME_PLAN.md` for the full
build history.*
