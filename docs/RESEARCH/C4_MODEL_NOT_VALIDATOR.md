# C4 — "Model, not validator": scoping + a safe evidence grader

**Phase 5 (modeling scope), deliverable C4.** Roadmap: `05_OSS_REALTIME_PLAN.md` §Phase-5.
**Status: DONE (2026-06-15).** Sources: this scoping statement + `evaluation/path_validator.py`.

The C4 critique item asked for either **BAS-lite validation** or an **explicit honest
"model-not-validator" scoping statement**. We do both: the honest scoping statement below, plus a
**safe, non-firing evidence grader** that operationalizes it.

## The scoping statement (honest boundary)

**CTPPO is a prioritization / attack-path *planning* model. It is not a Breach-and-Attack
Simulation (BAS) *validator*.** It computes the exact multi-objective Pareto set of attacker paths
over a data-grounded attack graph and tells you *which fix breaks the most valuable paths*. It does
**not** fire exploits across a live estate to *prove* each path is exploitable.

| | CTPPO (model / planner) | Commercial BAS (validator): Cymulate, Pentera, SafeBreach, Horizon3 |
|---|---|---|
| Core action | exact Pareto search over a cost-graph | actually executes safe attack payloads against live hosts |
| Output | prioritized, choke-point-aware remediation + the full Pareto front | pass/fail evidence that a specific technique worked here, now |
| Grounding | EPSS/KEV/CVSS per CVE (data) + heuristic priors for lateral/credential/cloud/misconfig | empirical execution result |
| Strength | reasons over the *whole* graph and *multiple objectives* at once; cheap, offline, reproducible | ground-truth proof for the paths it actually fires |
| Blind spot | a path's exploitability is *modeled*, not *proven* (except the 3c sandbox) | only sees the paths it was scripted to fire; no global Pareto reasoning |

**What IS empirically validated in CTPPO:** the **3c live container/VM testbed** — 2 vulnerable
Apache hosts, 2 CVEs *actually exploited* with a safe path-traversal PoC, and NAMOA\*'s predicted
Pareto path matched the ground-truth exploitable path (recall 1.00 / soundness 1.00). That is a
spot validation, not estate-wide BAS.

**What is NOT validated (out of scope, by design):** automated multi-host exploit *chaining*,
safe-payload execution across an arbitrary estate, or post-exploitation. Building that is what a
full BAS product does; for an **OSS, local-first** tool it is out of scope on both safety and
effort grounds (firing exploits broadly is dangerous and a different product). The honest framing
already lives in `METRICS.md` §1 (scope caveat) and `01_NOVELTY.md` (the claim is the *integration*
— exact multi-objective Pareto + provenance + honest ablation + open repro — not "we validate
exploits"). C4 makes that boundary explicit and adds a tool that respects it.

## The safe evidence grader (BAS-lite, non-firing)

`evaluation/path_validator.py` is the safe counterpart to a BAS validator. Instead of *executing*
attacks, it **grades the evidence behind each edge** of a recommended path and reports, per path,
how much of it is data-grounded vs heuristic. It executes nothing.

Each attacker-decision edge is classified into an evidence tier (strongest first):

| Tier | Meaning | Data-grounded? |
|---|---|---|
| `live_exploited` | actually exploited in the 3c sandbox testbed | ✅ |
| `kev` | CISA Known-Exploited-Vulnerabilities listed | ✅ |
| `high_epss` | EPSS ≥ 0.5 (likely exploited in the wild) | ✅ |
| `data_grounded` | real CVE with EPSS data present (below the high bar) | ✅ |
| `heuristic` | credential / cloud-IAM / misconfig / lateral **prior** (C1/C2/C3, B3) | ❌ |

Entry / discovery / "reach" connector edges carry no attacker-decision evidence and are excluded.
A path then gets a **grounded fraction** and a label: `data-grounded` (100%), `mixed`, or
`heuristic-only` (0%).

## Measured (2026-06-15)

Running the grader on the recovered Pareto paths of three scenarios:

| Scenario | Recovered path(s) | Grounded fraction | Label |
|---|---|---:|---|
| **C1** AD kill chain | 2 paths (3–4 action edges) | **0%** | heuristic-only |
| **C3** misconfig breach | 2 paths (3–4 action edges) | **0%** | heuristic-only |
| **3c** live testbed (offline replay) | 1 path (2 action edges: entry CVE + lateral pivot) | **50%** | mixed |

These are exactly the honest expectations:
- **C1 / C3 are heuristic-only (0% grounded)** — every credential / misconfiguration cost is a
  flagged prior, *no* edge is EPSS/KEV-grounded. The grader makes that visible at a glance: these
  recommendations are *modeling* output, to be confirmed, not *validated* attack proof.
- **The 3c live testbed path is `mixed` (50%), not 100%** — and that is the most instructive
  result. The entry CVE (CVE-2021-41773) is `live_exploited` (top tier), but the web→app **lateral
  pivot rests on the heuristic segmentation prior** (the 3c doc already flagged that pivot as
  "by-construction"). So even on the one scenario where we *did* fire a real exploit, the grader
  honestly shows the recommended path is half live-verified, half modeled. That is precisely the
  transparency C4 is about.

The B1–B8 lesson reinforces the boundary: heuristic priors move reachability *magnitude*; the
prioritization *decision* is driven by graph structure. The grader lets an operator see, per
recommendation, how much rests on data vs priors — without ever firing an exploit.

## Files

`evaluation/path_validator.py` (`classify_edge_evidence`, `validate_path`, `PathValidation`),
`tests/evaluation/test_path_validator.py` (9 tests). This scoping statement.
Next in Phase 5: E1/E2/E3 ML-role honesty.
