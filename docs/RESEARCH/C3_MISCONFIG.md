# C3 — Misconfiguration (non-CVE weakness) modeling (+ CWE on edges)

**Phase 5 (modeling scope), deliverable C3.** Roadmap: `05_OSS_REALTIME_PLAN.md` §Phase-5.
**Status: DONE (2026-06-15).** Source: `core/misconfig_graph.py`.

## The gap

C1 added identity/credential movement; C2 added cloud IAM. C3 closes the **non-CVE weakness**
gap. A large share of real breaches never touch a CVE — they walk in through
**misconfigurations**: default/weak credentials, services exposed with no authentication,
world-readable shares / overly permissive ACLs, secrets left in config files or backups. These
are **CWE-class weaknesses, not CVEs**, so EPSS/KEV don't score them — yet they are frequently
the *easiest* edges in the whole graph.

## What this delivers

`core/misconfig_graph.py` builds the **same canonical** `AttackGraph` (so it plugs straight into
NAMOA\* and everything downstream), but the transitions are **misconfigurations** instead of CVE
exploits:

- `Misconfiguration(weakness_id, name, cwe_id, mitre_technique_id, tactic, success, time, detection)`
  — a weakness step; carries its **CWE id** and an ATT&CK technique id where one applies (e.g.
  default creds → T1078 Valid Accounts; exposed service → T1190).
- `MisconfigHost` / `MisconfigMove` / `MisconfigScenario` — a spec for a network + the attacker's
  weakness-driven moves; `build_misconfig_graph()` turns it into the canonical graph.
- Two new edge relations: `MISCONFIG_INITIAL_ACCESS`, `MISCONFIG_MOVE`. Every transition's **CWE
  id** (and ATT&CK id where applicable) rides on the `ExploitNode` metadata and the edge metadata,
  so a recovered path reads as a weakness chain.

## Measured — a CVE-free breach chain recovered (2026-06-15)

`create_misconfig_breach_scenario()` (4 hosts: DMZ web host → app server → backup server →
database goal) → 11 nodes / 11 edges → NAMOA\* returns **2 Pareto-optimal weakness chains** to the
database, **with no CVE anywhere in the graph**:

| # | Recovered weakness chain (CWE) | time | success | impact |
|---|---|---:|---:|---:|
| 1 | **CWE-798** default creds → **CWE-306** exposed no-auth → **CWE-306** DB no-auth | 9.4 | 0.390 | 9.5 |
| 2 | **CWE-798** default creds → **CWE-306** exposed no-auth → **CWE-732** world-readable share → **CWE-522** secrets-in-backup | 10.5 | **0.458** | 9.5 |

Both are valid breach paths to the crown jewel built **entirely from misconfigurations**. The
engine surfaces the same kind of operator tradeoff seen in C1/C2: route 1 is **fewer hops / faster
but lower-success** (hit a database left exposed with no authentication directly from the app
tier); route 2 is the **slower, higher-success** chain (pivot through a world-readable backup
share and recover a database password left in a backup). Neither dominates the other on (time,
success), so multi-objective Pareto keeps both.

## Honest caveat (important)

Like the C1/C2 priors, **misconfiguration exploit costs are heuristic** — there is no
per-misconfig exploit-probability feed, and they are flagged `heuristic=True` /
`data_grounded=False` in every edge's metadata. The honest nuance **specific to misconfigs**: the
success priors are deliberately **high** (default creds ≈ 0.90, exposed-no-auth ≈ 0.85,
secrets-in-backup ≈ 0.95) because the hard question for a misconfig is **presence, not
exploitability** — once the weakness exists, exploiting it is usually trivial and near-certain.
That presence is exactly what a scanner's config findings (or a tool like ScoutSuite/Prowler/Lynis)
report, so **the grounded part is the *structure*** (which weakness gates which hop); **the
contribution is the modeling capability + CWE provenance, not a data-grounded probability.** The
B1–B8 sensitivity lesson applies: such priors move reachability *magnitude*, while the
prioritization *decision* is driven by graph structure (here, the default-cred entry and the
exposed-service pivot that every route must cross).

Misconfigurations and CVE exploits share the **same canonical `AttackGraph`**, so in principle
they compose into one mixed graph (a CVE on one host, a default credential on the next); C3
delivers the misconfiguration modality and scenario, and that composition is the natural next
extension.

## Files

`core/misconfig_graph.py` (`Misconfiguration`, `MisconfigHost/Move/Scenario`,
`build_misconfig_graph`, `create_misconfig_breach_scenario`, `_misconfig_cost`),
`tests/core/test_misconfig_graph.py` (6 tests, offline).
Next in Phase 5: C4 BAS-lite/scoping; E1/E2/E3 ML-role honesty.
