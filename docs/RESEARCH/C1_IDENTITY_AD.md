# C1 — Identity / credential / Active-Directory modeling (+ ATT&CK on edges)

**Phase 5 (modeling scope), deliverable C1 — the biggest scope gap.** Roadmap:
`05_OSS_REALTIME_PLAN.md` §Phase-5. **Status: DONE (2026-06-15).** Source:
`core/identity_graph.py`.

## The gap

CTPPO's CVE-centric model (`core/network_builder`) captures **vulnerability-driven** lateral
movement. But real intrusions mostly pivot through **identity** — phish a user, dump
credentials, pass-the-hash to the next host, escalate to Domain Admin via DCSync/Kerberoasting.
**None of that is a CVE.** C1 adds that modality.

## What this delivers

`core/identity_graph.py` builds the **same canonical** `AttackGraph` (so it plugs straight into
NAMOA\* and everything downstream), but the transitions are **MITRE ATT&CK techniques** between
hosts instead of CVE exploits:

- `Technique(technique_id, name, tactic, success, time, detection)` — an ATT&CK step.
- `IdentityHost` / `IdentityMove` / `IdentityScenario` — a spec for an AD estate + the attacker's
  credential moves; `build_identity_graph()` turns it into the canonical graph.
- Two new edge relations: `IDENTITY_INITIAL_ACCESS`, `CREDENTIAL_MOVE`. Every transition's
  **ATT&CK technique id + tactic** rides on both the `ExploitNode` (`mitre_technique_id`/
  `mitre_tactic`) and the edge metadata, so a recovered path reads as a kill chain.

## Measured — the AD kill chain recovered (2026-06-15)

`create_ad_kill_chain_scenario()` (4 hosts: phished workstation → file server → app/SQL server →
Domain Controller, the goal) → 11 nodes / 11 edges → NAMOA\* returns **2 Pareto-optimal
credential paths** to Domain Admin:

| # | Recovered kill chain (ATT&CK) | time | success | impact |
|---|---|---:|---:|---:|
| 1 | **T1566.001** Phish → **T1550.002** Pass-the-Hash → **T1021.001** RDP → DC | 11.9 | 0.195 | 9.5 |
| 2 | **T1566.001** Phish → **T1550.002** Pass-the-Hash → **T1558.003** Kerberoast → **T1003.006** DCSync → DC | 14.0 | **0.246** | 9.5 |

Both are valid **AD/credential lateral paths** ending in domain dominance — the Phase-5 exit
criterion ("an AD/credential lateral path appears in a testbed scenario"), met twice. The engine
surfaces the real operator tradeoff: route 1 is **faster but louder** (RDP straight to the DC);
route 2 is the **slower, higher-success credential chain** (Kerberoast a service account, then
DCSync the DC). Neither dominates the other on (time, success), so multi-objective Pareto keeps
both — exactly the value over single-objective ranking, now in the identity domain.

## Honest caveat (important)

Unlike the CVE edges (EPSS/KEV-grounded), **credential-technique costs are heuristic** — there is
no per-technique exploit-probability feed. The success/time priors are a documented calibration
target, flagged `heuristic=True` and `data_grounded=False` in **every** credential edge's
metadata (the same discipline as the lateral-movement prior, B3). **The contribution is the
modeling capability + ATT&CK provenance, not a data-grounded probability for credential
attacks.** Grounding these (e.g., from detection telemetry or red-team frequencies) is future
work; the B1–B8 sensitivity lesson applies — such priors move magnitude, and the prioritization
decision is driven by graph structure (here, the choke points every credential route crosses).
**Grounding seam (2026-06-15):** `build_identity_graph(..., frequencies=)` now accepts an observed
ATT&CK-technique frequency map that flips touched edges to `data_grounded=True`; no public source is
bundled so the default stays heuristic-flagged — see `C1_GROUNDING_NOTE.md`.

## Files

`core/identity_graph.py` (`Technique`, `IdentityHost/Move/Scenario`, `build_identity_graph`,
`create_ad_kill_chain_scenario`, `_identity_cost`), `tests/core/test_identity_graph.py` (6 tests).
Next in Phase 5: C2 cloud IAM, C3 misconfiguration, C4 BAS-lite/scoping; E1/E2/E3 ML-role honesty.
