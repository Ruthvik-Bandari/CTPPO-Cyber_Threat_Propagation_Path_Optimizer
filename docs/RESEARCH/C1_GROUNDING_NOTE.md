# C1 grounding note — credential-technique costs (optional follow-up)

**Optional follow-up to C1.** Roadmap: `05_OSS_REALTIME_PLAN.md` §Phase-5.
**Status: investigated 2026-06-15 — no public source available offline → costs remain
heuristic-flagged; a grounding seam was added for when one is.** Source: `core/identity_graph.py`.

## The ask

C1's credential-technique costs (success/time priors for Phish → PtH → DCSync, etc.) are honest
heuristics, flagged `heuristic=True` / `data_grounded=False`. The optional follow-up: **ground them
from detection telemetry or red-team frequencies if a source is available; else leave flagged.**

## What we found

**No detection-telemetry / red-team-frequency source is available offline.** The repo's `data/`
holds only `cve_cache` (NVD), `pignn` (the AD GNN dataset), and `threat_cache` (EPSS/KEV) — none
carry per-ATT&CK-technique success/prevalence frequencies. Public sources exist (e.g. the Red Canary
Threat Detection Report's technique prevalence, Picus/Recorded Future attack-frequency data), but
none are bundled or installable offline here, and **we will not hardcode frequencies from memory** —
that would be fabrication, which the project's honesty rule forbids.

**Decision: leave the C1 credential costs heuristic-flagged** (the existing, honest state).

## What we added (the grounding seam)

So that the priors become *groundable* the moment a real source appears — without ever faking
numbers — `build_identity_graph(scenario, frequencies=...)` now accepts an optional
`{ATT&CK technique id -> observed success frequency}` map:

- **Default (`frequencies=None`)** — byte-identical to before: every credential edge uses its
  heuristic `success` prior and is flagged `heuristic=True` / `data_grounded=False`.
- **With a frequency map** — a move whose technique id is in the map takes the **observed frequency**
  as its success prior, and its edge is flagged `data_grounded=True` with
  `grounding_source="observed technique frequency"`. Untouched techniques stay heuristic.

This is the same discipline as everywhere else in CTPPO: the seam is real and tested (with a
*clearly synthetic, test-only* map in `tests/core/test_identity_graph.py`), but the default stays
honest because no real frequency data is in hand. When a user has a Red Canary / red-team export,
they pass it as `frequencies=` and the touched edges flip to grounded automatically.

The B1–B8 lesson still applies: grounding these priors would move reachability *magnitude*, while
the prioritization *decision* is driven by graph structure (the choke points every credential route
crosses). And the C4 evidence grader already reports, per recovered path, how much rests on
data-grounded vs heuristic edges — so an operator can see exactly when grounding has (not) happened.

## Files

`core/identity_graph.py` (`_identity_cost(..., grounded_success=)`, `build_identity_graph(...,
frequencies=)`), `tests/core/test_identity_graph.py` (grounding-seam test). Same seam could be
mirrored to C2 cloud IAM / C3 misconfig if a corresponding source appears.
