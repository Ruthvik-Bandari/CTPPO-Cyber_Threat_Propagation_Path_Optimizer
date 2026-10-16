# QC results, 2026-10-14

This folder records the benchmark data checks in the order they ran. The JSON reports are from the latest runs: `python -m aegisbench qc` (Slurm job 11105891) and `python -m aegisbench replay` (job 11105959) on Explorer. The SigmaHQ section below describes the first run (job 11085056). They contain counts, reason codes, rule IDs and repository paths only, with no event values. Before reading anything, QC re-verified every file against its acquisition manifest.

| Source | Commit | Content SHA-256 (prefix) |
| --- | --- | --- |
| SigmaHQ `rules/windows/process_creation` and its `regression_data` | `552f3fee420e` | `dacdaa87c9f4` |
| OTRF `datasets/atomic/windows` and `_metadata` | `d9d40ef123d2` | `034b77c5b7e7` |
| Atomic Red Team `atomics/` | `388942adbd96` | `ba04ee420a90` |

## SigmaHQ

- 1,182 process_creation rules: 0 load errors, 0 missing IDs, 0 duplicate IDs and 0 exact duplicate detection blocks.
- Status: 1,075 `test`, 87 `experimental`, 20 `stable`.
- **192 rules (16%) fit the v1 subset.** The causes for the rest:

| Rules | Cause |
| --- | --- |
| 636 | A selection is a list of maps (OR of field maps), the most common SigmaHQ idiom |
| 161 | The `contains\|all` modifier |
| 86 | `1 of selection_*` conditions |
| 47 | `all of selection_*` conditions |
| 20 | The `windash` modifier |
| 12 | The `re` modifier |
| 11 | Null matching |
| 8 | Wildcards in values |

A rule can have several of these causes; each rule is counted once, under the first one found.

- 128 rules have positive regression data, giving 137 Sysmon EID 1 events in all. **Only 12 of the 192 supported rules have such data.**

## OTRF

Corrected on 2026-10-15 (Slurm job 11105891). OTRF reuses 37 archive names under several tactic folders, and every one of those archives has different contents. The first QC run keyed archives by file name, so it collapsed 155 archives into 118. QC now keys each archive by its path below `datasets/atomic/windows`.

- 100 Windows metadata files and 155 zip archives, covering 33 ATT&CK techniques.
- 788,932 records, of which 1,540 are Sysmon EID 1 (process creation). Those come from 107 archives.
- 13 archives have no metadata file. Two metadata links have no archive at this commit: `credential_access/host/cmd_copy_ntds_from_volume_shadow_copy` and `lateral_movement/network/empire_dcom_shellwindows_stager`.
- macOS `__MACOSX/._*` members are skipped, since they are not telemetry.

## Atomic Red Team

- 344 techniques and 1,878 tests, of which 1,260 run on Windows.
- Windows executors: 689 PowerShell, 562 command prompt, 9 manual.
- These test definitions are data only; none of them has been run.

## After ADR 0002 (Slurm job 11086173)

[ADR 0002](../../adr/0002-sigma-subset-common-idioms.md) widened the subset to lists of field maps, `|all`, and `1 of` / `all of`. QC now also requires each supported rule to convert with the pinned pySigma Lucene backend.

- **997 of 1,182 rules (84%) are supported, and every one of them converts.** Before the change, 192 rules were supported.
- **101 supported rules have SigmaHQ positive regression events.** Before the change, 12 did.
- The 185 remaining rules are excluded for these reasons:
  - `windash` (78)
  - `re` (41)
  - null matching (23)
  - wildcards (21)
  - value-count and empty-value limits (17)
  - `base64offset` (4)
  - more than 16 alternative maps (1)

## Replay on the pinned engine (Slurm job 11105959, 2026-10-15)

`python -m aegisbench replay` (`hpc/replay.sbatch`) ran Elasticsearch 8.19.3 on a compute node. It loaded one disposable index with 137 SigmaHQ regression events and 1,540 OTRF process-creation events, reduced to the v1 fields. Every supported rule was then replayed against that index. `replay-positives.json` lists, for each rule, its own regression matches, SigmaHQ's declared match count, any other regression events it matched, and its OTRF candidate events and dataset paths. It holds no field values.

- **997 rules replayed, 0 engine errors.**
- **Fidelity: 83 of 83 rules match exactly the number of events SigmaHQ declares (`match_count`).** Single-rule regression folders are the only ones with an unambiguous declared count. Two regression files hold 3 recorded events each but declare one match, and the replay found exactly one for each. The extra events are context, not missed detections.
- **176 rules have at least one positive event.**
  - 91 have only their own regression events.
  - 75 have only OTRF candidates.
  - 10 have both.
- **43 rules have two or more positive events.** The number of positive events per rule is:

| Positive events | Rules |
| --- | --- |
| 1 | 133 |
| 2 | 19 |
| 3 | 9 |
| 4 | 6 |
| 5 | 2 |
| 6 | 1 |
| 10 or more | 6 |

An OTRF match is a *candidate* positive. OTRF captures are attack simulations recorded on hosts that also ran background activity, so a match can be benign. Each candidate needs a reviewer's label (malicious, benign or unknown) before it enters the benchmark. Rules with many candidates (up to 46 events) are the most likely to include benign matches.

## What this means for the benchmark

The plan targets 60 clean roots with at least two attack variants each "where feasible". After the subset widening and the replay:

- **43 roots have two or more positive events** (own regression events plus unreviewed OTRF candidates).
- **176 roots have at least one.**

To reach 60 roots with two variants, the remaining options are:

1. Review the OTRF candidates. This both confirms the 43 roots and shows which candidates are benign; benign candidates become confounders.
2. Accept roots with a single verified positive. Record them as single-variant roots and report results separately.
3. Add a second variant by authoring a documented synthetic event for each single-positive root, labeled with provenance `synthetic`, and report those results separately.
4. Capture Atomic Red Team runs in an authorized, isolated lab (`policy.md` section 7). Those would be labeled `lab_introduced`.

## Review sheet and split preview (Slurm jobs 11107577 and 11107581, 2026-10-15)

- **The review sheet holds 175 distinct OTRF candidate events, matched by 85 rules across 73 archives.** It is written privately on the cluster. How to label it is in [`../review.md`](../review.md).
- **Before any review**, only SigmaHQ regression matches count as verified positives:
  - 101 roots have at least one verified positive;
  - 3 have two or more.
- **The split preview** (`split-preview.json`, seed `aegis-bench-v1`) puts roots in the same group when they share a rule family or a positive event:
  - test: 12 roots in 10 groups;
  - development: 12 roots in 6 groups;
  - train: 37 roots in 25 groups;
  - reserve: 40 roots in 14 groups.

  Train has 37 roots rather than 36 because groups are never split. The largest group is 19 `wmic` rules, which landed in reserve.
- The preview is not frozen. It changes once labels are added, and it is frozen only after review is complete.

## Impairment variants from the split preview (Slurm job 11108295, 2026-10-15)

`python -m aegisbench variants` (`hpc/variants.sbatch`) injected faults into every root in the preview split. It verified each one on the pinned engine. The aggregate report is `variants.json`; the case folders hold raw events and stay private on the cluster.

- **153 cases from 61 roots, with no root left without a variant.** By fault:
  - logic: 61;
  - mapping drift: 46;
  - missing telemetry: 46.
- By split: test 32, development 28 and train 93.
- **Discarded because the fault did not change engine behavior:**
  - 29 logic edits;
  - 15 mapping faults and 15 missing-telemetry faults. These are mostly rules whose preferred field is not what decides the match.
- **144 of the 153 cases have no validation suite.** Their root has a single verified positive, so there is no independent attack event to hold out. The workflow reports their repairs as provisional.

Only reviewed OTRF positives, or documented synthetic second variants, can close that gap. This run used the unreviewed preview, so the cases are regenerated after review and the split freeze.

## First baselines: B0 and B1 (Slurm jobs 11138719, 11138730, 11138731, 2026-10-16)

The variants were regenerated with healthy controls and the fairness rule that every fault must lose a detection. That gave 214 cases: 61 healthy, 61 logic, 46 mapping and 46 missing telemetry. B0 and B1 then ran on the 170 train and development cases from 49 roots. The test split was not read. The full results are in `comparison.md`.

| System | Validated success | Outcome match (incl. provisional) | Wrong change | Abstained |
| --- | --- | --- | --- | --- |
| B0 | 0.529 (95% CI 0.494–0.574) | 0.988 | 0.000 | 0.006 |
| B1 | 0.529 | 0.988 | 0.000 | 0.006 |

Outcome match by fault, for both systems:

- healthy 1.00;
- logic 1.00;
- mapping 0.97;
- missing telemetry 0.97.

**What this shows.**

1. **The synthetic benchmark is too easy for B0, and it is circular.**
   - The logic faults are made with the same one-edit condition mutations that B0 searches, so B0 always finds the inverse edit.
   - The mapping faults use a stale `winlog.event_data.*` name, while the right field is observed in the data, which is exactly B0's alternative-field diagnosis.
   - With the deterministic baseline at 0.99 outcome match, B1, B2 and M1 have no room to show a gain on these faults. This is the measured gap gate in plan section 12: M1 is not justified on this benchmark.
2. **Validated success is capped by evidence, not by repair ability.** 78 of 84 repairs were correct but provisional, because their root has a single verified positive and no validation suite. Reviewed OTRF positives raise this number directly.
3. **The next benchmark needs faults B0 does not generate:**
   - natural maintenance faults mined from SigmaHQ's own history, where a rule was later fixed (plan section 11 provenance `natural`);
   - multi-edit faults;
   - mappings where the replacement field is renamed differently from the stale one.
