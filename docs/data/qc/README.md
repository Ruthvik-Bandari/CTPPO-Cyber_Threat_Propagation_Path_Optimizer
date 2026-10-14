# QC results, 2026-10-14

The aggregate reports in this folder come from `python -m aegisbench qc` (Slurm job 11085056 on Explorer). They contain counts, reason codes, rule IDs and repository paths only, with no event values. Before reading anything, QC re-verified every file against its acquisition manifest.

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

- 100 Windows metadata files and 118 zip archives, covering 33 ATT&CK techniques.
- 586,275 records, of which 1,216 are Sysmon EID 1 (process creation). Those come from 74 archives.
- 9 archives have no metadata file. One metadata link (`cmd_copy_ntds_from_volume_shadow_copy.zip`) has no archive at this commit.
- macOS `__MACOSX/._*` members are skipped, since they are not telemetry.

## Atomic Red Team

- 344 techniques and 1,878 tests, of which 1,260 run on Windows.
- Windows executors: 689 PowerShell, 562 command prompt, 9 manual.
- These test definitions are data only; none of them has been run.

## What this means for the benchmark

The plan targets 60 clean roots, each with at least 2 attack variants. Under v1 semantics there are 192 candidate rules, but only 12 come with ready-made positive events. There are two ways to close the gap (plan section 18, scope adjustment gates):

1. Find positives for the other supported rules by replaying OTRF EID 1 events on the pinned engine, and supplement them with documented, labeled lab captures.
2. Widen the v1 subset to cover list-of-maps selections, `contains|all`, and `1 of`/`all of` quantifiers. These are all single-event semantics, and together they account for most of the excluded rules. Widening would change the shipped parser and the candidate contract, so it needs an ADR.
