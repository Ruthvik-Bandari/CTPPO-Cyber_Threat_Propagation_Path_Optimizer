# Reviewing OTRF candidate positives

The replay found OTRF process-creation events that supported SigmaHQ rules match. OTRF captures
are attack simulations recorded on hosts that also ran normal background activity, so a match
can be the attack, or something benign that happens to look like it. A person labels each
candidate before it counts as a positive in the benchmark (plan section 11).

## Files

`hpc/review_split.sbatch` writes these on the cluster, under `/scratch/$USER/aegis-sec/data/review/`.
The directory has mode 0700 and the files 0600.

| File | Content |
| --- | --- |
| `candidates.jsonl` | One line per candidate event: `event_id`, `dataset` (OTRF archive path), `fields` (the v1 Sysmon fields) and `rules` (every rule that matched it, with its title). |
| `labels.csv` | One row per candidate with the columns `event_id,label,rationale,reviewer`. It is created once and never overwritten. |

**Keep both files private.** They contain raw event values: command lines, paths and user names
from the recorded lab hosts.

- Review them on the cluster, or copy them to your own machine.
- Do not commit them.
- Do not paste them into an AI assistant session.
- Only the aggregate `reports/review-status.json` leaves the cluster.

`/scratch` is purged on the first Tuesday of each month. Copy `labels.csv` somewhere persistent
(your home directory or `/work`) after each review session.

## How to label

For each row in `labels.csv`:

| `label` | Use when |
| --- | --- |
| `malicious` | The event is part of the simulated attack in its dataset. The dataset's metadata (`datasets/atomic/_metadata/SDWIN-*.yaml`) describes the attack and its ATT&CK techniques. |
| `benign` | The event is normal activity: system services, updaters, the capture tooling itself, or an administrator action unrelated to the simulation. A benign match becomes a confounder for that rule, which is useful negative evidence. |
| `unknown` | You cannot tell from the event and the dataset description. |

Leave `label` empty for rows you have not reviewed yet.

- **`rationale`** is required for `malicious` and `benign`, up to 1,000 characters. Say what decided it, for example "child of the Covenant launcher in the dataset's attack chain" or "Windows Update service, starts every capture".
- **`reviewer`** holds your initials. It is required for every labeled row.

The plan also asks a second reviewer to label a sample, at least 10%, independently. Disagreements are then adjudicated. Record the second pass in a separate copy of the file.

## Checking progress

```bash
ssh explorer 'cd ~/aegis-sec && sbatch hpc/review_split.sbatch'
```

The job validates `labels.csv`. `reports/review-status.json` then holds:

- counts by label;
- the number of unreviewed rows;
- any invalid rows, given by row number and reason only;
- how many roots now have one, or two or more, verified positives.

A verified positive is either a SigmaHQ regression match or an event you labeled `malicious`.
The same job rewrites `reports/split-preview.json` using the current labels.

## Freezing the split

When review is complete, freeze the split once:

```bash
python -m aegisbench split --freeze --root /scratch/$USER/aegis-sec/data
```

It writes `benchmark/split-manifest.json` with each root rule's source SHA-256 and refuses to
overwrite an existing manifest. Copy the manifest, which holds ids and hashes only, into
`docs/data/` so the split is versioned with the code.
