# Phase 4 — continuous-improvement loop

**Roadmap:** `05_OSS_REALTIME_PLAN.md` §Phase-4. **Status: harness + A2/A4 DONE (2026-06-15);
scheduled agent = opt-in setup below.** The loop has two halves: a **repo harness** that
re-proves the engine's value on every run, and a **scheduled agent** that drives it and reports.

## Half 1 — the repo harness (`evaluation/continuous_eval.py`)

On each run: pull the **latest threat data** (online `ThreatDataProvider` → auto-refreshes a
stale EPSS/KEV cache, the 3a feeds) → rebuild the evaluation networks → re-run **NAMOA\* + the
A4 baselines** (`evaluation/baseline_study.py`, neutral generator) → record the headline metrics
to a **timeseries** (`evaluation/history/continuous_eval_history.json`) → **flag regressions**.
Each record stamps the feed provenance/staleness, tying the metric to the data it was computed on.

**Tracked metrics:** `pareto_recovery`, `cvss_recovery`, `epss_recovery`, `pareto_ge_cvss`,
`pareto_gt_cvss` (oracle-reduction recovery + win-rate vs CVSS).

**Regression =** a metric below its absolute **floor** (`pareto_recovery` < 0.60,
`pareto_ge_cvss` < 0.70) **or** a **drop** beyond tolerance vs the previous run
(`pareto_recovery`/`pareto_ge_cvss` > 0.10, `pareto_gt_cvss` > 0.15). Exit code is non-zero on
any regression (cron-mail / CI / agent friendly).

**Verified (2026-06-15):**
- Real run: `pareto_recovery=0.909`, `cvss=0.435`, `epss=0.433`, `pareto≥cvss=0.923` (n=39);
  all three feeds stamped `fresh`; exit 0, no regressions.
- **Injected-regression exit criterion:** `--inject-regression` forces `pareto_recovery=0.0` →
  the harness flags *"pareto_recovery=0.000 below floor 0.60"* and **exits 1**. The loop catches
  a regression rather than letting it rot silently.

```bash
./scripts/continuous-eval.sh                 # one cycle (online, latest data)
python3 evaluation/continuous_eval.py --offline --n 60
./scripts/continuous-eval.sh --inject-regression --history /tmp/h.json   # demo a caught regression
# unattended (local cron):
#   0 7 * * *  /path/to/CTPPO/scripts/continuous-eval.sh >> /tmp/ctppo-eval.log 2>&1
```

## Half 2 — the scheduled agent

The agent half fires the harness on a schedule, reads the history/exit code, and reports. Two
ways, with an honest constraint:

**Local cron (works now, recommended).** The harness reads the local repo + EPSS cache and
appends to the local history — exactly what an unattended local agent needs:

```cron
0 7 * * *  /path/to/CTPPO/scripts/continuous-eval.sh >> /tmp/ctppo-eval.log 2>&1
```

**Cloud `/schedule` routine (requires setup).** `/schedule` agents run in Anthropic's cloud with
their **own git checkout** — they cannot see local files, the local EPSS cache, or persist the
local history. So a cloud routine needs, first: (1) this work **committed + pushed** to GitHub
(as of 2026-06-15 the repo's `main` has no upstream and the harness is uncommitted — a cloud
checkout would not contain it), (2) the **Claude GitHub App installed** on the repo, and (3) the
cloud env provisioned with the deps + a way to **persist history** (commit it, or post results
out). Until (1)+(2) are done a cloud routine would fail every run, so it is **not** created here.
The verified, working unattended path today is the local cron above. Recipe for the cloud prompt:

> In the CTPPO repo, run `./scripts/continuous-eval.sh`. If it exits non-zero (a regression),
> summarize the flagged metrics + the latest two history records (which metric dropped, feed
> as_of dates) and report; else report one healthy line with the current `pareto_recovery`.

## A2 + A4 results

The harness's metric is the A2/A4 study — see **`A2_A4_BASELINES.md`** and METRICS §8. Headline:
on a **neutral (un-stacked)** generator, Pareto still recovers **~85%** of oracle reduction vs
**~33–37%** for CVSS/EPSS/risk/MulVAL-style — the advantage is **not** a stacking artifact (it is
path/choke-point awareness). Honest caveats there (metric aligned with path-awareness; synthetic
per-edge CVSS; one topology family).

## Exit criterion

- ✅ harness runs unattended with tracked history (`continuous_eval_history.json`) and **catches an
  injected regression** (exit 1).
- ◻ agent fires and reports — opt-in via `/schedule` (above); the harness it drives is ready.

## Files

`evaluation/continuous_eval.py`, `evaluation/baseline_study.py`, `scripts/continuous-eval.sh`,
`tests/evaluation/test_continuous_eval.py` + `test_baseline_study.py`, `A2_A4_BASELINES.md`.
